//! Fixed once-per-hand protection for both owner materializations.
use crate::{CompilerError, PlannedState, settlement::{SettlementGraph, build_origin_escrow}};
use bitcoin::{Amount, OutPoint, TxOut, secp256k1::XOnlyPublicKey};
use poker_bitcoin::{ActionProgram, CompiledTaprootState, LeafProgram, TransactionTemplate,
    channel::{ContestOutput, RevocationGuard}};
use poker_settlement_types::{Action, NodeId, Role};
use std::collections::{HashMap, HashSet};

fn invalid(reason: &'static str) -> CompilerError { CompilerError::Preparation { reason } }

/// All public retirement commitments for one owner materialization. Secrets are
/// held by each incoming edge's authorizer, not by the materialization owner.
#[derive(Clone)]
pub struct ChannelProtection {
    pub(crate) owner: Role,
    pub(crate) contest_blocks: u16,
    pub(crate) hand_commitment: [u8; 32],
    pub(crate) branches: HashMap<NodeId, ([u8; 32], Role)>,
}

impl SettlementGraph {
    /// Attach an independently agreed public commitment for every non-root node.
    /// Entries use plan preorder, omitting only the root. Authorizer ownership is
    /// derived here from the actual incoming action/timeout, never peer metadata.
    ///
    /// # Errors
    /// Rejects missing/reused commitments, invalid roles, delay overflow or late
    /// attempts to change a materialization that already has protection.
    pub fn with_channel_protection(mut self, owner: Role, contest_blocks: u16,
        hand_commitment: [u8; 32], commitments: &[[u8; 32]],
    ) -> Result<Self, CompilerError> {
        if self.channel.is_some() || contest_blocks == 0
            || commitments.len() + 1 != self.plan().nodes.len() {
            return Err(invalid("invalid channel protection inventory"));
        }
        let mut hashes = HashSet::new();
        hashes.insert(hand_commitment);
        for hash in commitments {
            if *hash == [0; 32] || !hashes.insert(*hash) { return Err(invalid("reused channel retirement commitment")); }
        }
        if hand_commitment == [0; 32] { return Err(invalid("zero hand commitment")); }
        let mut authors = HashMap::new();
        for node in &self.plan().nodes {
            for edge in &node.edges {
                let author = if let Some(timeout) = edge.timeout {
                    timeout.csv.checked_add(contest_blocks).ok_or_else(|| invalid("channel timeout overflow"))?;
                    timeout.beneficiary
                } else {
                    match node.state {
                        PlannedState::Betting { state, .. } => state.actor,
                        PlannedState::Reveal { pattern, .. } => pattern.revealer(),
                        PlannedState::AliceShowdown { .. } => Role::Alice,
                        PlannedState::BobTerminal { .. } => Role::Bob,
                        PlannedState::Terminal(_) => return Err(invalid("terminal has outgoing edge")),
                    }
                };
                if authors.insert(edge.child_node_id, author).is_some() { return Err(invalid("channel graph is not a tree")); }
            }
        }
        let branches = self.plan().nodes.iter().filter(|n| n.node_id != self.plan().root_node_id)
            .zip(commitments).map(|(node, hash)| {
                Ok((node.node_id, (*hash, *authors.get(&node.node_id).ok_or_else(|| invalid("missing channel edge"))?)))
            }).collect::<Result<HashMap<_, _>, CompilerError>>()?;
        self.payout_projection.take();
        self.channel = Some(ChannelProtection { owner, contest_blocks, hand_commitment, branches });
        Ok(self)
    }

    /// Delay applicable to ordinary transitions out of this state. The gameplay
    /// root follows the separate hand-entry gate and has no incoming branch.
    #[must_use]
    pub fn contest_delay(&self, node: NodeId) -> u16 {
        self.channel.as_ref().filter(|_| node != self.plan().root_node_id)
            .map_or(0, |c| c.contest_blocks)
    }

    /// Public justice condition for an incoming branch.
    pub fn branch_guard(&self, node: NodeId) -> Result<Option<RevocationGuard>, CompilerError> {
        let Some(c) = &self.channel else { return Ok(None); };
        if node == self.plan().root_node_id { return Ok(None); }
        let (commitment, author) = c.branches.get(&node).ok_or_else(|| invalid("missing branch guard"))?;
        Ok(Some(RevocationGuard { contest_blocks: c.contest_blocks, commitment: *commitment,
            counterparty: self.identity_keys[usize::from(author.other().code())] }))
    }

    pub(crate) fn preparation_payouts(&self, node: NodeId) -> Result<Vec<TxOut>, CompilerError> {
        let PlannedState::Terminal(t) = self.node(&node).ok_or_else(|| invalid("missing payout node"))?.state else {
            return Err(invalid("nonterminal payout"));
        };
        if self.channel.is_none() { return self.outputs(node); }
        let guard = self.branch_guard(node)?.ok_or_else(|| invalid("payout lacks guard"))?;
        [t.alice_output_sat, t.bob_output_sat].into_iter().enumerate().filter(|(_, value)| *value != 0)
            .map(|(role, value)| {
                use bitcoin::{script::Builder, opcodes::all::OP_CHECKSIG};
                let script = Builder::new().push_x_only_key(&self.identity_keys[role]).push_opcode(OP_CHECKSIG).into_script();
                Ok(TxOut { value: Amount::from_sat(value), script_pubkey:
                    ContestOutput::signing_output(&self.secp, &script, guard).map_err(|_| invalid("invalid protected payout"))? })
            }).collect()
    }

    /// Entry gate protects retirement of the whole owner's previous hand.
    pub fn hand_gate(&self) -> Result<CompiledTaprootState, CompilerError> {
        let c = self.channel.as_ref().ok_or_else(|| invalid("not a channel hand"))?;
        let program = LeafProgram::Action(ActionProgram::new(self.plan().chain_game_id,
            self.plan().root_node_id, Action::Check, self.identities())?);
        Ok(CompiledTaprootState::compile_contested(&self.secp,
            self.plan().chain_game_id, &[program], RevocationGuard {
                contest_blocks: c.contest_blocks, commitment: c.hand_commitment,
                counterparty: XOnlyPublicKey::from_slice(&self.identities()[usize::from(c.owner.other().code())])
                    .map_err(|_| invalid("invalid hand justice key"))?,
            })?)
    }

    /// Owner's commitment spends the permanent channel funding output. Give the
    /// owner only the peer signature; never send a complete root to its peer.
    pub fn hand_commitment(&self, funding: TxOut, fee: u64) -> Result<TransactionTemplate, CompilerError> {
        if funding.script_pubkey != build_origin_escrow(self.identities())?.script_pubkey() {
            return Err(invalid("wrong channel funding script"));
        }
        let value = funding.value.to_sat().checked_sub(fee).ok_or_else(|| invalid("insufficient channel funding"))?;
        Ok(TransactionTemplate::normal(self.parameters.network, self.parameters.origin, funding,
            vec![TxOut { value: Amount::from_sat(value), script_pubkey: self.hand_gate()?.script_pubkey() }], fee)?)
    }

    pub(crate) fn channel_activation(&self, funding: TxOut, fee: u64) -> Result<TransactionTemplate, CompilerError> {
        let c = self.channel.as_ref().ok_or_else(|| invalid("not a channel hand"))?;
        let commitment = self.hand_commitment(funding, fee)?;
        Ok(TransactionTemplate::timeout(self.parameters.network, OutPoint::new(commitment.transaction().compute_txid(), 0),
            commitment.transaction().output[0].clone(), self.outputs(self.plan().root_node_id)?, fee, c.contest_blocks)?)
    }

    /// A terminal payout remains contestable; an immediate key-path payout would
    /// let an abandoned fold/timeout/score escape the penalty window.
    pub fn guarded_payout(&self, node: NodeId, recipient: Role) -> Result<ContestOutput, CompilerError> {
        use bitcoin::{script::Builder, opcodes::all::OP_CHECKSIG};
        let guard = self.branch_guard(node)?.ok_or_else(|| invalid("payout lacks channel guard"))?;
        let key = XOnlyPublicKey::from_slice(&self.identities()[usize::from(recipient.code())])
            .map_err(|_| invalid("invalid payout key"))?;
        let script = Builder::new().push_x_only_key(&key).push_opcode(OP_CHECKSIG).into_script();
        ContestOutput::new(&self.secp, &script, guard.contest_blocks,
            guard.commitment, guard.counterparty).map_err(|_| invalid("invalid protected payout"))
    }
}
