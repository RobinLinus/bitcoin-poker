//! Dlog settlement uses the same complete finite poker topology as the reference
//! planner. No legacy deal, hash preimage, or cooperative-close leaf is involved.
use crate::{
    CompilerError,
    graph::{LogicalGraphPlan, PlannedState, compile_rules_graph},
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
use bp52_chain_bitcoin::{
    ActionProgram, AliceShowdownProgram, BobPayoutProgram, CompiledTaprootState, DlogRevealProgram,
    FeePolicy, LeafProgram, TimeoutProgram, TransactionTemplate, validate_network_identity,
};
use bp52_chain_types::{EdgeKind, NodeId, PokerRules, root_node_id, tagged_sha256};
use bp52_lamport::LamportPublicKey;
use dlog52_protocol::{VerifiedAcceptedDeal, accepted_body_hash};
use std::collections::{HashMap, HashSet};

/// One artifact that must be verified and stored before activation.
#[derive(Clone, Debug)]
pub enum DlogAuthorizationRequest {
    /// Exact opponent signature; the actor or timeout beneficiary signs live.
    Signature {
        /// Parent node.
        node_id: NodeId,
        /// Canonical outgoing edge index.
        edge_index: usize,
        /// Required preauthorizing identity role.
        signer: bp52_chain_types::Role,
        /// Exact BIP341 digest.
        sighash: [u8; 32],
    },
    /// Full 52-candidate package under the distinct slot-specific key.
    Reveal(Box<dlog52_bitcoin::reveal::RevealContext>),
}

/// Two-identity origin escrow used before dealing has a game ID.
pub fn origin_state(identities: [[u8; 32]; 2]) -> Result<CompiledTaprootState, CompilerError> {
    let id = tagged_sha256("DLOG52/origin-escrow/v1", &identities.concat());
    let program = LeafProgram::Action(ActionProgram::new(
        id,
        root_node_id(&id),
        bp52_chain_types::Action::Check,
        identities,
    )?);
    Ok(CompiledTaprootState::compile(
        &Secp256k1::verification_only(),
        id,
        &[program],
    )?)
}

fn invalid(reason: &'static str) -> CompilerError {
    bp52_chain_types::ChainError::InvalidLogicalRecord { reason }.into()
}

/// Pre-deal application parameters committed by the authenticated rules hash.
#[derive(Clone, Debug)]
pub struct DlogParameters {
    /// Regtest or Signet address/transaction family.
    pub network: Network,
    /// Genesis identifier, or full-challenge-bound custom Signet identifier.
    pub network_id: [u8; 32],
    /// Pre-existing origin escrow, not the later gameplay root.
    pub origin: OutPoint,
    /// Poker amounts and deadlines.
    pub rules: PokerRules,
    /// Exact fee policy identifier.
    pub fee_policy_id: [u8; 32],
    /// Opponent-controlled adaptor authorizers indexed by revealer then slot.
    pub reveal_keys: [[[u8; 32]; 9]; 2],
}

impl DlogParameters {
    /// Commit every pre-deal parameter using a fixed-width, versioned encoding.
    pub fn rules_hash(&self) -> Result<[u8; 32], CompilerError> {
        self.rules.validate()?;
        if !matches!(self.network, Network::Regtest | Network::Signet) {
            return Err(invalid("dlog on-chain profile requires regtest or Signet"));
        }
        validate_network_identity(self.network_id, self.network)?;
        if self.origin.is_null() || self.fee_policy_id == [0; 32] {
            return Err(invalid("missing dlog funding or fee binding"));
        }
        let r = self.rules;
        let mut bytes = self.network_id.to_vec();
        bytes.extend(bitcoin::consensus::serialize(&self.origin));
        bytes.extend(self.fee_policy_id);
        bytes.extend([
            r.button.code(),
            r.max_bets_per_street,
            r.reveal_order.flop_first.code(),
            r.reveal_order.turn_first.code(),
            r.reveal_order.river_first.code(),
            r.timeout_policy.code(),
            r.split_remainder_recipient.code(),
        ]);
        for value in [
            r.unit_sat,
            r.alice_starting_stack_sat,
            r.bob_starting_stack_sat,
            r.fee_reserve_sat,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [r.action_csv, r.reveal_csv, r.showdown_csv] {
            bytes.extend(value.to_le_bytes());
        }
        let mut seen = HashSet::new();
        for role in self.reveal_keys {
            for key in role {
                XOnlyPublicKey::from_slice(&key)
                    .map_err(|_| invalid("invalid dlog reveal authorizer"))?;
                if !seen.insert(key) {
                    return Err(invalid("reused dlog reveal authorizer"));
                }
                bytes.extend(key);
            }
        }
        Ok(tagged_sha256("DLOG52/onchain-poker-rules/v1", &bytes))
    }

    /// Session anchor binds dealing to the already-known escrow outpoint.
    pub fn session_anchor(&self) -> [u8; 32] {
        tagged_sha256(
            "DLOG52/onchain-origin/v1",
            &bitcoin::consensus::serialize(&self.origin),
        )
    }

    /// Derive the game context before constructing its root-bound score keys.
    pub fn chain_id(&self, deal: &VerifiedAcceptedDeal) -> Result<[u8; 32], CompilerError> {
        let rules_hash = self.rules_hash()?;
        let config = deal.game_config();
        if config.rules_hash != rules_hash
            || config.session_anchor != self.session_anchor()
            || config.network_genesis
                != bitcoin::blockdata::constants::genesis_block(self.network)
                    .block_hash()
                    .to_byte_array()
        {
            return Err(invalid(
                "dlog accepted deal does not bind these chain parameters",
            ));
        }
        let mut forbidden: HashSet<_> =
            [config.identity_a, config.identity_b].into_iter().collect();
        for slot in &deal.catalogue().keys {
            for point in slot {
                forbidden.insert(
                    dlog52_protocol::point_xonly(point)
                        .map_err(|_| invalid("invalid dlog catalogue"))?,
                );
            }
        }
        if self
            .reveal_keys
            .iter()
            .flatten()
            .any(|key| forbidden.contains(key))
        {
            return Err(invalid(
                "reveal authorizer overlaps an identity or candidate key",
            ));
        }
        let mut bytes = accepted_body_hash(&deal.as_deal().body).to_vec();
        bytes.extend(rules_hash);
        Ok(tagged_sha256("DLOG52/onchain-poker-game/v1", &bytes))
    }
}

/// Complete logical tree with deterministic, on-demand Bitcoin materialization.
/// Scripts are rebuilt per node so the full tree does not retain gigabytes of
/// repeated candidate catalogues. Funding still requires exchanging every exact
/// transaction preauthorization and adaptor package before activation.
pub struct DlogGraph<'a> {
    deal: &'a VerifiedAcceptedDeal,
    parameters: DlogParameters,
    plan: LogicalGraphPlan,
    indices: HashMap<NodeId, usize>,
    scores: [LamportPublicKey; 2],
    identities: [[u8; 32]; 2],
}

impl<'a> DlogGraph<'a> {
    /// Compile every betting, reveal, showdown, fold and timeout branch.
    pub fn compile(
        deal: &'a VerifiedAcceptedDeal,
        parameters: DlogParameters,
        fees: &dyn FeePolicy,
        scores: [LamportPublicKey; 2],
    ) -> Result<Self, CompilerError> {
        let id = parameters.chain_id(deal)?;
        if fees.policy_id() != parameters.fee_policy_id {
            return Err(CompilerError::FeePolicyMismatch);
        }
        let plan = compile_rules_graph(&parameters.rules, id, fees)?;
        let indices = plan
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.node_id, i))
            .collect();
        let identities = [deal.game_config().identity_a, deal.game_config().identity_b];
        let mut score_hashes = HashSet::new();
        for key in &scores {
            for hash in key.public_hash_pairs().iter().flatten() {
                if !score_hashes.insert(*hash) {
                    return Err(invalid("score keys reuse a Lamport hash"));
                }
            }
        }
        // Constructors enforce both score-key purposes and the game-root context.
        AliceShowdownProgram::new_dlog(deal, id, root_node_id(&id), scores[0].clone(), identities)?;
        BobPayoutProgram::new_dlog(
            deal,
            id,
            root_node_id(&id),
            root_node_id(&id),
            bp52_chain_types::ShowdownOutcome::Split,
            scores[0].clone(),
            scores[1].clone(),
            identities,
        )?;
        Ok(Self {
            deal,
            parameters,
            plan,
            indices,
            scores,
            identities,
        })
    }

    /// Full unpruned semantic graph, including forced all-in runouts.
    pub fn plan(&self) -> &LogicalGraphPlan {
        &self.plan
    }

    /// Canonical identities authenticated by accepted-deal replay.
    pub fn identities(&self) -> [[u8; 32]; 2] {
        self.identities
    }

    /// Activation is fixed before the authorization exchange; its txid is
    /// independent of both funding signatures.
    pub fn activation(
        &self,
        origin_output: TxOut,
        fee_sat: u64,
    ) -> Result<TransactionTemplate, CompilerError> {
        if origin_output.script_pubkey != origin_state(self.identities)?.script_pubkey() {
            return Err(invalid("origin output is not the agreed dlog escrow"));
        }
        Ok(TransactionTemplate::normal(
            self.parameters.network,
            self.parameters.origin,
            origin_output,
            self.outputs(self.plan.root_node_id)?,
            fee_sat,
        )?)
    }

    /// Stream the complete authorization inventory in canonical preorder.
    /// The caller must durably store and verify every response before signing
    /// activation. Runtime state advances only after confirmed transactions.
    pub fn visit_authorizations(
        &self,
        activation: &TransactionTemplate,
        mut visitor: impl FnMut(DlogAuthorizationRequest) -> Result<(), CompilerError>,
    ) -> Result<(), CompilerError> {
        let expected = self.activation(activation.parent_output().clone(), activation.fee_sat())?;
        if expected.transaction() != activation.transaction() {
            return Err(invalid("foreign dlog activation"));
        }
        let mut outpoints = HashMap::new();
        outpoints.insert(
            self.plan.root_node_id,
            OutPoint::new(activation.transaction().compute_txid(), 0),
        );
        for node in &self.plan.nodes {
            if node.edges.is_empty() {
                continue;
            }
            let parent = outpoints
                .remove(&node.node_id)
                .ok_or(CompilerError::DanglingNode)?;
            let state = self.state(node.node_id)?;
            for (edge_index, edge) in node.edges.iter().enumerate() {
                let template = self.transition(node.node_id, edge_index, parent)?;
                if !matches!(
                    self.plan.nodes[self.index(edge.child_node_id)?].state,
                    PlannedState::Terminal(_)
                ) {
                    outpoints.insert(
                        edge.child_node_id,
                        OutPoint::new(template.transaction().compute_txid(), 0),
                    );
                }
                let leaf = state
                    .leaf(self.program(node.node_id, edge_index)?.predicate_id())
                    .ok_or(CompilerError::DanglingNode)?;
                let sighash = bp52_chain_bitcoin::taproot_script_sighash_default(
                    template.transaction(),
                    0,
                    std::slice::from_ref(template.parent_output()),
                    leaf.script(),
                )?;
                if matches!(
                    edge.kind,
                    EdgeKind::HoleCardReveal { .. } | EdgeKind::CommunityReveal { .. }
                ) {
                    let PlannedState::Reveal { pattern, .. } = node.state else {
                        return Err(invalid("invalid reveal node"));
                    };
                    let role = pattern.revealer().code();
                    for &slot in pattern.slots() {
                        let body = &self.deal.as_deal().body;
                        let commitment = if role == 0 {
                            body.commitments_a[usize::from(slot)]
                        } else {
                            body.commitments_b[usize::from(slot)]
                        };
                        visitor(DlogAuthorizationRequest::Reveal(Box::new(
                            dlog52_bitcoin::reveal::RevealContext {
                                deal_id: accepted_body_hash(body),
                                graph_id: self.plan.chain_game_id,
                                node_id: node.node_id,
                                revealer: role,
                                slot,
                                authorizer: self.parameters.reveal_keys[usize::from(role)]
                                    [usize::from(slot)],
                                sighash,
                                commitment,
                            },
                        )))?;
                    }
                } else {
                    use bp52_chain_types::Role;
                    let actor = if let Some(timeout) = edge.timeout {
                        timeout.beneficiary
                    } else {
                        match node.state {
                            PlannedState::Betting { state, .. } => state.actor,
                            PlannedState::AliceShowdown { .. } => Role::Alice,
                            PlannedState::BobTerminal { .. } => Role::Bob,
                            _ => return Err(invalid("invalid signed dlog transition")),
                        }
                    };
                    visitor(DlogAuthorizationRequest::Signature {
                        node_id: node.node_id,
                        edge_index,
                        signer: actor.other(),
                        sighash,
                    })?;
                }
            }
        }
        if !outpoints.is_empty() {
            return Err(invalid("unvisited dlog transaction branch"));
        }
        Ok(())
    }

    fn index(&self, id: NodeId) -> Result<usize, CompilerError> {
        self.indices
            .get(&id)
            .copied()
            .ok_or(CompilerError::DanglingNode)
    }

    /// Compile one exact outgoing predicate; no witness-free progression exists.
    pub fn program(
        &self,
        node_id: NodeId,
        edge_index: usize,
    ) -> Result<LeafProgram, CompilerError> {
        let node = &self.plan.nodes[self.index(node_id)?];
        let edge = node
            .edges
            .get(edge_index)
            .ok_or(CompilerError::DanglingNode)?;
        let id = self.plan.chain_game_id;
        Ok(match edge.kind {
            EdgeKind::Action(action) => {
                LeafProgram::Action(ActionProgram::new(id, node_id, action, self.identities)?)
            }
            EdgeKind::HoleCardReveal { .. } | EdgeKind::CommunityReveal { .. } => {
                let PlannedState::Reveal { pattern, .. } = node.state else {
                    return Err(invalid("non-reveal state"));
                };
                let role = usize::from(pattern.revealer().code());
                let slots: Vec<_> = pattern
                    .slots()
                    .iter()
                    .map(|&slot| (slot, self.parameters.reveal_keys[role][usize::from(slot)]))
                    .collect();
                LeafProgram::DlogReveal(DlogRevealProgram::new(
                    accepted_body_hash(&self.deal.as_deal().body),
                    node_id,
                    self.identities[role],
                    &slots,
                )?)
            }
            EdgeKind::AliceShowdown => LeafProgram::AliceShowdown(AliceShowdownProgram::new_dlog(
                self.deal,
                id,
                node_id,
                self.scores[0].clone(),
                self.identities,
            )?),
            EdgeKind::BobPayout(outcome) => LeafProgram::BobPayout(BobPayoutProgram::new_dlog(
                self.deal,
                id,
                node_id,
                node.parent_node_id.ok_or(CompilerError::DanglingNode)?,
                outcome,
                self.scores[0].clone(),
                self.scores[1].clone(),
                self.identities,
            )?),
            EdgeKind::Timeout(_) => LeafProgram::Timeout(TimeoutProgram::new(
                id,
                node_id,
                edge.timeout.ok_or_else(|| invalid("missing timeout"))?.csv,
                self.identities,
            )?),
            EdgeKind::Advance { .. } => {
                return Err(invalid(
                    "on-chain dlog graph cannot contain witness-free advancement",
                ));
            }
        })
    }

    /// Build a complete Taproot state, including every available timeout.
    pub fn state(&self, node_id: NodeId) -> Result<CompiledTaprootState, CompilerError> {
        let node = &self.plan.nodes[self.index(node_id)?];
        if node.edges.is_empty() {
            return Err(invalid("terminal node has no game output"));
        }
        let programs = (0..node.edges.len())
            .map(|i| self.program(node_id, i))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CompiledTaprootState::compile(
            &Secp256k1::verification_only(),
            node.logical_state_digest,
            &programs,
        )?)
    }

    /// Exact output(s) created by entering a node; settlement pays the identities.
    pub fn outputs(&self, node_id: NodeId) -> Result<Vec<TxOut>, CompilerError> {
        let node = &self.plan.nodes[self.index(node_id)?];
        if let PlannedState::Terminal(t) = node.state {
            [t.alice_output_sat, t.bob_output_sat]
                .into_iter()
                .zip(self.identities)
                .filter(|(v, _)| *v != 0)
                .map(|(value, key)| {
                    Ok(TxOut {
                        value: Amount::from_sat(value),
                        script_pubkey: ScriptBuf::new_p2tr(
                            &Secp256k1::verification_only(),
                            XOnlyPublicKey::from_slice(&key)
                                .map_err(|_| invalid("invalid payout identity"))?,
                            None,
                        ),
                    })
                })
                .collect()
        } else {
            Ok(vec![TxOut {
                value: Amount::from_sat(node.state.amounts().game_value()?),
                script_pubkey: self.state(node_id)?.script_pubkey(),
            }])
        }
    }

    /// Exact child template for a known parent outpoint. All inputs and outputs
    /// are derived locally; a relay cannot supply alternate payout templates.
    pub fn transition(
        &self,
        node_id: NodeId,
        edge_index: usize,
        parent: OutPoint,
    ) -> Result<TransactionTemplate, CompilerError> {
        let node = &self.plan.nodes[self.index(node_id)?];
        let edge = node
            .edges
            .get(edge_index)
            .ok_or(CompilerError::DanglingNode)?;
        let parent_output = self.outputs(node_id)?.remove(0);
        let outputs = self.outputs(edge.child_node_id)?;
        Ok(if let Some(timeout) = edge.timeout {
            TransactionTemplate::timeout(
                self.parameters.network,
                parent,
                parent_output,
                outputs,
                edge.fee_sat,
                timeout.csv,
            )?
        } else {
            TransactionTemplate::normal(
                self.parameters.network,
                parent,
                parent_output,
                outputs,
                edge.fee_sat,
            )?
        })
    }
}
