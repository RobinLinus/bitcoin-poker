//! Materialized settlement graph and transaction authorizations.
pub use crate::config::SettlementConfig;
// Dlog settlement uses the same complete finite poker topology as the reference
// planner. No legacy deal, hash preimage, or cooperative-close leaf is involved.
pub(super) use crate::{
    CompilerError,
    graph::{LogicalGraphPlan, PlannedState, compile_rules_graph},
};
pub(super) use bitcoin::hashes::Hash;
pub(super) use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
pub(super) use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
pub(super) use dealer_protocol::{VerifiedAcceptedDeal, accepted_body_hash};
pub(super) use poker_bitcoin::{
    ActionProgram, AliceShowdownProgram, BobPayoutProgram, CompiledTaprootState, FeePolicy,
    LeafProgram, RevealProgram, TimeoutProgram, TransactionTemplate, validate_network_identity,
};
pub(super) use poker_score_ots::LamportPublicKey;
pub(super) use poker_settlement_types::{
    EdgeKind, NodeId, PokerRules, root_node_id, tagged_sha256,
};
pub(super) use std::collections::{HashMap, HashSet};

/// One artifact that must be verified and stored before activation.
#[derive(Clone, Debug)]
pub enum AuthorizationRequest {
    /// Exact opponent signature; the actor or timeout beneficiary signs live.
    Signature {
        /// Parent node.
        node_id: NodeId,
        /// Canonical outgoing edge index.
        edge_index: usize,
        /// Required preauthorizing identity role.
        signer: poker_settlement_types::Role,
        /// Exact BIP341 digest.
        sighash: [u8; 32],
    },
    /// Full 52-candidate package under the distinct slot-specific key.
    Reveal(Box<dealer_bitcoin::reveal::RevealContext>),
}

/// Two-identity origin escrow used before dealing has a game ID.
///
/// # Errors
///
/// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
pub fn build_origin_escrow(
    identities: [[u8; 32]; 2],
) -> Result<CompiledTaprootState, CompilerError> {
    let id = tagged_sha256("DLOG52/origin-escrow/v1", &identities.concat());
    let program = LeafProgram::Action(ActionProgram::new(
        id,
        root_node_id(&id),
        poker_settlement_types::Action::Check,
        identities,
    )?);
    Ok(CompiledTaprootState::compile(
        &Secp256k1::verification_only(),
        id,
        &[program],
    )?)
}

pub(super) fn invalid(reason: &'static str) -> CompilerError {
    poker_settlement_types::ChainError::InvalidLogicalRecord { reason }.into()
}

/// Complete logical tree with deterministic, on-demand Bitcoin materialization.
/// Scripts are rebuilt per node so the full tree does not retain gigabytes of
/// repeated candidate catalogues. Funding still requires exchanging every exact
/// transaction preauthorization and adaptor package before activation.
pub struct SettlementGraph<'a> {
    deal: &'a VerifiedAcceptedDeal,
    parameters: SettlementConfig,
    plan: LogicalGraphPlan,
    indices: HashMap<NodeId, usize>,
    scores: [LamportPublicKey; 2],
    identities: [[u8; 32]; 2],
}

impl<'a> SettlementGraph<'a> {
    /// Compile every betting, reveal, showdown, fold and timeout branch.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn compile(
        deal: &'a VerifiedAcceptedDeal,
        parameters: SettlementConfig,
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
        AliceShowdownProgram::new(deal, id, root_node_id(&id), scores[0].clone(), identities)?;
        BobPayoutProgram::new(
            deal,
            id,
            root_node_id(&id),
            root_node_id(&id),
            poker_settlement_types::ShowdownOutcome::Split,
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
    #[must_use]
    pub fn plan(&self) -> &LogicalGraphPlan {
        &self.plan
    }

    /// Canonical identities authenticated by accepted-deal replay.
    #[must_use]
    pub fn identities(&self) -> [[u8; 32]; 2] {
        self.identities
    }

    /// Activation is fixed before the authorization exchange; its txid is
    /// independent of both funding signatures.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn activation(
        &self,
        origin_output: TxOut,
        fee_sat: u64,
    ) -> Result<TransactionTemplate, CompilerError> {
        if origin_output.script_pubkey != build_origin_escrow(self.identities)?.script_pubkey() {
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
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn visit_authorizations(
        &self,
        activation: &TransactionTemplate,
        mut visitor: impl FnMut(AuthorizationRequest) -> Result<(), CompilerError>,
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
                let sighash = poker_bitcoin::taproot_script_sighash_default(
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
                        visitor(AuthorizationRequest::Reveal(Box::new(
                            dealer_bitcoin::reveal::RevealContext {
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
                    use poker_settlement_types::Role;
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
                    visitor(AuthorizationRequest::Signature {
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
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
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
                LeafProgram::Reveal(RevealProgram::new(
                    accepted_body_hash(&self.deal.as_deal().body),
                    node_id,
                    self.identities[role],
                    &slots,
                )?)
            }
            EdgeKind::AliceShowdown => LeafProgram::AliceShowdown(AliceShowdownProgram::new(
                self.deal,
                id,
                node_id,
                self.scores[0].clone(),
                self.identities,
            )?),
            EdgeKind::BobPayout(outcome) => LeafProgram::BobPayout(BobPayoutProgram::new(
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
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
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
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
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
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
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
