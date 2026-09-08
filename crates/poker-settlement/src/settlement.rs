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
#[derive(Clone)]
pub struct SettlementGraph {
    pub(crate) channel: Option<crate::channel::ChannelProtection>,
    pub(crate) payout_projection: std::sync::OnceLock<Vec<u8>>,
    commitments: [[k256::ProjectivePoint; 9]; 2],
    pub(crate) parameters: SettlementConfig,
    plan: LogicalGraphPlan,
    indices: HashMap<NodeId, usize>,
    showdown_a: AliceShowdownProgram,
    showdown_b: [BobPayoutProgram; 3],
    deal_id: [u8; 32],
    payout_scripts: [ScriptBuf; 2],
    identities: [[u8; 32]; 2],
    pub(crate) identity_keys: [XOnlyPublicKey; 2],
    pub(crate) secp: Secp256k1<bitcoin::secp256k1::All>,
}

struct MaterializedNode {
    outputs: Vec<TxOut>,
    leaf_hashes: Vec<bitcoin::taproot::TapLeafHash>,
}

impl SettlementGraph {
    /// Compile every betting, reveal, showdown, fold and timeout branch.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn compile(
        deal: &VerifiedAcceptedDeal,
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
        let cards = poker_bitcoin::PreparedShowdownCards::new(deal)?;
        let showdown_b = [
            poker_settlement_types::ShowdownOutcome::AliceWin,
            poker_settlement_types::ShowdownOutcome::BobWin,
            poker_settlement_types::ShowdownOutcome::Split,
        ]
        .map(|outcome| {
            BobPayoutProgram::from_prepared(
                &cards,
                id,
                root_node_id(&id),
                root_node_id(&id),
                outcome,
                scores[0].clone(),
                scores[1].clone(),
                identities,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| invalid("wrong outcome count"))?;
        let [alice_score, _] = scores;
        let showdown_a = AliceShowdownProgram::from_prepared(
            &cards,
            id,
            root_node_id(&id),
            alice_score,
            identities,
        )?;
        let payout_scripts = identities
            .map(|key| {
                XOnlyPublicKey::from_slice(&key)
                    .map(|key| ScriptBuf::new_p2tr(&Secp256k1::verification_only(), key, None))
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("invalid payout identity"))?
            .try_into()
            .map_err(|_| invalid("wrong identity count"))?;
        Ok(Self {
            channel: None,
            payout_projection: std::sync::OnceLock::new(),
            commitments: [
                deal.as_deal().body.commitments_a,
                deal.as_deal().body.commitments_b,
            ],
            parameters,
            plan,
            indices,
            showdown_a,
            showdown_b,
            deal_id: cards.deal_id(),
            payout_scripts,
            identities,
            identity_keys: [XOnlyPublicKey::from_slice(&identities[0]).map_err(|_| invalid("invalid identity"))?, XOnlyPublicKey::from_slice(&identities[1]).map_err(|_| invalid("invalid identity"))?],
            secp: Secp256k1::new(),
        })
    }

    /// Full unpruned semantic graph, including forced all-in runouts.
    #[must_use]
    pub fn plan(&self) -> &LogicalGraphPlan {
        &self.plan
    }

    /// Resolve a node without scanning the full hand tree.
    #[must_use]
    pub fn node(&self, id: &NodeId) -> Option<&crate::graph::PlannedNode> {
        self.indices
            .get(id)
            .and_then(|index| self.plan.nodes.get(*index))
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
        if self.channel.is_some() { return self.channel_activation(origin_output, fee_sat); }
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

    // Compile each nonterminal node once, retaining only output and leaf hashes.
    fn materialize(&self) -> Result<Vec<MaterializedNode>, CompilerError> {
        let mut records = Vec::with_capacity(self.plan.nodes.len());
        let secp = &self.secp;
        let mut script_hashes = HashMap::new();
        for node in &self.plan.nodes {
            if node.edges.is_empty() {
                records.push(MaterializedNode {
                    outputs: self.preparation_payouts(node.node_id)?,
                    leaf_hashes: Vec::new(),
                });
                continue;
            }
            let programs = (0..node.edges.len())
                .map(|edge| self.program(node.node_id, edge))
                .collect::<Result<Vec<_>, _>>()?;
            let (script_pubkey, hashes) = CompiledTaprootState::signing_projection(
                secp, node.node_id, &programs,
                self.branch_guard(node.node_id)?, &mut script_hashes)?;
            records.push(MaterializedNode {
                outputs: vec![TxOut {
                    value: Amount::from_sat(node.state.amounts().game_value()?),
                    script_pubkey,
                }],
                leaf_hashes: hashes,
            });
        }
        Ok(records)
    }

    /// Stream the complete authorization inventory in canonical preorder.
    /// The caller must durably store and verify every response before signing
    /// activation. Runtime state advances only after confirmed transactions.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    #[allow(
        clippy::too_many_lines,
        reason = "Keep canonical authorization ordering visible in one traversal."
    )]
    pub fn visit_authorizations(
        &self,
        activation: &TransactionTemplate,
        mut visitor: impl FnMut(AuthorizationRequest) -> Result<(), CompilerError>,
    ) -> Result<(), CompilerError> {
        let funding = if self.channel.is_some() {
            TxOut { value: Amount::from_sat(activation.parent_output().value.to_sat()
                .checked_add(activation.fee_sat()).ok_or_else(|| invalid("funding overflow"))?),
                script_pubkey: build_origin_escrow(self.identities)?.script_pubkey() }
        } else { activation.parent_output().clone() };
        let expected = self.activation(funding, activation.fee_sat())?;
        if expected.transaction() != activation.transaction() {
            return Err(invalid("foreign dlog activation"));
        }
        let records = self.materialize()?;
        let mut payouts = crate::payout_projection::ProjectionWriter::new();
        // Pass B: child outputs are now known; parent txids propagate in preorder.
        let mut outpoints = vec![None; self.plan.nodes.len()];
        outpoints[self.index(self.plan.root_node_id)?] =
            Some(OutPoint::new(activation.transaction().compute_txid(), 0));
        for (index, node) in self.plan.nodes.iter().enumerate() {
            if node.edges.is_empty() {
                continue;
            }
            let parent = outpoints[index].take().ok_or(CompilerError::DanglingNode)?;
            for (edge_index, edge) in node.edges.iter().enumerate() {
                let child_index = self.index(edge.child_node_id)?;
                let parent_output = records[index].outputs[0].clone();
                let outputs = records[child_index].outputs.clone();
                let template = if let Some(timeout) = edge.timeout {
                    TransactionTemplate::timeout(
                        self.parameters.network,
                        parent,
                        parent_output,
                        outputs,
                        edge.fee_sat,
                        timeout.csv.checked_add(self.contest_delay(node.node_id)).ok_or_else(|| invalid("timeout overflow"))?,
                    )?
                } else if self.contest_delay(node.node_id) > 0 {
                    TransactionTemplate::timeout(self.parameters.network, parent, parent_output, outputs,
                        edge.fee_sat, self.contest_delay(node.node_id))?
                } else {
                    TransactionTemplate::normal(
                        self.parameters.network,
                        parent,
                        parent_output,
                        outputs,
                        edge.fee_sat,
                    )?
                };
                if !matches!(
                    self.plan.nodes[child_index].state,
                    PlannedState::Terminal(_)
                ) {
                    outpoints[child_index] =
                        Some(OutPoint::new(template.transaction().compute_txid(), 0));
                }
                if let PlannedState::Terminal(terminal) = self.plan.nodes[child_index].state {
                    payouts.push(node.node_id, edge_index, &template, records[index].leaf_hashes[edge_index],
                        u8::from(terminal.alice_output_sat!=0) | (u8::from(terminal.bob_output_sat!=0)<<1))?;
                }
                let sighash = poker_bitcoin::taproot_leaf_sighash_default(
                    template.transaction(),
                    0,
                    std::slice::from_ref(template.parent_output()),
                    records[index].leaf_hashes[edge_index],
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
                        let commitment = self.commitments[usize::from(role)][usize::from(slot)];
                        visitor(AuthorizationRequest::Reveal(Box::new(
                            dealer_bitcoin::reveal::RevealContext {
                                deal_id: self.deal_id,
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
        if outpoints.iter().any(Option::is_some) {
            return Err(invalid("unvisited dlog transaction branch"));
        }
        let _ = self.payout_projection.set(payouts.finish());
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
                    self.deal_id,
                    node_id,
                    self.identities[role],
                    &slots,
                )?)
            }
            EdgeKind::AliceShowdown => {
                LeafProgram::AliceShowdown(self.showdown_a.at_node(node_id)?)
            }
            EdgeKind::BobPayout(outcome) => {
                LeafProgram::BobPayout(self.showdown_b[usize::from(outcome.code())].at_node(
                    node_id,
                    node.parent_node_id.ok_or(CompilerError::DanglingNode)?,
                )?)
            }
            EdgeKind::Timeout(_) => LeafProgram::Timeout(TimeoutProgram::new(
                id,
                node_id,
                edge.timeout.ok_or_else(|| invalid("missing timeout"))?.csv
                    .checked_add(self.contest_delay(node_id)).ok_or_else(|| invalid("timeout overflow"))?,
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
        Ok(if let Some(guard) = self.branch_guard(node_id)? {
            CompiledTaprootState::compile_contested(&Secp256k1::verification_only(),
                node.node_id, &programs, guard)?
        } else {
            CompiledTaprootState::compile(&Secp256k1::verification_only(),
                node.node_id, &programs)?
        })
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
                .enumerate()
                .filter(|(_, v)| *v != 0)
                .map(|(role, value)| {
                    let script_pubkey = if self.channel.is_some() {
                        self.guarded_payout(node_id, if role == 0 { poker_settlement_types::Role::Alice }
                            else { poker_settlement_types::Role::Bob })?.script_pubkey()
                    } else { self.payout_scripts[role].clone() };
                    Ok(TxOut { value: Amount::from_sat(value), script_pubkey })
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
                timeout.csv.checked_add(self.contest_delay(node_id)).ok_or_else(|| invalid("timeout overflow"))?,
            )?
        } else if self.contest_delay(node_id) > 0 {
            TransactionTemplate::timeout(self.parameters.network, parent, parent_output, outputs,
                edge.fee_sat, self.contest_delay(node_id))?
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
