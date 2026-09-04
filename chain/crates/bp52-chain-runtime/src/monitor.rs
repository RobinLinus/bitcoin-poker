//! Deterministic confirmation and timeout state machine.

use std::num::NonZeroU16;

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, TxOut};
use bp52_chain_types::{NodeId, NodeKind, TimeoutKind};
use bp52_lamport::LamportSecretKey;

use crate::backend::reject_mainnet;
use crate::witness::recover_confirmed_witness;
use crate::{ChainBackend, PublicPreimageStore, RuntimeError, Witness};

/// Callback into encrypted runtime secret storage after any branch confirms.
///
/// Implementations must erase every unused OTS secret associated with the
/// parent node and commit that erasure durably before returning success.
pub trait SecretEraser {
    /// Erase unused secrets for one now-spent state output.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed storage/lifecycle error. Callers must halt.
    fn erase_node_secrets(
        &mut self,
        chain_game_id: [u8; 32],
        node_id: NodeId,
    ) -> Result<(), RuntimeError>;
}

/// Exact BIP68 height maturity for the active state's timeout edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutMaturity {
    /// Timeout class.
    pub kind: TimeoutKind,
    /// State whose confirmation starts the relative delay.
    pub node_id: NodeId,
    /// Configured relative delay in blocks.
    pub csv: u16,
    /// First height at which the timeout transaction may be mined.
    pub matures_at: u32,
}

/// Opaque evidence that the exact compiled state output is confirmed and is
/// the monitor's current live node.
#[derive(Debug)]
pub struct ConfirmedActiveNode<'monitor> {
    monitor: &'monitor ChainMonitor,
    node_id: NodeId,
    confirmed_height: u32,
}

impl ConfirmedActiveNode<'_> {
    /// Return the confirmed live node.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Return the height at which the live state output confirmed.
    #[must_use]
    pub const fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }

    pub(crate) fn validate(
        &self,
        graph: &dyn ChainBackend,
        expected_node_id: NodeId,
    ) -> Result<(), RuntimeError> {
        if self.monitor.chain_game_id != graph.chain_game_id()
            || self.monitor.graph_root != graph.graph_root()
        {
            return Err(RuntimeError::WrongChainGame);
        }
        if !matches!(
            self.monitor.state,
            MonitorState::Active {
                node_id,
                confirmed_height,
                ..
            } if node_id == self.node_id && confirmed_height == self.confirmed_height
        ) {
            return Err(RuntimeError::NoConfirmedActiveNode);
        }
        if self.node_id != expected_node_id {
            return Err(RuntimeError::InactiveNode {
                expected: self.node_id,
                actual: expected_node_id,
            });
        }
        Ok(())
    }

    pub(crate) fn validate_prepared(
        &self,
        prepared: &crate::PreparedTransaction,
    ) -> Result<(), RuntimeError> {
        if self.monitor.chain_game_id != prepared.chain_game_id
            || self.monitor.graph_root != prepared.graph_root
        {
            return Err(RuntimeError::WrongChainGame);
        }
        if self.node_id != prepared.parent_node_id {
            return Err(RuntimeError::InactiveNode {
                expected: self.node_id,
                actual: prepared.parent_node_id,
            });
        }
        if !matches!(
            self.monitor.state,
            MonitorState::Active {
                node_id,
                confirmed_height,
                ..
            } if node_id == self.node_id && confirmed_height == self.confirmed_height
        ) {
            return Err(RuntimeError::NoConfirmedActiveNode);
        }
        Ok(())
    }
}

/// Opaque evidence that the current active node's exact CSV timeout has
/// reached maturity at the monitor's observed best-chain height.
#[derive(Debug)]
pub struct MatureTimeout<'monitor> {
    active: ConfirmedActiveNode<'monitor>,
    maturity: TimeoutMaturity,
}

impl MatureTimeout<'_> {
    /// Return the active node whose timeout matured.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.active.node_id
    }

    /// Return the checked timeout schedule.
    #[must_use]
    pub const fn maturity(&self) -> TimeoutMaturity {
        self.maturity
    }

    pub(crate) fn validate(
        &self,
        graph: &dyn ChainBackend,
        expected_node_id: NodeId,
    ) -> Result<(), RuntimeError> {
        self.active.validate(graph, expected_node_id)
    }
}

impl TimeoutMaturity {
    /// Return whether a chain tip has reached this timeout's maturity height.
    #[must_use]
    pub const fn is_mature(self, current_height: u32) -> bool {
        current_height >= self.matures_at
    }
}

/// Persistable high-level state of one chain runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorState {
    /// Waiting for the precomputed funding output to confirm.
    AwaitingFunding {
        /// Canonical funded-root node identifier.
        root_node_id: NodeId,
    },
    /// One nonterminal state outpoint is currently live.
    Active {
        /// Canonical active node identifier.
        node_id: NodeId,
        /// Height at which this state output confirmed.
        confirmed_height: u32,
        /// Txid of the transaction that created this state, absent for the
        /// external funding output.
        creating_txid: Option<[u8; 32]>,
    },
    /// A terminal settlement has confirmed.
    Terminal {
        /// Canonical terminal node identifier.
        node_id: NodeId,
        /// Confirmation height.
        confirmed_height: u32,
        /// Terminal transaction identifier.
        txid: [u8; 32],
    },
    /// Monitoring halted after a reorg or failed mandatory secret erasure.
    Halted,
}

/// One-outpoint-per-state chain follower.
#[derive(Debug, Eq, PartialEq)]
pub struct ChainMonitor {
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    funding_confirmation_depth: NonZeroU16,
    state: MonitorState,
    highest_tip: Option<u32>,
    issued_authorization_witness: Option<Witness>,
}

impl ChainMonitor {
    /// Create a monitor before funding confirmation.
    #[must_use]
    pub const fn new(
        chain_game_id: [u8; 32],
        graph_root: [u8; 32],
        root_node_id: NodeId,
        funding_confirmation_depth: NonZeroU16,
    ) -> Self {
        Self {
            chain_game_id,
            graph_root,
            funding_confirmation_depth,
            state: MonitorState::AwaitingFunding { root_node_id },
            highest_tip: None,
            issued_authorization_witness: None,
        }
    }

    /// Return the current persistable monitor state.
    #[must_use]
    pub const fn state(&self) -> MonitorState {
        self.state
    }

    #[cfg(test)]
    pub(crate) const fn active_for_test(
        chain_game_id: [u8; 32],
        graph_root: [u8; 32],
        node_id: NodeId,
        confirmed_height: u32,
        observed_tip_height: u32,
    ) -> Self {
        Self {
            chain_game_id,
            graph_root,
            funding_confirmation_depth: NonZeroU16::MIN,
            state: MonitorState::Active {
                node_id,
                confirmed_height,
                creating_txid: Some([0x5a; 32]),
            },
            highest_tip: Some(observed_tip_height),
            issued_authorization_witness: None,
        }
    }

    pub(crate) fn issued_authorization_witness(&self, node_id: NodeId) -> Option<&Witness> {
        self.issued_authorization_witness
            .as_ref()
            .filter(|witness| witness.node_id() == node_id)
    }

    pub(crate) fn halt_for_authorization_conflict(&mut self) {
        self.state = MonitorState::Halted;
    }

    pub(crate) fn begin_authorization_issuance(
        &mut self,
        node_id: NodeId,
    ) -> Result<MonitorState, RuntimeError> {
        let prior = self.state;
        if !matches!(prior, MonitorState::Active { node_id: active, .. } if active == node_id) {
            return Err(RuntimeError::NoConfirmedActiveNode);
        }
        self.state = MonitorState::Halted;
        Ok(prior)
    }

    pub(crate) fn complete_authorization_issuance(
        &mut self,
        prior: MonitorState,
        witness: Witness,
    ) {
        self.issued_authorization_witness = Some(witness);
        self.state = prior;
    }

    /// Record a root confirmation observed and supplied by an external chain
    /// backend after checking its exact outpoint and output contract.
    ///
    /// This monitor does not query Bitcoin Core and therefore does not itself
    /// prove that the UTXO exists or is confirmed. The caller supplies that
    /// observation; this method only rejects it unless both consensus objects
    /// exactly match the compiled graph requirement.
    ///
    /// # Errors
    ///
    /// Rejects mainnet, graph/game substitution, a non-root node, an
    /// unexpected monitor state, a repeated confirmation at another height,
    /// or an observed-tip regression (which permanently halts the monitor).
    pub fn confirm_funding(
        &mut self,
        graph: &dyn ChainBackend,
        observed_outpoint: OutPoint,
        observed_output: &TxOut,
        confirmed_height: u32,
        observed_tip_height: u32,
    ) -> Result<(), RuntimeError> {
        reject_mainnet(graph.network())?;
        if graph.chain_game_id() != self.chain_game_id {
            return Err(RuntimeError::WrongChainGame);
        }
        if graph.graph_root() != self.graph_root {
            return Err(RuntimeError::InconsistentGraph {
                reason: "runtime graph root differs from monitor binding",
            });
        }
        if graph.expected_funding_state_outpoint() != Some(observed_outpoint)
            || graph.expected_funding_state_output() != Some(observed_output)
        {
            return Err(RuntimeError::InconsistentGraph {
                reason: "observed funding UTXO differs from compiled root requirement",
            });
        }
        if self
            .highest_tip
            .is_some_and(|prior| observed_tip_height < prior)
        {
            self.state = MonitorState::Halted;
            return Err(RuntimeError::ReorgDetected);
        }
        if observed_tip_height < confirmed_height {
            return Err(RuntimeError::UnexpectedConfirmation);
        }
        self.highest_tip = Some(observed_tip_height);
        let confirmations = observed_tip_height
            .checked_sub(confirmed_height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(RuntimeError::HeightOverflow)?;
        if confirmations < u32::from(self.funding_confirmation_depth.get()) {
            return Err(RuntimeError::FundingConfirmationImmature {
                actual: confirmations,
                required: self.funding_confirmation_depth.get(),
            });
        }
        let root_node_id = match self.state {
            MonitorState::AwaitingFunding { root_node_id } => root_node_id,
            MonitorState::Active {
                node_id,
                confirmed_height: existing,
                creating_txid: None,
            } if existing == confirmed_height => {
                let root = graph
                    .node(node_id)
                    .ok_or(RuntimeError::NodeNotFound { node_id })?;
                return if root.node_kind == NodeKind::Funded {
                    Ok(())
                } else {
                    Err(RuntimeError::UnexpectedConfirmation)
                };
            }
            _ => return Err(RuntimeError::UnexpectedConfirmation),
        };
        let root = graph.node(root_node_id).ok_or(RuntimeError::NodeNotFound {
            node_id: root_node_id,
        })?;
        root.validate()?;
        if root.node_kind != NodeKind::Funded
            || root.parent_node_id.is_some()
            || root.transaction.is_some()
        {
            return Err(RuntimeError::InconsistentGraph {
                reason: "funding monitor root is not the canonical funded node",
            });
        }
        self.state = MonitorState::Active {
            node_id: root_node_id,
            confirmed_height,
            creating_txid: None,
        };
        Ok(())
    }

    /// Mint evidence for the exact currently confirmed, nonterminal state.
    ///
    /// # Errors
    ///
    /// Rejects the wrong game, mainnet, funding-not-confirmed, halted, terminal,
    /// missing, or malformed active state.
    pub fn confirmed_active_node(
        &self,
        graph: &dyn ChainBackend,
    ) -> Result<ConfirmedActiveNode<'_>, RuntimeError> {
        reject_mainnet(graph.network())?;
        if graph.chain_game_id() != self.chain_game_id || graph.graph_root() != self.graph_root {
            return Err(RuntimeError::WrongChainGame);
        }
        let (node_id, confirmed_height) = match self.state {
            MonitorState::Active {
                node_id,
                confirmed_height,
                ..
            } => (node_id, confirmed_height),
            MonitorState::AwaitingFunding { .. }
            | MonitorState::Terminal { .. }
            | MonitorState::Halted => return Err(RuntimeError::NoConfirmedActiveNode),
        };
        let node = graph
            .node(node_id)
            .ok_or(RuntimeError::NodeNotFound { node_id })?;
        node.validate()?;
        if node.node_kind.is_terminal() {
            return Err(RuntimeError::NoConfirmedActiveNode);
        }
        Ok(ConfirmedActiveNode {
            monitor: self,
            node_id,
            confirmed_height,
        })
    }

    /// Mint timeout authorization only after the active node's CSV maturity.
    ///
    /// # Errors
    ///
    /// Rejects absent timeout metadata, missing best-chain observation,
    /// arithmetic overflow, or an immature timeout.
    pub fn mature_timeout(
        &self,
        graph: &dyn ChainBackend,
    ) -> Result<MatureTimeout<'_>, RuntimeError> {
        let active = self.confirmed_active_node(graph)?;
        let maturity = self
            .timeout_maturity(graph)?
            .ok_or(RuntimeError::InconsistentGraph {
                reason: "active node has no timeout metadata",
            })?;
        let current_height = self
            .highest_tip
            .ok_or(RuntimeError::UnexpectedConfirmation)?;
        if !maturity.is_mature(current_height) {
            return Err(RuntimeError::TimeoutImmature {
                current_height,
                matures_at: maturity.matures_at,
            });
        }
        Ok(MatureTimeout { active, maturity })
    }

    /// Observe a new best-chain height.
    ///
    /// A tip below the active state's confirmation height is treated as a
    /// reorganization and halts automatic signing/broadcast until explicit
    /// application-level recovery.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ReorgDetected`] when the active confirmation is
    /// no longer buried by the supplied tip.
    pub fn observe_tip(&mut self, height: u32) -> Result<(), RuntimeError> {
        let confirmation = match self.state {
            MonitorState::Active {
                confirmed_height, ..
            }
            | MonitorState::Terminal {
                confirmed_height, ..
            } => Some(confirmed_height),
            MonitorState::AwaitingFunding { .. } | MonitorState::Halted => None,
        };
        if confirmation.is_some_and(|confirmed| height < confirmed)
            || self.highest_tip.is_some_and(|prior| height < prior)
        {
            self.state = MonitorState::Halted;
            return Err(RuntimeError::ReorgDetected);
        }
        self.highest_tip = Some(height);
        Ok(())
    }

    /// Return the active node's exact timeout maturity, if it has one.
    ///
    /// # Errors
    ///
    /// Returns an overflow error if `confirmation_height + csv` exceeds
    /// `u32`, or a state error when funding has not confirmed/runtime halted.
    pub fn timeout_maturity(
        &self,
        graph: &dyn ChainBackend,
    ) -> Result<Option<TimeoutMaturity>, RuntimeError> {
        if graph.chain_game_id() != self.chain_game_id || graph.graph_root() != self.graph_root {
            return Err(RuntimeError::WrongChainGame);
        }
        let (node_id, confirmed_height) = match self.state {
            MonitorState::Active {
                node_id,
                confirmed_height,
                ..
            } => (node_id, confirmed_height),
            MonitorState::Terminal { .. } => return Ok(None),
            MonitorState::AwaitingFunding { .. } | MonitorState::Halted => {
                return Err(RuntimeError::UnexpectedConfirmation);
            }
        };
        let node = graph
            .node(node_id)
            .ok_or(RuntimeError::NodeNotFound { node_id })?;
        node.timeout
            .map(|timeout| {
                Ok(TimeoutMaturity {
                    kind: timeout.kind,
                    node_id,
                    csv: timeout.csv,
                    matures_at: confirmed_height
                        .checked_add(u32::from(timeout.csv))
                        .ok_or(RuntimeError::HeightOverflow)?,
                })
            })
            .transpose()
    }

    /// Confirm exactly one child of the active outpoint.
    ///
    /// `confirmed_transaction` must be the complete transaction returned by
    /// the trusted chain backend, including its witness. Public values are
    /// recovered edge-aware from that Bitcoin witness and transactionally
    /// ingested only after full cryptographic and semantic validation.
    /// Consensus-equivalent showdown Script-number encodings are accepted;
    /// signatures, preimages, tapscript, and control block remain byte-exact.
    /// Mandatory secret erasure begins immediately after recognizing the exact
    /// template spend and completes before any witness parsing. Repeating the
    /// same confirmation is idempotent.
    ///
    /// # Errors
    ///
    /// Rejects a sibling/unrelated confirmation, a transaction differing from
    /// the fixed template, a missing/invalid/mismatched runtime witness,
    /// invalid repeated public data, height regression, or secret erasure
    /// failure.
    #[allow(clippy::too_many_lines)]
    pub fn confirm_child(
        &mut self,
        graph: &dyn ChainBackend,
        child_node_id: NodeId,
        confirmed_transaction: &Transaction,
        confirmed_height: u32,
        public_preimages: &mut PublicPreimageStore,
        secret_eraser: &mut dyn SecretEraser,
    ) -> Result<(), RuntimeError> {
        reject_mainnet(graph.network())?;
        if graph.chain_game_id() != self.chain_game_id {
            return Err(RuntimeError::WrongChainGame);
        }
        if graph.graph_root() != self.graph_root {
            return Err(RuntimeError::InconsistentGraph {
                reason: "runtime graph root differs from monitor binding",
            });
        }
        let txid = confirmed_transaction.compute_txid().to_byte_array();
        match self.state {
            MonitorState::Active {
                node_id,
                confirmed_height: existing_height,
                creating_txid: Some(existing_txid),
            } if node_id == child_node_id
                && existing_txid == txid
                && existing_height == confirmed_height =>
            {
                return Ok(());
            }
            MonitorState::Terminal {
                node_id,
                confirmed_height: existing_height,
                txid: existing_txid,
            } if node_id == child_node_id
                && existing_txid == txid
                && existing_height == confirmed_height =>
            {
                return Ok(());
            }
            _ => {}
        }
        let MonitorState::Active {
            node_id: parent_node_id,
            confirmed_height: parent_height,
            ..
        } = self.state
        else {
            return Err(RuntimeError::UnexpectedConfirmation);
        };
        if confirmed_height < parent_height {
            return Err(RuntimeError::UnexpectedConfirmation);
        }
        let observed_tip = self
            .highest_tip
            .ok_or(RuntimeError::UnexpectedConfirmation)?;
        if confirmed_height > observed_tip {
            return Err(RuntimeError::UnexpectedConfirmation);
        }
        let parent = graph
            .node(parent_node_id)
            .ok_or(RuntimeError::NodeNotFound {
                node_id: parent_node_id,
            })?;
        if !parent.child_node_ids.contains(&child_node_id) {
            return Err(RuntimeError::UnexpectedConfirmation);
        }
        let edge =
            graph
                .edge(parent_node_id, child_node_id)
                .ok_or(RuntimeError::MissingListedEdge {
                    parent_node_id,
                    child_node_id,
                })?;
        edge.validate()?;
        let template =
            graph
                .transaction_template(child_node_id)
                .ok_or(RuntimeError::InconsistentGraph {
                    reason: "confirmed child has no fixed Bitcoin template",
                })?;
        let mut witness_free_transaction = confirmed_transaction.clone();
        if witness_free_transaction.input.len() != 1 {
            return Err(RuntimeError::InconsistentGraph {
                reason: "confirmed transaction does not have exactly one input",
            });
        }
        witness_free_transaction.input[0].witness = bitcoin::Witness::new();
        if template.to_logical_transaction() != edge.transaction
            || template.txid() != txid
            || &witness_free_transaction != template.transaction()
        {
            return Err(RuntimeError::InconsistentGraph {
                reason: "confirmed transaction differs from the fixed template",
            });
        }
        // From this point onward the trusted chain observation proves that the
        // active outpoint was spent by an exact precompiled child template. If
        // any local semantic check now fails or unwinds, a sibling must never
        // be signed. Success below replaces this fail-closed state atomically.
        self.state = MonitorState::Halted;
        secret_eraser.erase_node_secrets(self.chain_game_id, parent_node_id)?;
        let staged = (|| -> Result<(PublicPreimageStore, bool), RuntimeError> {
            if let Some(timeout) = edge.timeout {
                let matures_at = parent_height
                    .checked_add(u32::from(timeout.csv))
                    .ok_or(RuntimeError::HeightOverflow)?;
                if confirmed_height < matures_at {
                    return Err(RuntimeError::TimeoutImmature {
                        current_height: confirmed_height,
                        matures_at,
                    });
                }
            }
            let child = graph
                .node(child_node_id)
                .ok_or(RuntimeError::NodeNotFound {
                    node_id: child_node_id,
                })?;
            child.validate()?;
            if child.parent_node_id != Some(parent_node_id)
                || child.transaction.as_ref() != Some(&edge.transaction)
                || edge.transaction.txid != txid
            {
                return Err(RuntimeError::InconsistentGraph {
                    reason: "confirmed child, edge, and transaction disagree",
                });
            }
            let mut next_public = public_preimages.clone();
            next_public.ensure_binding(graph.chain_game_id(), graph.accepted_deal())?;
            let witness = recover_confirmed_witness(
                graph,
                crate::ValidatedEdge {
                    parent,
                    edge,
                    child,
                    template,
                },
                &confirmed_transaction.input[0].witness,
            )?;
            ingest_public_witness(&mut next_public, &witness)?;
            Ok((next_public, child.node_kind.is_terminal()))
        })();
        let (next_public, child_is_terminal) = staged?;
        *public_preimages = next_public;
        self.state = if child_is_terminal {
            MonitorState::Terminal {
                node_id: child_node_id,
                confirmed_height,
                txid,
            }
        } else {
            MonitorState::Active {
                node_id: child_node_id,
                confirmed_height,
                creating_txid: Some(txid),
            }
        };
        self.issued_authorization_witness = None;
        self.highest_tip = Some(
            self.highest_tip
                .map_or(confirmed_height, |height| height.max(confirmed_height)),
        );
        Ok(())
    }
}

/// Erase one in-memory Lamport key after any branch of its node confirms.
///
/// # Errors
///
/// Rejects a key belonging to another game or node without erasing it.
pub fn erase_lamport_key(
    key: &mut LamportSecretKey,
    chain_game_id: [u8; 32],
    node_id: NodeId,
) -> Result<(), RuntimeError> {
    let context = key.context();
    if context.chain_game_id != chain_game_id {
        return Err(RuntimeError::WrongChainGame);
    }
    if context.node_id != node_id {
        return Err(RuntimeError::SecretErasure {
            reason: "Lamport key belongs to another node",
        });
    }
    key.erase_after_branch_confirmation();
    Ok(())
}

fn ingest_public_witness(
    store: &mut PublicPreimageStore,
    witness: &Witness,
) -> Result<(), RuntimeError> {
    match witness {
        Witness::Reveal {
            pattern, preimages, ..
        } => {
            store.insert_reveal(*pattern, preimages)?;
        }
        Witness::AliceShowdown {
            node_id,
            hand,
            certificate,
            ..
        } => {
            store.insert_showdown_openings(hand.openings())?;
            store.insert_alice_score_certificate(*node_id, certificate.clone())?;
        }
        Witness::BobPayout { hand, .. } => {
            // Section 23 permits Bob to use any valid score certificate Alice
            // released. The validator checks it cryptographically, but a
            // different valid certificate must not overwrite or conflict with
            // the one recovered from the confirmed Alice-showdown parent.
            store.insert_showdown_openings(hand.openings())?;
        }
        Witness::Advance { .. } | Witness::Action { .. } | Witness::Timeout { .. } => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
    use bp52_chain_bitcoin::{CompiledTapLeaf, DefaultSighashSignature, TransactionTemplate};
    use bp52_chain_types::{
        AcceptedDeal, LogicalEdge, LogicalNodeRecord, NodeId, NodeKind, Role, TimeoutKind,
    };
    use bp52_lamport::{KeyContext, LamportPublicKey, LamportPurpose, generate_key};
    use rand_core::OsRng;

    use super::{ChainMonitor, MonitorState, SecretEraser, TimeoutMaturity, erase_lamport_key};
    use crate::{ChainBackend, PublicPreimageStore, RuntimeError};

    struct NoopEraser;

    impl SecretEraser for NoopEraser {
        fn erase_node_secrets(
            &mut self,
            _chain_game_id: [u8; 32],
            _node_id: NodeId,
        ) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    struct FundingGraph {
        deal: AcceptedDeal,
        graph_root: [u8; 32],
        root: LogicalNodeRecord,
        expected_outpoint: OutPoint,
        expected_output: TxOut,
    }

    impl crate::backend::sealed::Sealed for FundingGraph {}

    impl ChainBackend for FundingGraph {
        fn network(&self) -> Network {
            Network::Regtest
        }

        fn network_id(&self) -> [u8; 32] {
            [0x11; 32]
        }

        fn chain_game_id(&self) -> [u8; 32] {
            [1; 32]
        }

        fn graph_root(&self) -> [u8; 32] {
            self.graph_root
        }

        fn accepted_deal(&self) -> &AcceptedDeal {
            &self.deal
        }

        fn identity_key(&self, _role: Role) -> [u8; 32] {
            [2; 32]
        }

        fn expected_funding_state_outpoint(&self) -> Option<OutPoint> {
            Some(self.expected_outpoint)
        }

        fn expected_funding_state_output(&self) -> Option<&TxOut> {
            Some(&self.expected_output)
        }

        fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
            (self.root.node_id == node_id).then_some(&self.root)
        }

        fn edge(&self, _parent_node_id: NodeId, _child_node_id: NodeId) -> Option<&LogicalEdge> {
            None
        }

        fn transaction_template(&self, _child_node_id: NodeId) -> Option<&TransactionTemplate> {
            None
        }

        fn tap_leaf(
            &self,
            _parent_node_id: NodeId,
            _child_node_id: NodeId,
        ) -> Option<&CompiledTapLeaf> {
            None
        }

        fn lamport_public_key(
            &self,
            _node_id: NodeId,
            _purpose: LamportPurpose,
        ) -> Option<&LamportPublicKey> {
            None
        }

        fn preauthorization(
            &self,
            _parent_node_id: NodeId,
            _child_node_id: NodeId,
            _role: Role,
        ) -> Option<DefaultSighashSignature> {
            None
        }
    }

    fn funding_graph() -> FundingGraph {
        FundingGraph {
            deal: AcceptedDeal {
                protocol_version: 1,
                game_id: [3; 32],
                attempt: 0,
                hashes_a: [[4; 32]; bp52_protocol::N_SLOTS],
                hashes_b: [[5; 32]; bp52_protocol::N_SLOTS],
                verification_transcript_root: [6; 32],
                signature_a: [7; 64],
                signature_b: [8; 64],
            },
            graph_root: [0xa5; 32],
            root: LogicalNodeRecord {
                node_id: [9; 32],
                parent_node_id: None,
                node_kind: NodeKind::Funded,
                logical_state_digest: [10; 32],
                transaction: None,
                required_predicate_id: [11; 32],
                timeout: None,
                child_node_ids: vec![[12; 32]],
            },
            expected_outpoint: OutPoint::new(Txid::from_byte_array([13; 32]), 0),
            expected_output: TxOut {
                value: Amount::from_sat(2_200),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        }
    }

    #[test]
    fn timeout_maturity_uses_exact_confirmation_plus_csv() {
        let maturity = TimeoutMaturity {
            kind: TimeoutKind::Reveal,
            node_id: [2; 32],
            csv: 6,
            matures_at: 106,
        };
        assert!(!maturity.is_mature(105));
        assert!(maturity.is_mature(106));
    }

    #[test]
    fn monitor_halts_on_any_observed_tip_regression() {
        let mut monitor = ChainMonitor {
            chain_game_id: [1; 32],
            graph_root: [0xa5; 32],
            funding_confirmation_depth: NonZeroU16::MIN,
            state: MonitorState::Active {
                node_id: [2; 32],
                confirmed_height: 100,
                creating_txid: Some([3; 32]),
            },
            highest_tip: Some(103),
            issued_authorization_witness: None,
        };
        assert!(matches!(
            monitor.observe_tip(101),
            Err(RuntimeError::ReorgDetected)
        ));
        assert_eq!(monitor.state(), MonitorState::Halted);
    }

    #[test]
    fn funding_confirmation_requires_exact_externally_observed_utxo() -> Result<(), RuntimeError> {
        let graph = funding_graph();
        let mut monitor = ChainMonitor::new(
            graph.chain_game_id(),
            graph.graph_root(),
            graph.root.node_id,
            NonZeroU16::new(2).ok_or(RuntimeError::HeightOverflow)?,
        );
        let wrong_outpoint = OutPoint::new(Txid::from_byte_array([14; 32]), 0);
        assert!(matches!(
            monitor.confirm_funding(&graph, wrong_outpoint, &graph.expected_output, 100, 101),
            Err(RuntimeError::InconsistentGraph { .. })
        ));
        assert_eq!(
            monitor.state(),
            MonitorState::AwaitingFunding {
                root_node_id: graph.root.node_id
            }
        );

        let mut wrong_output = graph.expected_output.clone();
        wrong_output.value = Amount::from_sat(2_199);
        assert!(matches!(
            monitor.confirm_funding(&graph, graph.expected_outpoint, &wrong_output, 100, 101,),
            Err(RuntimeError::InconsistentGraph { .. })
        ));

        assert!(matches!(
            monitor.confirm_funding(
                &graph,
                graph.expected_outpoint,
                &graph.expected_output,
                100,
                100,
            ),
            Err(RuntimeError::FundingConfirmationImmature {
                actual: 1,
                required: 2
            })
        ));

        monitor.confirm_funding(
            &graph,
            graph.expected_outpoint,
            &graph.expected_output,
            100,
            101,
        )?;
        assert_eq!(
            monitor.state(),
            MonitorState::Active {
                node_id: graph.root.node_id,
                confirmed_height: 100,
                creating_txid: None,
            }
        );

        monitor.confirm_funding(
            &graph,
            graph.expected_outpoint,
            &graph.expected_output,
            100,
            110,
        )?;
        assert_eq!(monitor.highest_tip, Some(110));
        assert!(matches!(
            monitor.confirm_funding(
                &graph,
                graph.expected_outpoint,
                &graph.expected_output,
                100,
                109,
            ),
            Err(RuntimeError::ReorgDetected)
        ));
        assert_eq!(monitor.state(), MonitorState::Halted);
        assert!(matches!(
            monitor.confirmed_active_node(&graph),
            Err(RuntimeError::NoConfirmedActiveNode)
        ));
        Ok(())
    }

    #[test]
    fn first_funding_confirmation_cannot_regress_an_observed_tip() -> Result<(), RuntimeError> {
        let graph = funding_graph();
        let mut monitor = ChainMonitor::new(
            graph.chain_game_id(),
            graph.graph_root(),
            graph.root.node_id,
            NonZeroU16::MIN,
        );
        monitor.observe_tip(110)?;
        assert!(matches!(
            monitor.confirm_funding(
                &graph,
                graph.expected_outpoint,
                &graph.expected_output,
                100,
                109,
            ),
            Err(RuntimeError::ReorgDetected)
        ));
        assert_eq!(monitor.state(), MonitorState::Halted);
        Ok(())
    }

    #[test]
    fn child_confirmation_rejects_graph_root_substitution_before_idempotence() {
        let mut graph = funding_graph();
        let authoritative_root = graph.graph_root;
        graph.graph_root[0] ^= 1;
        let mut public = PublicPreimageStore::new(graph.chain_game_id(), graph.deal);
        let mut eraser = NoopEraser;

        for state in [
            MonitorState::Active {
                node_id: graph.root.node_id,
                confirmed_height: 100,
                creating_txid: None,
            },
            MonitorState::Terminal {
                node_id: [12; 32],
                confirmed_height: 101,
                txid: [13; 32],
            },
        ] {
            let mut monitor = ChainMonitor {
                chain_game_id: graph.chain_game_id(),
                graph_root: authoritative_root,
                funding_confirmation_depth: NonZeroU16::MIN,
                state,
                highest_tip: Some(101),
                issued_authorization_witness: None,
            };
            assert!(matches!(
                monitor.confirm_child(
                    &graph,
                    [12; 32],
                    &genesis_block(Network::Regtest).txdata[0],
                    101,
                    &mut public,
                    &mut eraser,
                ),
                Err(RuntimeError::InconsistentGraph { .. })
            ));
            assert_eq!(monitor.state(), state);
        }
    }

    #[test]
    fn confirmed_branch_erasure_checks_context_and_zeroizes() -> Result<(), RuntimeError> {
        let (mut key, _) = generate_key(
            &mut OsRng,
            KeyContext::new([1; 32], [2; 32], LamportPurpose::AliceScore24Bit),
        )?;
        assert!(matches!(
            erase_lamport_key(&mut key, [1; 32], [3; 32]),
            Err(RuntimeError::SecretErasure { .. })
        ));
        assert!(!key.is_erased());
        erase_lamport_key(&mut key, [1; 32], [2; 32])?;
        assert!(key.is_erased());
        Ok(())
    }
}
