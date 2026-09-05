//! Narrow adapter over compiler graph storage and Bitcoin leaf assembly.

use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::{Network, OutPoint, Transaction, TxOut};
use bp52_chain_bitcoin::{
    CompiledTapLeaf, DefaultSighashSignature, TransactionTemplate, taproot_script_sighash_default,
};
use bp52_chain_types::{AcceptedDeal, EdgeKind, LogicalEdge, LogicalNodeRecord, NodeId, Role};
use bp52_lamport::{LamportPublicKey, LamportPurpose};
use bp52_poker::{HandCategory, HandScore};

use crate::builders::{validate_non_timeout_witness, validate_timeout_witness};
use crate::{MatureTimeout, RuntimeError, Witness};

pub(crate) mod sealed {
    /// Internal marker preventing unverified external graph implementations.
    pub trait Sealed {}
}

/// Redacted failure returned by an external Bitcoin signing device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerError {
    reason: &'static str,
}

impl SignerError {
    /// Construct a redacted signer failure.
    #[must_use]
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for SignerError {}

/// Live signer for signatures that MUST NOT be exchanged before funding.
pub trait BitcoinSigner {
    /// Sign one already-computed BIP341 `SIGHASH_DEFAULT` digest.
    ///
    /// The node and child identifiers are supplied so hardware/encrypted
    /// keystores can enforce their own policy before releasing a signature.
    ///
    /// # Errors
    ///
    /// Returns a redacted device/keystore policy or signing failure.
    fn sign_sighash_default(
        &self,
        role: Role,
        node_id: NodeId,
        child_node_id: NodeId,
        digest: [u8; 32],
    ) -> Result<DefaultSighashSignature, SignerError>;
}

/// Stable, sealed runtime view over the verified concrete compiler graph.
///
/// This is intentionally small and cannot be implemented outside this crate.
/// The runtime rechecks every local association before consuming secrets or
/// requesting a live signature.
pub trait ChainBackend: sealed::Sealed {
    /// Network selected by all fixed templates.
    fn network(&self) -> Network;
    /// Exact descriptor network identifier.
    ///
    /// Unlike [`Self::network`], this opaque identifier distinguishes custom
    /// signets that share Bitcoin's standard signet genesis block.
    fn network_id(&self) -> [u8; 32];
    /// Identifier binding Lamport keys and runtime public data.
    fn chain_game_id(&self) -> [u8; 32];
    /// Authenticated deterministic graph root used to prevent backend
    /// substitution after the monitor is initialized.
    fn graph_root(&self) -> [u8; 32];
    /// Exact accepted deal committed by the graph.
    fn accepted_deal(&self) -> &AcceptedDeal;
    /// Identity key used for one role's fixed or live transaction signatures.
    fn identity_key(&self, role: Role) -> [u8; 32];
    /// Return the required root-state outpoint, if the backend models the
    /// surrounding funding contract.
    fn expected_funding_state_outpoint(&self) -> Option<OutPoint> {
        None
    }
    /// Return the required root-state output, if the backend models the
    /// surrounding funding contract.
    fn expected_funding_state_output(&self) -> Option<&TxOut> {
        None
    }
    /// Look up one canonical logical node.
    fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord>;
    /// Look up one directed logical edge by exact endpoints.
    fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge>;
    /// Look up the fixed Bitcoin template creating one child.
    fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate>;
    /// Look up the exact script leaf spending a parent into one child.
    fn tap_leaf(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&CompiledTapLeaf>;
    /// Look up the showdown leaf selected by the proved hand category.
    fn showdown_tap_leaf(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        category: HandCategory,
    ) -> Option<&CompiledTapLeaf> {
        let leaf = self.tap_leaf(parent_node_id, child_node_id)?;
        (leaf.showdown_category().is_none() || leaf.showdown_category() == Some(category))
            .then_some(leaf)
    }
    /// Return the predicate identifier committed for an edge.
    ///
    /// Current action, reveal, and timeout adapters can inherit this method.
    /// A future consensus showdown adapter may override it while its concrete
    /// leaf representation remains isolated in the Bitcoin backend.
    fn predicate_id(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<[u8; 32]> {
        self.tap_leaf(parent_node_id, child_node_id)
            .map(CompiledTapLeaf::predicate_id)
    }
    /// Compute the fixed template's exact script-path `SIGHASH_DEFAULT` digest.
    ///
    /// # Errors
    ///
    /// Rejects a missing template/leaf or an invalid BIP341 sighash context.
    fn signature_digest(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
    ) -> Result<[u8; 32], RuntimeError> {
        let template =
            self.transaction_template(child_node_id)
                .ok_or(RuntimeError::InconsistentGraph {
                    reason: "selected edge has no Bitcoin transaction template",
                })?;
        let leaf = self.tap_leaf(parent_node_id, child_node_id).ok_or(
            RuntimeError::InconsistentGraph {
                reason: "selected edge has no compiled Taproot leaf",
            },
        )?;
        Ok(taproot_script_sighash_default(
            template.transaction(),
            0,
            std::slice::from_ref(template.parent_output()),
            leaf.script(),
        )?)
    }
    /// Assemble semantic stack elements for one exact edge.
    ///
    /// # Errors
    ///
    /// Rejects a missing compiled leaf or an invalid witness stack.
    fn assemble_witness(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        elements: &[Vec<u8>],
    ) -> Result<bitcoin::Witness, RuntimeError> {
        let leaf = self.tap_leaf(parent_node_id, child_node_id).ok_or(
            RuntimeError::InconsistentGraph {
                reason: "selected edge has no compiled Taproot leaf",
            },
        )?;
        Ok(leaf.assemble_witness(elements)?)
    }

    /// Assemble a witness through the selected category-specific showdown leaf.
    fn assemble_showdown_witness(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        category: HandCategory,
        elements: &[Vec<u8>],
    ) -> Result<bitcoin::Witness, RuntimeError> {
        let Some(leaf) = self.showdown_tap_leaf(parent_node_id, child_node_id, category) else {
            return self.assemble_witness(parent_node_id, child_node_id, elements);
        };
        Ok(leaf.assemble_witness(elements)?)
    }
    /// Look up context-bound public OTS material.
    fn lamport_public_key(
        &self,
        node_id: NodeId,
        purpose: LamportPurpose,
    ) -> Option<&LamportPublicKey>;
    /// Look up a verified pre-exchanged transaction signature.
    fn preauthorization(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
    ) -> Option<DefaultSighashSignature>;

    /// Resolve the preauthorization for an exact leaf-specific sighash.
    fn preauthorization_for_sighash(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
        _sighash: [u8; 32],
    ) -> Option<DefaultSighashSignature> {
        self.preauthorization(parent_node_id, child_node_id, role)
    }
}

/// One fully cross-checked parent/edge/child/template/predicate association.
#[derive(Clone, Copy)]
pub struct ValidatedEdge<'a> {
    /// Parent logical node.
    pub parent: &'a LogicalNodeRecord,
    /// Selected logical edge.
    pub edge: &'a LogicalEdge,
    /// Child logical node.
    pub child: &'a LogicalNodeRecord,
    /// Fixed Bitcoin transaction template.
    pub template: &'a TransactionTemplate,
}

impl fmt::Debug for ValidatedEdge<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedEdge")
            .field("parent", &self.parent.node_id)
            .field("edge_kind", &self.edge.kind)
            .field("child", &self.child.node_id)
            .field("txid", &self.template.txid())
            .finish()
    }
}

/// A fixed transaction after one validated runtime witness is attached.
#[derive(Debug)]
pub struct PreparedTransaction {
    pub(crate) transaction: Transaction,
    pub(crate) template_txid: [u8; 32],
    pub(crate) network: Network,
    pub(crate) network_id: [u8; 32],
    pub(crate) chain_game_id: [u8; 32],
    pub(crate) graph_root: [u8; 32],
    pub(crate) parent_node_id: NodeId,
    pub(crate) child_node_id: NodeId,
}

impl PreparedTransaction {
    /// Return the transaction ready for non-mainnet broadcast.
    #[must_use]
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Return the txid committed before runtime witness data was known.
    #[must_use]
    pub const fn template_txid(&self) -> [u8; 32] {
        self.template_txid
    }

    /// Return the exact descriptor network identifier bound to this branch.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Return the exact chain game bound to this prepared branch.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Return the parent and child nodes selected by this transaction.
    #[must_use]
    pub const fn endpoints(&self) -> (NodeId, NodeId) {
        (self.parent_node_id, self.child_node_id)
    }
}

/// Resolve exactly one semantic child and validate every graph association.
///
/// # Errors
///
/// Rejects missing/ambiguous edges, malformed records, endpoint/linkage
/// mismatches, a substituted transaction template, or a substituted leaf.
pub fn validate_exact_edge(
    graph: &dyn ChainBackend,
    parent_node_id: NodeId,
    kind: EdgeKind,
) -> Result<ValidatedEdge<'_>, RuntimeError> {
    reject_mainnet(graph.network())?;
    let parent = graph
        .node(parent_node_id)
        .ok_or(RuntimeError::NodeNotFound {
            node_id: parent_node_id,
        })?;
    parent.validate()?;

    let mut selected = None;
    for child_node_id in &parent.child_node_ids {
        let edge =
            graph
                .edge(parent_node_id, *child_node_id)
                .ok_or(RuntimeError::MissingListedEdge {
                    parent_node_id,
                    child_node_id: *child_node_id,
                })?;
        if edge.kind == kind && selected.replace((*child_node_id, edge)).is_some() {
            return Err(RuntimeError::AmbiguousEdge {
                node_id: parent_node_id,
                kind,
            });
        }
    }
    let (child_node_id, edge) = selected.ok_or(RuntimeError::EdgeNotFound {
        node_id: parent_node_id,
        kind,
    })?;
    edge.validate()?;
    if edge.parent_node_id != parent_node_id || edge.child_node_id != child_node_id {
        return Err(RuntimeError::InconsistentGraph {
            reason: "edge endpoints disagree with graph lookup",
        });
    }
    let child = graph
        .node(child_node_id)
        .ok_or(RuntimeError::NodeNotFound {
            node_id: child_node_id,
        })?;
    child.validate()?;
    if child.parent_node_id != Some(parent_node_id) {
        return Err(RuntimeError::InconsistentGraph {
            reason: "child does not name the selected parent",
        });
    }
    if child.transaction.as_ref() != Some(&edge.transaction) {
        return Err(RuntimeError::InconsistentGraph {
            reason: "child creating transaction differs from selected edge",
        });
    }
    let template =
        graph
            .transaction_template(child_node_id)
            .ok_or(RuntimeError::InconsistentGraph {
                reason: "selected edge has no Bitcoin transaction template",
            })?;
    if template.to_logical_transaction() != edge.transaction {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Bitcoin template differs from canonical logical transaction",
        });
    }
    let predicate_id = graph.predicate_id(parent_node_id, child_node_id).ok_or(
        RuntimeError::InconsistentGraph {
            reason: "selected edge has no compiled predicate",
        },
    )?;
    if predicate_id != child.required_predicate_id {
        return Err(RuntimeError::InconsistentGraph {
            reason: "compiled leaf differs from child predicate identifier",
        });
    }
    Ok(ValidatedEdge {
        parent,
        edge,
        child,
        template,
    })
}

/// Compute the exact script-path `SIGHASH_DEFAULT` digest for a validated edge.
///
/// # Errors
///
/// Returns the underlying Bitcoin sighash error.
pub(crate) fn edge_sighash(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
) -> Result<[u8; 32], RuntimeError> {
    graph.signature_digest(edge.parent.node_id, edge.child.node_id)
}

/// Compute the sighash for a category-specific showdown leaf.
pub(crate) fn showdown_sighash(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    category: HandCategory,
) -> Result<[u8; 32], RuntimeError> {
    let Some(leaf) = graph.showdown_tap_leaf(edge.parent.node_id, edge.child.node_id, category)
    else {
        return graph.signature_digest(edge.parent.node_id, edge.child.node_id);
    };
    Ok(taproot_script_sighash_default(
        edge.template.transaction(),
        0,
        std::slice::from_ref(edge.template.parent_output()),
        leaf.script(),
    )?)
}

/// Validate and attach a non-timeout runtime witness to its exact fixed
/// template.
///
/// # Errors
///
/// Rejects a timeout witness, invalid Bitcoin or Lamport signatures, invalid
/// reveal/showdown data, a witness bound to another edge, an invalid graph
/// association, wrong stack shape, or any change to the precommitted txid.
pub fn attach_witness(
    graph: &dyn ChainBackend,
    active: &crate::ConfirmedActiveNode<'_>,
    witness: &Witness,
) -> Result<PreparedTransaction, RuntimeError> {
    let edge = validate_non_timeout_witness(graph, active, witness)?;
    prepare_transaction(graph, edge, witness)
}

/// Validate and attach a fully authorized non-timeout witness whose parent is
/// the current durable off-chain ratchet head rather than a confirmed UTXO.
///
/// Confirmation is intentionally not fabricated here. The caller supplies the
/// exact expected parent node from its authenticated hash chain, while this
/// boundary rechecks all graph semantics, signatures, predicates, and the
/// witness-independent transaction id. CSV timeout witnesses remain forbidden
/// until the real chain monitor proves maturity.
pub fn attach_offchain_witness(
    graph: &dyn ChainBackend,
    expected_parent_node_id: NodeId,
    witness: &Witness,
) -> Result<PreparedTransaction, RuntimeError> {
    if witness.node_id() != expected_parent_node_id || matches!(witness, Witness::Timeout { .. }) {
        return Err(RuntimeError::WrongAuthorization);
    }
    let edge = crate::builders::validate_witness_semantics(graph, witness)?;
    if edge.parent.node_id != expected_parent_node_id {
        return Err(RuntimeError::InactiveNode {
            expected: expected_parent_node_id,
            actual: edge.parent.node_id,
        });
    }
    prepare_transaction(graph, edge, witness)
}

/// Validate a selected off-chain witness and transactionally ingest any
/// public reveal/showdown material it carries.
///
/// This does not fabricate a confirmation or unlock CSV paths. It only moves
/// the caller's authenticated off-chain projection after every witness
/// predicate and Bitcoin signature has verified.
pub fn apply_offchain_witness(
    graph: &dyn ChainBackend,
    expected_parent_node_id: NodeId,
    witness: &Witness,
    public_preimages: &mut crate::PublicPreimageStore,
) -> Result<PreparedTransaction, RuntimeError> {
    let prepared = attach_offchain_witness(graph, expected_parent_node_id, witness)?;
    let mut next_public = public_preimages.clone();
    next_public.ensure_binding(graph.chain_game_id(), graph.accepted_deal())?;
    crate::monitor::ingest_public_witness(&mut next_public, witness)?;
    *public_preimages = next_public;
    Ok(prepared)
}

/// Validate and attach a timeout witness after its exact CSV maturity.
///
/// The opaque [`MatureTimeout`] capability proves both that the witness spends
/// the monitor's confirmed active state and that its graph-committed relative
/// delay has elapsed.
///
/// # Errors
///
/// Rejects a non-timeout witness, an immature or mismatched capability, a
/// missing or invalid opponent preauthorization, an invalid beneficiary
/// signature, an invalid graph association, wrong stack shape, or any change
/// to the precommitted txid.
pub fn attach_timeout_witness(
    graph: &dyn ChainBackend,
    mature_timeout: &MatureTimeout<'_>,
    witness: &Witness,
) -> Result<PreparedTransaction, RuntimeError> {
    let edge = validate_timeout_witness(graph, mature_timeout, witness)?;
    prepare_transaction(graph, edge, witness)
}

fn prepare_transaction(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    witness: &Witness,
) -> Result<PreparedTransaction, RuntimeError> {
    let elements = witness.to_witness_elements(graph.accepted_deal())?;
    let bitcoin_witness = match witness {
        Witness::AliceShowdown { hand, .. } | Witness::BobPayout { hand, .. } => {
            let category = HandScore::try_from(hand.claimed_score())?.category();
            graph.assemble_showdown_witness(
                edge.parent.node_id,
                edge.child.node_id,
                category,
                &elements,
            )?
        }
        _ => graph.assemble_witness(edge.parent.node_id, edge.child.node_id, &elements)?,
    };
    let transaction = edge.template.with_witness(bitcoin_witness)?;
    let actual_txid = transaction.compute_txid().to_byte_array();
    let template_txid = edge.template.txid();
    if actual_txid != template_txid || template_txid != edge.edge.transaction.txid {
        return Err(RuntimeError::InconsistentGraph {
            reason: "runtime witness changed the fixed transaction id",
        });
    }
    Ok(PreparedTransaction {
        transaction,
        template_txid,
        network: graph.network(),
        network_id: graph.network_id(),
        chain_game_id: graph.chain_game_id(),
        graph_root: graph.graph_root(),
        parent_node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
    })
}

pub(crate) fn reject_mainnet(network: Network) -> Result<(), RuntimeError> {
    if network == Network::Bitcoin {
        Err(RuntimeError::MainnetDisabled)
    } else {
        Ok(())
    }
}
