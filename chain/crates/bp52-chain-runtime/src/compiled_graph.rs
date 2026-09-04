//! Runtime adapter for the compiler's immutable concrete graph.

use bitcoin::{Network, OutPoint, TxOut};
use bp52_chain_bitcoin::{CompiledTapLeaf, DefaultSighashSignature, TransactionTemplate};
use bp52_chain_compiler::{CompiledGraph, MaterializedGraphWindow};
use bp52_chain_types::{AcceptedDeal, LogicalEdge, LogicalNodeRecord, NodeId, Role};
use bp52_lamport::{LamportPublicKey, LamportPurpose};
use bp52_poker::HandCategory;

use crate::ChainBackend;

/// Role-aware signature lookup kept outside the deterministic graph.
///
/// A CHAIN worker can retain one packed peer vector and derive its own
/// signatures on demand without copying either capability into
/// [`CompiledGraph`].
pub trait PreauthorizationSource {
    /// Resolve one exact graph edge signature for `role`.
    fn preauthorization(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
    ) -> Option<DefaultSighashSignature>;

    /// Resolve a signature when one logical edge has multiple Taproot leaves.
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

/// Runtime view that overlays external signature ownership on a compiled graph.
pub struct AuthorizedGraph<'a> {
    graph: &'a dyn ChainBackend,
    preauthorizations: &'a dyn PreauthorizationSource,
}

impl<'a> AuthorizedGraph<'a> {
    /// Borrow a graph with its role-local, single-owner signature source.
    #[must_use]
    pub const fn new(
        graph: &'a dyn ChainBackend,
        preauthorizations: &'a dyn PreauthorizationSource,
    ) -> Self {
        Self {
            graph,
            preauthorizations,
        }
    }
}

impl crate::backend::sealed::Sealed for MaterializedGraphWindow {}

impl ChainBackend for MaterializedGraphWindow {
    fn network(&self) -> Network {
        self.summary().network()
    }

    fn network_id(&self) -> [u8; 32] {
        self.summary().descriptor().network_id
    }

    fn chain_game_id(&self) -> [u8; 32] {
        self.summary().manifest().chain_game_id
    }

    fn graph_root(&self) -> [u8; 32] {
        self.summary().manifest().graph_root
    }

    fn accepted_deal(&self) -> &AcceptedDeal {
        &self.summary().descriptor().deal
    }

    fn identity_key(&self, role: Role) -> [u8; 32] {
        *self.summary().descriptor().identity_key(role)
    }

    fn expected_funding_state_outpoint(&self) -> Option<OutPoint> {
        Some(self.summary().root_state_outpoint())
    }

    fn expected_funding_state_output(&self) -> Option<&TxOut> {
        Some(self.summary().root_state_output())
    }

    fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
        MaterializedGraphWindow::node(self, node_id)
    }

    fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge> {
        MaterializedGraphWindow::edge(self, parent_node_id, child_node_id)
    }

    fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate> {
        MaterializedGraphWindow::transaction_template(self, child_node_id)
    }

    fn tap_leaf(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&CompiledTapLeaf> {
        MaterializedGraphWindow::tap_leaf(self, parent_node_id, child_node_id)
    }

    fn showdown_tap_leaf(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        category: HandCategory,
    ) -> Option<&CompiledTapLeaf> {
        MaterializedGraphWindow::showdown_tap_leaf(self, parent_node_id, child_node_id, category)
    }

    fn lamport_public_key(
        &self,
        node_id: NodeId,
        purpose: LamportPurpose,
    ) -> Option<&LamportPublicKey> {
        MaterializedGraphWindow::lamport_public_key(self, node_id, purpose)
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

impl crate::backend::sealed::Sealed for AuthorizedGraph<'_> {}

impl ChainBackend for AuthorizedGraph<'_> {
    fn network(&self) -> Network {
        self.graph.network()
    }

    fn network_id(&self) -> [u8; 32] {
        self.graph.network_id()
    }

    fn chain_game_id(&self) -> [u8; 32] {
        self.graph.chain_game_id()
    }

    fn graph_root(&self) -> [u8; 32] {
        self.graph.graph_root()
    }

    fn accepted_deal(&self) -> &AcceptedDeal {
        self.graph.accepted_deal()
    }

    fn identity_key(&self, role: Role) -> [u8; 32] {
        self.graph.identity_key(role)
    }

    fn expected_funding_state_outpoint(&self) -> Option<OutPoint> {
        self.graph.expected_funding_state_outpoint()
    }

    fn expected_funding_state_output(&self) -> Option<&TxOut> {
        self.graph.expected_funding_state_output()
    }

    fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
        self.graph.node(node_id)
    }

    fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge> {
        self.graph.edge(parent_node_id, child_node_id)
    }

    fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate> {
        self.graph.transaction_template(child_node_id)
    }

    fn tap_leaf(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&CompiledTapLeaf> {
        self.graph.tap_leaf(parent_node_id, child_node_id)
    }

    fn showdown_tap_leaf(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        category: HandCategory,
    ) -> Option<&CompiledTapLeaf> {
        self.graph
            .showdown_tap_leaf(parent_node_id, child_node_id, category)
    }

    fn lamport_public_key(
        &self,
        node_id: NodeId,
        purpose: LamportPurpose,
    ) -> Option<&LamportPublicKey> {
        self.graph.lamport_public_key(node_id, purpose)
    }

    fn preauthorization(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
    ) -> Option<DefaultSighashSignature> {
        self.preauthorizations
            .preauthorization(parent_node_id, child_node_id, role)
    }

    fn preauthorization_for_sighash(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
        sighash: [u8; 32],
    ) -> Option<DefaultSighashSignature> {
        self.preauthorizations.preauthorization_for_sighash(
            parent_node_id,
            child_node_id,
            role,
            sighash,
        )
    }
}

impl crate::backend::sealed::Sealed for CompiledGraph {}

impl ChainBackend for CompiledGraph {
    fn network(&self) -> Network {
        CompiledGraph::network(self)
    }

    fn network_id(&self) -> [u8; 32] {
        self.descriptor().network_id
    }

    fn chain_game_id(&self) -> [u8; 32] {
        self.manifest().chain_game_id
    }

    fn graph_root(&self) -> [u8; 32] {
        self.manifest().graph_root
    }

    fn accepted_deal(&self) -> &AcceptedDeal {
        &self.descriptor().deal
    }

    fn identity_key(&self, role: Role) -> [u8; 32] {
        *self.descriptor().identity_key(role)
    }

    fn expected_funding_state_outpoint(&self) -> Option<OutPoint> {
        Some(CompiledGraph::expected_funding_state_outpoint(self))
    }

    fn expected_funding_state_output(&self) -> Option<&TxOut> {
        Some(CompiledGraph::expected_funding_state_output(self))
    }

    fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
        CompiledGraph::node(self, node_id)
    }

    fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge> {
        CompiledGraph::edge(self, parent_node_id, child_node_id)
    }

    fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate> {
        CompiledGraph::transaction_template(self, child_node_id)
    }

    fn tap_leaf(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&CompiledTapLeaf> {
        CompiledGraph::tap_leaf(self, parent_node_id, child_node_id)
    }

    fn showdown_tap_leaf(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        category: HandCategory,
    ) -> Option<&CompiledTapLeaf> {
        CompiledGraph::showdown_tap_leaf(self, parent_node_id, child_node_id, category)
    }

    fn lamport_public_key(
        &self,
        node_id: NodeId,
        purpose: LamportPurpose,
    ) -> Option<&LamportPublicKey> {
        CompiledGraph::lamport_public_key(self, node_id, purpose)
    }

    fn preauthorization(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
    ) -> Option<DefaultSighashSignature> {
        CompiledGraph::preauthorization(self, parent_node_id, child_node_id, role)
    }

    fn preauthorization_for_sighash(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
        sighash: [u8; 32],
    ) -> Option<DefaultSighashSignature> {
        CompiledGraph::preauthorization_for_sighash(
            self,
            parent_node_id,
            child_node_id,
            role,
            sighash,
        )
    }
}
