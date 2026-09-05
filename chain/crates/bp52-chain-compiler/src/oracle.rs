//! Compact graph facts and bounded runtime pages.
//!
//! Whole-graph compilation is an audit/setup operation. Long-lived GAME and
//! CHAIN runtimes retain the types in this module instead of a
//! `CompiledGraph`, keeping unrelated branches out of steady-state memory.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, OutPoint, TxOut, Txid};
use bp52_chain_bitcoin::{
    CompiledTapLeaf, CompiledTaprootState, TransactionTemplate, taproot_script_sighash_default,
};
use bp52_chain_types::{
    ChainGameDescriptor, LogicalEdge, LogicalNodeRecord, NodeId, Role, root_node_id,
};
use bp52_codec::Encode;
use bp52_lamport::{LamportPublicKey, LamportPurpose};
use bp52_poker::HandCategory;
use sha2::{Digest, Sha256};

use crate::graph::PlannedState;
use crate::manifest::GraphManifest;
use crate::materialize::{
    LamportPublicMaterial, PreparedChainGraph, collect_lamport_keys, funded_root_predicate,
    outputs_for_child_state, preauthorized_roles, programs_for_edge, programs_for_node,
    runtime_signature_role_and_kind, state_output, terminal_script, verify_activation_template,
    verify_local_retained_preimages, verify_ordered_lamport_keys,
};
use crate::{CompilerError, RuntimeSignatureRequest, SignatureRequest};
use bp52_lamport::LamportSecretKey;
use bp52_protocol::RetainedPreimages;

/// Compact immutable facts needed after whole-graph setup has completed.
///
/// This value contains no logical-plan nodes, transaction tree, Taproot-state
/// map, Lamport bundle, or signature-request vectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledGraphSummary {
    pub(crate) descriptor: ChainGameDescriptor,
    pub(crate) network: Network,
    pub(crate) manifest: GraphManifest,
    pub(crate) origin_outpoint: OutPoint,
    pub(crate) origin_output: TxOut,
    pub(crate) activation_template: TransactionTemplate,
    pub(crate) root_state_outpoint: OutPoint,
    pub(crate) root_state_output: TxOut,
    pub(crate) root_node_id: NodeId,
    pub(crate) preauthorization_counts: [u32; 2],
    pub(crate) runtime_signature_counts: [u32; 2],
    pub(crate) lamport_counts: [u32; 2],
}

impl CompiledGraphSummary {
    /// Exact signed descriptor from which the graph was compiled.
    #[must_use]
    pub const fn descriptor(&self) -> &ChainGameDescriptor {
        &self.descriptor
    }

    /// Non-mainnet Bitcoin parameter family used by every template.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Authenticated graph manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GraphManifest {
        &self.manifest
    }

    /// Pre-existing two-party origin outpoint.
    #[must_use]
    pub const fn origin_outpoint(&self) -> OutPoint {
        self.origin_outpoint
    }

    /// Exact origin output observed before setup.
    #[must_use]
    pub const fn origin_output(&self) -> &TxOut {
        &self.origin_output
    }

    /// Witness-independent origin-to-root transaction.
    #[must_use]
    pub const fn activation_template(&self) -> &TransactionTemplate {
        &self.activation_template
    }

    /// Outpoint created by the activation transaction.
    #[must_use]
    pub const fn root_state_outpoint(&self) -> OutPoint {
        self.root_state_outpoint
    }

    /// Exact gameplay-root output.
    #[must_use]
    pub const fn root_state_output(&self) -> &TxOut {
        &self.root_state_output
    }

    /// Logical gameplay-root node identifier.
    #[must_use]
    pub const fn root_node_id(&self) -> NodeId {
        self.root_node_id
    }

    /// Number of fixed preauthorizations exchanged by `role`.
    #[must_use]
    pub const fn preauthorization_count(&self, role: Role) -> u32 {
        match role {
            Role::Alice => self.preauthorization_counts[0],
            Role::Bob => self.preauthorization_counts[1],
        }
    }

    /// Number of role-local signatures available only after setup.
    #[must_use]
    pub const fn runtime_signature_count(&self, role: Role) -> u32 {
        match role {
            Role::Alice => self.runtime_signature_counts[0],
            Role::Bob => self.runtime_signature_counts[1],
        }
    }

    /// Number of role-local Lamport keys committed by the graph.
    #[must_use]
    pub const fn lamport_count(&self, role: Role) -> u32 {
        match role {
            Role::Alice => self.lamport_counts[0],
            Role::Bob => self.lamport_counts[1],
        }
    }
}

/// Bounded runtime projection containing one active node and its direct
/// transaction choices.
///
/// The active node's parent is retained only because Bob's payout validation
/// authenticates the already-confirmed Alice score certificate against that
/// parent. No unrelated branch is present.
#[derive(Clone, Debug)]
pub struct MaterializedGraphWindow {
    pub(crate) summary: CompiledGraphSummary,
    pub(crate) active_node_id: NodeId,
    pub(crate) active_state: PlannedState,
    pub(crate) nodes: HashMap<NodeId, LogicalNodeRecord>,
    pub(crate) edges: HashMap<(NodeId, NodeId), LogicalEdge>,
    pub(crate) templates: HashMap<NodeId, TransactionTemplate>,
    pub(crate) leaves: HashMap<(NodeId, NodeId), CompiledTapLeaf>,
    pub(crate) showdown_leaves: HashMap<(NodeId, NodeId, HandCategory), CompiledTapLeaf>,
    pub(crate) lamport_keys: HashMap<(NodeId, LamportPurpose), LamportPublicKey>,
    pub(crate) lamport_key_indices: HashMap<(NodeId, LamportPurpose), usize>,
    pub(crate) preauthorization_requests:
        HashMap<(NodeId, NodeId, Role), (usize, SignatureRequest)>,
    pub(crate) preauthorization_requests_by_sighash:
        HashMap<(NodeId, NodeId, Role, [u8; 32]), (usize, SignatureRequest)>,
}

impl MaterializedGraphWindow {
    /// Compact graph facts shared by every runtime window.
    #[must_use]
    pub const fn summary(&self) -> &CompiledGraphSummary {
        &self.summary
    }

    /// Node whose outgoing choices are materialized in this window.
    #[must_use]
    pub const fn active_node_id(&self) -> NodeId {
        self.active_node_id
    }

    /// Semantic state used for player stack and pot projection.
    #[must_use]
    pub const fn active_state(&self) -> &PlannedState {
        &self.active_state
    }

    /// Number of logical records retained by this bounded projection.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of outgoing transaction templates retained by this projection.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.templates.len()
    }

    /// Find one record in the active node, its parent, or its children.
    #[must_use]
    pub fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
        self.nodes.get(&node_id)
    }

    /// Find one outgoing edge from the active node.
    #[must_use]
    pub fn edge(&self, parent: NodeId, child: NodeId) -> Option<&LogicalEdge> {
        self.edges.get(&(parent, child))
    }

    /// Find one outgoing transaction template from the active node.
    #[must_use]
    pub fn transaction_template(&self, child: NodeId) -> Option<&TransactionTemplate> {
        self.templates.get(&child)
    }

    /// Find one exact active-node Taproot leaf.
    #[must_use]
    pub fn tap_leaf(&self, parent: NodeId, child: NodeId) -> Option<&CompiledTapLeaf> {
        self.leaves.get(&(parent, child))
    }

    /// Find one category-specific showdown leaf in this runtime window.
    #[must_use]
    pub fn showdown_tap_leaf(
        &self,
        parent: NodeId,
        child: NodeId,
        category: HandCategory,
    ) -> Option<&CompiledTapLeaf> {
        self.showdown_leaves.get(&(parent, child, category))
    }

    /// Find score-verification material required by the active transition.
    #[must_use]
    pub fn lamport_public_key(
        &self,
        node_id: NodeId,
        purpose: LamportPurpose,
    ) -> Option<&LamportPublicKey> {
        self.lamport_keys
            .get(&(node_id, purpose))
            .or_else(|| self.lamport_keys.get(&(self.summary.root_node_id, purpose)))
    }

    /// Return the role-local canonical inventory position for a score key.
    #[must_use]
    pub fn lamport_key_index(&self, node_id: NodeId, purpose: LamportPurpose) -> Option<usize> {
        self.lamport_key_indices
            .get(&(node_id, purpose))
            .or_else(|| {
                self.lamport_key_indices
                    .get(&(self.summary.root_node_id, purpose))
            })
            .copied()
    }

    /// Return the canonical bundle position and request for an active edge.
    ///
    /// The position is stable in the globally sorted role bundle even though
    /// the window retains no global request vector.
    #[must_use]
    pub fn preauthorization_request(
        &self,
        parent: NodeId,
        child: NodeId,
        role: Role,
    ) -> Option<(usize, SignatureRequest)> {
        self.preauthorization_requests
            .get(&(parent, child, role))
            .copied()
    }

    /// Return the bundle position for one leaf-specific sighash.
    #[must_use]
    pub fn preauthorization_request_for_sighash(
        &self,
        parent: NodeId,
        child: NodeId,
        role: Role,
        sighash: [u8; 32],
    ) -> Option<(usize, SignatureRequest)> {
        self.preauthorization_requests_by_sighash
            .get(&(parent, child, role, sighash))
            .copied()
    }
}

/// Transient signature-request inventory emitted by the streaming compiler.
///
/// Callers consume and drop this value during setup. It is intentionally
/// separate from [`CompiledGraphSummary`] and [`MaterializedGraphWindow`] so a
/// long-lived runtime cannot accidentally retain it as part of its graph
/// state.
#[derive(Debug)]
pub struct OracleSignatureRequests {
    alice_preauthorizations: Vec<SignatureRequest>,
    bob_preauthorizations: Vec<SignatureRequest>,
    alice_runtime: Vec<RuntimeSignatureRequest>,
    bob_runtime: Vec<RuntimeSignatureRequest>,
}

impl OracleSignatureRequests {
    /// Drop runtime-only requests once their setup counts have been audited.
    ///
    /// Runtime pages rederive these requests from the active path, so retaining
    /// the whole-graph vectors after the streaming pass only wastes memory.
    pub fn discard_runtime_requests(&mut self) {
        self.alice_runtime.clear();
        self.alice_runtime.shrink_to_fit();
        self.bob_runtime.clear();
        self.bob_runtime.shrink_to_fit();
    }

    /// Sorted fixed preauthorization requests for one role.
    #[must_use]
    pub fn preauthorizations(&self, role: Role) -> &[SignatureRequest] {
        match role {
            Role::Alice => &self.alice_preauthorizations,
            Role::Bob => &self.bob_preauthorizations,
        }
    }

    /// Sorted role-local runtime requests for one role.
    #[must_use]
    pub fn runtime(&self, role: Role) -> &[RuntimeSignatureRequest] {
        match role {
            Role::Alice => &self.alice_runtime,
            Role::Bob => &self.bob_runtime,
        }
    }
}

/// Allocation-shape counters for regression tests and browser telemetry.
///
/// These are collection element counts rather than allocator-specific bytes,
/// making the bound deterministic across native and Wasm allocators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphOracleMetrics {
    /// Total Taproot-state compilation calls made by this pass.
    pub compiled_states: usize,
    /// Maximum simultaneously live compiled Taproot states.
    pub peak_compiled_states: usize,
    /// Maximum unresolved state outpoints retained during preorder traversal.
    pub peak_spend_points: usize,
    /// One 32-byte hash retained per record until the Merkle reduction.
    pub record_hashes: usize,
    /// Signature requests retained transiently for canonical sorting.
    pub setup_signature_requests: usize,
    /// Logical records retained after setup.
    pub retained_window_nodes: usize,
    /// Transaction templates retained after setup.
    pub retained_window_templates: usize,
}

/// Result of one streaming whole-graph audit pass.
#[derive(Debug)]
pub struct GraphOracleSetup {
    /// Compact immutable graph facts.
    pub summary: CompiledGraphSummary,
    /// Bounded page for the requested active node.
    pub window: MaterializedGraphWindow,
    /// Transient sorted setup requests; consume and drop after exchange.
    pub requests: OracleSignatureRequests,
    /// Deterministic allocation-shape counters.
    pub metrics: GraphOracleMetrics,
}

/// Result of paging one active state after the whole graph was audited.
///
/// Unlike [`GraphOracleSetup`], this contains no whole-graph request inventory
/// and does not recompute the graph commitment. It authenticates the supplied
/// setup summary, walks only the root-to-active path, and materializes only the
/// active node's direct children.
#[derive(Debug)]
pub struct GraphOraclePage {
    /// Bounded active-node projection.
    pub window: MaterializedGraphWindow,
    /// Deterministic work/allocation counters.
    pub metrics: GraphOracleMetrics,
}

/// Verify local one-time keys and DEAL preimages against a prepared streamed
/// graph without precomputing any transaction signatures.
///
/// # Errors
///
/// Rejects missing, reordered, stale, reused, or graph-mismatched Lamport
/// keys, or any retained preimage that does not match the accepted deal.
pub fn verify_oracle_local_inventory(
    prepared: &PreparedChainGraph,
    role: Role,
    secret_keys: &[LamportSecretKey],
    retained_preimages: &RetainedPreimages,
) -> Result<(u32, u8), CompilerError> {
    let expected = match role {
        Role::Alice => &prepared.plan.expected_alice_lamport,
        Role::Bob => &prepared.plan.expected_bob_lamport,
    };
    let public_material = match role {
        Role::Alice => prepared.public_material.alice(),
        Role::Bob => prepared.public_material.bob(),
    };
    let public_keys = public_material
        .entries()
        .iter()
        .map(|entry| entry.to_public_key(prepared.plan.chain_game_id))
        .collect::<Result<Vec<_>, _>>()?;
    let public_refs = public_keys.iter().collect::<Vec<_>>();
    verify_ordered_lamport_keys(
        prepared.plan.chain_game_id,
        expected,
        &public_refs,
        secret_keys,
    )?;
    verify_local_retained_preimages(role, retained_preimages, &prepared.descriptor.deal)?;
    Ok((
        usize_to_u32(secret_keys.len())?,
        u8::try_from(retained_preimages.len()).map_err(|_| {
            CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local retained-preimage count exceeds u8",
            }
        })?,
    ))
}

/// Compile and commit the graph without constructing a full `CompiledGraph`.
///
/// Taproot states are compiled only for the current parent and one child at a
/// time. Records are immediately reduced to `(node_id, hash)` pairs, templates
/// and leaves are retained only for the requested active window, and signature
/// requests are retained only long enough to impose their canonical order.
///
/// # Errors
///
/// Rejects any activation, topology, template, predicate, value, or canonical
/// request inconsistency.
#[allow(clippy::too_many_lines)]
pub fn compile_graph_oracle(
    prepared: PreparedChainGraph,
    activation_template: TransactionTemplate,
) -> Result<GraphOracleSetup, CompilerError> {
    let root_node_id = prepared.plan.root_node_id;
    compile_graph_oracle_setup_window(prepared, activation_template, root_node_id)
}

#[allow(clippy::too_many_lines)]
fn compile_graph_oracle_setup_window(
    prepared: PreparedChainGraph,
    activation_template: TransactionTemplate,
    active_node_id: NodeId,
) -> Result<GraphOracleSetup, CompilerError> {
    verify_activation_template(&prepared, &activation_template)?;
    let PreparedChainGraph {
        descriptor,
        network,
        plan,
        fee_policy_snapshot,
        public_material,
        origin_outpoint,
        origin_output,
        root_state_output,
    } = prepared;
    let active_node = plan
        .node(&active_node_id)
        .ok_or_else(|| mismatch("requested window node is absent from logical plan"))?;
    let active_state = active_node.state.clone();
    let active_parent_id = active_node.parent_node_id;
    let lamport_keys = collect_lamport_keys(&plan, &public_material)?;
    let secp = Secp256k1::verification_only();
    let root_node = plan
        .node(&plan.root_node_id)
        .ok_or_else(|| mismatch("graph root is absent from logical plan"))?;
    let root_programs = programs_for_node(&descriptor, &plan, root_node, &lamport_keys)?;
    let root_state =
        CompiledTaprootState::compile(&secp, root_node.logical_state_digest, &root_programs)?;
    let mut compiled_states = 1_usize;
    let mut peak_compiled_states = 1_usize;
    let expected_root_output =
        state_output(root_node, &root_state, fee_policy_snapshot.dust_threshold())?;
    if expected_root_output != root_state_output {
        return Err(mismatch("streamed root output differs from prepared root"));
    }
    let root_predicate = funded_root_predicate(&root_state);
    let root_state_outpoint = OutPoint::new(Txid::from_byte_array(activation_template.txid()), 0);
    let alice_terminal_script = terminal_script(&secp, descriptor.alice_xonly_pk, Role::Alice)?;
    let bob_terminal_script = terminal_script(&secp, descriptor.bob_xonly_pk, Role::Bob)?;
    let by_node: HashMap<_, _> = plan
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.node_id, index))
        .collect();
    if by_node.len() != plan.nodes.len() {
        return Err(mismatch("logical plan contains duplicate nodes"));
    }

    let mut spend_points = HashMap::new();
    spend_points.insert(
        plan.root_node_id,
        (root_state_outpoint, root_state_output.clone(), root_state),
    );
    let mut peak_spend_points = spend_points.len();
    let mut record_hashes = Vec::with_capacity(plan.nodes.len());
    let root_record = LogicalNodeRecord {
        node_id: root_node.node_id,
        parent_node_id: None,
        node_kind: root_node.node_kind,
        logical_state_digest: root_node.logical_state_digest,
        transaction: None,
        required_predicate_id: root_predicate,
        timeout: root_node.timeout,
        child_node_ids: root_node
            .edges
            .iter()
            .map(|edge| edge.child_node_id)
            .collect(),
    };
    push_record_hash(&mut record_hashes, &root_record)?;

    let mut window_nodes = HashMap::new();
    if active_node_id == plan.root_node_id || active_parent_id == Some(plan.root_node_id) {
        window_nodes.insert(root_record.node_id, root_record.clone());
    }
    let mut window_edges = HashMap::new();
    let mut window_templates = HashMap::new();
    let mut window_leaves = HashMap::new();
    let mut window_showdown_leaves = HashMap::new();
    let mut window_lamport_keys = HashMap::new();
    for purpose in [
        LamportPurpose::AliceScore24Bit,
        LamportPurpose::BobScore24Bit,
    ] {
        for node_id in [Some(active_node_id), active_parent_id]
            .into_iter()
            .flatten()
        {
            if let Some(key) = lamport_keys.get(&(node_id, purpose)) {
                window_lamport_keys.insert((node_id, purpose), key.clone());
            }
        }
    }

    let mut alice_preauthorizations = Vec::new();
    let mut bob_preauthorizations = Vec::new();
    let mut alice_runtime = Vec::new();
    let mut bob_runtime = Vec::new();
    let mut transaction_count = 0_usize;

    for parent in &plan.nodes {
        if matches!(parent.state, PlannedState::Terminal(_)) {
            continue;
        }
        let (parent_outpoint, parent_output, parent_state) =
            spend_points
                .remove(&parent.node_id)
                .ok_or_else(|| mismatch("streamed parent spend point is unavailable"))?;
        if parent_state.logical_state_digest() != parent.logical_state_digest {
            return Err(mismatch(
                "cached parent Taproot state differs from the logical plan",
            ));
        }
        for edge in &parent.edges {
            let edge_programs = programs_for_edge(&descriptor, &plan, parent, edge, &lamport_keys)?;
            let program = edge_programs
                .last()
                .ok_or_else(|| mismatch("streamed edge has no Taproot program"))?;
            let child = &plan.nodes[*by_node
                .get(&edge.child_node_id)
                .ok_or(CompilerError::DanglingNode)?];
            if child.parent_node_id != Some(parent.node_id) {
                return Err(mismatch("streamed child names another parent"));
            }
            let child_state = if matches!(child.state, PlannedState::Terminal(_)) {
                None
            } else {
                let child_programs = programs_for_node(&descriptor, &plan, child, &lamport_keys)?;
                Some(CompiledTaprootState::compile(
                    &secp,
                    child.logical_state_digest,
                    &child_programs,
                )?)
            };
            if child_state.is_some() {
                compiled_states = compiled_states
                    .checked_add(1)
                    .ok_or_else(|| mismatch("streamed compiled-state count overflow"))?;
                peak_compiled_states = 2;
            }
            let outputs = outputs_for_child_state(
                child,
                child_state.as_ref(),
                &alice_terminal_script,
                &bob_terminal_script,
                fee_policy_snapshot.dust_threshold(),
            )?;
            let template = match edge.timeout {
                Some(timeout) => TransactionTemplate::timeout(
                    network,
                    parent_outpoint,
                    parent_output.clone(),
                    outputs,
                    edge.fee_sat,
                    timeout.csv,
                )?,
                None => TransactionTemplate::normal(
                    network,
                    parent_outpoint,
                    parent_output.clone(),
                    outputs,
                    edge.fee_sat,
                )?,
            };
            let predicate_id = program.predicate_id();
            let leaf = parent_state
                .leaf(predicate_id)
                .ok_or_else(|| mismatch("streamed parent leaf is unavailable"))?;
            let logical_transaction = template.to_logical_transaction();
            let logical_edge = LogicalEdge {
                parent_node_id: parent.node_id,
                child_node_id: child.node_id,
                kind: edge.kind,
                transaction: logical_transaction.clone(),
                authorization: edge.authorization,
                timeout: edge.timeout,
            };
            logical_edge.validate()?;
            let child_record = LogicalNodeRecord {
                node_id: child.node_id,
                parent_node_id: child.parent_node_id,
                node_kind: child.node_kind,
                logical_state_digest: child.logical_state_digest,
                transaction: Some(logical_transaction),
                required_predicate_id: predicate_id,
                timeout: child.timeout,
                child_node_ids: child
                    .edges
                    .iter()
                    .map(|child_edge| child_edge.child_node_id)
                    .collect(),
            };
            push_record_hash(&mut record_hashes, &child_record)?;
            if child.node_id == active_node_id || Some(child.node_id) == active_parent_id {
                window_nodes.insert(child.node_id, child_record.clone());
            }
            let sighash = taproot_script_sighash_default(
                template.transaction(),
                0,
                std::slice::from_ref(template.parent_output()),
                leaf.script(),
            )?;
            for role in preauthorized_roles(edge.authorization) {
                let request = SignatureRequest {
                    parent_node_id: parent.node_id,
                    child_node_id: child.node_id,
                    signer: role,
                    sighash,
                };
                match role {
                    Role::Alice => alice_preauthorizations.push(request),
                    Role::Bob => bob_preauthorizations.push(request),
                }
            }
            if let Some((role, kind)) = runtime_signature_role_and_kind(edge.authorization) {
                let request = RuntimeSignatureRequest {
                    request: SignatureRequest {
                        parent_node_id: parent.node_id,
                        child_node_id: child.node_id,
                        signer: role,
                        sighash,
                    },
                    kind,
                };
                match role {
                    Role::Alice => alice_runtime.push(request),
                    Role::Bob => bob_runtime.push(request),
                }
            }
            if !matches!(child.state, PlannedState::Terminal(_)) {
                let output = template
                    .transaction()
                    .output
                    .first()
                    .cloned()
                    .ok_or_else(|| mismatch("streamed state transaction has no first output"))?;
                if spend_points
                    .insert(
                        child.node_id,
                        (
                            OutPoint::new(Txid::from_byte_array(template.txid()), 0),
                            output,
                            child_state.ok_or_else(|| {
                                mismatch("nonterminal child lost its compiled Taproot state")
                            })?,
                        ),
                    )
                    .is_some()
                {
                    return Err(mismatch(
                        "streamed child spend point was materialized twice",
                    ));
                }
                peak_spend_points = peak_spend_points.max(spend_points.len());
            }
            if parent.node_id == active_node_id {
                window_nodes.insert(child.node_id, child_record);
                window_edges.insert((parent.node_id, child.node_id), logical_edge);
                window_templates.insert(child.node_id, template.clone());
                window_leaves.insert((parent.node_id, child.node_id), leaf.clone());
                if matches!(
                    edge.kind,
                    bp52_chain_types::EdgeKind::AliceShowdown
                        | bp52_chain_types::EdgeKind::BobPayout(_)
                ) {
                    for category in bp52_chain_bitcoin::SHOWDOWN_CATEGORIES {
                        let outcome = match edge.kind {
                            bp52_chain_types::EdgeKind::BobPayout(outcome) => Some(outcome),
                            _ => None,
                        };
                        let category_leaf = parent_state
                            .showdown_leaf(category, outcome)
                            .ok_or_else(|| mismatch("streamed showdown category leaf is absent"))?;
                        window_showdown_leaves.insert(
                            (parent.node_id, child.node_id, category),
                            category_leaf.clone(),
                        );
                    }
                }
                for purpose in [
                    LamportPurpose::AliceScore24Bit,
                    LamportPurpose::BobScore24Bit,
                ] {
                    if let Some(key) = lamport_keys.get(&(child.node_id, purpose)) {
                        window_lamport_keys.insert((child.node_id, purpose), key.clone());
                    }
                }
            }
            transaction_count = transaction_count
                .checked_add(1)
                .ok_or_else(|| mismatch("streamed transaction count overflow"))?;
        }
    }
    if !spend_points.is_empty()
        || record_hashes.len() != plan.nodes.len()
        || transaction_count != plan.transaction_count()
    {
        return Err(mismatch("streamed graph counts or spend frontier disagree"));
    }

    sort_and_reject_duplicate_requests(&mut alice_preauthorizations)?;
    sort_and_reject_duplicate_requests(&mut bob_preauthorizations)?;
    sort_and_reject_duplicate_runtime(&mut alice_runtime)?;
    sort_and_reject_duplicate_runtime(&mut bob_runtime)?;
    let graph_root = reduce_record_hashes(&mut record_hashes)?;
    let manifest = GraphManifest {
        chain_game_id: plan.chain_game_id,
        graph_root,
        alice_lamport_bundle_root: public_material.alice().bundle_root(),
        bob_lamport_bundle_root: public_material.bob().bundle_root(),
        compiler_id: descriptor.compiler_id,
        fee_policy_id: descriptor.fee_policy_id,
        node_count: usize_to_u32(plan.nodes.len())?,
        transaction_count: usize_to_u32(transaction_count)?,
        maximum_path_length: plan.maximum_path_length,
    };
    let summary = CompiledGraphSummary {
        descriptor,
        network,
        manifest,
        origin_outpoint,
        origin_output,
        activation_template,
        root_state_outpoint,
        root_state_output,
        root_node_id: plan.root_node_id,
        preauthorization_counts: [
            usize_to_u32(alice_preauthorizations.len())?,
            usize_to_u32(bob_preauthorizations.len())?,
        ],
        runtime_signature_counts: [
            usize_to_u32(alice_runtime.len())?,
            usize_to_u32(bob_runtime.len())?,
        ],
        lamport_counts: [
            usize_to_u32(plan.expected_alice_lamport.len())?,
            usize_to_u32(plan.expected_bob_lamport.len())?,
        ],
    };
    let mut window_preauthorizations = HashMap::new();
    let mut window_preauthorizations_by_sighash = HashMap::new();
    for (role, requests) in [
        (Role::Alice, alice_preauthorizations.as_slice()),
        (Role::Bob, bob_preauthorizations.as_slice()),
    ] {
        for (index, request) in requests.iter().copied().enumerate() {
            if request.parent_node_id == active_node_id {
                window_preauthorizations.insert(
                    (request.parent_node_id, request.child_node_id, role),
                    (index, request),
                );
                window_preauthorizations_by_sighash.insert(
                    (
                        request.parent_node_id,
                        request.child_node_id,
                        role,
                        request.sighash,
                    ),
                    (index, request),
                );
            }
        }
    }
    if !window_nodes.contains_key(&active_node_id) {
        return Err(mismatch("streamed active-window record was not retained"));
    }
    let window_lamport_key_indices = window_lamport_keys
        .keys()
        .map(|(node_id, purpose)| {
            Ok((
                (*node_id, *purpose),
                lamport_inventory_index(&plan, *node_id, *purpose)?,
            ))
        })
        .collect::<Result<HashMap<_, _>, CompilerError>>()?;
    let window = MaterializedGraphWindow {
        summary: summary.clone(),
        active_node_id,
        active_state,
        nodes: window_nodes,
        edges: window_edges,
        templates: window_templates,
        leaves: window_leaves,
        showdown_leaves: window_showdown_leaves,
        lamport_keys: window_lamport_keys,
        lamport_key_indices: window_lamport_key_indices,
        preauthorization_requests: window_preauthorizations,
        preauthorization_requests_by_sighash: window_preauthorizations_by_sighash,
    };
    let setup_signature_requests = alice_preauthorizations
        .len()
        .checked_add(bob_preauthorizations.len())
        .and_then(|count| count.checked_add(alice_runtime.len()))
        .and_then(|count| count.checked_add(bob_runtime.len()))
        .ok_or_else(|| mismatch("streamed signature request count overflow"))?;
    let metrics = GraphOracleMetrics {
        compiled_states,
        peak_compiled_states,
        peak_spend_points,
        record_hashes: plan.nodes.len(),
        setup_signature_requests,
        retained_window_nodes: window.node_count(),
        retained_window_templates: window.transaction_count(),
    };
    Ok(GraphOracleSetup {
        summary,
        window,
        requests: OracleSignatureRequests {
            alice_preauthorizations,
            bob_preauthorizations,
            alice_runtime,
            bob_runtime,
        },
        metrics,
    })
}

/// Materialize one runtime page from an already-audited graph summary.
///
/// The Bitcoin work is proportional to `active depth + active degree`: only
/// the root-to-active transaction chain and the active node's direct children
/// are compiled. Canonical fixed-signature positions are ranked with a
/// logical-only walk, so unrelated Taproot states, scripts, and templates are
/// never constructed.
///
/// # Errors
///
/// Rejects an unknown active node, a summary that is not bound to the exact
/// prepared descriptor/material/activation, or any inconsistent path/page.
#[allow(clippy::too_many_lines)]
pub fn compile_graph_oracle_window(
    prepared: PreparedChainGraph,
    activation_template: TransactionTemplate,
    audited_summary: &CompiledGraphSummary,
    active_node_id: NodeId,
) -> Result<GraphOraclePage, CompilerError> {
    verify_runtime_summary(&prepared, &activation_template, audited_summary)?;
    let PreparedChainGraph {
        descriptor,
        network,
        plan,
        fee_policy_snapshot,
        public_material,
        origin_outpoint: _,
        origin_output: _,
        root_state_output,
    } = prepared;

    let active_node = plan
        .node(&active_node_id)
        .ok_or_else(|| mismatch("requested runtime page node is absent from logical plan"))?;
    let active_state = active_node.state.clone();
    let active_parent_id = active_node.parent_node_id;

    // Follow authenticated parent links backwards, then reverse into the only
    // path whose transaction IDs can affect this active outpoint.
    let mut reverse_path = Vec::with_capacity(usize::from(active_node.depth) + 1);
    let mut seen = HashSet::with_capacity(usize::from(active_node.depth) + 1);
    let mut cursor = active_node_id;
    loop {
        if !seen.insert(cursor) {
            return Err(mismatch("runtime page path contains a parent cycle"));
        }
        reverse_path.push(cursor);
        if cursor == plan.root_node_id {
            break;
        }
        cursor = plan
            .node(&cursor)
            .and_then(|node| node.parent_node_id)
            .ok_or_else(|| mismatch("runtime page path does not reach the graph root"))?;
        if reverse_path.len() > usize::from(plan.maximum_path_length) + 1 {
            return Err(mismatch("runtime page path exceeds the committed maximum"));
        }
    }
    reverse_path.reverse();

    let mut materialized_node_ids: HashSet<NodeId> = reverse_path.iter().copied().collect();
    materialized_node_ids.extend(active_node.edges.iter().map(|edge| edge.child_node_id));
    let path_lamport_keys = collect_selected_lamport_keys(
        plan.chain_game_id,
        &public_material,
        &materialized_node_ids,
    )?;

    let secp = Secp256k1::verification_only();
    let alice_terminal_script = terminal_script(&secp, descriptor.alice_xonly_pk, Role::Alice)?;
    let bob_terminal_script = terminal_script(&secp, descriptor.bob_xonly_pk, Role::Bob)?;
    let root_node = plan
        .node(&plan.root_node_id)
        .ok_or_else(|| mismatch("runtime page root is absent from logical plan"))?;
    let root_programs = programs_for_node(&descriptor, &plan, root_node, &path_lamport_keys)?;
    let root_state =
        CompiledTaprootState::compile(&secp, root_node.logical_state_digest, &root_programs)?;
    let mut compiled_states = 1_usize;
    let mut peak_compiled_states = 1_usize;
    let expected_root_output =
        state_output(root_node, &root_state, fee_policy_snapshot.dust_threshold())?;
    if expected_root_output != root_state_output
        || expected_root_output != *audited_summary.root_state_output()
    {
        return Err(mismatch(
            "runtime page root output differs from audited setup",
        ));
    }
    let root_record = LogicalNodeRecord {
        node_id: root_node.node_id,
        parent_node_id: None,
        node_kind: root_node.node_kind,
        logical_state_digest: root_node.logical_state_digest,
        transaction: None,
        required_predicate_id: funded_root_predicate(&root_state),
        timeout: root_node.timeout,
        child_node_ids: root_node
            .edges
            .iter()
            .map(|edge| edge.child_node_id)
            .collect(),
    };
    root_record.validate()?;

    let mut window_nodes = HashMap::new();
    if active_node_id == plan.root_node_id || active_parent_id == Some(plan.root_node_id) {
        window_nodes.insert(root_record.node_id, root_record);
    }
    let mut current_outpoint = audited_summary.root_state_outpoint();
    let mut current_output = root_state_output;
    let mut current_state = Some(root_state);

    for path_pair in reverse_path.windows(2) {
        let parent = plan
            .node(&path_pair[0])
            .ok_or_else(|| mismatch("runtime page path parent disappeared"))?;
        let child = plan
            .node(&path_pair[1])
            .ok_or_else(|| mismatch("runtime page path child disappeared"))?;
        let edge_index = parent
            .edges
            .iter()
            .position(|edge| edge.child_node_id == child.node_id)
            .ok_or_else(|| mismatch("runtime page path child is not an outgoing edge"))?;
        let edge = &parent.edges[edge_index];
        if child.parent_node_id != Some(parent.node_id) {
            return Err(mismatch("runtime page child names a different parent"));
        }
        if current_state.is_none() {
            return Err(mismatch("runtime page attempts to spend a terminal state"));
        }
        let edge_programs =
            programs_for_edge(&descriptor, &plan, parent, edge, &path_lamport_keys)?;
        let program = edge_programs
            .last()
            .ok_or_else(|| mismatch("runtime page program is absent"))?;
        let child_programs = if matches!(child.state, PlannedState::Terminal(_)) {
            Vec::new()
        } else {
            programs_for_node(&descriptor, &plan, child, &path_lamport_keys)?
        };
        let child_state = if matches!(child.state, PlannedState::Terminal(_)) {
            None
        } else {
            compiled_states = compiled_states
                .checked_add(1)
                .ok_or_else(|| mismatch("runtime page compiled-state count overflow"))?;
            peak_compiled_states = 2;
            Some(CompiledTaprootState::compile(
                &secp,
                child.logical_state_digest,
                &child_programs,
            )?)
        };
        let outputs = outputs_for_child_state(
            child,
            child_state.as_ref(),
            &alice_terminal_script,
            &bob_terminal_script,
            fee_policy_snapshot.dust_threshold(),
        )?;
        let template = edge_template(
            network,
            current_outpoint,
            current_output.clone(),
            outputs,
            edge.fee_sat,
            edge.timeout,
        )?;
        let predicate_id = program.predicate_id();
        let logical_transaction = template.to_logical_transaction();
        let record = LogicalNodeRecord {
            node_id: child.node_id,
            parent_node_id: child.parent_node_id,
            node_kind: child.node_kind,
            logical_state_digest: child.logical_state_digest,
            transaction: Some(logical_transaction),
            required_predicate_id: predicate_id,
            timeout: child.timeout,
            child_node_ids: child
                .edges
                .iter()
                .map(|child_edge| child_edge.child_node_id)
                .collect(),
        };
        record.validate()?;
        if child.node_id == active_node_id || Some(child.node_id) == active_parent_id {
            window_nodes.insert(child.node_id, record);
        }
        if child_state.is_some() {
            current_output = template
                .transaction()
                .output
                .first()
                .cloned()
                .ok_or_else(|| mismatch("runtime path transaction has no state output"))?;
            current_outpoint = OutPoint::new(Txid::from_byte_array(template.txid()), 0);
        }
        current_state = child_state;
    }

    let mut window_edges = HashMap::with_capacity(active_node.edges.len());
    let mut window_templates = HashMap::with_capacity(active_node.edges.len());
    let mut window_leaves = HashMap::with_capacity(active_node.edges.len());
    let mut window_showdown_leaves = HashMap::new();
    let mut window_preauthorizations = HashMap::with_capacity(active_node.edges.len());
    let mut window_preauthorizations_by_sighash = HashMap::new();
    if !matches!(active_node.state, PlannedState::Terminal(_)) {
        let active_taproot = current_state
            .as_ref()
            .ok_or_else(|| mismatch("active runtime state was not compiled"))?;
        for edge in &active_node.edges {
            let child = plan
                .node(&edge.child_node_id)
                .ok_or(CompilerError::DanglingNode)?;
            if child.parent_node_id != Some(active_node.node_id) {
                return Err(mismatch("runtime window child names a different parent"));
            }
            let child_programs = if matches!(child.state, PlannedState::Terminal(_)) {
                Vec::new()
            } else {
                programs_for_node(&descriptor, &plan, child, &path_lamport_keys)?
            };
            let child_state = if matches!(child.state, PlannedState::Terminal(_)) {
                None
            } else {
                compiled_states = compiled_states
                    .checked_add(1)
                    .ok_or_else(|| mismatch("runtime page compiled-state count overflow"))?;
                peak_compiled_states = 2;
                Some(CompiledTaprootState::compile(
                    &secp,
                    child.logical_state_digest,
                    &child_programs,
                )?)
            };
            let outputs = outputs_for_child_state(
                child,
                child_state.as_ref(),
                &alice_terminal_script,
                &bob_terminal_script,
                fee_policy_snapshot.dust_threshold(),
            )?;
            let template = edge_template(
                network,
                current_outpoint,
                current_output.clone(),
                outputs,
                edge.fee_sat,
                edge.timeout,
            )?;
            let edge_programs =
                programs_for_edge(&descriptor, &plan, active_node, edge, &path_lamport_keys)?;
            let program = edge_programs
                .last()
                .ok_or_else(|| mismatch("active runtime program is absent"))?;
            let predicate_id = program.predicate_id();
            let leaf = active_taproot
                .leaf(predicate_id)
                .ok_or_else(|| mismatch("active runtime Taproot leaf is absent"))?;
            let logical_transaction = template.to_logical_transaction();
            let logical_edge = LogicalEdge {
                parent_node_id: active_node.node_id,
                child_node_id: child.node_id,
                kind: edge.kind,
                transaction: logical_transaction.clone(),
                authorization: edge.authorization,
                timeout: edge.timeout,
            };
            logical_edge.validate()?;
            let child_record = LogicalNodeRecord {
                node_id: child.node_id,
                parent_node_id: child.parent_node_id,
                node_kind: child.node_kind,
                logical_state_digest: child.logical_state_digest,
                transaction: Some(logical_transaction),
                required_predicate_id: predicate_id,
                timeout: child.timeout,
                child_node_ids: child
                    .edges
                    .iter()
                    .map(|child_edge| child_edge.child_node_id)
                    .collect(),
            };
            child_record.validate()?;
            let sighash = taproot_script_sighash_default(
                template.transaction(),
                0,
                std::slice::from_ref(template.parent_output()),
                leaf.script(),
            )?;
            let edge_sighashes = [sighash];
            for role in preauthorized_roles(edge.authorization) {
                let request = SignatureRequest {
                    parent_node_id: active_node.node_id,
                    child_node_id: child.node_id,
                    signer: role,
                    sighash,
                };
                let rank = logical_preauthorization_rank(&plan, role, &request, &edge_sighashes)?;
                window_preauthorizations
                    .insert((active_node.node_id, child.node_id, role), (rank, request));
                window_preauthorizations_by_sighash.insert(
                    (active_node.node_id, child.node_id, role, request.sighash),
                    (rank, request),
                );
            }
            window_nodes.insert(child.node_id, child_record);
            window_edges.insert((active_node.node_id, child.node_id), logical_edge);
            window_templates.insert(child.node_id, template);
            window_leaves.insert((active_node.node_id, child.node_id), leaf.clone());
            if matches!(
                edge.kind,
                bp52_chain_types::EdgeKind::AliceShowdown
                    | bp52_chain_types::EdgeKind::BobPayout(_)
            ) {
                for category in bp52_chain_bitcoin::SHOWDOWN_CATEGORIES {
                    let outcome = match edge.kind {
                        bp52_chain_types::EdgeKind::BobPayout(outcome) => Some(outcome),
                        _ => None,
                    };
                    let category_leaf = active_taproot
                        .showdown_leaf(category, outcome)
                        .ok_or_else(|| mismatch("runtime showdown category leaf is absent"))?;
                    window_showdown_leaves.insert(
                        (active_node.node_id, child.node_id, category),
                        category_leaf.clone(),
                    );
                }
            }
        }
    }
    if !window_nodes.contains_key(&active_node_id) {
        return Err(mismatch("runtime active-window record was not retained"));
    }

    let window_node_ids: HashSet<_> = window_nodes.keys().copied().collect();
    let window_lamport_keys: HashMap<_, _> = path_lamport_keys
        .into_iter()
        // The fixed profile uses one root-bound score key per player for every
        // possible showdown leaf. Keep those root keys in each paged runtime
        // window even after the root record itself has fallen out of the page.
        .filter(|((node_id, _), _)| {
            window_node_ids.contains(node_id) || *node_id == plan.root_node_id
        })
        .collect();
    let window_lamport_key_indices = window_lamport_keys
        .keys()
        .map(|(node_id, purpose)| {
            Ok((
                (*node_id, *purpose),
                lamport_inventory_index(&plan, *node_id, *purpose)?,
            ))
        })
        .collect::<Result<HashMap<_, _>, CompilerError>>()?;
    let window = MaterializedGraphWindow {
        summary: audited_summary.clone(),
        active_node_id,
        active_state,
        nodes: window_nodes,
        edges: window_edges,
        templates: window_templates,
        leaves: window_leaves,
        showdown_leaves: window_showdown_leaves,
        lamport_keys: window_lamport_keys,
        lamport_key_indices: window_lamport_key_indices,
        preauthorization_requests: window_preauthorizations,
        preauthorization_requests_by_sighash: window_preauthorizations_by_sighash,
    };
    let path_bound = reverse_path
        .len()
        .checked_add(active_node.edges.len())
        .ok_or_else(|| mismatch("runtime page work bound overflow"))?;
    if compiled_states > path_bound {
        return Err(mismatch("runtime page compiled unrelated Taproot states"));
    }
    Ok(GraphOraclePage {
        metrics: GraphOracleMetrics {
            compiled_states,
            peak_compiled_states,
            peak_spend_points: 1,
            record_hashes: 0,
            setup_signature_requests: 0,
            retained_window_nodes: window.node_count(),
            retained_window_templates: window.transaction_count(),
        },
        window,
    })
}

fn verify_runtime_summary(
    prepared: &PreparedChainGraph,
    activation_template: &TransactionTemplate,
    summary: &CompiledGraphSummary,
) -> Result<(), CompilerError> {
    verify_activation_template(prepared, activation_template)?;
    let plan = &prepared.plan;
    let (preauthorization_counts, runtime_signature_counts) = logical_signature_counts(plan)?;
    let expected_root_outpoint =
        OutPoint::new(Txid::from_byte_array(activation_template.txid()), 0);
    macro_rules! require_summary_match {
        ($condition:expr, $field:literal) => {
            if !$condition {
                return Err(mismatch(concat!(
                    "runtime page inputs differ from the audited graph summary: ",
                    $field,
                )));
            }
        };
    }
    require_summary_match!(summary.descriptor == prepared.descriptor, "descriptor");
    require_summary_match!(summary.network == prepared.network, "network");
    require_summary_match!(
        summary.origin_outpoint == prepared.origin_outpoint,
        "origin outpoint"
    );
    require_summary_match!(
        summary.origin_output == prepared.origin_output,
        "origin output"
    );
    require_summary_match!(
        summary.activation_template == *activation_template,
        "activation template"
    );
    require_summary_match!(
        summary.root_state_outpoint == expected_root_outpoint,
        "root outpoint"
    );
    require_summary_match!(
        summary.root_state_output == prepared.root_state_output,
        "root output"
    );
    require_summary_match!(summary.root_node_id == plan.root_node_id, "root node");
    require_summary_match!(
        summary.manifest.chain_game_id == plan.chain_game_id,
        "chain game id"
    );
    require_summary_match!(
        summary.manifest.alice_lamport_bundle_root
            == prepared.public_material.alice().bundle_root(),
        "Alice Lamport root"
    );
    require_summary_match!(
        summary.manifest.bob_lamport_bundle_root == prepared.public_material.bob().bundle_root(),
        "Bob Lamport root"
    );
    require_summary_match!(
        summary.manifest.compiler_id == prepared.descriptor.compiler_id,
        "compiler id"
    );
    require_summary_match!(
        summary.manifest.fee_policy_id == prepared.descriptor.fee_policy_id,
        "fee policy id"
    );
    require_summary_match!(
        summary.manifest.node_count == usize_to_u32(plan.nodes.len())?,
        "node count"
    );
    require_summary_match!(
        summary.manifest.transaction_count == usize_to_u32(plan.transaction_count())?,
        "transaction count"
    );
    require_summary_match!(
        summary.manifest.maximum_path_length == plan.maximum_path_length,
        "maximum path length"
    );
    require_summary_match!(
        summary.preauthorization_counts[0] >= preauthorization_counts[0],
        "Alice preauthorization count is lower"
    );
    require_summary_match!(
        summary.preauthorization_counts[0] <= preauthorization_counts[0],
        "Alice preauthorization count is higher"
    );
    require_summary_match!(
        summary.preauthorization_counts[1] >= preauthorization_counts[1],
        "Bob preauthorization count is lower"
    );
    require_summary_match!(
        summary.preauthorization_counts[1] <= preauthorization_counts[1],
        "Bob preauthorization count is higher"
    );
    require_summary_match!(
        summary.runtime_signature_counts == runtime_signature_counts,
        "runtime signature counts"
    );
    require_summary_match!(
        summary.lamport_counts
            == [
                usize_to_u32(plan.expected_alice_lamport.len())?,
                usize_to_u32(plan.expected_bob_lamport.len())?,
            ],
        "Lamport counts"
    );
    Ok(())
}

fn logical_signature_counts(
    plan: &crate::LogicalGraphPlan,
) -> Result<([u32; 2], [u32; 2]), CompilerError> {
    let mut preauthorizations = [0_u32; 2];
    let mut runtime = [0_u32; 2];
    for edge in plan.nodes.iter().flat_map(|node| &node.edges) {
        for role in preauthorized_roles(edge.authorization) {
            let index = role_index(role);
            preauthorizations[index] = preauthorizations[index]
                .checked_add(1)
                .ok_or_else(|| mismatch("logical preauthorization count overflow"))?;
        }
        if let Some((role, _)) = runtime_signature_role_and_kind(edge.authorization) {
            let index = role_index(role);
            runtime[index] = runtime[index]
                .checked_add(1)
                .ok_or_else(|| mismatch("logical runtime-signature count overflow"))?;
        }
    }
    Ok((preauthorizations, runtime))
}

fn logical_preauthorization_rank(
    plan: &crate::LogicalGraphPlan,
    role: Role,
    target: &SignatureRequest,
    same_edge_sighashes: &[[u8; 32]],
) -> Result<usize, CompilerError> {
    let target_key = (target.parent_node_id, target.child_node_id);
    let mut rank = 0_usize;
    let mut found = false;
    for parent in &plan.nodes {
        for edge in &parent.edges {
            if !preauthorized_roles(edge.authorization).any(|candidate| candidate == role) {
                continue;
            }
            match (parent.node_id, edge.child_node_id).cmp(&target_key) {
                Ordering::Less => {
                    rank = rank
                        .checked_add(1)
                        .ok_or_else(|| mismatch("logical preauthorization rank overflow"))?;
                }
                Ordering::Equal => {
                    if found {
                        return Err(mismatch("duplicate logical preauthorization rank key"));
                    }
                    found = true;
                    rank = rank
                        .checked_add(
                            same_edge_sighashes
                                .iter()
                                .filter(|sighash| **sighash < target.sighash)
                                .count(),
                        )
                        .ok_or_else(|| mismatch("logical preauthorization rank overflow"))?;
                }
                Ordering::Greater => {}
            }
        }
    }
    if !found {
        return Err(mismatch(
            "active request is absent from logical preauthorization ordering",
        ));
    }
    Ok(rank)
}

fn collect_selected_lamport_keys(
    chain_game_id: [u8; 32],
    material: &LamportPublicMaterial,
    node_ids: &HashSet<NodeId>,
) -> Result<HashMap<(NodeId, LamportPurpose), LamportPublicKey>, CompilerError> {
    let mut keys = HashMap::new();
    for entry in material
        .alice()
        .entries()
        .iter()
        .chain(material.bob().entries())
        .filter(|entry| {
            node_ids.contains(&entry.node_id()) || entry.node_id() == root_node_id(&chain_game_id)
        })
    {
        let key = entry.to_public_key(chain_game_id)?;
        if keys
            .insert((entry.node_id(), entry.purpose()), key)
            .is_some()
        {
            return Err(mismatch(
                "runtime Lamport selection contains a cross-role duplicate",
            ));
        }
    }
    Ok(keys)
}

pub(crate) fn lamport_inventory_index(
    plan: &crate::LogicalGraphPlan,
    _node_id: NodeId,
    purpose: LamportPurpose,
) -> Result<usize, CompilerError> {
    let expected = match purpose {
        LamportPurpose::AliceScore24Bit => &plan.expected_alice_lamport,
        LamportPurpose::BobScore24Bit => &plan.expected_bob_lamport,
    };
    expected
        .binary_search_by_key(&(plan.root_node_id, purpose), |entry| {
            (entry.node_id, entry.purpose)
        })
        .map_err(|_| mismatch("window Lamport key is absent from canonical inventory"))
}

fn edge_template(
    network: Network,
    parent_outpoint: OutPoint,
    parent_output: TxOut,
    outputs: Vec<TxOut>,
    fee_sat: u64,
    timeout: Option<bp52_chain_types::TimeoutSpec>,
) -> Result<TransactionTemplate, CompilerError> {
    Ok(match timeout {
        Some(timeout) => TransactionTemplate::timeout(
            network,
            parent_outpoint,
            parent_output,
            outputs,
            fee_sat,
            timeout.csv,
        )?,
        None => {
            TransactionTemplate::normal(network, parent_outpoint, parent_output, outputs, fee_sat)?
        }
    })
}

const fn role_index(role: Role) -> usize {
    match role {
        Role::Alice => 0,
        Role::Bob => 1,
    }
}

fn push_record_hash(
    output: &mut Vec<(NodeId, [u8; 32])>,
    record: &LogicalNodeRecord,
) -> Result<(), CompilerError> {
    record.validate()?;
    output.push((
        record.node_id,
        Sha256::digest(record.encode_to_vec()?).into(),
    ));
    Ok(())
}

fn reduce_record_hashes(records: &mut Vec<(NodeId, [u8; 32])>) -> Result<[u8; 32], CompilerError> {
    if records.is_empty() {
        return Err(mismatch("streamed graph contains no record hashes"));
    }
    records.sort_unstable_by_key(|(node_id, _)| *node_id);
    if records.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(mismatch(
            "streamed graph contains duplicate record identifiers",
        ));
    }
    let mut level: Vec<_> = records.iter().map(|(_, hash)| *hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        for pair in &mut chunks {
            let mut hash = Sha256::new();
            hash.update(pair[0]);
            hash.update(pair[1]);
            next.push(hash.finalize().into());
        }
        if let Some(last) = chunks.remainder().first() {
            next.push(*last);
        }
        level = next;
    }
    Ok(Sha256::digest(level[0]).into())
}

fn sort_and_reject_duplicate_requests(
    requests: &mut [SignatureRequest],
) -> Result<(), CompilerError> {
    requests.sort_unstable_by_key(|request| {
        (
            request.parent_node_id,
            request.child_node_id,
            request.sighash,
        )
    });
    if requests.windows(2).any(|pair| {
        pair[0].parent_node_id == pair[1].parent_node_id
            && pair[0].child_node_id == pair[1].child_node_id
            && pair[0].sighash == pair[1].sighash
    }) {
        return Err(mismatch(
            "streamed graph contains duplicate preauthorization requests",
        ));
    }
    Ok(())
}

fn sort_and_reject_duplicate_runtime(
    requests: &mut [RuntimeSignatureRequest],
) -> Result<(), CompilerError> {
    requests.sort_unstable_by_key(|request| {
        (
            request.request.parent_node_id,
            request.request.child_node_id,
            request.kind,
            request.request.sighash,
        )
    });
    if requests.windows(2).any(|pair| {
        pair[0].request.parent_node_id == pair[1].request.parent_node_id
            && pair[0].request.child_node_id == pair[1].request.child_node_id
            && pair[0].kind == pair[1].kind
            && pair[0].request.sighash == pair[1].request.sighash
    }) {
        return Err(mismatch(
            "streamed graph contains duplicate runtime requests",
        ));
    }
    Ok(())
}

fn usize_to_u32(value: usize) -> Result<u32, CompilerError> {
    u32::try_from(value).map_err(|_| mismatch("streamed graph count exceeds u32"))
}

fn mismatch(reason: &'static str) -> CompilerError {
    CompilerError::CompiledGraphMismatch { reason }
}
