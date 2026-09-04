//! Concrete, witness-independent graph materialization.
//!
//! The logical planner deliberately contains no Bitcoin objects. This module
//! verifies both identity-signed Lamport bundles, builds every Taproot state,
//! exposes the exact gameplay-root output, verifies a canonical activation
//! transaction from the descriptor-bound origin escrow, and instantiates every
//! gameplay child transaction in parent-before-child order.

use std::collections::{HashMap, HashSet};
use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
use bp52_chain_bitcoin::{
    ActionProgram, AliceShowdownProgram, BobPayoutProgram, CompiledTapLeaf, CompiledTaprootState,
    DefaultSighashSignature, FeePolicy, LeafProgram, RevealProgram, SHOWDOWN_CATEGORIES,
    ShareRevealPredicate, TimeoutProgram, TransactionTemplate, ensure_non_mainnet,
    outpoint_from_consensus_bytes, taproot_script_sighash_default, validate_network_identity,
    verify_sighash_default,
};
use bp52_chain_types::{
    AuthorizationPolicy, ChainGameDescriptor, EdgeKind, LogicalEdge, LogicalNodeRecord, NodeId,
    Role, VerifiedChainDescriptor, chain_game_id, root_node_id, tagged_sha256,
};
use bp52_lamport::{
    ExpectedLamportEntry, LamportPublicBundle, LamportPublicKey, LamportPurpose, LamportRole,
    LamportSecretKey,
};
use bp52_poker::HandCategory;
use bp52_protocol::contribution::RetainedPreimages;
use sha2::{Digest, Sha256};

use crate::CompilerError;
use crate::exchange::{
    AgreedGraphRoot, PrivateRuntimeSignatureBundle, RuntimeSignatureRequest,
    RuntimeSignatureResponse, SignatureBundleOpening, SignatureRequest, SignedCommitment,
    verify_signature_bundle_descriptor,
};
use crate::graph::{
    FeePolicySnapshot, LogicalGraphPlan, PlannedEdge, PlannedNode, PlannedState,
    compile_logical_graph_descriptor, verify_plan_against_descriptor, verify_plan_against_snapshot,
};
use crate::manifest::{GraphManifest, compute_graph_root, verify_tree_links};
use crate::oracle::{CompiledGraphSummary, MaterializedGraphWindow, lamport_inventory_index};
use crate::readiness::{
    FundingReadinessReport, LocalRuntimeInventorySummary, RuntimeSignatureIntent,
    RuntimeSignatureKind, VerifiedLocalRuntimeInventory, build_funding_readiness_report,
};

const ROOT_PREDICATE_TAG: &str = "BP52/chain-funded-root-predicate/v1";

type SignatureRequestSets = (
    Vec<SignatureRequest>,
    Vec<SignatureRequest>,
    Vec<RuntimeSignatureRequest>,
    Vec<RuntimeSignatureRequest>,
);

/// Exact fixed preauthorizations Alice exchanges for the deep-stack reference graph.
pub const REFERENCE_ALICE_PREAUTHORIZATIONS: usize = 33_168;
/// Exact fixed preauthorizations Bob exchanges for the deep-stack reference graph.
pub const REFERENCE_BOB_PREAUTHORIZATIONS: usize = 22_963;
/// Exact timeout signatures Alice retains for the deep-stack reference graph.
pub const REFERENCE_ALICE_RUNTIME_SIGNATURES: usize = 8_930;
/// Exact payout and timeout signatures Bob retains for the deep-stack reference graph.
pub const REFERENCE_BOB_RUNTIME_SIGNATURES: usize = 24_239;

/// Both canonical identity-signed public OTS bundles required by compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LamportPublicMaterial {
    alice: LamportPublicBundle,
    bob: LamportPublicBundle,
}

impl LamportPublicMaterial {
    /// Construct the complete two-role public material container.
    #[must_use]
    pub const fn new(alice: LamportPublicBundle, bob: LamportPublicBundle) -> Self {
        Self { alice, bob }
    }

    /// Return Alice's signed bundle.
    #[must_use]
    pub const fn alice(&self) -> &LamportPublicBundle {
        &self.alice
    }

    /// Return Bob's signed bundle.
    #[must_use]
    pub const fn bob(&self) -> &LamportPublicBundle {
        &self.bob
    }
}

/// Results of independently rechecking one concrete graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphVerificationReport {
    /// Recomputed canonical node-record root.
    pub graph_root: [u8; 32],
    /// Number of logical records, including the post-activation gameplay root.
    pub node_count: u32,
    /// Number of post-activation gameplay transaction templates.
    pub transaction_count: u32,
    /// Longest post-activation gameplay path.
    pub maximum_path_length: u16,
    /// Exact number of Alice fixed-signature requests.
    pub alice_signature_requests: u32,
    /// Exact number of Bob fixed-signature requests.
    pub bob_signature_requests: u32,
    /// Exact number of Alice role-local runtime signature requests.
    pub alice_runtime_signature_requests: u32,
    /// Exact number of Bob role-local runtime signature requests.
    pub bob_runtime_signature_requests: u32,
    /// Number of installed and reverified Alice preauthorizations.
    pub verified_alice_preauthorizations: u32,
    /// Number of installed and reverified Bob preauthorizations.
    pub verified_bob_preauthorizations: u32,
}

/// Fully materialized witness-independent state and transaction tree.
pub struct CompiledGraph {
    descriptor: ChainGameDescriptor,
    network: Network,
    plan: LogicalGraphPlan,
    fee_policy_snapshot: FeePolicySnapshot,
    public_material: LamportPublicMaterial,
    manifest: GraphManifest,
    origin_outpoint: OutPoint,
    origin_output: TxOut,
    activation_template: TransactionTemplate,
    root_state_outpoint: OutPoint,
    root_state_output: TxOut,
    records: Vec<LogicalNodeRecord>,
    edges: Vec<LogicalEdge>,
    templates: Vec<TransactionTemplate>,
    states: HashMap<NodeId, CompiledTaprootState>,
    record_index: HashMap<NodeId, usize>,
    edge_index: HashMap<(NodeId, NodeId), usize>,
    template_index: HashMap<NodeId, usize>,
    edge_predicates: HashMap<(NodeId, NodeId), [u8; 32]>,
    lamport_keys: HashMap<(NodeId, LamportPurpose), LamportPublicKey>,
    alice_signature_requests: Vec<SignatureRequest>,
    bob_signature_requests: Vec<SignatureRequest>,
    alice_runtime_signature_requests: Vec<RuntimeSignatureRequest>,
    bob_runtime_signature_requests: Vec<RuntimeSignatureRequest>,
    alice_preauthorizations: Option<(SignedCommitment, SignatureBundleOpening)>,
    bob_preauthorizations: Option<(SignedCommitment, SignatureBundleOpening)>,
}

/// Descriptor-bound states prepared before the activation transaction exists.
///
/// The descriptor's `funding_outpoint` identifies an already-created origin
/// escrow. Preparation binds the caller-observed origin `TxOut`, compiles every
/// Taproot state, and exposes the exact root-state output. It deliberately does
/// not claim that the origin was jointly funded or is present on chain.
pub struct PreparedChainGraph {
    pub(crate) descriptor: ChainGameDescriptor,
    pub(crate) network: Network,
    pub(crate) plan: LogicalGraphPlan,
    pub(crate) fee_policy_snapshot: FeePolicySnapshot,
    pub(crate) public_material: LamportPublicMaterial,
    pub(crate) origin_outpoint: OutPoint,
    pub(crate) origin_output: TxOut,
    pub(crate) root_state_output: TxOut,
}

impl fmt::Debug for PreparedChainGraph {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedChainGraph")
            .field("network", &self.network)
            .field("chain_game_id", &self.plan.chain_game_id)
            .field("origin_outpoint", &self.origin_outpoint)
            .field("root_state_output", &self.root_state_output)
            .field("node_count", &self.plan.nodes.len())
            .finish_non_exhaustive()
    }
}

impl PreparedChainGraph {
    /// Return the exact signed descriptor used during preparation.
    #[must_use]
    pub const fn descriptor(&self) -> &ChainGameDescriptor {
        &self.descriptor
    }

    /// Return the selected non-mainnet network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Return the immutable semantic plan whose states were compiled.
    #[must_use]
    pub const fn logical_plan(&self) -> &LogicalGraphPlan {
        &self.plan
    }

    /// Return the pre-existing origin outpoint bound by BP52-DEAL.
    #[must_use]
    pub const fn origin_outpoint(&self) -> OutPoint {
        self.origin_outpoint
    }

    /// Return the exact caller-observed origin output bound during preparation.
    ///
    /// This is authenticated compiler input, not proof that the UTXO exists or
    /// was funded by both players.
    #[must_use]
    pub const fn origin_output(&self) -> &TxOut {
        &self.origin_output
    }

    /// Return the only output the activation transaction may create.
    #[must_use]
    pub const fn expected_root_state_output(&self) -> &TxOut {
        &self.root_state_output
    }

    /// Return the activation fee implied by the bound origin and root values.
    #[must_use]
    pub fn activation_fee_sat(&self) -> u64 {
        self.origin_output
            .value
            .to_sat()
            .saturating_sub(self.root_state_output.value.to_sat())
    }

    /// Construct the only activation template accepted for this prepared
    /// origin and gameplay root.
    ///
    /// This lets coordinators obtain the exact transaction without copying a
    /// profile's fee, output, sequence, version, or locktime constants.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained origin cannot fund the prepared root
    /// or either output violates the Bitcoin transaction-template profile.
    pub fn canonical_activation_template(&self) -> Result<TransactionTemplate, CompilerError> {
        canonical_activation_template(
            self.network,
            self.origin_outpoint,
            &self.origin_output,
            &self.root_state_output,
        )
    }
}

impl fmt::Debug for CompiledGraph {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledGraph")
            .field("network", &self.network)
            .field("chain_game_id", &self.manifest.chain_game_id)
            .field("graph_root", &self.manifest.graph_root)
            .field("origin_outpoint", &self.origin_outpoint)
            .field("root_state_outpoint", &self.root_state_outpoint)
            .field("node_count", &self.records.len())
            .field("transaction_count", &self.templates.len())
            .field(
                "verified_preauthorizations",
                &[
                    self.alice_preauthorizations
                        .as_ref()
                        .map_or(0, |(_, opening)| opening.bundle().len()),
                    self.bob_preauthorizations
                        .as_ref()
                        .map_or(0, |(_, opening)| opening.bundle().len()),
                ]
                .into_iter()
                .sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

impl CompiledGraph {
    /// Copy the small immutable graph facts needed by a long-lived runtime.
    ///
    /// The returned value deliberately excludes the full transaction tree,
    /// logical plan, Taproot states, public Lamport bundles, and request lists.
    ///
    /// # Errors
    ///
    /// Returns an error if any retained collection length cannot be represented
    /// by its canonical 32-bit count.
    pub fn summary(&self) -> Result<CompiledGraphSummary, CompilerError> {
        Ok(CompiledGraphSummary {
            descriptor: self.descriptor,
            network: self.network,
            manifest: self.manifest.clone(),
            origin_outpoint: self.origin_outpoint,
            origin_output: self.origin_output.clone(),
            activation_template: self.activation_template.clone(),
            root_state_outpoint: self.root_state_outpoint,
            root_state_output: self.root_state_output.clone(),
            root_node_id: self.plan.root_node_id,
            preauthorization_counts: [
                usize_to_u32(self.alice_signature_requests.len())?,
                usize_to_u32(self.bob_signature_requests.len())?,
            ],
            runtime_signature_counts: [
                usize_to_u32(self.alice_runtime_signature_requests.len())?,
                usize_to_u32(self.bob_runtime_signature_requests.len())?,
            ],
            lamport_counts: [
                usize_to_u32(self.plan.expected_alice_lamport.len())?,
                usize_to_u32(self.plan.expected_bob_lamport.len())?,
            ],
        })
    }

    /// Extract the bounded runtime view for one node.
    ///
    /// Only the active node, its direct children, its optional parent, outgoing
    /// templates/leaves, and score keys referenced by those records are cloned.
    /// All unrelated branches remain outside the returned window.
    ///
    /// # Errors
    ///
    /// Rejects a node that is absent from the verified graph or any missing
    /// association that would make the window unsafe to use independently.
    pub fn window(&self, active_node_id: NodeId) -> Result<MaterializedGraphWindow, CompilerError> {
        let active_record = self
            .node(active_node_id)
            .ok_or_else(|| mismatch("active window node is absent from graph"))?;
        let active_state = self
            .plan
            .node(&active_node_id)
            .ok_or_else(|| mismatch("active window semantic state is absent from plan"))?
            .state
            .clone();

        let mut node_ids = HashSet::with_capacity(active_record.child_node_ids.len() + 2);
        node_ids.insert(active_node_id);
        if let Some(parent_node_id) = active_record.parent_node_id {
            node_ids.insert(parent_node_id);
        }
        node_ids.extend(active_record.child_node_ids.iter().copied());

        let mut nodes = HashMap::with_capacity(node_ids.len());
        for node_id in &node_ids {
            let record = self
                .node(*node_id)
                .ok_or_else(|| mismatch("active window references an absent node"))?
                .clone();
            nodes.insert(*node_id, record);
        }

        let mut edges = HashMap::with_capacity(active_record.child_node_ids.len());
        let mut templates = HashMap::with_capacity(active_record.child_node_ids.len());
        let mut leaves = HashMap::with_capacity(active_record.child_node_ids.len());
        let mut showdown_leaves = HashMap::new();
        let mut preauthorization_requests =
            HashMap::with_capacity(active_record.child_node_ids.len());
        let mut preauthorization_requests_by_sighash = HashMap::new();
        for child_node_id in &active_record.child_node_ids {
            let edge = self
                .edge(active_node_id, *child_node_id)
                .ok_or_else(|| mismatch("active window edge is absent from graph"))?
                .clone();
            let template = self
                .transaction_template(*child_node_id)
                .ok_or_else(|| mismatch("active window template is absent from graph"))?
                .clone();
            let leaf = self
                .tap_leaf(active_node_id, *child_node_id)
                .ok_or_else(|| mismatch("active window Taproot leaf is absent from graph"))?
                .clone();
            let is_showdown = matches!(edge.kind, EdgeKind::AliceShowdown | EdgeKind::BobPayout(_));
            let showdown_outcome = match edge.kind {
                EdgeKind::BobPayout(outcome) => Some(outcome),
                _ => None,
            };
            edges.insert((active_node_id, *child_node_id), edge);
            templates.insert(*child_node_id, template);
            leaves.insert((active_node_id, *child_node_id), leaf);
            if is_showdown {
                let state = self
                    .states
                    .get(&active_node_id)
                    .ok_or_else(|| mismatch("showdown window state is absent"))?;
                for category in SHOWDOWN_CATEGORIES {
                    let category_leaf = state
                        .showdown_leaf(category, showdown_outcome)
                        .ok_or_else(|| mismatch("showdown category leaf is absent"))?;
                    showdown_leaves.insert(
                        (active_node_id, *child_node_id, category),
                        category_leaf.clone(),
                    );
                }
            }
            for role in [Role::Alice, Role::Bob] {
                let requests = self.signature_requests(role);
                for (index, request) in
                    requests.iter().copied().enumerate().filter(|(_, request)| {
                        request.parent_node_id == active_node_id
                            && request.child_node_id == *child_node_id
                    })
                {
                    preauthorization_requests
                        .insert((active_node_id, *child_node_id, role), (index, request));
                    preauthorization_requests_by_sighash.insert(
                        (active_node_id, *child_node_id, role, request.sighash),
                        (index, request),
                    );
                }
            }
        }

        let mut lamport_keys = HashMap::new();
        let mut lamport_key_indices = HashMap::new();
        for node_id in node_ids {
            for purpose in [
                LamportPurpose::AliceScore24Bit,
                LamportPurpose::BobScore24Bit,
            ] {
                if let Some(key) = self.lamport_public_key(node_id, purpose) {
                    lamport_keys.insert((node_id, purpose), key.clone());
                    lamport_key_indices.insert(
                        (node_id, purpose),
                        lamport_inventory_index(&self.plan, node_id, purpose)?,
                    );
                }
            }
        }

        Ok(MaterializedGraphWindow {
            summary: self.summary()?,
            active_node_id,
            active_state,
            nodes,
            edges,
            templates,
            leaves,
            showdown_leaves,
            lamport_keys,
            lamport_key_indices,
            preauthorization_requests,
            preauthorization_requests_by_sighash,
        })
    }

    /// Return the exact descriptor used for compilation.
    #[must_use]
    pub const fn descriptor(&self) -> &ChainGameDescriptor {
        &self.descriptor
    }

    /// Return one authenticated public Lamport bundle retained by the graph.
    ///
    /// Callers should borrow this owner instead of cloning the multi-megabyte
    /// bundle into an adjacent runtime state container.
    #[must_use]
    pub const fn lamport_public_bundle(&self, role: Role) -> &LamportPublicBundle {
        match role {
            Role::Alice => self.public_material.alice(),
            Role::Bob => self.public_material.bob(),
        }
    }

    /// Return the selected non-mainnet Bitcoin network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Return the immutable semantic plan that was materialized.
    #[must_use]
    pub const fn logical_plan(&self) -> &LogicalGraphPlan {
        &self.plan
    }

    /// Return the canonical graph manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GraphManifest {
        &self.manifest
    }

    /// Return the pre-existing origin-escrow outpoint bound by the descriptor.
    #[must_use]
    pub const fn origin_outpoint(&self) -> OutPoint {
        self.origin_outpoint
    }

    /// Return the exact origin output supplied to state preparation.
    ///
    /// This compiler binding is not proof that the outpoint exists or that
    /// both players contributed to it.
    #[must_use]
    pub const fn origin_output(&self) -> &TxOut {
        &self.origin_output
    }

    /// Return the exact witness-independent origin-to-root transaction.
    #[must_use]
    pub const fn activation_template(&self) -> &TransactionTemplate {
        &self.activation_template
    }

    /// Return the activation output spent by the first gameplay transaction.
    #[must_use]
    pub const fn root_state_outpoint(&self) -> OutPoint {
        self.root_state_outpoint
    }

    /// Return the exact Taproot output at the gameplay root.
    #[must_use]
    pub const fn root_state_output(&self) -> &TxOut {
        &self.root_state_output
    }

    /// Compatibility alias for the confirmed gameplay-root output.
    #[must_use]
    pub const fn expected_funding_state_output(&self) -> &TxOut {
        self.root_state_output()
    }

    /// Compatibility alias for the confirmed gameplay-root outpoint.
    #[must_use]
    pub const fn expected_funding_state_outpoint(&self) -> OutPoint {
        self.root_state_outpoint()
    }

    /// Return canonical records in parent-before-child order.
    #[must_use]
    pub fn records(&self) -> &[LogicalNodeRecord] {
        &self.records
    }

    /// Return logical edges in parent and path-code order.
    #[must_use]
    pub fn edges(&self) -> &[LogicalEdge] {
        &self.edges
    }

    /// Find one canonical node record.
    #[must_use]
    pub fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
        self.record_index
            .get(&node_id)
            .map(|index| &self.records[*index])
    }

    /// Find one exact directed logical edge.
    #[must_use]
    pub fn edge(&self, parent: NodeId, child: NodeId) -> Option<&LogicalEdge> {
        self.edge_index
            .get(&(parent, child))
            .map(|index| &self.edges[*index])
    }

    /// Find the fixed transaction template that creates a child node.
    #[must_use]
    pub fn transaction_template(&self, child: NodeId) -> Option<&TransactionTemplate> {
        self.template_index
            .get(&child)
            .map(|index| &self.templates[*index])
    }

    /// Find the Taproot state output associated with a nonterminal node.
    #[must_use]
    pub fn taproot_state(&self, node_id: NodeId) -> Option<&CompiledTaprootState> {
        self.states.get(&node_id)
    }

    /// Find the exact compiled leaf authorizing one directed edge.
    #[must_use]
    pub fn tap_leaf(&self, parent: NodeId, child: NodeId) -> Option<&CompiledTapLeaf> {
        let predicate_id = self.edge_predicates.get(&(parent, child))?;
        self.states.get(&parent)?.leaf(*predicate_id)
    }

    /// Find the category-specific showdown leaf authorizing one edge.
    #[must_use]
    pub fn showdown_tap_leaf(
        &self,
        parent: NodeId,
        child: NodeId,
        category: HandCategory,
    ) -> Option<&CompiledTapLeaf> {
        let outcome = match self.edge(parent, child)?.kind {
            EdgeKind::BobPayout(outcome) => Some(outcome),
            EdgeKind::AliceShowdown => None,
            _ => return None,
        };
        self.states.get(&parent)?.showdown_leaf(category, outcome)
    }

    /// Find one context-bound OTS public key.
    #[must_use]
    pub fn lamport_public_key(
        &self,
        node_id: NodeId,
        purpose: LamportPurpose,
    ) -> Option<&LamportPublicKey> {
        self.lamport_keys
            .get(&(node_id, purpose))
            .or_else(|| self.lamport_keys.get(&(self.plan.root_node_id, purpose)))
    }

    /// Return the exact sorted fixed-signature requests for a role.
    #[must_use]
    pub fn signature_requests(&self, role: Role) -> &[SignatureRequest] {
        match role {
            Role::Alice => &self.alice_signature_requests,
            Role::Bob => &self.bob_signature_requests,
        }
    }

    /// Return the exact sorted payout/timeout signatures retained by a role.
    ///
    /// Betting actions are deliberately absent: the actor signs only the
    /// selected exact edge on demand rather than precomputing every branch.
    #[must_use]
    pub fn runtime_signature_requests(&self, role: Role) -> &[RuntimeSignatureRequest] {
        match role {
            Role::Alice => &self.alice_runtime_signature_requests,
            Role::Bob => &self.bob_runtime_signature_requests,
        }
    }

    /// Verify exact graph membership and every locally retained runtime signature.
    ///
    /// The response vector must already be in the canonical order returned by
    /// [`Self::runtime_signature_requests`]. The resulting bundle is bound to
    /// this chain game, graph root, and role and owns zeroizing signature data.
    ///
    /// # Errors
    ///
    /// Rejects a stale or invalid graph, a missing, extra, reordered, or
    /// substituted request, or any signature that fails under the role's
    /// descriptor identity key.
    pub fn verify_private_runtime_signature_bundle(
        &self,
        role: Role,
        responses: Vec<RuntimeSignatureResponse>,
    ) -> Result<PrivateRuntimeSignatureBundle, CompilerError> {
        verify_compiled_graph_descriptor(&self.descriptor, self)?;
        let expected = self.runtime_signature_requests(role);
        verify_runtime_signature_responses(&self.descriptor, role, expected, &responses)?;
        Ok(PrivateRuntimeSignatureBundle::verified(
            self.manifest.chain_game_id,
            self.manifest.graph_root,
            role,
            responses,
        ))
    }

    /// Verify and take ownership of every role-local gameplay capability.
    ///
    /// Lamport keys must exactly follow the canonical graph order and must all
    /// still be fresh private halves of the committed public keys. The nine
    /// preimages must match the accepted deal's hash locks for `role`. The
    /// private runtime-signature bundle must have been verified for this exact
    /// graph and role.
    ///
    /// # Errors
    ///
    /// Rejects missing, extra, reordered, stale, reused, or mismatched local
    /// material. All supplied secret owners are dropped and erased on error.
    pub fn verify_local_runtime_inventory(
        &self,
        role: Role,
        lamport_secret_keys: Vec<LamportSecretKey>,
        retained_preimages: RetainedPreimages,
        runtime_signatures: PrivateRuntimeSignatureBundle,
    ) -> Result<VerifiedLocalRuntimeInventory, CompilerError> {
        verify_compiled_graph_descriptor(&self.descriptor, self)?;
        verify_local_lamport_keys(self, role, &lamport_secret_keys)?;
        verify_local_retained_preimages(role, &retained_preimages, &self.descriptor.deal)?;
        verify_private_runtime_bundle_binding(
            self.manifest.chain_game_id,
            self.manifest.graph_root,
            role,
            self.runtime_signature_requests(role).len(),
            &runtime_signatures,
        )?;
        let runtime_signature_intents =
            runtime_signature_inventory(role, self.runtime_signature_requests(role))?;
        let retained_preimage_count = u8::try_from(retained_preimages.len()).map_err(|_| {
            CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local retained-preimage count exceeds u8",
            }
        })?;
        let summary = LocalRuntimeInventorySummary::verified(
            role,
            usize_to_u32(lamport_secret_keys.len())?,
            retained_preimage_count,
            usize_to_u32(runtime_signatures.len())?,
        );
        Ok(VerifiedLocalRuntimeInventory {
            chain_game_id: self.manifest.chain_game_id,
            graph_root: self.manifest.graph_root,
            role,
            lamport_secret_keys,
            retained_preimages,
            runtime_signatures,
            runtime_signature_intents,
            summary,
        })
    }

    /// Return one installed, fully verified fixed preauthorization.
    #[must_use]
    pub fn preauthorization(
        &self,
        parent: NodeId,
        child: NodeId,
        role: Role,
    ) -> Option<DefaultSighashSignature> {
        let (_, opening) = match role {
            Role::Alice => self.alice_preauthorizations.as_ref(),
            Role::Bob => self.bob_preauthorizations.as_ref(),
        }?;
        let index = self
            .signature_requests(role)
            .binary_search_by_key(&(parent, child), |request| {
                (request.parent_node_id, request.child_node_id)
            })
            .ok()?;
        opening
            .bundle()
            .signatures()
            .get(index)
            .copied()
            .and_then(|signature| DefaultSighashSignature::from_bytes(signature).ok())
    }

    /// Return the installed signature for one exact category-leaf sighash.
    #[must_use]
    pub fn preauthorization_for_sighash(
        &self,
        parent: NodeId,
        child: NodeId,
        role: Role,
        sighash: [u8; 32],
    ) -> Option<DefaultSighashSignature> {
        let (_, opening) = match role {
            Role::Alice => self.alice_preauthorizations.as_ref(),
            Role::Bob => self.bob_preauthorizations.as_ref(),
        }?;
        let index = self
            .signature_requests(role)
            .binary_search_by_key(&(parent, child, sighash), |request| {
                (
                    request.parent_node_id,
                    request.child_node_id,
                    request.sighash,
                )
            })
            .ok()?;
        opening
            .bundle()
            .signatures()
            .get(index)
            .copied()
            .and_then(|signature| DefaultSighashSignature::from_bytes(signature).ok())
    }

    /// Return one installed authenticated bundle opening.
    ///
    /// This is primarily used to persist the peer's non-derivable signatures.
    /// A participant's own deterministic signatures need not be retained.
    #[must_use]
    pub fn installed_signature_bundle(
        &self,
        role: Role,
    ) -> Option<(&SignedCommitment, &SignatureBundleOpening)> {
        match role {
            Role::Alice => self.alice_preauthorizations.as_ref(),
            Role::Bob => self.bob_preauthorizations.as_ref(),
        }
        .map(|(commitment, opening)| (commitment, opening))
    }

    /// Verify and immutably install one role's authenticated complete bundle.
    ///
    /// # Errors
    ///
    /// Rejects the wrong commitment, role, request membership, any invalid
    /// transaction signature, or replacement of an already installed bundle.
    pub fn install_verified_signature_bundle(
        &mut self,
        signed: SignedCommitment,
        opening: SignatureBundleOpening,
    ) -> Result<(), CompilerError> {
        let role = opening.bundle().role();
        if match role {
            Role::Alice => self.alice_preauthorizations.is_some(),
            Role::Bob => self.bob_preauthorizations.is_some(),
        } {
            return Err(CompilerError::PreauthorizationBundleAlreadyInstalled { role });
        }
        verify_signature_bundle_descriptor(
            &self.descriptor,
            self.manifest.graph_root,
            &signed,
            &opening,
            self.signature_requests(role),
        )?;
        match role {
            Role::Alice => self.alice_preauthorizations = Some((signed, opening)),
            Role::Bob => self.bob_preauthorizations = Some((signed, opening)),
        }
        Ok(())
    }

    /// Build the funding-readiness report for the mutually authenticated graph.
    ///
    /// `agreed_graph_root` is the opaque result of the authenticated graph-root
    /// commit/open exchange. The report remains blocked until both complete
    /// preauthorization bundles have been installed.
    ///
    /// # Errors
    ///
    /// Rejects a graph that no longer verifies or a root other than the exact
    /// manifest root.
    pub fn funding_readiness_report<'inventory>(
        &self,
        agreed_graph_root: &AgreedGraphRoot,
        local_inventory: &'inventory VerifiedLocalRuntimeInventory,
    ) -> Result<FundingReadinessReport<'inventory>, CompilerError> {
        verify_compiled_graph_descriptor(&self.descriptor, self)?;
        if agreed_graph_root.chain_game_id() != self.manifest.chain_game_id
            || agreed_graph_root.graph_root() != self.manifest.graph_root
        {
            return Err(CompilerError::GraphRootDisagreement);
        }
        let required = self
            .alice_signature_requests
            .len()
            .checked_add(self.bob_signature_requests.len())
            .ok_or_else(|| mismatch("preauthorization count overflow"))?;
        let verified = [
            self.alice_preauthorizations.as_ref(),
            self.bob_preauthorizations.as_ref(),
        ]
        .into_iter()
        .flatten()
        .try_fold(0_usize, |count, (_, opening)| {
            count
                .checked_add(opening.bundle().len())
                .ok_or_else(|| mismatch("preauthorization count overflow"))
        })?;
        build_funding_readiness_report(
            &self.descriptor,
            &self.manifest,
            agreed_graph_root.graph_root(),
            usize_to_u32(verified)?,
            usize_to_u32(required)?,
            usize_to_u32(match local_inventory.role {
                Role::Alice => self.plan.expected_alice_lamport.len(),
                Role::Bob => self.plan.expected_bob_lamport.len(),
            })?,
            local_inventory,
            true,
        )
    }
}

/// Prepare every descriptor-bound state before the activation txid exists.
///
/// # Errors
///
/// Fails closed for mainnet or a network identifier that contradicts the
/// configured Bitcoin parameter family, invalid descriptor or deal data,
/// either incorrect identity-signed Lamport bundle, any unavailable consensus
/// predicate, dust, value mismatch, an invalid caller-observed origin output,
/// or nondeterministic graph data.
pub fn prepare_chain_graph(
    bitcoin_network: Network,
    verified_descriptor: &VerifiedChainDescriptor,
    verified_deal: &bp52_protocol::VerifiedAcceptedDeal,
    lamport_public_material: &LamportPublicMaterial,
    origin_output: TxOut,
    fee_policy: &dyn FeePolicy,
) -> Result<PreparedChainGraph, CompilerError> {
    let descriptor = verified_descriptor.as_descriptor();
    validate_network_identity(descriptor.network_id, bitcoin_network)?;
    ensure_non_mainnet(bitcoin_network)?;
    if verified_deal.as_deal() != &descriptor.deal {
        return Err(CompilerError::DealMismatch);
    }
    let plan = compile_logical_graph_descriptor(descriptor, verified_deal.as_deal(), fee_policy)?;
    prepare_chain_graph_from_verified_plan(
        bitcoin_network,
        descriptor,
        plan,
        lamport_public_material,
        origin_output,
        fee_policy,
    )
}

/// Prepare a chain graph from a previously compiled and still fully verified plan.
///
/// This avoids expanding the deterministic betting tree twice when a caller
/// needs the plan first to derive its graph-bound public material.
///
/// # Errors
///
/// Applies the same descriptor, network, deal, fee, plan, Lamport, and origin
/// checks as [`prepare_chain_graph`].
pub fn prepare_chain_graph_from_plan(
    bitcoin_network: Network,
    verified_descriptor: &VerifiedChainDescriptor,
    verified_deal: &bp52_protocol::VerifiedAcceptedDeal,
    plan: LogicalGraphPlan,
    lamport_public_material: &LamportPublicMaterial,
    origin_output: TxOut,
    fee_policy: &dyn FeePolicy,
) -> Result<PreparedChainGraph, CompilerError> {
    let descriptor = verified_descriptor.as_descriptor();
    validate_network_identity(descriptor.network_id, bitcoin_network)?;
    ensure_non_mainnet(bitcoin_network)?;
    if verified_deal.as_deal() != &descriptor.deal {
        return Err(CompilerError::DealMismatch);
    }
    verify_plan_against_descriptor(&plan, descriptor, fee_policy)?;
    prepare_chain_graph_from_verified_plan(
        bitcoin_network,
        descriptor,
        plan,
        lamport_public_material,
        origin_output,
        fee_policy,
    )
}

fn prepare_chain_graph_from_verified_plan(
    bitcoin_network: Network,
    descriptor: &ChainGameDescriptor,
    plan: LogicalGraphPlan,
    lamport_public_material: &LamportPublicMaterial,
    origin_output: TxOut,
    fee_policy: &dyn FeePolicy,
) -> Result<PreparedChainGraph, CompilerError> {
    verify_lamport_material(descriptor, &plan, lamport_public_material)?;
    prepare_plan(
        descriptor,
        bitcoin_network,
        plan,
        lamport_public_material.clone(),
        origin_output,
        fee_policy,
    )
}

/// Materialize every gameplay descendant from one exact activation template.
///
/// The activation must be a canonical witness-independent version-2 template
/// with one final-sequence input spending the prepared origin and exactly one
/// output at vout 0 equal to [`PreparedChainGraph::expected_root_state_output`].
/// Its implied fee is fixed by the two bound output values. Activation remains
/// outside the descriptor-derived gameplay graph and its recorded maximum path.
///
/// # Errors
///
/// Rejects any origin outpoint, parent-output, root-output, fee, version,
/// locktime, sequence, or output-count substitution, and any inconsistent
/// descendant materialization.
pub fn compile_chain_graph(
    prepared: PreparedChainGraph,
    activation_template: TransactionTemplate,
) -> Result<CompiledGraph, CompilerError> {
    let descriptor = prepared.descriptor;
    let graph = materialize_prepared(prepared, activation_template)?;
    verify_compiled_graph_descriptor(&descriptor, &graph)?;
    Ok(graph)
}

/// Independently verify the graph's retained inputs, semantic transitions,
/// topology, templates, exact signature requests, installed bundles, and
/// manifest root.
///
/// Arbitrary [`FeePolicy`] implementations are not cloneable. The graph
/// therefore retains an immutable private snapshot of every fee result that
/// affected this finite plan and uses it to recompute fees, dust checks, and
/// terminal reserve disposition here.
///
/// # Errors
///
/// Returns the first descriptor, Lamport, Bitcoin, topology, transaction, or
/// manifest discrepancy. Mainnet and unknown networks fail closed.
pub fn verify_compiled_graph(
    verified_descriptor: &VerifiedChainDescriptor,
    graph: &CompiledGraph,
) -> Result<GraphVerificationReport, CompilerError> {
    verify_compiled_graph_descriptor(verified_descriptor.as_descriptor(), graph)
}

fn verify_compiled_graph_descriptor(
    descriptor: &ChainGameDescriptor,
    graph: &CompiledGraph,
) -> Result<GraphVerificationReport, CompilerError> {
    bp52_chain_types::validate_chain_descriptor(descriptor)?;
    if descriptor != &graph.descriptor {
        return Err(mismatch("descriptor differs from compiled graph"));
    }
    validate_network_identity(descriptor.network_id, graph.network)?;
    ensure_non_mainnet(graph.network)?;
    verify_plan_against_snapshot(&graph.plan, descriptor, &graph.fee_policy_snapshot)?;
    let descriptor_chain_game_id = chain_game_id(descriptor)?;
    if graph.plan.chain_game_id != descriptor_chain_game_id
        || graph.plan.root_node_id != root_node_id(&descriptor_chain_game_id)
    {
        return Err(mismatch("logical plan is not bound to the descriptor"));
    }
    verify_lamport_material(descriptor, &graph.plan, &graph.public_material)?;
    verify_materialized_graph(graph)?;

    let root = verify_tree_links(&graph.records)?;
    if root != graph.plan.root_node_id {
        return Err(mismatch("logical record root differs from plan"));
    }
    let graph_root = compute_graph_root(&graph.records)?;
    let expected_manifest = GraphManifest {
        chain_game_id: graph.plan.chain_game_id,
        graph_root,
        alice_lamport_bundle_root: graph.public_material.alice.bundle_root(),
        bob_lamport_bundle_root: graph.public_material.bob.bundle_root(),
        compiler_id: descriptor.compiler_id,
        fee_policy_id: descriptor.fee_policy_id,
        node_count: usize_to_u32(graph.records.len())?,
        transaction_count: usize_to_u32(graph.templates.len())?,
        maximum_path_length: graph.plan.maximum_path_length,
    };
    if graph.manifest != expected_manifest {
        return Err(mismatch("manifest differs from recomputed graph"));
    }

    let recomputed_requests = recompute_signature_requests(graph)?;
    if graph.alice_signature_requests != recomputed_requests.0
        || graph.bob_signature_requests != recomputed_requests.1
        || graph.alice_runtime_signature_requests != recomputed_requests.2
        || graph.bob_runtime_signature_requests != recomputed_requests.3
    {
        return Err(mismatch("fixed-signature request set differs from graph"));
    }
    verify_installed_bundle(graph, Role::Alice)?;
    verify_installed_bundle(graph, Role::Bob)?;

    Ok(GraphVerificationReport {
        graph_root,
        node_count: usize_to_u32(graph.records.len())?,
        transaction_count: usize_to_u32(graph.templates.len())?,
        maximum_path_length: graph.plan.maximum_path_length,
        alice_signature_requests: usize_to_u32(graph.alice_signature_requests.len())?,
        bob_signature_requests: usize_to_u32(graph.bob_signature_requests.len())?,
        alice_runtime_signature_requests: usize_to_u32(
            graph.alice_runtime_signature_requests.len(),
        )?,
        bob_runtime_signature_requests: usize_to_u32(graph.bob_runtime_signature_requests.len())?,
        verified_alice_preauthorizations: installed_count(graph, Role::Alice)?,
        verified_bob_preauthorizations: installed_count(graph, Role::Bob)?,
    })
}

fn prepare_plan(
    descriptor: &ChainGameDescriptor,
    network: Network,
    plan: LogicalGraphPlan,
    public_material: LamportPublicMaterial,
    origin_output: TxOut,
    fee_policy: &dyn FeePolicy,
) -> Result<PreparedChainGraph, CompilerError> {
    let fee_policy_snapshot = FeePolicySnapshot::capture(fee_policy, descriptor, &plan)?;
    let lamport_keys = collect_lamport_keys(&plan, &public_material)?;
    let secp = Secp256k1::verification_only();
    let root_node = plan
        .node(&plan.root_node_id)
        .ok_or_else(|| mismatch("gameplay root is absent from the plan"))?;
    let root_programs = programs_for_node(descriptor, &plan, root_node, &lamport_keys)?;
    let root_state =
        CompiledTaprootState::compile(&secp, root_node.logical_state_digest, &root_programs)?;
    let origin_outpoint = outpoint_from_consensus_bytes(descriptor.funding_outpoint)?;
    let root_state_output = state_output(
        plan.nodes
            .first()
            .ok_or_else(|| mismatch("logical plan is empty"))?,
        &root_state,
        fee_policy_snapshot.dust_threshold(),
    )?;

    // Constructing the canonical template here validates the exact observed
    // parent output and proves that it can fund the root without underflow.
    canonical_activation_template(network, origin_outpoint, &origin_output, &root_state_output)?;

    Ok(PreparedChainGraph {
        descriptor: *descriptor,
        network,
        plan,
        fee_policy_snapshot,
        public_material,
        origin_outpoint,
        origin_output,
        root_state_output,
    })
}

fn canonical_activation_template(
    network: Network,
    origin_outpoint: OutPoint,
    origin_output: &TxOut,
    root_state_output: &TxOut,
) -> Result<TransactionTemplate, CompilerError> {
    let activation_fee_sat = origin_output
        .value
        .to_sat()
        .checked_sub(root_state_output.value.to_sat())
        .ok_or_else(|| mismatch("origin value cannot fund the gameplay root"))?;
    Ok(TransactionTemplate::normal(
        network,
        origin_outpoint,
        origin_output.clone(),
        vec![root_state_output.clone()],
        activation_fee_sat,
    )?)
}

pub(crate) fn verify_activation_template(
    prepared: &PreparedChainGraph,
    activation_template: &TransactionTemplate,
) -> Result<(), CompilerError> {
    verify_activation_contract(
        prepared.network,
        prepared.origin_outpoint,
        &prepared.origin_output,
        &prepared.root_state_output,
        activation_template,
    )
}

fn verify_activation_contract(
    network: Network,
    origin_outpoint: OutPoint,
    origin_output: &TxOut,
    root_state_output: &TxOut,
    activation_template: &TransactionTemplate,
) -> Result<(), CompilerError> {
    let expected =
        canonical_activation_template(network, origin_outpoint, origin_output, root_state_output)?;
    if activation_template != &expected {
        return Err(mismatch(
            "activation template differs from the prepared origin-to-root contract",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn materialize_prepared(
    prepared: PreparedChainGraph,
    activation_template: TransactionTemplate,
) -> Result<CompiledGraph, CompilerError> {
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
    let lamport_keys = collect_lamport_keys(&plan, &public_material)?;
    let secp = Secp256k1::verification_only();
    let mut states = HashMap::with_capacity(plan.nodes.len());
    let mut edge_predicates = HashMap::with_capacity(plan.transaction_count());
    for node in &plan.nodes {
        if matches!(node.state, PlannedState::Terminal(_)) {
            continue;
        }
        let programs = programs_for_node(&descriptor, &plan, node, &lamport_keys)?;
        for edge in &node.edges {
            let edge_programs = programs_for_edge(&descriptor, &plan, node, edge, &lamport_keys)?;
            let program = edge_programs
                .last()
                .ok_or_else(|| mismatch("directed edge has no Taproot programs"))?;
            if edge_predicates
                .insert((node.node_id, edge.child_node_id), program.predicate_id())
                .is_some()
            {
                return Err(mismatch("duplicate directed edge predicate"));
            }
        }
        let state = CompiledTaprootState::compile(&secp, node.logical_state_digest, &programs)?;
        if states.insert(node.node_id, state).is_some() {
            return Err(mismatch("duplicate Taproot state node"));
        }
    }
    let root_outpoint = OutPoint::new(Txid::from_byte_array(activation_template.txid()), 0);
    let root_output = root_state_output.clone();
    let root_state = states
        .get(&plan.root_node_id)
        .ok_or_else(|| mismatch("gameplay root has no Taproot state"))?;

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

    let mut spend_points = HashMap::with_capacity(plan.nodes.len());
    spend_points.insert(plan.root_node_id, (root_outpoint, root_output.clone()));
    let mut templates = Vec::with_capacity(plan.transaction_count());
    let mut template_index = HashMap::with_capacity(plan.transaction_count());
    let mut edges = Vec::with_capacity(plan.transaction_count());
    let mut edge_index = HashMap::with_capacity(plan.transaction_count());
    let mut incoming_predicates = HashMap::with_capacity(plan.transaction_count());
    let mut creating_transactions = HashMap::with_capacity(plan.transaction_count());

    for parent in &plan.nodes {
        if matches!(parent.state, PlannedState::Terminal(_)) {
            continue;
        }
        let (parent_outpoint, parent_output) = spend_points
            .get(&parent.node_id)
            .cloned()
            .ok_or_else(|| mismatch("parent spend point was not materialized top-down"))?;
        for edge in &parent.edges {
            let child_index = *by_node
                .get(&edge.child_node_id)
                .ok_or(CompilerError::DanglingNode)?;
            let child = &plan.nodes[child_index];
            if child.parent_node_id != Some(parent.node_id) {
                return Err(mismatch("planned child names another parent"));
            }
            let outputs = outputs_for_child(
                child,
                &states,
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
            let predicate_id = *edge_predicates
                .get(&(parent.node_id, child.node_id))
                .ok_or_else(|| mismatch("directed edge has no predicate"))?;
            let logical = template.to_logical_transaction();
            let logical_edge = LogicalEdge {
                parent_node_id: parent.node_id,
                child_node_id: child.node_id,
                kind: edge.kind,
                transaction: logical.clone(),
                authorization: edge.authorization,
                timeout: edge.timeout,
            };
            logical_edge.validate()?;
            if edge_index
                .insert((parent.node_id, child.node_id), edges.len())
                .is_some()
            {
                return Err(mismatch("duplicate concrete directed edge"));
            }
            edges.push(logical_edge);
            if template_index
                .insert(child.node_id, templates.len())
                .is_some()
                || creating_transactions
                    .insert(child.node_id, logical)
                    .is_some()
                || incoming_predicates
                    .insert(child.node_id, predicate_id)
                    .is_some()
            {
                return Err(mismatch("child has more than one creating transaction"));
            }
            if !matches!(child.state, PlannedState::Terminal(_)) {
                let output = template
                    .transaction()
                    .output
                    .first()
                    .cloned()
                    .ok_or_else(|| mismatch("state transaction has no first output"))?;
                let outpoint = OutPoint::new(Txid::from_byte_array(template.txid()), 0);
                if spend_points
                    .insert(child.node_id, (outpoint, output))
                    .is_some()
                {
                    return Err(mismatch("child spend point was materialized twice"));
                }
            }
            templates.push(template);
        }
    }

    let root_predicate = funded_root_predicate(root_state);
    let mut records = Vec::with_capacity(plan.nodes.len());
    let mut record_index = HashMap::with_capacity(plan.nodes.len());
    for node in &plan.nodes {
        let record = LogicalNodeRecord {
            node_id: node.node_id,
            parent_node_id: node.parent_node_id,
            node_kind: node.node_kind,
            logical_state_digest: node.logical_state_digest,
            transaction: creating_transactions.get(&node.node_id).cloned(),
            required_predicate_id: incoming_predicates
                .get(&node.node_id)
                .copied()
                .unwrap_or(root_predicate),
            timeout: node.timeout,
            child_node_ids: node.edges.iter().map(|edge| edge.child_node_id).collect(),
        };
        record.validate()?;
        if record_index.insert(node.node_id, records.len()).is_some() {
            return Err(mismatch("duplicate concrete node record"));
        }
        records.push(record);
    }

    if templates.len() != plan.transaction_count()
        || edges.len() != plan.transaction_count()
        || records.len() != plan.nodes.len()
    {
        return Err(mismatch(
            "materialized graph count differs from logical plan",
        ));
    }
    let graph_root = compute_graph_root(&records)?;
    let manifest = GraphManifest {
        chain_game_id: plan.chain_game_id,
        graph_root,
        alice_lamport_bundle_root: public_material.alice.bundle_root(),
        bob_lamport_bundle_root: public_material.bob.bundle_root(),
        compiler_id: descriptor.compiler_id,
        fee_policy_id: descriptor.fee_policy_id,
        node_count: usize_to_u32(records.len())?,
        transaction_count: usize_to_u32(templates.len())?,
        maximum_path_length: plan.maximum_path_length,
    };
    let (
        alice_signature_requests,
        bob_signature_requests,
        alice_runtime_signature_requests,
        bob_runtime_signature_requests,
    ) = signature_requests_from_parts(
        &edges,
        &templates,
        &template_index,
        &states,
        &edge_predicates,
    )?;

    Ok(CompiledGraph {
        descriptor,
        network,
        plan,
        fee_policy_snapshot,
        public_material,
        manifest,
        origin_outpoint,
        origin_output,
        activation_template,
        root_state_outpoint: root_outpoint,
        root_state_output: root_output,
        records,
        edges,
        templates,
        states,
        record_index,
        edge_index,
        template_index,
        edge_predicates,
        lamport_keys,
        alice_signature_requests,
        bob_signature_requests,
        alice_runtime_signature_requests,
        bob_runtime_signature_requests,
        alice_preauthorizations: None,
        bob_preauthorizations: None,
    })
}

fn verify_lamport_material(
    descriptor: &ChainGameDescriptor,
    plan: &LogicalGraphPlan,
    material: &LamportPublicMaterial,
) -> Result<(), CompilerError> {
    verify_one_lamport_bundle(
        &material.alice,
        plan.chain_game_id,
        LamportRole::Alice,
        &plan.expected_alice_lamport,
        descriptor.alice_xonly_pk,
    )?;
    verify_one_lamport_bundle(
        &material.bob,
        plan.chain_game_id,
        LamportRole::Bob,
        &plan.expected_bob_lamport,
        descriptor.bob_xonly_pk,
    )?;
    verify_global_lamport_hash_uniqueness(material)
}

fn verify_global_lamport_hash_uniqueness(
    material: &LamportPublicMaterial,
) -> Result<(), CompilerError> {
    let count = material
        .alice
        .entries()
        .iter()
        .chain(material.bob.entries())
        .map(|entry| entry.public_hash_pairs().len().saturating_mul(2))
        .sum();
    let mut seen = HashSet::with_capacity(count);
    for hash in material
        .alice
        .entries()
        .iter()
        .chain(material.bob.entries())
        .flat_map(|entry| entry.public_hash_pairs().iter().flatten())
    {
        if !seen.insert(*hash) {
            return Err(bp52_lamport::LamportError::DuplicatePublicHash.into());
        }
    }
    Ok(())
}

fn verify_one_lamport_bundle(
    bundle: &LamportPublicBundle,
    chain_game_id: [u8; 32],
    role: LamportRole,
    expected: &[ExpectedLamportEntry],
    identity_key: [u8; 32],
) -> Result<(), CompilerError> {
    bundle.verify(chain_game_id, role, expected, |digest, signature| {
        let Ok(public_key) = XOnlyPublicKey::from_slice(&identity_key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &Message::from_digest(digest), &public_key)
            .is_ok()
    })?;
    Ok(())
}

pub(crate) fn collect_lamport_keys(
    plan: &LogicalGraphPlan,
    material: &LamportPublicMaterial,
) -> Result<HashMap<(NodeId, LamportPurpose), LamportPublicKey>, CompilerError> {
    let mut keys =
        HashMap::with_capacity(material.alice.entries().len() + material.bob.entries().len());
    for entry in material
        .alice
        .entries()
        .iter()
        .chain(material.bob.entries())
    {
        let key = entry.to_public_key(plan.chain_game_id)?;
        if keys
            .insert((entry.node_id(), entry.purpose()), key)
            .is_some()
        {
            return Err(mismatch("Lamport bundles contain a cross-role duplicate"));
        }
    }
    Ok(keys)
}

pub(crate) fn programs_for_node(
    descriptor: &ChainGameDescriptor,
    plan: &LogicalGraphPlan,
    node: &PlannedNode,
    lamport_keys: &HashMap<(NodeId, LamportPurpose), LamportPublicKey>,
) -> Result<Vec<LeafProgram>, CompilerError> {
    let mut programs = Vec::new();
    for edge in &node.edges {
        programs.extend(programs_for_edge(
            descriptor,
            plan,
            node,
            edge,
            lamport_keys,
        )?);
    }
    Ok(programs)
}

pub(crate) fn programs_for_edge(
    descriptor: &ChainGameDescriptor,
    plan: &LogicalGraphPlan,
    node: &PlannedNode,
    edge: &PlannedEdge,
    lamport_keys: &HashMap<(NodeId, LamportPurpose), LamportPublicKey>,
) -> Result<Vec<LeafProgram>, CompilerError> {
    let both = [descriptor.alice_xonly_pk, descriptor.bob_xonly_pk];
    match edge.kind {
        EdgeKind::Action(action) => Ok(vec![LeafProgram::Action(ActionProgram::new(
            plan.chain_game_id,
            node.node_id,
            action,
            both,
        )?)]),
        EdgeKind::HoleCardReveal { .. } | EdgeKind::CommunityReveal { .. } => {
            let PlannedState::Reveal { pattern, .. } = node.state else {
                return Err(mismatch("reveal edge leaves a non-reveal state"));
            };
            Ok(vec![LeafProgram::Reveal(RevealProgram::new(
                plan.chain_game_id,
                node.node_id,
                ShareRevealPredicate::new(&descriptor.deal, pattern),
                both,
            )?)])
        }
        EdgeKind::AliceShowdown => {
            let key = required_lamport_key(
                lamport_keys,
                plan.root_node_id,
                LamportPurpose::AliceScore24Bit,
            )?;
            Ok(vec![LeafProgram::AliceShowdown(AliceShowdownProgram::new(
                &descriptor.deal,
                plan.chain_game_id,
                node.node_id,
                key,
                both,
            )?)])
        }
        EdgeKind::BobPayout(outcome) => {
            let alice_showdown_node_id = node
                .parent_node_id
                .ok_or_else(|| mismatch("Bob terminal node has no Alice-showdown parent"))?;
            let alice_score_key = required_lamport_key(
                lamport_keys,
                plan.root_node_id,
                LamportPurpose::AliceScore24Bit,
            )?;
            let bob_score_key = required_lamport_key(
                lamport_keys,
                plan.root_node_id,
                LamportPurpose::BobScore24Bit,
            )?;
            Ok(vec![LeafProgram::BobPayout(BobPayoutProgram::new(
                &descriptor.deal,
                plan.chain_game_id,
                node.node_id,
                alice_showdown_node_id,
                outcome,
                alice_score_key,
                bob_score_key,
                both,
            )?)])
        }
        EdgeKind::Timeout(_) => {
            let timeout = edge
                .timeout
                .ok_or_else(|| mismatch("timeout edge lacks timeout metadata"))?;
            Ok(vec![LeafProgram::Timeout(TimeoutProgram::new(
                plan.chain_game_id,
                node.node_id,
                timeout.csv,
                both,
            )?)])
        }
        EdgeKind::Advance { .. } => Err(mismatch(
            "descriptor-derived reference plan cannot materialize an Advance edge",
        )),
    }
}

fn required_lamport_key(
    keys: &HashMap<(NodeId, LamportPurpose), LamportPublicKey>,
    node_id: NodeId,
    purpose: LamportPurpose,
) -> Result<&LamportPublicKey, CompilerError> {
    keys.get(&(node_id, purpose))
        .ok_or_else(|| mismatch("required Lamport key is absent"))
}

fn outputs_for_child(
    child: &PlannedNode,
    states: &HashMap<NodeId, CompiledTaprootState>,
    alice_terminal_script: &ScriptBuf,
    bob_terminal_script: &ScriptBuf,
    dust_threshold: u64,
) -> Result<Vec<TxOut>, CompilerError> {
    match child.state {
        PlannedState::Terminal(terminal) => {
            let mut outputs = Vec::with_capacity(2);
            push_terminal_output(
                &mut outputs,
                terminal.alice_output_sat,
                alice_terminal_script,
                dust_threshold,
            )?;
            push_terminal_output(
                &mut outputs,
                terminal.bob_output_sat,
                bob_terminal_script,
                dust_threshold,
            )?;
            if outputs.is_empty() {
                return Err(mismatch("terminal transaction has no nonzero output"));
            }
            Ok(outputs)
        }
        _ => Ok(vec![state_output(
            child,
            states
                .get(&child.node_id)
                .ok_or_else(|| mismatch("nonterminal child has no Taproot state"))?,
            dust_threshold,
        )?]),
    }
}

pub(crate) fn outputs_for_child_state(
    child: &PlannedNode,
    state: Option<&CompiledTaprootState>,
    alice_terminal_script: &ScriptBuf,
    bob_terminal_script: &ScriptBuf,
    dust_threshold: u64,
) -> Result<Vec<TxOut>, CompilerError> {
    match child.state {
        PlannedState::Terminal(terminal) => {
            let mut outputs = Vec::with_capacity(2);
            push_terminal_output(
                &mut outputs,
                terminal.alice_output_sat,
                alice_terminal_script,
                dust_threshold,
            )?;
            push_terminal_output(
                &mut outputs,
                terminal.bob_output_sat,
                bob_terminal_script,
                dust_threshold,
            )?;
            if outputs.is_empty() {
                return Err(mismatch("terminal transaction has no nonzero output"));
            }
            Ok(outputs)
        }
        _ => Ok(vec![state_output(
            child,
            state.ok_or_else(|| mismatch("nonterminal child has no Taproot state"))?,
            dust_threshold,
        )?]),
    }
}

pub(crate) fn state_output(
    node: &PlannedNode,
    state: &CompiledTaprootState,
    dust_threshold: u64,
) -> Result<TxOut, CompilerError> {
    if state.logical_state_digest() != node.logical_state_digest {
        return Err(mismatch(
            "Taproot state output is bound to another logical state digest",
        ));
    }
    let value = node.state.amounts().game_value()?;
    validate_output_value(value, dust_threshold)?;
    Ok(TxOut {
        value: Amount::from_sat(value),
        script_pubkey: state.script_pubkey(),
    })
}

fn push_terminal_output(
    outputs: &mut Vec<TxOut>,
    value: u64,
    script: &ScriptBuf,
    dust_threshold: u64,
) -> Result<(), CompilerError> {
    validate_output_value(value, dust_threshold)?;
    if value != 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script.clone(),
        });
    }
    Ok(())
}

fn validate_output_value(value: u64, dust_threshold: u64) -> Result<(), CompilerError> {
    if dust_threshold == 0 {
        return Err(bp52_chain_bitcoin::FeeError::ZeroDustThreshold.into());
    }
    if value != 0 && value < dust_threshold {
        return Err(bp52_chain_bitcoin::FeeError::DustOutput {
            value,
            dust_threshold,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn terminal_script(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    key: [u8; 32],
    role: Role,
) -> Result<ScriptBuf, CompilerError> {
    let key = UntweakedPublicKey::from_slice(&key)
        .map_err(|_| bp52_chain_types::ChainError::InvalidIdentityKey { role })?;
    Ok(ScriptBuf::new_p2tr(secp, key, None))
}

pub(crate) fn funded_root_predicate(state: &CompiledTaprootState) -> [u8; 32] {
    tagged_sha256(ROOT_PREDICATE_TAG, state.script_pubkey().as_bytes())
}

fn signature_requests_from_parts(
    edges: &[LogicalEdge],
    templates: &[TransactionTemplate],
    template_index: &HashMap<NodeId, usize>,
    states: &HashMap<NodeId, CompiledTaprootState>,
    edge_predicates: &HashMap<(NodeId, NodeId), [u8; 32]>,
) -> Result<SignatureRequestSets, CompilerError> {
    let mut alice = Vec::new();
    let mut bob = Vec::new();
    let mut alice_runtime = Vec::new();
    let mut bob_runtime = Vec::new();
    for edge in edges {
        let template = template_index
            .get(&edge.child_node_id)
            .map(|index| &templates[*index])
            .ok_or_else(|| mismatch("signature request has no template"))?;
        let predicate = edge_predicates
            .get(&(edge.parent_node_id, edge.child_node_id))
            .ok_or_else(|| mismatch("signature request has no predicate"))?;
        let primary_leaf = states
            .get(&edge.parent_node_id)
            .and_then(|state| state.leaf(*predicate))
            .ok_or_else(|| mismatch("signature request has no Taproot leaf"))?;
        let sighash = taproot_script_sighash_default(
            template.transaction(),
            0,
            std::slice::from_ref(template.parent_output()),
            primary_leaf.script(),
        )?;
        for role in preauthorized_roles(edge.authorization) {
            let request = SignatureRequest {
                parent_node_id: edge.parent_node_id,
                child_node_id: edge.child_node_id,
                signer: role,
                sighash,
            };
            match role {
                Role::Alice => alice.push(request),
                Role::Bob => bob.push(request),
            }
        }
        if let Some((role, kind)) = runtime_signature_role_and_kind(edge.authorization) {
            let request = RuntimeSignatureRequest {
                request: SignatureRequest {
                    parent_node_id: edge.parent_node_id,
                    child_node_id: edge.child_node_id,
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
    }
    alice.sort_unstable_by_key(|request| {
        (
            request.parent_node_id,
            request.child_node_id,
            request.sighash,
        )
    });
    bob.sort_unstable_by_key(|request| {
        (
            request.parent_node_id,
            request.child_node_id,
            request.sighash,
        )
    });
    alice_runtime.sort_unstable_by_key(|request| {
        (
            request.request.parent_node_id,
            request.request.child_node_id,
            request.kind,
            request.request.sighash,
        )
    });
    bob_runtime.sort_unstable_by_key(|request| {
        (
            request.request.parent_node_id,
            request.request.child_node_id,
            request.kind,
            request.request.sighash,
        )
    });
    if has_duplicate_requests(&alice)
        || has_duplicate_requests(&bob)
        || has_duplicate_runtime_requests(&alice_runtime)
        || has_duplicate_runtime_requests(&bob_runtime)
    {
        return Err(mismatch("duplicate fixed or retained signature request"));
    }
    Ok((alice, bob, alice_runtime, bob_runtime))
}

fn has_duplicate_requests(requests: &[SignatureRequest]) -> bool {
    requests.windows(2).any(|pair| {
        pair[0].parent_node_id == pair[1].parent_node_id
            && pair[0].child_node_id == pair[1].child_node_id
            && pair[0].sighash == pair[1].sighash
    })
}

fn has_duplicate_runtime_requests(requests: &[RuntimeSignatureRequest]) -> bool {
    requests.windows(2).any(|pair| {
        pair[0].request.parent_node_id == pair[1].request.parent_node_id
            && pair[0].request.child_node_id == pair[1].request.child_node_id
            && pair[0].kind == pair[1].kind
            && pair[0].request.sighash == pair[1].request.sighash
    })
}

pub(crate) fn preauthorized_roles(policy: AuthorizationPolicy) -> impl Iterator<Item = Role> {
    let roles = match policy {
        AuthorizationPolicy::BothPresigned => [Some(Role::Alice), Some(Role::Bob)],
        AuthorizationPolicy::BettingAction { actor } => [Some(actor.other()), None],
        AuthorizationPolicy::RevealPreimages { revealer } => [Some(revealer.other()), None],
        AuthorizationPolicy::AliceScore => [Some(Role::Bob), None],
        AuthorizationPolicy::BobLivePayout => [Some(Role::Alice), None],
        AuthorizationPolicy::Timeout { beneficiary } => [Some(beneficiary.other()), None],
    };
    roles.into_iter().flatten()
}

pub(crate) fn runtime_signature_role_and_kind(
    policy: AuthorizationPolicy,
) -> Option<(Role, RuntimeSignatureKind)> {
    match policy {
        AuthorizationPolicy::BobLivePayout => {
            Some((Role::Bob, RuntimeSignatureKind::BobTerminalPayout))
        }
        AuthorizationPolicy::Timeout { beneficiary } => {
            Some((beneficiary, RuntimeSignatureKind::Timeout))
        }
        AuthorizationPolicy::BothPresigned
        | AuthorizationPolicy::BettingAction { .. }
        | AuthorizationPolicy::RevealPreimages { .. }
        | AuthorizationPolicy::AliceScore => None,
    }
}

#[allow(clippy::too_many_lines)]
fn verify_materialized_graph(graph: &CompiledGraph) -> Result<(), CompilerError> {
    if graph.records.len() != graph.plan.nodes.len()
        || graph.edges.len() != graph.plan.transaction_count()
        || graph.templates.len() != graph.plan.transaction_count()
        || graph.record_index.len() != graph.records.len()
        || graph.edge_index.len() != graph.edges.len()
        || graph.template_index.len() != graph.templates.len()
        || graph.edge_predicates.len() != graph.edges.len()
    {
        return Err(mismatch("concrete graph counts or indices disagree"));
    }
    let root_state = graph
        .states
        .get(&graph.plan.root_node_id)
        .ok_or_else(|| mismatch("gameplay root has no concrete state"))?;
    let root_predicate = funded_root_predicate(root_state);
    let origin_outpoint = outpoint_from_consensus_bytes(graph.descriptor.funding_outpoint)?;
    if graph.origin_outpoint != origin_outpoint {
        return Err(mismatch("stored origin outpoint differs from descriptor"));
    }
    let root_node = graph
        .plan
        .nodes
        .first()
        .ok_or_else(|| mismatch("logical plan is empty"))?;
    let expected_root_output = state_output(
        root_node,
        root_state,
        graph.fee_policy_snapshot.dust_threshold(),
    )?;
    if graph.root_state_output != expected_root_output {
        return Err(mismatch(
            "stored gameplay-root output differs from compiled root",
        ));
    }
    let expected_activation = canonical_activation_template(
        graph.network,
        origin_outpoint,
        &graph.origin_output,
        &expected_root_output,
    )?;
    if graph.activation_template != expected_activation {
        return Err(mismatch(
            "stored activation template differs from origin-to-root contract",
        ));
    }
    let root_outpoint = OutPoint::new(Txid::from_byte_array(graph.activation_template.txid()), 0);
    if graph.root_state_outpoint != root_outpoint {
        return Err(mismatch(
            "stored gameplay-root outpoint differs from activation txid",
        ));
    }
    let mut spend_points = HashMap::with_capacity(graph.plan.nodes.len());
    spend_points.insert(
        graph.plan.root_node_id,
        (root_outpoint, expected_root_output),
    );

    for (position, node) in graph.plan.nodes.iter().enumerate() {
        let record = graph
            .node(node.node_id)
            .ok_or_else(|| mismatch("planned node is absent from records"))?;
        let expected_transaction = node
            .parent_node_id
            .and_then(|_| graph.transaction_template(node.node_id))
            .map(TransactionTemplate::to_logical_transaction);
        let expected_predicate = node
            .parent_node_id
            .and_then(|parent| graph.edge_predicates.get(&(parent, node.node_id)).copied())
            .unwrap_or(root_predicate);
        let expected_children: Vec<_> = node.edges.iter().map(|edge| edge.child_node_id).collect();
        if graph.record_index.get(&node.node_id) != Some(&position)
            || record.parent_node_id != node.parent_node_id
            || record.node_kind != node.node_kind
            || record.logical_state_digest != node.logical_state_digest
            || record.transaction != expected_transaction
            || record.required_predicate_id != expected_predicate
            || record.timeout != node.timeout
            || record.child_node_ids != expected_children
        {
            return Err(mismatch("logical record differs from planned node"));
        }
        record.validate()?;
        if matches!(node.state, PlannedState::Terminal(_)) {
            if graph.states.contains_key(&node.node_id) {
                return Err(mismatch("terminal node unexpectedly has a Taproot state"));
            }
            continue;
        }
        let actual_state = graph
            .states
            .get(&node.node_id)
            .ok_or_else(|| mismatch("nonterminal node has no Taproot state"))?;
        if actual_state.logical_state_digest() != node.logical_state_digest {
            return Err(mismatch(
                "Taproot state commitment differs from logical state digest",
            ));
        }
        let (parent_outpoint, parent_output) = spend_points
            .get(&node.node_id)
            .cloned()
            .ok_or_else(|| mismatch("concrete graph is not topologically materialized"))?;
        if actual_state.script_pubkey() != parent_output.script_pubkey
            || node.state.amounts().game_value()? != parent_output.value.to_sat()
        {
            return Err(mismatch("state output differs from planned state"));
        }
        let expected_leaf_count =
            programs_for_node(&graph.descriptor, &graph.plan, node, &graph.lamport_keys)?.len();
        if actual_state.leaves().len() != expected_leaf_count {
            return Err(mismatch("Taproot leaf count differs from planned edges"));
        }

        for planned_edge in &node.edges {
            let concrete = graph
                .edge(node.node_id, planned_edge.child_node_id)
                .ok_or_else(|| mismatch("planned edge is absent from concrete graph"))?;
            if concrete.kind != planned_edge.kind
                || concrete.authorization != planned_edge.authorization
                || concrete.timeout != planned_edge.timeout
                || concrete.transaction.fee_sat != planned_edge.fee_sat
            {
                return Err(mismatch("concrete edge differs from planned edge"));
            }
            concrete.validate()?;
            let template = graph
                .transaction_template(planned_edge.child_node_id)
                .ok_or_else(|| mismatch("concrete edge has no transaction template"))?;
            if template.to_logical_transaction() != concrete.transaction
                || template.parent_output() != &parent_output
                || template.transaction().input.len() != 1
                || template.transaction().input[0].previous_output != parent_outpoint
            {
                return Err(mismatch("transaction template differs from top-down edge"));
            }
            let predicate = *graph
                .edge_predicates
                .get(&(node.node_id, planned_edge.child_node_id))
                .ok_or_else(|| mismatch("edge predicate index is incomplete"))?;
            let leaf = graph
                .tap_leaf(node.node_id, planned_edge.child_node_id)
                .ok_or_else(|| mismatch("concrete edge has no exact Taproot leaf"))?;
            if leaf.predicate_id() != predicate {
                return Err(mismatch("Taproot leaf predicate differs from edge"));
            }
            let child = graph
                .plan
                .node(&planned_edge.child_node_id)
                .ok_or(CompilerError::DanglingNode)?;
            verify_child_outputs(graph, child, template)?;
            if !matches!(child.state, PlannedState::Terminal(_)) {
                spend_points.insert(
                    child.node_id,
                    (
                        OutPoint::new(Txid::from_byte_array(template.txid()), 0),
                        template.transaction().output[0].clone(),
                    ),
                );
            }
        }
    }
    let expected_states = graph
        .plan
        .nodes
        .iter()
        .filter(|node| !matches!(node.state, PlannedState::Terminal(_)))
        .count();
    if graph.states.len() != expected_states || spend_points.len() != expected_states {
        return Err(mismatch("state index contains an extra or missing node"));
    }
    Ok(())
}

fn verify_child_outputs(
    graph: &CompiledGraph,
    child: &PlannedNode,
    template: &TransactionTemplate,
) -> Result<(), CompilerError> {
    let transaction = template.transaction();
    let expected = if let PlannedState::Terminal(terminal) = child.state {
        let secp = Secp256k1::verification_only();
        let alice = terminal_script(&secp, graph.descriptor.alice_xonly_pk, Role::Alice)?;
        let bob = terminal_script(&secp, graph.descriptor.bob_xonly_pk, Role::Bob)?;
        let mut outputs = Vec::with_capacity(2);
        if terminal.alice_output_sat != 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(terminal.alice_output_sat),
                script_pubkey: alice,
            });
        }
        if terminal.bob_output_sat != 0 {
            outputs.push(TxOut {
                value: Amount::from_sat(terminal.bob_output_sat),
                script_pubkey: bob,
            });
        }
        outputs
    } else {
        let state = graph
            .states
            .get(&child.node_id)
            .ok_or_else(|| mismatch("state child has no Taproot output"))?;
        vec![TxOut {
            value: Amount::from_sat(child.state.amounts().game_value()?),
            script_pubkey: state.script_pubkey(),
        }]
    };
    if transaction.output != expected {
        return Err(mismatch(
            "transaction outputs differ from exact child state",
        ));
    }
    Ok(())
}

fn recompute_signature_requests(
    graph: &CompiledGraph,
) -> Result<SignatureRequestSets, CompilerError> {
    signature_requests_from_parts(
        &graph.edges,
        &graph.templates,
        &graph.template_index,
        &graph.states,
        &graph.edge_predicates,
    )
}

fn verify_installed_bundle(graph: &CompiledGraph, role: Role) -> Result<(), CompilerError> {
    let proof = match role {
        Role::Alice => graph.alice_preauthorizations.as_ref(),
        Role::Bob => graph.bob_preauthorizations.as_ref(),
    };
    let Some((signed, opening)) = proof else {
        return Ok(());
    };
    verify_signature_bundle_descriptor(
        &graph.descriptor,
        graph.manifest.graph_root,
        signed,
        opening,
        graph.signature_requests(role),
    )?;
    for (request, signature) in graph
        .signature_requests(role)
        .iter()
        .zip(opening.bundle().signatures())
    {
        let expected = DefaultSighashSignature::from_bytes(*signature)?;
        if graph.preauthorization(request.parent_node_id, request.child_node_id, role)
            != Some(expected)
        {
            return Err(mismatch(
                "preauthorization index differs from verified bundle",
            ));
        }
    }
    Ok(())
}

fn installed_count(graph: &CompiledGraph, role: Role) -> Result<u32, CompilerError> {
    let count = match role {
        Role::Alice => graph
            .alice_preauthorizations
            .as_ref()
            .map_or(0, |(_, opening)| opening.bundle().len()),
        Role::Bob => graph
            .bob_preauthorizations
            .as_ref()
            .map_or(0, |(_, opening)| opening.bundle().len()),
    };
    usize_to_u32(count)
}

fn runtime_signature_inventory(
    role: Role,
    requests: &[RuntimeSignatureRequest],
) -> Result<Vec<RuntimeSignatureIntent>, CompilerError> {
    let mut bob_payout = 0_usize;
    let mut timeout = 0_usize;
    for request in requests {
        if request.request.signer != role {
            return Err(mismatch("runtime request is assigned to the wrong role"));
        }
        match request.kind {
            RuntimeSignatureKind::BobTerminalPayout => bob_payout += 1,
            RuntimeSignatureKind::Timeout => timeout += 1,
        }
    }
    let mut inventory = Vec::with_capacity(2);
    for (kind, count) in [
        (RuntimeSignatureKind::BobTerminalPayout, bob_payout),
        (RuntimeSignatureKind::Timeout, timeout),
    ] {
        if count != 0 {
            inventory.push(RuntimeSignatureIntent {
                role,
                kind,
                count: usize_to_u32(count)?,
            });
        }
    }
    Ok(inventory)
}

fn verify_runtime_signature_responses(
    descriptor: &ChainGameDescriptor,
    role: Role,
    expected: &[RuntimeSignatureRequest],
    responses: &[RuntimeSignatureResponse],
) -> Result<(), CompilerError> {
    if responses.len() != expected.len()
        || responses
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.request() != *expected)
    {
        return Err(CompilerError::RuntimeSignatureBundleMembershipMismatch);
    }
    let secp = Secp256k1::verification_only();
    let identity_key = *descriptor.identity_key(role);
    for response in responses {
        let request = response.request();
        if request.request.signer != role {
            return Err(CompilerError::RuntimeSignatureBundleMembershipMismatch);
        }
        verify_sighash_default(
            &secp,
            identity_key,
            request.request.sighash,
            DefaultSighashSignature::from_bytes(response.signature_bytes())?,
        )?;
    }
    Ok(())
}

fn verify_private_runtime_bundle_binding(
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    role: Role,
    expected_count: usize,
    bundle: &PrivateRuntimeSignatureBundle,
) -> Result<(), CompilerError> {
    if bundle.chain_game_id != chain_game_id
        || bundle.graph_root != graph_root
        || bundle.role != role
        || bundle.len() != expected_count
    {
        return Err(CompilerError::LocalRuntimeInventoryMismatch {
            reason: "private runtime-signature bundle has the wrong graph or role binding",
        });
    }
    Ok(())
}

fn verify_local_lamport_keys(
    graph: &CompiledGraph,
    role: Role,
    secret_keys: &[LamportSecretKey],
) -> Result<(), CompilerError> {
    let expected = match role {
        Role::Alice => &graph.plan.expected_alice_lamport,
        Role::Bob => &graph.plan.expected_bob_lamport,
    };
    let public_keys = expected
        .iter()
        .map(|entry| {
            graph
                .lamport_public_key(entry.node_id, entry.purpose)
                .ok_or_else(|| mismatch("expected local Lamport public key is absent"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_ordered_lamport_keys(
        graph.manifest.chain_game_id,
        expected,
        &public_keys,
        secret_keys,
    )
}

pub(crate) fn verify_ordered_lamport_keys(
    chain_game_id: [u8; 32],
    expected: &[ExpectedLamportEntry],
    public_keys: &[&LamportPublicKey],
    secret_keys: &[LamportSecretKey],
) -> Result<(), CompilerError> {
    if secret_keys.len() != expected.len() {
        return Err(CompilerError::LocalRuntimeInventoryMismatch {
            reason: "local Lamport key count differs from the graph",
        });
    }
    if public_keys.len() != expected.len() {
        return Err(mismatch("expected local Lamport public-key count differs"));
    }
    for ((secret, expected), public) in secret_keys.iter().zip(expected).zip(public_keys) {
        let expected_context =
            bp52_lamport::KeyContext::new(chain_game_id, expected.node_id, expected.purpose);
        if public.context() != expected_context
            || secret.context() != expected_context
            || !secret.matches_public_key(public)
        {
            return Err(CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local Lamport key order, context, freshness, or public half differs",
            });
        }
    }
    Ok(())
}

pub(crate) fn verify_local_retained_preimages(
    role: Role,
    retained: &RetainedPreimages,
    deal: &bp52_chain_types::AcceptedDeal,
) -> Result<(), CompilerError> {
    let hashes = match role {
        Role::Alice => &deal.hashes_a,
        Role::Bob => &deal.hashes_b,
    };
    let preimages = (0..retained.len())
        .map(|slot| retained.get(slot))
        .collect::<Option<Vec<_>>>()
        .ok_or(CompilerError::LocalRuntimeInventoryMismatch {
            reason: "local retained preimage is missing",
        })?;
    verify_preimage_slices(hashes, &preimages)
}

fn verify_preimage_slices(
    hashes: &[[u8; 32]; bp52_protocol::N_SLOTS],
    preimages: &[&[u8]],
) -> Result<(), CompilerError> {
    if preimages.len() != bp52_protocol::N_SLOTS {
        return Err(CompilerError::LocalRuntimeInventoryMismatch {
            reason: "local retained-preimage count differs from the deal",
        });
    }
    for (preimage, expected_hash) in preimages.iter().zip(hashes) {
        if !(bp52_protocol::PREIMAGE_BASE_LEN..=bp52_protocol::PREIMAGE_MAX_LEN)
            .contains(&preimage.len())
            || <[u8; 32]>::from(Sha256::digest(*preimage)) != *expected_hash
        {
            return Err(CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local retained preimage length or hash differs from the deal",
            });
        }
    }
    Ok(())
}

fn usize_to_u32(value: usize) -> Result<u32, CompilerError> {
    u32::try_from(value).map_err(|_| mismatch("graph count exceeds u32"))
}

fn mismatch(reason: &'static str) -> CompilerError {
    CompilerError::CompiledGraphMismatch { reason }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
    use bp52_chain_bitcoin::{
        ActionProgram, CompiledTaprootState, FeeClass, FeePolicy, FixedFeePolicy, LeafProgram,
        RevealPattern, TransactionTemplate, outpoint_from_consensus_bytes,
    };
    use bp52_chain_types::{
        AcceptedDeal, Action, AmountState, AuthorizationPolicy, ChainGameDescriptor, EdgeKind,
        NodeKind, Phase, Role, SettlementReason, TerminalAccounting, TerminalOutcome, TimeoutKind,
        TimeoutSpec, child_node_id, logical_state_digest,
    };
    use bp52_lamport::{
        ExpectedLamportEntry, KeyContext, LamportError, LamportPublicBundle, LamportPublicKey,
        LamportPurpose, LamportRole, Score24, generate_key, sign_alice_score,
    };
    use sha2::{Digest, Sha256};

    use super::{
        LamportPublicMaterial, RuntimeSignatureKind, canonical_activation_template,
        materialize_prepared, preauthorized_roles, prepare_plan, runtime_signature_role_and_kind,
        verify_activation_contract, verify_global_lamport_hash_uniqueness,
        verify_materialized_graph, verify_ordered_lamport_keys, verify_preimage_slices,
        verify_private_runtime_bundle_binding, verify_runtime_signature_responses,
    };
    use crate::graph::compile_logical_graph_descriptor;
    use crate::{
        CompilerError, HEADS_UP_FIXED_LIMIT_V1_PROFILE, LogicalGraphPlan, PlannedEdge, PlannedNode,
        PlannedState, PlannedTerminal, PrivateRuntimeSignatureBundle,
        REFERENCE_ALICE_PREAUTHORIZATIONS, REFERENCE_ALICE_RUNTIME_SIGNATURES,
        REFERENCE_BOB_PREAUTHORIZATIONS, REFERENCE_BOB_RUNTIME_SIGNATURES,
        REFERENCE_TOTAL_NODE_COUNT, REFERENCE_TRANSACTION_COUNT, RuntimeSignatureRequest,
        RuntimeSignatureResponse, SignatureRequest, test_support::descriptor_fixture,
    };

    #[test]
    fn each_live_policy_has_exactly_one_counterparty_preauthorizer() {
        let roles = |policy| preauthorized_roles(policy).collect::<Vec<_>>();
        assert_eq!(
            roles(AuthorizationPolicy::RevealPreimages {
                revealer: Role::Alice,
            }),
            [Role::Bob]
        );
        assert_eq!(
            roles(AuthorizationPolicy::RevealPreimages {
                revealer: Role::Bob,
            }),
            [Role::Alice]
        );
        assert_eq!(roles(AuthorizationPolicy::AliceScore), [Role::Bob]);
        assert_eq!(roles(AuthorizationPolicy::BobLivePayout), [Role::Alice]);
        assert_eq!(
            roles(AuthorizationPolicy::BettingAction { actor: Role::Alice }),
            [Role::Bob]
        );
        assert_eq!(
            roles(AuthorizationPolicy::Timeout {
                beneficiary: Role::Alice,
            }),
            [Role::Bob]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn logical_amount_mutation_changes_state_output_and_descendant_txid()
    -> Result<(), Box<dyn Error>> {
        let descriptor = descriptor_fixture()?;
        let first_amounts = AmountState {
            alice_remaining: 900,
            bob_remaining: 800,
            pot: 300,
            fee_reserve_remaining: 100,
        };
        let mutated_amounts = AmountState {
            alice_remaining: 899,
            pot: 301,
            ..first_amounts
        };
        assert_eq!(first_amounts.game_value()?, mutated_amounts.game_value()?);
        let first_digest = logical_state_digest(&first_amounts)?;
        let mutated_digest = logical_state_digest(&mutated_amounts)?;
        assert_ne!(first_digest, mutated_digest);

        let parent_node_id = [0x31; 32];
        let edge = EdgeKind::Action(Action::Call);
        assert_ne!(
            child_node_id(&parent_node_id, edge, &first_digest),
            child_node_id(&parent_node_id, edge, &mutated_digest)
        );

        let program = LeafProgram::Action(ActionProgram::new(
            [0x32; 32],
            parent_node_id,
            Action::Check,
            [descriptor.alice_xonly_pk, descriptor.bob_xonly_pk],
        )?);
        let secp = Secp256k1::verification_only();
        let first_state =
            CompiledTaprootState::compile(&secp, first_digest, std::slice::from_ref(&program))?;
        let mutated_state =
            CompiledTaprootState::compile(&secp, mutated_digest, std::slice::from_ref(&program))?;
        assert_eq!(first_state.logical_state_digest(), first_digest);
        assert_eq!(mutated_state.logical_state_digest(), mutated_digest);
        assert_eq!(first_state.leaves().len(), 1);
        assert_eq!(mutated_state.leaves().len(), 1);
        assert_eq!(
            first_state.leaves()[0].predicate_id(),
            mutated_state.leaves()[0].predicate_id()
        );
        assert_ne!(first_state.script_pubkey(), mutated_state.script_pubkey());

        let origin_outpoint = OutPoint::new(Txid::from_byte_array([0x33; 32]), 0);
        let origin_output = TxOut {
            value: Amount::from_sat(3_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let first_output = TxOut {
            value: Amount::from_sat(first_amounts.game_value()?),
            script_pubkey: first_state.script_pubkey(),
        };
        let mutated_output = TxOut {
            value: Amount::from_sat(mutated_amounts.game_value()?),
            script_pubkey: mutated_state.script_pubkey(),
        };
        let first_template = TransactionTemplate::normal(
            Network::Regtest,
            origin_outpoint,
            origin_output.clone(),
            vec![first_output.clone()],
            900,
        )?;
        let mutated_template = TransactionTemplate::normal(
            Network::Regtest,
            origin_outpoint,
            origin_output,
            vec![mutated_output.clone()],
            900,
        )?;
        assert_eq!(first_template.transaction().output.len(), 1);
        assert_eq!(mutated_template.transaction().output.len(), 1);
        assert!(
            first_template.transaction().output[0]
                .script_pubkey
                .is_p2tr()
        );
        assert!(
            mutated_template.transaction().output[0]
                .script_pubkey
                .is_p2tr()
        );
        assert_ne!(first_template.txid(), mutated_template.txid());

        let descendant_output = TxOut {
            value: Amount::from_sat(1_200),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let first_descendant = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array(first_template.txid()), 0),
            first_output,
            vec![descendant_output.clone()],
            900,
        )?;
        let mutated_descendant = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array(mutated_template.txid()), 0),
            mutated_output,
            vec![descendant_output],
            900,
        )?;
        assert_ne!(first_descendant.txid(), mutated_descendant.txid());
        Ok(())
    }

    #[test]
    fn activation_contract_rejects_outpoint_output_parent_and_fee_substitution()
    -> Result<(), Box<dyn Error>> {
        let network = Network::Regtest;
        let origin_outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 7);
        let origin_output = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let root_output = TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x51]),
        };
        let valid =
            canonical_activation_template(network, origin_outpoint, &origin_output, &root_output)?;
        verify_activation_contract(
            network,
            origin_outpoint,
            &origin_output,
            &root_output,
            &valid,
        )?;

        let wrong_outpoint = TransactionTemplate::normal(
            network,
            OutPoint::new(Txid::from_byte_array([2; 32]), 7),
            origin_output.clone(),
            vec![root_output.clone()],
            1_000,
        )?;
        let substituted_parent = TransactionTemplate::normal(
            network,
            origin_outpoint,
            TxOut {
                value: Amount::from_sat(10_001),
                ..origin_output.clone()
            },
            vec![root_output.clone()],
            1_001,
        )?;
        let substituted_output = TransactionTemplate::normal(
            network,
            origin_outpoint,
            origin_output.clone(),
            vec![TxOut {
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x52]),
                ..root_output.clone()
            }],
            1_000,
        )?;
        let substituted_fee = TransactionTemplate::normal(
            network,
            origin_outpoint,
            origin_output.clone(),
            vec![TxOut {
                value: Amount::from_sat(8_999),
                ..root_output.clone()
            }],
            1_001,
        )?;

        for substituted in [
            wrong_outpoint,
            substituted_parent,
            substituted_output,
            substituted_fee,
        ] {
            assert!(matches!(
                verify_activation_contract(
                    network,
                    origin_outpoint,
                    &origin_output,
                    &root_output,
                    &substituted,
                ),
                Err(CompilerError::CompiledGraphMismatch { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn retained_signature_classes_are_exactly_payout_and_timeout() {
        assert_eq!(
            runtime_signature_role_and_kind(AuthorizationPolicy::BettingAction {
                actor: Role::Alice,
            }),
            None
        );
        assert_eq!(
            runtime_signature_role_and_kind(AuthorizationPolicy::BobLivePayout),
            Some((Role::Bob, RuntimeSignatureKind::BobTerminalPayout))
        );
        assert_eq!(
            runtime_signature_role_and_kind(AuthorizationPolicy::Timeout {
                beneficiary: Role::Alice,
            }),
            Some((Role::Alice, RuntimeSignatureKind::Timeout))
        );
        assert_eq!(
            runtime_signature_role_and_kind(AuthorizationPolicy::BothPresigned),
            None
        );
    }

    #[test]
    fn betting_authorization_exchanges_only_the_opponent_signature() {
        for actor in [Role::Alice, Role::Bob] {
            let policy = AuthorizationPolicy::BettingAction { actor };
            assert_eq!(
                preauthorized_roles(policy).collect::<Vec<_>>(),
                [actor.other()]
            );
            assert_eq!(runtime_signature_role_and_kind(policy), None);
        }
    }

    #[test]
    fn timeout_authorization_exchanges_opponent_and_retains_beneficiary_signature() {
        for beneficiary in [Role::Alice, Role::Bob] {
            let policy = AuthorizationPolicy::Timeout { beneficiary };
            assert_eq!(
                preauthorized_roles(policy).collect::<Vec<_>>(),
                [beneficiary.other()]
            );
            assert_eq!(
                runtime_signature_role_and_kind(policy),
                Some((beneficiary, RuntimeSignatureKind::Timeout))
            );
        }
    }

    #[test]
    fn public_hash_reuse_across_role_bundles_is_rejected() -> Result<(), LamportError> {
        let game = [1; 32];
        let alice_pairs: Vec<_> = (0_u8..24)
            .map(|index| [[index.wrapping_add(1); 32], [index.wrapping_add(25); 32]])
            .collect();
        let mut bob_pairs: Vec<_> = (0_u8..24)
            .map(|index| [[index.wrapping_add(49); 32], [index.wrapping_add(73); 32]])
            .collect();
        bob_pairs[0][0] = alice_pairs[0][0];
        let alice_key = LamportPublicKey::from_parts(
            KeyContext::new(game, [2; 32], LamportPurpose::AliceScore24Bit),
            alice_pairs,
        )?;
        let bob_key = LamportPublicKey::from_parts(
            KeyContext::new(game, [9; 32], LamportPurpose::BobScore24Bit),
            bob_pairs,
        )?;
        let alice = LamportPublicBundle::sign(game, LamportRole::Alice, &[alice_key], |_| [0; 64])?;
        let bob = LamportPublicBundle::sign(game, LamportRole::Bob, &[bob_key], |_| [0; 64])?;
        let material = LamportPublicMaterial::new(alice, bob);
        assert!(matches!(
            verify_global_lamport_hash_uniqueness(&material),
            Err(crate::CompilerError::Lamport(
                LamportError::DuplicatePublicHash
            ))
        ));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn small_plan_materializes_top_down_with_terminal_outputs() -> Result<(), Box<dyn Error>> {
        let secp = Secp256k1::new();
        let first = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32])?);
        let second = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[2; 32])?);
        let mut keys = [
            first.x_only_public_key().0.serialize(),
            second.x_only_public_key().0.serialize(),
        ];
        keys.sort_unstable();
        let policy = FixedFeePolicy::new(100, 1)?;
        let chain_game_id = [21; 32];
        let root_node_id = [22; 32];
        let timeout = TimeoutSpec::new(TimeoutKind::Reveal, 10, Role::Bob, Role::Alice)?;
        let root_amounts = AmountState {
            alice_remaining: 1_000,
            bob_remaining: 1_000,
            pot: 0,
            fee_reserve_remaining: 200,
        };
        let child_amounts = AmountState {
            fee_reserve_remaining: 100,
            ..root_amounts
        };
        let accounting = TerminalAccounting {
            alice_sat: 2_000,
            bob_sat: 0,
            fee_reserve_remaining: 100,
            reason: SettlementReason::Fold,
        };
        let normal_state = PlannedState::Terminal(PlannedTerminal {
            outcome: TerminalOutcome::Fold { folded: Role::Bob },
            amounts: child_amounts,
            accounting,
            alice_output_sat: 2_050,
            bob_output_sat: 50,
        });
        let timeout_state = PlannedState::Terminal(PlannedTerminal {
            outcome: TerminalOutcome::Timeout {
                kind: TimeoutKind::Reveal,
                defaulting: Role::Bob,
            },
            amounts: child_amounts,
            accounting: TerminalAccounting {
                reason: SettlementReason::RevealTimeout,
                ..accounting
            },
            alice_output_sat: 2_050,
            bob_output_sat: 50,
        });
        let normal_kind = EdgeKind::HoleCardReveal {
            revealer: Role::Bob,
        };
        let timeout_kind = EdgeKind::Timeout(TimeoutKind::Reveal);
        let normal_digest = logical_state_digest(&normal_state)?;
        let timeout_digest = logical_state_digest(&timeout_state)?;
        let normal_id = child_node_id(&root_node_id, normal_kind, &normal_digest);
        let timeout_id = child_node_id(&root_node_id, timeout_kind, &timeout_digest);
        let root_state = PlannedState::Reveal {
            phase: Phase::DealAlice,
            pattern: RevealPattern::DealAlice,
            amounts: root_amounts,
        };
        let plan = LogicalGraphPlan {
            chain_game_id,
            root_node_id,
            nodes: vec![
                PlannedNode {
                    node_id: root_node_id,
                    parent_node_id: None,
                    node_kind: NodeKind::Funded,
                    logical_state_digest: logical_state_digest(&root_state)?,
                    state: root_state,
                    depth: 0,
                    timeout: Some(timeout),
                    edges: vec![
                        PlannedEdge {
                            kind: normal_kind,
                            authorization: AuthorizationPolicy::RevealPreimages {
                                revealer: Role::Bob,
                            },
                            child_node_id: normal_id,
                            fee_class: FeeClass::Reveal,
                            fee_sat: 100,
                            timeout: None,
                        },
                        PlannedEdge {
                            kind: timeout_kind,
                            authorization: AuthorizationPolicy::Timeout {
                                beneficiary: Role::Alice,
                            },
                            child_node_id: timeout_id,
                            fee_class: FeeClass::Timeout,
                            fee_sat: 100,
                            timeout: Some(timeout),
                        },
                    ],
                },
                PlannedNode {
                    node_id: normal_id,
                    parent_node_id: Some(root_node_id),
                    node_kind: NodeKind::Terminal,
                    state: normal_state,
                    logical_state_digest: normal_digest,
                    depth: 1,
                    timeout: None,
                    edges: Vec::new(),
                },
                PlannedNode {
                    node_id: timeout_id,
                    parent_node_id: Some(root_node_id),
                    node_kind: NodeKind::Terminal,
                    state: timeout_state,
                    logical_state_digest: timeout_digest,
                    depth: 1,
                    timeout: None,
                    edges: Vec::new(),
                },
            ],
            expected_alice_lamport: Vec::new(),
            expected_bob_lamport: Vec::new(),
            maximum_path_fee_sat: 100,
            maximum_path_length: 1,
        };
        let empty_alice =
            LamportPublicBundle::sign(chain_game_id, LamportRole::Alice, &[], |_| [1; 64])?;
        let empty_bob =
            LamportPublicBundle::sign(chain_game_id, LamportRole::Bob, &[], |_| [2; 64])?;
        let mut hashes_a = [[0_u8; 32]; bp52_protocol::N_SLOTS];
        let mut hashes_b = [[0_u8; 32]; bp52_protocol::N_SLOTS];
        for (index, hash) in hashes_a.iter_mut().enumerate() {
            let byte = u8::try_from(index)?;
            *hash = [byte; 32];
        }
        for (index, hash) in hashes_b.iter_mut().enumerate() {
            let byte = u8::try_from(index)?;
            *hash = [byte + 20; 32];
        }
        let descriptor = ChainGameDescriptor {
            chain_protocol_version: 1,
            deal: AcceptedDeal {
                protocol_version: 1,
                game_id: [3; 32],
                attempt: 0,
                hashes_a,
                hashes_b,
                verification_transcript_root: [4; 32],
                signature_a: [5; 64],
                signature_b: [6; 64],
            },
            network_id: genesis_block(Network::Regtest).block_hash().to_byte_array(),
            funding_outpoint: [7; 36],
            deal_session_nonce: [8; 32],
            alice_xonly_pk: keys[0],
            bob_xonly_pk: keys[1],
            button: Role::Alice,
            unit_sat: 1,
            max_bets_per_street: bp52_chain_types::MAX_BETS_PER_STREET,
            alice_starting_stack_sat: 1_000,
            bob_starting_stack_sat: 1_000,
            fee_reserve_sat: 200,
            action_csv: 10,
            reveal_csv: 10,
            showdown_csv: 10,
            reveal_order: bp52_chain_types::RevealOrder {
                flop_first: Role::Alice,
                turn_first: Role::Bob,
                river_first: Role::Alice,
            },
            timeout_policy: bp52_chain_types::TimeoutSettlementPolicy::PotOnly,
            split_remainder_recipient: Role::Alice,
            fee_policy_id: policy.policy_id(),
            compiler_id: [9; 32],
        };
        let origin_output = TxOut {
            value: Amount::from_sat(2_300),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let public_material = LamportPublicMaterial::new(empty_alice, empty_bob);
        let oracle_prepared = prepare_plan(
            &descriptor,
            Network::Regtest,
            plan.clone(),
            public_material.clone(),
            origin_output.clone(),
            &policy,
        )?;
        let page_prepared = prepare_plan(
            &descriptor,
            Network::Regtest,
            plan.clone(),
            public_material.clone(),
            origin_output.clone(),
            &policy,
        )?;
        let root_page_prepared = prepare_plan(
            &descriptor,
            Network::Regtest,
            plan.clone(),
            public_material.clone(),
            origin_output.clone(),
            &policy,
        )?;
        let prepared = prepare_plan(
            &descriptor,
            Network::Regtest,
            plan,
            public_material,
            origin_output.clone(),
            &policy,
        )?;
        assert_eq!(prepared.origin_output(), &origin_output);
        assert_eq!(prepared.expected_root_state_output().value.to_sat(), 2_200);
        let activation = canonical_activation_template(
            prepared.network(),
            prepared.origin_outpoint(),
            prepared.origin_output(),
            prepared.expected_root_state_output(),
        )?;
        let activation_txid = Txid::from_byte_array(activation.txid());
        let oracle = crate::compile_graph_oracle(oracle_prepared, activation.clone())?;
        let page = crate::compile_graph_oracle_window(
            page_prepared,
            activation.clone(),
            &oracle.summary,
            timeout_id,
        )?;
        let root_page = crate::compile_graph_oracle_window(
            root_page_prepared,
            activation.clone(),
            &oracle.summary,
            root_node_id,
        )?;
        let graph = materialize_prepared(prepared, activation)?;
        verify_materialized_graph(&graph)?;
        assert_eq!(graph.records().len(), 3);
        assert_eq!(graph.edges().len(), 2);
        assert_eq!(graph.signature_requests(Role::Alice).len(), 1);
        assert_eq!(graph.signature_requests(Role::Bob).len(), 1);
        assert_eq!(graph.runtime_signature_requests(Role::Alice).len(), 1);
        assert!(graph.runtime_signature_requests(Role::Bob).is_empty());
        let runtime_timeout = graph.runtime_signature_requests(Role::Alice)[0];
        assert_eq!(runtime_timeout.kind, RuntimeSignatureKind::Timeout);
        let fixed_timeout = graph
            .signature_requests(Role::Bob)
            .iter()
            .find(|request| request.child_node_id == timeout_id)
            .ok_or_else(|| std::io::Error::other("timeout lacks Bob preauthorization request"))?;
        assert_eq!(runtime_timeout.request.parent_node_id, root_node_id);
        assert_eq!(runtime_timeout.request.child_node_id, timeout_id);
        assert_eq!(runtime_timeout.request.signer, Role::Alice);
        assert_eq!(fixed_timeout.signer, Role::Bob);
        assert_eq!(runtime_timeout.request.sighash, fixed_timeout.sighash);
        assert_eq!(graph.origin_output(), &origin_output);
        assert_eq!(graph.root_state_output().value.to_sat(), 2_200);
        assert_eq!(
            graph.root_state_outpoint(),
            OutPoint::new(activation_txid, 0)
        );
        assert_eq!(
            graph.activation_template().transaction().input[0].previous_output,
            outpoint_from_consensus_bytes(descriptor.funding_outpoint)?
        );
        assert_eq!(
            graph.activation_template().transaction().output,
            [graph.root_state_output().clone()]
        );
        assert_eq!(
            graph
                .transaction_template(normal_id)
                .ok_or_else(|| std::io::Error::other("missing normal template"))?
                .transaction()
                .input[0]
                .previous_output,
            graph.root_state_outpoint()
        );
        assert_ne!(graph.manifest().graph_root, [0; 32]);
        let summary = graph.summary()?;
        assert_eq!(oracle.summary, summary);
        assert_eq!(oracle.window.active_node_id(), root_node_id);
        assert_eq!(oracle.window.node_count(), 3);
        assert_eq!(oracle.window.transaction_count(), 2);
        assert_eq!(
            oracle.requests.preauthorizations(Role::Alice),
            graph.signature_requests(Role::Alice)
        );
        assert_eq!(
            oracle.requests.preauthorizations(Role::Bob),
            graph.signature_requests(Role::Bob)
        );
        assert_eq!(
            oracle.requests.runtime(Role::Alice),
            graph.runtime_signature_requests(Role::Alice)
        );
        assert_eq!(
            oracle.requests.runtime(Role::Bob),
            graph.runtime_signature_requests(Role::Bob)
        );
        assert_eq!(oracle.metrics.peak_compiled_states, 1);
        assert!(oracle.metrics.compiled_states <= 2 * graph.records().len());
        assert_eq!(oracle.metrics.record_hashes, 3);
        assert_eq!(oracle.metrics.retained_window_nodes, 3);
        assert_eq!(oracle.metrics.retained_window_templates, 2);
        assert_eq!(summary.manifest(), graph.manifest());
        assert_eq!(summary.root_node_id(), root_node_id);
        assert_eq!(summary.root_state_outpoint(), graph.root_state_outpoint());
        assert_eq!(summary.root_state_output(), graph.root_state_output());
        assert_eq!(summary.preauthorization_count(Role::Alice), 1);
        assert_eq!(summary.preauthorization_count(Role::Bob), 1);
        assert_eq!(summary.runtime_signature_count(Role::Alice), 1);
        assert_eq!(summary.runtime_signature_count(Role::Bob), 0);

        let root_window = graph.window(root_node_id)?;
        assert_eq!(root_window.summary(), &summary);
        assert_eq!(root_window.active_node_id(), root_node_id);
        assert_eq!(root_window.node(root_node_id), graph.node(root_node_id));
        assert_eq!(root_window.node(normal_id), graph.node(normal_id));
        assert_eq!(
            root_window.transaction_template(normal_id),
            graph.transaction_template(normal_id)
        );
        assert_eq!(
            root_window.tap_leaf(root_node_id, normal_id),
            graph.tap_leaf(root_node_id, normal_id)
        );
        assert_eq!(root_window.node_count(), 3);
        assert_eq!(root_window.transaction_count(), 2);

        // A terminal page retains just itself and its parent, rather than the
        // complete sibling branch or either outgoing transaction.
        let terminal_window = graph.window(normal_id)?;
        assert_eq!(terminal_window.node_count(), 2);
        assert_eq!(terminal_window.transaction_count(), 0);
        assert!(terminal_window.node(timeout_id).is_none());

        // Runtime paging follows only root -> selected child. The unrelated
        // sibling is neither compiled nor retained, and global bundle rank is
        // recovered by a logical-only ordering pass.
        let expected_page = graph.window(timeout_id)?;
        assert_eq!(page.window.active_node_id(), timeout_id);
        assert_eq!(page.window.node_count(), expected_page.node_count());
        assert_eq!(page.window.transaction_count(), 0);
        assert!(page.window.node(normal_id).is_none());
        assert_eq!(page.metrics.compiled_states, 1);
        assert_eq!(page.metrics.peak_compiled_states, 1);
        assert_eq!(page.metrics.record_hashes, 0);
        assert_eq!(page.metrics.setup_signature_requests, 0);
        assert!(page.metrics.compiled_states <= 2);
        assert_eq!(
            root_page
                .window
                .preauthorization_request(root_node_id, timeout_id, Role::Bob),
            graph.window(root_node_id)?.preauthorization_request(
                root_node_id,
                timeout_id,
                Role::Bob
            )
        );
        Ok(())
    }

    #[test]
    fn runtime_signature_responses_require_exact_order_and_valid_signatures()
    -> Result<(), Box<dyn Error>> {
        let descriptor = descriptor_fixture()?;
        let role = Role::Bob;
        let secp = Secp256k1::new();
        let signer = keypair_for_identity(&secp, *descriptor.identity_key(role))?;
        let wrong_signer = keypair_for_identity(&secp, *descriptor.identity_key(role.other()))?;
        let expected = [
            RuntimeSignatureRequest {
                request: SignatureRequest {
                    parent_node_id: [1; 32],
                    child_node_id: [2; 32],
                    signer: role,
                    sighash: [3; 32],
                },
                kind: RuntimeSignatureKind::BobTerminalPayout,
            },
            RuntimeSignatureRequest {
                request: SignatureRequest {
                    parent_node_id: [4; 32],
                    child_node_id: [5; 32],
                    signer: role,
                    sighash: [6; 32],
                },
                kind: RuntimeSignatureKind::Timeout,
            },
        ];

        let valid = runtime_responses(&secp, &signer, &expected)?;
        verify_runtime_signature_responses(&descriptor, role, &expected, &valid)?;

        let missing = runtime_responses(&secp, &signer, &expected[..1])?;
        assert!(matches!(
            verify_runtime_signature_responses(&descriptor, role, &expected, &missing),
            Err(CompilerError::RuntimeSignatureBundleMembershipMismatch)
        ));

        let mut extra_expected = expected.to_vec();
        extra_expected.push(RuntimeSignatureRequest {
            request: SignatureRequest {
                parent_node_id: [7; 32],
                child_node_id: [8; 32],
                signer: role,
                sighash: [9; 32],
            },
            kind: RuntimeSignatureKind::Timeout,
        });
        let extra = runtime_responses(&secp, &signer, &extra_expected)?;
        assert!(matches!(
            verify_runtime_signature_responses(&descriptor, role, &expected, &extra),
            Err(CompilerError::RuntimeSignatureBundleMembershipMismatch)
        ));

        let reordered_requests = [expected[1], expected[0]];
        let reordered = runtime_responses(&secp, &signer, &reordered_requests)?;
        assert!(matches!(
            verify_runtime_signature_responses(&descriptor, role, &expected, &reordered),
            Err(CompilerError::RuntimeSignatureBundleMembershipMismatch)
        ));

        let bad_signature = runtime_responses(&secp, &wrong_signer, &expected)?;
        assert!(matches!(
            verify_runtime_signature_responses(&descriptor, role, &expected, &bad_signature),
            Err(CompilerError::Bitcoin(_))
        ));
        let bundle = PrivateRuntimeSignatureBundle::verified([10; 32], [11; 32], role, valid);
        assert!(bundle.signature(expected[0]).is_some());
        assert!(bundle.signature(expected[1]).is_some());
        Ok(())
    }

    #[test]
    fn private_runtime_bundle_binding_rejects_graph_role_and_count_substitution() {
        let game = [21; 32];
        let root = [22; 32];
        let role = Role::Alice;
        let valid = PrivateRuntimeSignatureBundle::verified(game, root, role, Vec::new());
        assert!(verify_private_runtime_bundle_binding(game, root, role, 0, &valid).is_ok());

        let wrong_graph = PrivateRuntimeSignatureBundle::verified(game, [23; 32], role, Vec::new());
        assert!(matches!(
            verify_private_runtime_bundle_binding(game, root, role, 0, &wrong_graph),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        assert!(matches!(
            verify_private_runtime_bundle_binding(game, root, Role::Bob, 0, &valid),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        assert!(matches!(
            verify_private_runtime_bundle_binding(game, root, role, 1, &valid),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
    }

    #[test]
    fn local_lamport_inventory_rejects_missing_extra_reordered_wrong_and_used_keys()
    -> Result<(), Box<dyn Error>> {
        let game = [31; 32];
        let expected = [
            ExpectedLamportEntry::new([32; 32], LamportPurpose::AliceScore24Bit),
            ExpectedLamportEntry::new([33; 32], LamportPurpose::AliceScore24Bit),
        ];
        let mut rng = bitcoin::secp256k1::rand::thread_rng();
        let (first_secret, first_public) = generate_key(
            &mut rng,
            KeyContext::new(game, expected[0].node_id, expected[0].purpose),
        )?;
        let (second_secret, second_public) = generate_key(
            &mut rng,
            KeyContext::new(game, expected[1].node_id, expected[1].purpose),
        )?;
        let public = [&first_public, &second_public];
        let mut secret = vec![first_secret, second_secret];
        verify_ordered_lamport_keys(game, &expected, &public, &secret)?;

        assert!(matches!(
            verify_ordered_lamport_keys(game, &expected, &public, &secret[..1]),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        let (extra_secret, _) = generate_key(
            &mut rng,
            KeyContext::new(game, [34; 32], LamportPurpose::AliceScore24Bit),
        )?;
        secret.push(extra_secret);
        assert!(matches!(
            verify_ordered_lamport_keys(game, &expected, &public, &secret),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        drop(secret.pop());

        secret.swap(0, 1);
        assert!(matches!(
            verify_ordered_lamport_keys(game, &expected, &public, &secret),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        secret.swap(0, 1);

        let (wrong_secret, _) = generate_key(
            &mut rng,
            KeyContext::new(game, expected[0].node_id, expected[0].purpose),
        )?;
        let displaced = core::mem::replace(&mut secret[0], wrong_secret);
        assert!(matches!(
            verify_ordered_lamport_keys(game, &expected, &public, &secret),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        secret[0] = displaced;

        sign_alice_score(&mut secret[0], Score24::new(1)?)?;
        assert!(matches!(
            verify_ordered_lamport_keys(game, &expected, &public, &secret),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn local_preimages_require_exact_role_hashes_count_and_lengths() -> Result<(), Box<dyn Error>> {
        let preimages: [Vec<u8>; bp52_protocol::N_SLOTS] = core::array::from_fn(|slot| {
            vec![u8::try_from(slot).unwrap_or(0).wrapping_add(1); bp52_protocol::PREIMAGE_BASE_LEN]
        });
        let hashes_a: [[u8; 32]; bp52_protocol::N_SLOTS] =
            core::array::from_fn(|slot| Sha256::digest(&preimages[slot]).into());
        let hashes_b: [[u8; 32]; bp52_protocol::N_SLOTS] =
            core::array::from_fn(|slot| [u8::try_from(slot).unwrap_or(0).wrapping_add(70); 32]);
        let refs: Vec<&[u8]> = preimages.iter().map(Vec::as_slice).collect();
        verify_preimage_slices(&hashes_a, &refs)?;
        assert!(matches!(
            verify_preimage_slices(&hashes_a, &refs[..bp52_protocol::N_SLOTS - 1]),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        let mut extra = refs.clone();
        extra.push(refs[0]);
        assert!(matches!(
            verify_preimage_slices(&hashes_a, &extra),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        assert!(matches!(
            verify_preimage_slices(&hashes_b, &refs),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));

        let short = [0_u8; bp52_protocol::PREIMAGE_BASE_LEN - 1];
        let mut wrong_length = refs.clone();
        wrong_length[0] = &short;
        assert!(matches!(
            verify_preimage_slices(&hashes_a, &wrong_length),
            Err(CompilerError::LocalRuntimeInventoryMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    #[ignore = "stream-compiles all 56,132 exact 100-BB profile records"]
    fn full_reference_oracle_has_bounded_compiled_and_retained_state() -> Result<(), Box<dyn Error>>
    {
        let profile = HEADS_UP_FIXED_LIMIT_V1_PROFILE;
        let policy = profile.fee_policy()?;
        let mut descriptor = descriptor_fixture()?;
        descriptor.chain_protocol_version = profile.chain_protocol_version;
        descriptor.unit_sat = profile.unit_sat;
        descriptor.max_bets_per_street = profile.max_bets_per_street;
        descriptor.alice_starting_stack_sat = profile.stack_per_player_sat;
        descriptor.bob_starting_stack_sat = profile.stack_per_player_sat;
        descriptor.fee_reserve_sat = profile.fee_reserve_sat;
        descriptor.action_csv = profile.csv_blocks;
        descriptor.reveal_csv = profile.csv_blocks;
        descriptor.showdown_csv = profile.csv_blocks;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = profile.compiler_id();
        profile.validate_descriptor(&descriptor)?;
        let plan = compile_logical_graph_descriptor(&descriptor, &descriptor.deal, &policy)?;
        let alice = deterministic_bundle(
            plan.chain_game_id,
            LamportRole::Alice,
            &plan.expected_alice_lamport,
        )?;
        let bob = deterministic_bundle(
            plan.chain_game_id,
            LamportRole::Bob,
            &plan.expected_bob_lamport,
        )?;
        let material = LamportPublicMaterial::new(alice, bob);
        verify_global_lamport_hash_uniqueness(&material)?;
        let root_value = plan
            .nodes
            .first()
            .ok_or_else(|| std::io::Error::other("empty reference plan"))?
            .state
            .amounts()
            .game_value()?;
        let prepared = prepare_plan(
            &descriptor,
            Network::Regtest,
            plan,
            material,
            TxOut {
                value: Amount::from_sat(root_value + profile.activation_fee_sat),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            &policy,
        )?;
        let activation = canonical_activation_template(
            prepared.network(),
            prepared.origin_outpoint(),
            prepared.origin_output(),
            prepared.expected_root_state_output(),
        )?;
        let oracle = crate::compile_graph_oracle(prepared, activation)?;
        profile.validate_graph_summary(&oracle.summary)?;
        assert_eq!(
            usize::try_from(oracle.summary.manifest().node_count)?,
            REFERENCE_TOTAL_NODE_COUNT
        );
        assert_eq!(
            usize::try_from(oracle.summary.manifest().transaction_count)?,
            REFERENCE_TRANSACTION_COUNT
        );
        assert_eq!(
            oracle.requests.preauthorizations(Role::Alice).len(),
            REFERENCE_ALICE_PREAUTHORIZATIONS
        );
        assert_eq!(
            oracle.requests.preauthorizations(Role::Bob).len(),
            REFERENCE_BOB_PREAUTHORIZATIONS
        );
        assert_eq!(
            oracle.requests.runtime(Role::Alice).len(),
            REFERENCE_ALICE_RUNTIME_SIGNATURES
        );
        assert_eq!(
            oracle.requests.runtime(Role::Bob).len(),
            REFERENCE_BOB_RUNTIME_SIGNATURES
        );
        assert!(oracle.metrics.peak_compiled_states <= 2);
        assert_eq!(oracle.metrics.record_hashes, REFERENCE_TOTAL_NODE_COUNT);
        assert!(oracle.metrics.compiled_states <= 2 * REFERENCE_TOTAL_NODE_COUNT);
        assert!(oracle.metrics.retained_window_nodes <= 3);
        assert!(oracle.metrics.retained_window_templates <= 2);
        assert!(
            oracle.metrics.retained_window_nodes * 1_000
                < usize::try_from(oracle.summary.manifest().node_count)?
        );
        Ok(())
    }

    fn runtime_responses(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        signer: &Keypair,
        requests: &[RuntimeSignatureRequest],
    ) -> Result<Vec<RuntimeSignatureResponse>, CompilerError> {
        requests
            .iter()
            .map(|request| {
                let message = Message::from_digest(request.request.sighash);
                RuntimeSignatureResponse::new(
                    *request,
                    secp.sign_schnorr_no_aux_rand(&message, signer).serialize(),
                )
            })
            .collect()
    }

    fn keypair_for_identity(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        identity: [u8; 32],
    ) -> Result<Keypair, bitcoin::secp256k1::Error> {
        for number in [1_u8, 2] {
            let mut secret = [0_u8; 32];
            secret[31] = number;
            let candidate = Keypair::from_seckey_slice(secp, &secret)?;
            if candidate.x_only_public_key().0.serialize() == identity {
                return Ok(candidate);
            }
        }
        Keypair::from_seckey_slice(secp, &[1; 32])
    }

    fn deterministic_bundle(
        chain_game_id: [u8; 32],
        role: LamportRole,
        expected: &[ExpectedLamportEntry],
    ) -> Result<LamportPublicBundle, LamportError> {
        let mut keys = Vec::with_capacity(expected.len());
        for entry in expected {
            let mut pairs = Vec::with_capacity(usize::from(entry.purpose.bit_width()));
            for bit in 0..entry.purpose.bit_width() {
                let mut pair = [[0; 32]; 2];
                for choice in 0_u8..=1 {
                    let mut hash = Sha256::new();
                    hash.update(b"BP52/materializer-test-public-hash/v1");
                    hash.update(chain_game_id);
                    hash.update([role as u8, entry.purpose as u8, bit, choice]);
                    hash.update(entry.node_id);
                    pair[usize::from(choice)] = hash.finalize().into();
                }
                pairs.push(pair);
            }
            keys.push(LamportPublicKey::from_parts(
                KeyContext::new(chain_game_id, entry.node_id, entry.purpose),
                pairs,
            )?);
        }
        LamportPublicBundle::sign(chain_game_id, role, &keys, |_| [0; 64])
    }
}
