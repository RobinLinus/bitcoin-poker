#![forbid(unsafe_code)]
#![doc = "Deterministic literal-tree compiler for BP52-CHAIN-v1."]

/// Pure local betting-tree expansion.
pub mod betting;
mod error;
/// Authenticated commit-then-open graph and signature-bundle exchange.
pub mod exchange;
/// Complete deterministic semantic graph planning.
pub mod graph;
/// Canonical node-record Merkle commitments.
pub mod manifest;
/// Concrete Taproot states and top-down Bitcoin transaction materialization.
pub mod materialize;
/// Compact whole-graph facts and bounded active-node projections.
pub mod oracle;
/// Audited small-value deployment profiles.
pub mod profile;
/// Funding readiness report and opaque authorization gate.
pub mod readiness;
/// Compact identity-signed CHAIN-to-GAME setup and active-state receipts.
pub mod receipt;
/// Canonical reveal-phase construction.
pub mod reveals;
/// Checked terminal and showdown planning.
pub mod showdown;

#[cfg(test)]
mod test_support;

pub use betting::{
    BettingActionEdge, BettingTree, LocalBettingCounts, expand_postflop, expand_preflop,
};
pub use error::CompilerError;
pub use exchange::{
    AgreedGraphRoot, CommitmentPurpose, GraphRootOpening, MAX_PREAUTHORIZATIONS_PER_ROLE,
    PREAUTHORIZATION_RECEIPT_BYTES, PREAUTHORIZATION_RECEIPT_VERSION, Preauthorization,
    PreauthorizationBundle, PreauthorizationVerifiedReceipt, PrivateRuntimeSignatureBundle,
    RuntimeSignatureRequest, RuntimeSignatureResponse, SignatureBundleOpening, SignatureRequest,
    SignedCommitment, commit_graph_root, commit_signature_bundle,
    issue_externally_verified_preauthorization_receipt,
    issue_locally_generated_preauthorization_receipt, issue_preauthorization_verified_receipt,
    signature_bundle_opening_digest, signed_commitment_digest, verify_graph_root_opening,
    verify_matching_graph_roots, verify_preauthorization_verified_receipt, verify_signature_bundle,
    verify_signature_bundle_binding,
};
pub use graph::{
    LogicalGraphPlan, PlannedEdge, PlannedNode, PlannedState, PlannedTerminal,
    REFERENCE_ALICE_LAMPORT_ENTRIES, REFERENCE_BOB_LAMPORT_ENTRIES, compile_logical_graph,
    reference_compiler_id,
};
pub use manifest::{
    GraphManifest, REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT,
    REFERENCE_TRANSACTION_COUNT, REFERENCE_WITH_ACTIVATION_TRANSACTION_COUNT,
    REFERENCE_WITH_FUNDING_TRANSACTION_COUNT, compute_graph_root, verify_tree_links,
};
pub use materialize::{
    CompiledGraph, GraphVerificationReport, LamportPublicMaterial, PreparedChainGraph,
    REFERENCE_ALICE_PREAUTHORIZATIONS, REFERENCE_ALICE_RUNTIME_SIGNATURES,
    REFERENCE_BOB_PREAUTHORIZATIONS, REFERENCE_BOB_RUNTIME_SIGNATURES, compile_chain_graph,
    prepare_chain_graph, prepare_chain_graph_from_plan, verify_compiled_graph,
};
pub use oracle::{
    CompiledGraphSummary, GraphOracleMetrics, GraphOraclePage, GraphOracleSetup,
    MaterializedGraphWindow, OracleSignatureRequests, compile_graph_oracle,
    compile_graph_oracle_window, verify_oracle_local_inventory,
};
pub use profile::{
    HEADS_UP_FIXED_LIMIT_V1_PROFILE, HeadsUpFixedLimitV1Inventory, HeadsUpFixedLimitV1Profile,
    HeadsUpFixedLimitV1Session, HeadsUpInventory, HeadsUpProfile, HeadsUpSession,
};
pub use readiness::{
    FundingReadinessReport, FundingReady, LocalRuntimeInventorySummary, ReadinessBlocker,
    RuntimeSignatureIntent, RuntimeSignatureKind, TimeoutRule, VerifiedLocalRuntimeInventory,
    authorize_funding,
};
pub use receipt::{
    ConfirmedStateReceipt, GraphPreparedReceipt, PublicEdgeReceipt, PublicStateBalances,
    RuntimeAuthorizationReceipt, issue_confirmed_state_receipt, issue_graph_prepared_receipt,
    issue_runtime_authorization_receipt, verify_confirmed_state_receipt,
    verify_graph_prepared_receipt, verify_runtime_authorization_receipt,
};
pub use reveals::{RevealStep, community_reveal_steps, hole_reveal_steps};
pub use showdown::{
    ShowdownBranch, alice_showdown_timeout, bob_showdown_timeout, fold_accounting,
    showdown_branches, timeout_accounting,
};
