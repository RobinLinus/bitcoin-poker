//! Runtime errors.

use bp52_chain_types::{EdgeKind, NodeId, Role};

/// Fail-closed runtime validation, witness, signing, and monitoring errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// A logical graph record was invalid.
    #[error(transparent)]
    Chain(#[from] bp52_chain_types::ChainError),
    /// A Bitcoin template, predicate, or signature was invalid.
    #[error(transparent)]
    Bitcoin(#[from] bp52_chain_bitcoin::BitcoinBackendError),
    /// A Lamport key, message, signature, or lifecycle transition was invalid.
    #[error(transparent)]
    Lamport(#[from] bp52_lamport::LamportError),
    /// A poker score or subset was invalid.
    #[error(transparent)]
    Poker(#[from] bp52_poker::PokerError),
    /// The graph does not contain the requested node.
    #[error("graph has no node {node_id:?}")]
    NodeNotFound {
        /// Missing node identifier.
        node_id: NodeId,
    },
    /// No exact child edge has the requested semantic kind.
    #[error("node {node_id:?} has no edge {kind:?}")]
    EdgeNotFound {
        /// Parent node identifier.
        node_id: NodeId,
        /// Requested edge kind.
        kind: EdgeKind,
    },
    /// More than one child claims the same semantic edge kind.
    #[error("node {node_id:?} has more than one edge {kind:?}")]
    AmbiguousEdge {
        /// Parent node identifier.
        node_id: NodeId,
        /// Duplicated edge kind.
        kind: EdgeKind,
    },
    /// A backend omitted an edge explicitly listed by its parent node.
    #[error("graph omitted edge {parent_node_id:?} -> {child_node_id:?}")]
    MissingListedEdge {
        /// Parent node identifier.
        parent_node_id: NodeId,
        /// Child node identifier.
        child_node_id: NodeId,
    },
    /// A node/edge/template/predicate association was inconsistent.
    #[error("inconsistent graph association: {reason}")]
    InconsistentGraph {
        /// Stable failure reason.
        reason: &'static str,
    },
    /// An edge has an authorization policy incompatible with its kind.
    #[error("wrong authorization policy for runtime edge")]
    WrongAuthorization,
    /// A one-time key was asked to authorize a different message after an
    /// earlier issuance at the same active node.
    #[error("conflicting one-time authorization requested at node {node_id:?}; runtime halted")]
    ConflictingOtsAuthorization {
        /// Node whose one-time authorization would be reused.
        node_id: NodeId,
    },
    /// A live Bitcoin signer was asked to authorize a different action after
    /// the runtime had already issued an action witness at the active node.
    #[error("conflicting betting action requested at node {node_id:?}; runtime halted")]
    ConflictingActionAuthorization {
        /// Node whose first selected action remains authoritative.
        node_id: NodeId,
    },
    /// Runtime material belongs to a different compiled chain game.
    #[error("runtime material belongs to a different chain game")]
    WrongChainGame,
    /// A witness builder was asked to act on a node other than the monitor's
    /// confirmed live state.
    #[error("node {actual:?} is not the confirmed active node {expected:?}")]
    InactiveNode {
        /// Node authorized by the monitor capability.
        expected: NodeId,
        /// Node requested by the caller or witness.
        actual: NodeId,
    },
    /// No confirmed, nonterminal state is currently available for witness
    /// construction.
    #[error("no confirmed active protocol node is available")]
    NoConfirmedActiveNode,
    /// Timeout witnesses require proof that the exact graph-committed CSV
    /// delay has elapsed, not merely proof that their parent is active.
    #[error("timeout witness attachment requires a mature-timeout capability")]
    TimeoutCapabilityRequired,
    /// Runtime material belongs to a different accepted deal.
    #[error("runtime material belongs to a different accepted deal")]
    WrongAcceptedDeal,
    /// A public or secret preimage was unavailable.
    #[error("missing {role:?} preimage for slot {slot}")]
    MissingPreimage {
        /// Contributor whose preimage was required.
        role: Role,
        /// Fixed deal slot.
        slot: u8,
    },
    /// A slot was outside the fixed nine-slot mapping.
    #[error("invalid deal slot {slot}")]
    InvalidSlot {
        /// Rejected slot.
        slot: u8,
    },
    /// A preimage length was outside the consensus range.
    #[error("preimage for {role:?} slot {slot} has invalid length {actual}")]
    InvalidPreimageLength {
        /// Contributor whose preimage was rejected.
        role: Role,
        /// Fixed deal slot.
        slot: u8,
        /// Actual byte length.
        actual: usize,
    },
    /// A preimage did not open the accepted-deal hash.
    #[error("preimage for {role:?} slot {slot} does not match the accepted deal")]
    WrongPreimage {
        /// Contributor whose preimage was rejected.
        role: Role,
        /// Fixed deal slot.
        slot: u8,
    },
    /// New public data contradicted a value already observed on chain.
    #[error("conflicting public preimage for {role:?} slot {slot}")]
    ConflictingPreimage {
        /// Contributor whose entries conflicted.
        role: Role,
        /// Fixed deal slot.
        slot: u8,
    },
    /// A confirmed showdown exposed a score certificate that conflicts with
    /// the certificate already retained for this execution path.
    #[error("conflicting Alice score certificate for node {node_id:?}")]
    ConflictingAliceScoreCertificate {
        /// Alice-showdown node associated with the observed certificate.
        node_id: NodeId,
    },
    /// The confirmed Alice-showdown parent did not leave its public score
    /// certificate in the execution-path store.
    #[error("missing Alice score certificate for node {node_id:?}")]
    MissingAliceScoreCertificate {
        /// Alice-showdown node whose certificate is required for Bob's payout.
        node_id: NodeId,
    },
    /// Strict witness decoding rejected malformed or noncanonical bytes.
    #[error("invalid runtime witness encoding: {reason}")]
    InvalidWitnessEncoding {
        /// Stable codec failure reason.
        reason: &'static str,
    },
    /// A strict encoded witness exceeded the v1 bound.
    #[error("runtime witness encoding has {actual} bytes, maximum {maximum}")]
    WitnessTooLarge {
        /// Actual encoded length.
        actual: usize,
        /// Maximum permitted encoded length.
        maximum: usize,
    },
    /// A preauthorization required by the graph was absent.
    #[error("missing {role:?} preauthorization signature")]
    MissingPreauthorization {
        /// Required signer.
        role: Role,
    },
    /// An external Bitcoin signer failed closed.
    #[error("bitcoin signer failed: {0}")]
    Signer(#[from] crate::SignerError),
    /// An external broadcaster failed closed.
    #[error("broadcast failed: {0}")]
    Broadcast(#[from] crate::BroadcastError),
    /// A broadcaster returned a txid different from the transaction sent.
    #[error("broadcaster returned a mismatched transaction id")]
    BroadcastTxidMismatch,
    /// The connected Bitcoin node's exact chain-network identifier differs
    /// from the compiled descriptor network identifier.
    #[error("broadcaster is connected to a different Bitcoin network")]
    BroadcastNetworkMismatch,
    /// Mainnet broadcast or runtime execution is intentionally disabled.
    #[error("mainnet execution is disabled pending the production-readiness gates")]
    MainnetDisabled,
    /// A timeout was requested before its exact CSV maturity height.
    #[error("timeout is immature at height {current_height}; matures at {matures_at}")]
    TimeoutImmature {
        /// Current observed chain height.
        current_height: u32,
        /// First mature height.
        matures_at: u32,
    },
    /// The root state output has not reached the configured confirmation depth.
    #[error("funding has {actual} confirmations; {required} required")]
    FundingConfirmationImmature {
        /// Observed confirmation count, including the block containing funding.
        actual: u32,
        /// Locally configured minimum confirmation depth.
        required: u16,
    },
    /// Height arithmetic overflowed.
    #[error("block-height arithmetic overflow")]
    HeightOverflow,
    /// A confirmation did not extend the currently tracked state.
    #[error("confirmation does not spend the active protocol outpoint")]
    UnexpectedConfirmation,
    /// The chain tip moved below a height whose state has already been acted on.
    #[error("chain reorganization detected; runtime halted for explicit recovery")]
    ReorgDetected,
    /// Secret erasure failed and runtime operation halted.
    #[error("secret erasure failed: {reason}")]
    SecretErasure {
        /// Redacted lifecycle failure reason.
        reason: &'static str,
    },
}
