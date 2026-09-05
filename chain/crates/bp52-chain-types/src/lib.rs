#![forbid(unsafe_code)]
#![doc = "Canonical foundational types for BP52-CHAIN."]

/// Canonical codecs and deterministic identifier derivation.
pub mod codec;
/// Signed chain-game descriptors and their validation.
pub mod descriptor;
/// Logical transaction-tree nodes and edges.
pub mod node;
/// Terminal outcomes and checked settlement accounting.
pub mod outcome;
/// Deal-independent finite-poker rules.
pub mod rules;
/// Fixed-limit betting and amount state.
pub mod state;
pub use rules::PokerRules;

use bp52_codec::CodecError;

pub use codec::{
    CHAIN_DESCRIPTOR_TAG, CHAIN_GAME_TAG, CHAIN_NODE_TAG, CHAIN_ROOT_TAG, chain_game_id,
    child_node_id, child_node_id_from_code, decode_chain_descriptor, descriptor_signature_digest,
    logical_state_digest, root_node_id, tagged_sha256,
};
pub use descriptor::{
    AcceptedDeal, ChainGameDescriptor, RevealOrder, Role, SignedChainGameDescriptor,
    TimeoutSettlementPolicy, VerifiedChainDescriptor, validate_chain_descriptor,
    verify_signed_chain_descriptor,
};
pub use node::{
    AuthorizationPolicy, EdgeKind, LogicalEdge, LogicalNodeRecord, LogicalOutput,
    LogicalTransaction, NodeId, NodeKind, Phase, PredicateId, StateDigest,
};
pub use outcome::{
    SettlementReason, ShowdownOutcome, TerminalAccounting, TerminalOutcome, terminal_accounting,
};
pub use state::{
    Action, AmountState, BettingState, BettingTransition, Street, TimeoutKind, TimeoutSpec,
};

/// Fixed chain protocol wire version.
pub const CHAIN_PROTOCOL_VERSION: u16 = 4;
/// Largest descriptor-selectable number of bets, including the opening bet, per street.
pub const MAX_BETS_PER_STREET: u8 = 4;
/// Minimum starting-stack multiplier relative to the small-blind unit.
///
/// Two units are required so either player can post a complete big blind.
/// Later fixed-limit wagers may be capped by the effective stack.
pub const MIN_STARTING_STACK_UNITS: u64 = 2;
/// Longest post-activation gameplay path in the deep-stack compiler fixture.
pub const MAX_EXECUTED_PATH: u16 = 33;

/// Validation, accounting, and canonical logical-record failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// Canonical encoding or decoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The chain descriptor selected an unsupported protocol version.
    #[error("unsupported chain protocol version {actual}")]
    WrongChainProtocolVersion {
        /// Version found in the descriptor.
        actual: u16,
    },
    /// The embedded deal selected an unsupported protocol version.
    #[error("unsupported deal protocol version {actual}")]
    WrongDealProtocolVersion {
        /// Version found in the accepted deal.
        actual: u16,
    },
    /// One serialized BIP340 identity key was invalid.
    #[error("invalid {role:?} x-only identity key")]
    InvalidIdentityKey {
        /// Role whose key failed parsing.
        role: Role,
    },
    /// Alice and Bob were not the canonical lexicographic identity ordering.
    #[error("identity keys are not in canonical Alice/Bob order")]
    NonCanonicalIdentityOrder,
    /// An accepted-deal or descriptor signature failed verification.
    #[error("invalid {role:?} {object} signature")]
    InvalidSignature {
        /// Role whose signature failed.
        role: Role,
        /// Signed object name.
        object: &'static str,
    },
    /// The accepted deal was rebound to a different funding/session context.
    #[error("accepted-deal game identifier does not match descriptor context")]
    DealGameIdMismatch,
    /// The compiler was given an accepted deal other than the descriptor's.
    #[error("compiler deal does not exactly match descriptor deal")]
    DealMismatch,
    /// The concrete fee policy does not match the descriptor commitment.
    #[error("fee policy identifier does not match descriptor")]
    FeePolicyMismatch,
    /// The running compiler profile does not match the descriptor commitment.
    #[error("compiler identifier does not match descriptor")]
    CompilerIdMismatch,
    /// Lamport public material was incomplete, duplicated, or incorrectly bound.
    #[error("invalid Lamport public material")]
    LamportMaterialInvalid,
    /// A concrete Bitcoin transaction or script template failed validation.
    #[error("invalid Bitcoin transaction template")]
    BitcoinTemplateInvalid,
    /// Independent graph-root computation disagreed with the supplied root.
    #[error("compiled graph root mismatch")]
    GraphRootMismatch,
    /// Two accepted-deal hash locks were equal.
    #[error("duplicate accepted-deal hashes at indices {first} and {second}")]
    DuplicateDealHash {
        /// First global Alice-then-Bob hash index.
        first: usize,
        /// Second global Alice-then-Bob hash index.
        second: usize,
    },
    /// The fixed-limit unit was zero.
    #[error("small-blind unit must be nonzero")]
    ZeroUnit,
    /// The descriptor selected no betting or exceeded the supported fixed-limit cap.
    #[error("bets-per-street cap {actual} is outside 1..={maximum}")]
    UnsupportedBetsPerStreet {
        /// Descriptor-selected total wager cap.
        actual: u8,
        /// Largest cap supported by this protocol version.
        maximum: u8,
    },
    /// The descriptor did not reserve any fee value.
    #[error("fee reserve must be nonzero")]
    ZeroFeeReserve,
    /// A starting stack cannot cover a complete big blind.
    #[error("{role:?} starting stack {actual} is below required minimum {required}")]
    StackTooSmall {
        /// Underfunded role.
        role: Role,
        /// Minimum required satoshis.
        required: u64,
        /// Configured satoshis.
        actual: u64,
    },
    /// A relative timeout was configured as zero.
    #[error("{kind:?} relative timeout must be nonzero")]
    ZeroTimeout {
        /// Timeout class with the invalid value.
        kind: TimeoutKind,
    },
    /// The descriptor selected a settlement policy outside the v1 profile.
    #[error("timeout settlement policy {actual:?} is unsupported by BP52-CHAIN-v1")]
    UnsupportedTimeoutSettlementPolicy {
        /// Policy rejected by the reference v1 profile.
        actual: TimeoutSettlementPolicy,
    },
    /// A required domain identifier was all zero.
    #[error("{field} must not be the all-zero identifier")]
    ZeroIdentifier {
        /// Descriptor field containing the identifier.
        field: &'static str,
    },
    /// Checked addition or multiplication overflowed.
    #[error("amount arithmetic overflow")]
    ArithmeticOverflow,
    /// Checked subtraction would make an amount negative.
    #[error("amount arithmetic underflow")]
    ArithmeticUnderflow,
    /// A logical betting state violated a fixed v1 invariant.
    #[error("invalid betting state: {reason}")]
    InvalidBettingState {
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The requested action is not available in the current state.
    #[error("illegal action {action:?}")]
    IllegalAction {
        /// Rejected action.
        action: Action,
    },
    /// A player cannot cover a requested transfer.
    #[error("{role:?} stack {available} cannot cover required transfer {required}")]
    InsufficientStack {
        /// Underfunded actor.
        role: Role,
        /// Remaining stack.
        available: u64,
        /// Exact required transfer.
        required: u64,
    },
    /// A logical transaction or node record violated a structural invariant.
    #[error("invalid logical record: {reason}")]
    InvalidLogicalRecord {
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// A transition or settlement did not conserve the tracked game value.
    #[error("tracked value was not conserved")]
    ValueNotConserved,
    /// A bounded vector exceeded the canonical v1 maximum.
    #[error("{field} has {actual} entries/bytes, exceeding maximum {maximum}")]
    BoundExceeded {
        /// Bounded logical field.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum accepted length.
        maximum: usize,
    },
}
