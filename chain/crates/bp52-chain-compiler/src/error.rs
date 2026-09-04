//! Detailed compiler failures.

use bp52_chain_bitcoin::{BitcoinBackendError, FeeError};
use bp52_chain_types::ChainError;
use bp52_codec::CodecError;
use bp52_lamport::LamportError;
use thiserror::Error;

/// Failure while planning, materializing, or verifying a chain graph.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CompilerError {
    /// A compiler exchange or manifest failed canonical encoding.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A canonical descriptor, state, or record failed validation.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// The selected deterministic fee policy failed.
    #[error(transparent)]
    Fee(#[from] FeeError),
    /// A Bitcoin script, transaction, or signature operation failed.
    #[error(transparent)]
    Bitcoin(#[from] BitcoinBackendError),
    /// Lamport public material did not match the logical graph.
    #[error(transparent)]
    Lamport(#[from] LamportError),
    /// The separately supplied deal differs from the signed descriptor.
    #[error("compiler deal does not exactly match the descriptor deal")]
    DealMismatch,
    /// The fee-policy identifier differs from the signed descriptor.
    #[error("fee policy does not match the signed descriptor")]
    FeePolicyMismatch,
    /// The compiler identifier differs from the signed descriptor.
    #[error("compiler profile does not match the signed descriptor")]
    CompilerIdMismatch,
    /// The fee reserve cannot cover the descriptor-derived maximum path.
    #[error("fee reserve {available} cannot cover required maximum-path reserve {required}")]
    InsufficientMaximumPathReserve {
        /// Signed reserve amount.
        available: u64,
        /// Worst-case policy requirement.
        required: u64,
    },
    /// The logical graph did not satisfy the descriptor-derived compiler profile.
    #[error("compiled graph profile mismatch: {reason}")]
    ProfileMismatch {
        /// Stable reason suitable for logs and tests.
        reason: &'static str,
    },
    /// A graph index or path referenced a missing node.
    #[error("compiled graph contains a dangling node reference")]
    DanglingNode,
    /// A hiding commitment used the forbidden all-zero nonce.
    #[error("commitment nonce must be fresh and nonzero")]
    InvalidCommitmentNonce,
    /// An authenticated exchange object named the wrong chain game.
    #[error("commitment exchange is bound to another chain game")]
    ExchangeGameMismatch,
    /// An exchange object named a graph other than the agreed graph root.
    #[error("commitment exchange is bound to another graph root")]
    ExchangeGraphMismatch,
    /// An exchange object named the wrong signer, role, or commitment domain.
    #[error("commitment exchange role or purpose mismatch")]
    ExchangeRoleMismatch,
    /// A commitment did not open to the disclosed object.
    #[error("{purpose} commitment opening mismatch")]
    CommitmentMismatch {
        /// Human-readable commitment domain.
        purpose: &'static str,
    },
    /// Alice and Bob disclosed different independently compiled graph roots.
    #[error("participants disclosed different graph roots")]
    GraphRootDisagreement,
    /// A preauthorization bundle exceeded its defensive entry limit.
    #[error("signature bundle has {actual} entries; maximum is {maximum}")]
    SignatureBundleTooLarge {
        /// Entries supplied by the peer.
        actual: usize,
        /// Fixed defensive v1 maximum.
        maximum: usize,
    },
    /// Bundle entries were not in strict canonical request order.
    #[error("preauthorization bundle is not in strict canonical order")]
    NonCanonicalSignatureBundle,
    /// Opened preauthorizations did not exactly cover the expected request set.
    #[error("preauthorization bundle membership does not match the graph")]
    SignatureBundleMembershipMismatch,
    /// Locally retained runtime responses did not exactly cover the graph's
    /// canonical request set for one role.
    #[error("private runtime-signature bundle membership does not match the graph")]
    RuntimeSignatureBundleMembershipMismatch,
    /// A verified signature bundle was already installed for this role.
    #[error("a verified preauthorization bundle is already installed for {role:?}")]
    PreauthorizationBundleAlreadyInstalled {
        /// Role whose immutable bundle would be replaced.
        role: bp52_chain_types::Role,
    },
    /// A compact verified-opening receipt failed an authenticated binding.
    #[error("invalid verified preauthorization receipt: {reason}")]
    InvalidPreauthorizationReceipt {
        /// Stable diagnostic suitable for logs and tests.
        reason: &'static str,
    },
    /// A compact CHAIN-to-GAME graph or state receipt failed validation.
    #[error("invalid graph-runtime receipt: {reason}")]
    InvalidGraphReceipt {
        /// Stable diagnostic suitable for logs and tests.
        reason: &'static str,
    },
    /// A concrete graph failed an internal deterministic cross-check.
    #[error("compiled graph verification failed: {reason}")]
    CompiledGraphMismatch {
        /// Stable diagnostic suitable for logs and tests.
        reason: &'static str,
    },
    /// A readiness report was inconsistent with its descriptor or manifest.
    #[error("invalid funding-readiness report: {reason}")]
    InvalidReadinessReport {
        /// Stable diagnostic.
        reason: &'static str,
    },
    /// Role-local gameplay material did not exactly match the compiled graph.
    #[error("local runtime inventory mismatch: {reason}")]
    LocalRuntimeInventoryMismatch {
        /// Stable diagnostic suitable for logs and tests.
        reason: &'static str,
    },
    /// One or more mandatory funding gates remain unresolved.
    #[error("funding is not authorized while readiness blockers remain")]
    FundingNotReady,
}
