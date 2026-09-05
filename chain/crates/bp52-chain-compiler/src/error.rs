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
}
