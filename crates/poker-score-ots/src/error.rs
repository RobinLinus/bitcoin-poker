//! Error types for Lamport key, codec, and bundle operations.

use thiserror::Error;

/// Errors returned by the BP52 Lamport layer.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum LamportError {
    /// A score is not a positive 24-bit integer.
    #[error("score {0} is not a positive 24-bit value")]
    InvalidScore(u32),

    /// A purpose discriminant is unknown.
    #[error("invalid Lamport purpose discriminant {0}")]
    InvalidPurpose(u8),

    /// A role discriminant is unknown.
    #[error("invalid Lamport role discriminant {0}")]
    InvalidRole(u8),

    /// The encoded or supplied width does not match the purpose.
    #[error("invalid bit width: expected {expected}, got {actual}")]
    InvalidBitWidth {
        /// Width required by the key purpose.
        expected: u8,
        /// Width found in the input.
        actual: u8,
    },

    /// The key belongs to a different chain game.
    #[error("Lamport key belongs to a different chain game")]
    WrongGame,

    /// The key belongs to a different graph node.
    #[error("Lamport key belongs to a different graph node")]
    WrongNode,

    /// A public bundle was produced by the other protocol role.
    #[error("Lamport public bundle belongs to a different role")]
    WrongRole,

    /// The key or signature has the wrong purpose.
    #[error("Lamport purpose does not match the requested message")]
    WrongPurpose,

    /// A Lamport secret key has already authorized a message.
    #[error("Lamport one-time key has already been used")]
    KeyAlreadyUsed,

    /// A Lamport secret key was erased and cannot authorize a message.
    #[error("Lamport secret key has been erased")]
    KeyDestroyed,

    /// One generated secret unexpectedly duplicated another secret.
    #[error("random generator produced duplicate Lamport secret material")]
    DuplicateGeneratedSecret,

    /// A signature has an incorrect number of revealed preimages.
    #[error("invalid signature element count: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Element count required by the purpose.
        expected: usize,
        /// Element count found in the signature.
        actual: usize,
    },

    /// A revealed preimage does not match the selected public hash.
    #[error("Lamport signature verification failed at bit {bit_index}")]
    InvalidSignature {
        /// Zero-based, most-significant-first bit index.
        bit_index: usize,
    },

    /// A fixed format has a wrong magic prefix.
    #[error("invalid {kind} encoding prefix")]
    InvalidEncodingPrefix {
        /// Name of the decoded object.
        kind: &'static str,
    },

    /// An input ended before a complete field could be decoded.
    #[error("truncated {kind} encoding")]
    TruncatedEncoding {
        /// Name of the decoded object.
        kind: &'static str,
    },

    /// An otherwise complete input contains extra bytes.
    #[error("trailing data in {kind} encoding")]
    TrailingData {
        /// Name of the decoded object.
        kind: &'static str,
    },

    /// A bounded collection exceeds the protocol implementation limit.
    #[error("{kind} count {actual} exceeds maximum {maximum}")]
    CollectionTooLarge {
        /// Name of the collection.
        kind: &'static str,
        /// Decoded or supplied count.
        actual: usize,
        /// Maximum accepted count.
        maximum: usize,
    },

    /// A public-key entry is not in strict canonical order.
    #[error("Lamport public entries are not strictly sorted")]
    EntriesNotSorted,

    /// Two entries contain the same public hash, indicating key reuse.
    #[error("duplicate Lamport public hash detected")]
    DuplicatePublicHash,

    /// A bundle has a different number of entries than expected.
    #[error("invalid bundle entry count: expected {expected}, got {actual}")]
    UnexpectedEntryCount {
        /// Number of entries required by the graph.
        expected: usize,
        /// Number of entries found in the bundle.
        actual: usize,
    },

    /// A bundle entry does not match the graph's expected node and purpose.
    #[error("unexpected Lamport entry at canonical index {index}")]
    UnexpectedEntry {
        /// Index of the first mismatch.
        index: usize,
    },

    /// A bundle root does not match its canonical contents.
    #[error("Lamport public bundle root mismatch")]
    BundleRootMismatch,

    /// The caller-provided identity signature verifier rejected the bundle.
    #[error("Lamport public bundle identity signature is invalid")]
    BundleSignatureInvalid,
}
