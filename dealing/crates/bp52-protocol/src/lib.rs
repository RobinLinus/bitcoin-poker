#![forbid(unsafe_code)]
#![doc = "Authenticated attempt state machine for BP52-DEAL-v1."]

// Keep the public authentication types available at one stable path on both
// native and browser targets. Native builds continue to use rust-secp256k1;
// the browser build uses the pure-Rust BIP340-compatible adapter.
#[cfg(not(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "pure-rust-bip340",
    not(feature = "rust-secp256k1-auth")
)))]
pub use bitcoin::secp256k1;
#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "pure-rust-bip340",
    not(feature = "rust-secp256k1-auth")
))]
pub mod secp256k1;

// Existing internal modules deliberately import `bitcoin::secp256k1`. On the
// browser target this aliases the current crate, whose `secp256k1` module has
// the same narrow API used by the protocol.
#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    feature = "pure-rust-bip340",
    not(feature = "rust-secp256k1-auth")
))]
extern crate self as bitcoin;

/// Full replay and verification of accepted-deal archives.
pub mod archive;
pub use archive::{
    ACCEPTED_ARCHIVE_LENGTH, AcceptedArchiveError, ArchiveProgress, VerifiedAcceptedDeal,
    verify_accepted_archive,
};
/// Compact identity-signed evidence from a disposable DEAL verifier.
pub mod attestation;
pub use attestation::{
    DealVerificationAttestation, DealVerificationError, DealVerificationResult,
    DealVerificationStatement, VerifiedDealVerification, sign_deal_verification,
    verify_attested_accepted_deal, verify_deal_verification,
};
/// BIP340 message authentication and canonical identity roles.
pub mod auth;
/// Player-bundle proof construction and verification.
pub mod bundle;
/// Commit/open digests for simultaneous protocol flights.
pub mod commitments;
/// Secret contribution generation and public-slot prevalidation.
pub mod contribution;
/// Full authenticated semantic verifier for one attempt.
pub mod driver;
/// Fixed-parameter compatibility facade for the specification API.
pub mod facade;
/// Cumulative retry history and secret-erasure typestates.
pub mod history;
/// Canonical protocol messages.
pub mod messages;
/// Accepted, retry, and attributable-fault outcomes.
pub mod outcome;
/// Typed codecs for every authenticated envelope body.
pub mod payloads;
mod preimage_storage;
/// Domain-separated authorization for collision retries.
pub mod retry;
/// Attempt state machine.
pub mod state;
/// Transcript hashing and proof context.
pub mod transcript;
/// Standalone public uniqueness-certificate verification.
pub mod uniqueness;

pub use auth::CanonicalIdentities;
pub use contribution::{
    PreimageStorageError, PreimageStorageKey, RetainedPreimages, SealedRetainedPreimages,
    SecretContribution,
};
pub use facade::{
    ProtocolParams, derive_zero_test_ciphertexts, generate_player_bundle, verify_player_bundle,
    verify_uniqueness_transcript,
};
pub use messages::{Ciphertext, PlayerBundle, SlotPublic, ZERO_TEST_COUNT};
pub use outcome::ProtocolError;
pub use transcript::AttemptContext;
pub use uniqueness::{JointKeyPublic, UniquenessTranscript};

/// Number of cards dealt in one v1 attempt.
pub const N_SLOTS: usize = 9;
/// Number of cards in the deck.
pub const DECK_SIZE: u8 = 52;
/// Minimum share-preimage length.
pub const PREIMAGE_BASE_LEN: usize = 16;
/// Maximum share-preimage length.
pub const PREIMAGE_MAX_LEN: usize = 67;
/// Protocol wire version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Canonical party role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    /// Lexicographically smaller x-only Bitcoin identity key.
    Alice = 0,
    /// Lexicographically larger x-only Bitcoin identity key.
    Bob = 1,
}
