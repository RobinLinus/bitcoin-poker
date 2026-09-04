//! Context-bound Lamport one-time signatures used by `BP52-CHAIN-v1`.
//!
//! This crate deliberately does not expose plaintext serialization for secret
//! keys. Its versioned authenticated-ciphertext envelope is the persistence
//! boundary. A runtime must keep keys encrypted at rest and call
//! [`LamportSecretKey::erase_after_branch_confirmation`] when any branch of
//! the associated node confirms.

#![forbid(unsafe_code)]

mod bundle;
mod codec;
mod error;
mod key;
mod script;
mod sign;
mod storage;
mod verify;

pub use bundle::{
    ExpectedLamportEntry, LamportPublicBundle, LamportPublicEntry, LamportRole, MAX_BUNDLE_ENTRIES,
};
pub use error::LamportError;
pub use key::{
    HASH_SIZE, KeyContext, LamportMessage, LamportPublicKey, LamportPurpose, LamportSecretKey,
    SCORE_BIT_WIDTH, Score24, generate_key,
};
pub use script::LamportScriptPredicate;
pub use sign::{
    AliceScoreCertificate, BobScoreCertificate, LamportSignature, issue_alice_score_certificate,
    issue_bob_score_certificate, sign_alice_score, sign_bob_score,
};
pub use storage::{LamportStorageKey, SealedLamportSecretKey, SecretStorageError};
pub use verify::{verify_alice_score, verify_bob_score, verify_message};
