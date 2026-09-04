#![forbid(unsafe_code)]
#![doc = "Ristretto arithmetic for BP52-DEAL-v1."]

/// Threshold exponential ElGamal.
pub mod elgamal;
/// Deterministic protocol generators.
pub mod generators;
/// Bitcoin-style tagged SHA-256 helpers.
pub mod hash;

pub use elgamal::{
    CiphertextBytes, ElGamalCiphertext, GroupError, JointPublicKey, NonZeroScalar, PublicKeyShare,
    SecretKeyShare, commit, complete_decryption, decode_point, decode_scalar, sample_card_value,
};
pub use generators::ProtocolGenerators;
