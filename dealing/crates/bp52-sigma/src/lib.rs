#![forbid(unsafe_code)]
#![doc = "Generalized Schnorr and DLEQ proofs for BP52-DEAL-v1."]

use bp52_group::{GroupError, NonZeroScalar};
use curve25519_dalek::{RistrettoPoint, Scalar};
use merlin::{Transcript, TranscriptRng};
use rand_core::{CryptoRng, RngCore};

/// Pedersen-to-ElGamal link proof.
pub mod encryption_link;
/// Same-key batched partial-decryption proof.
pub mod partial_decrypt;
/// Ciphertext scale proofs.
pub mod scale;
/// Threshold-key proof of possession.
pub mod schnorr;

/// Fixed number of slots in every batched player proof.
pub const N_SLOTS: usize = 9;
/// Fixed number of derived zero-test ciphertexts.
pub const ZERO_TEST_COUNT: usize = 108;

/// Canonical identity of one `(i,j,t)` zero test.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZeroTestId {
    /// First card slot.
    pub i: u8,
    /// Second card slot.
    pub j: u8,
    /// `0=-52`, `1=0`, `2=+52`.
    pub offset_code: u8,
}

impl ZeroTestId {
    /// Returns the signed public offset represented by `offset_code`.
    #[must_use]
    pub const fn offset(self) -> i64 {
        match self.offset_code {
            0 => -52,
            2 => 52,
            _ => 0,
        }
    }
}

/// Exact v1 test order shared by derivation, proofs, and verification.
pub const CANONICAL_ZERO_TESTS: [ZeroTestId; ZERO_TEST_COUNT] = canonical_zero_tests();

const fn canonical_zero_tests() -> [ZeroTestId; ZERO_TEST_COUNT] {
    let mut tests = [ZeroTestId {
        i: 0,
        j: 0,
        offset_code: 0,
    }; ZERO_TEST_COUNT];
    let mut cursor = 0;
    let mut i = 0;
    while i < 8 {
        let mut j = i + 1;
        while j < 9 {
            let mut offset_code = 0;
            while offset_code < 3 {
                tests[cursor] = ZeroTestId { i, j, offset_code };
                cursor += 1;
                offset_code += 1;
            }
            j += 1;
        }
        i += 1;
    }
    tests
}

/// Errors produced by manual Sigma proofs.
#[derive(Debug, thiserror::Error)]
pub enum SigmaError {
    /// A point or scalar failed canonical or identity validation.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// The Fiat-Shamir transcript produced the forbidden zero challenge.
    #[error("zero Fiat-Shamir challenge")]
    ZeroChallenge,
    /// At least one proof equation was invalid.
    #[error("Sigma proof verification failed")]
    VerificationFailed,
    /// A proof vector had the wrong fixed size.
    #[error("wrong fixed proof length")]
    WrongProofLength,
}

pub(crate) fn append_point(
    transcript: &mut Transcript,
    label: &'static [u8],
    point: &RistrettoPoint,
) {
    transcript.append_message(label, point.compress().as_bytes());
}

pub(crate) fn append_index(transcript: &mut Transcript, index: usize) {
    let index = u16::try_from(index).unwrap_or(u16::MAX);
    transcript.append_message(b"index", &index.to_le_bytes());
}

pub(crate) fn challenge_scalar(transcript: &mut Transcript) -> Result<Scalar, SigmaError> {
    let mut wide = [0_u8; 64];
    transcript.challenge_bytes(b"challenge", &mut wide);
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);
    if challenge == Scalar::ZERO {
        Err(SigmaError::ZeroChallenge)
    } else {
        Ok(challenge)
    }
}

pub(crate) fn witness_rng<R>(
    transcript: &Transcript,
    witness_parts: &[&[u8]],
    rng: &mut R,
) -> TranscriptRng
where
    R: CryptoRng + RngCore,
{
    let mut builder = transcript.build_rng();
    for witness in witness_parts {
        builder = builder.rekey_with_witness_bytes(b"witness", witness);
    }
    builder.finalize(rng)
}

pub(crate) fn random_nonzero(rng: &mut TranscriptRng) -> Result<NonZeroScalar, SigmaError> {
    NonZeroScalar::random(rng).map_err(SigmaError::from)
}
