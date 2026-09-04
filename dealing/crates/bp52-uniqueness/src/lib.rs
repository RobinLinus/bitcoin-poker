#![forbid(unsafe_code)]
#![doc = "The fixed 108-test BP52 uniqueness protocol."]

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, GroupError, ProtocolGenerators, PublicKeyShare,
    SecretKeyShare, complete_decryption, decode_point,
};
use bp52_sigma::{
    SigmaError,
    partial_decrypt::{PartialDecryptionProof, PartialDecryptionStatement},
    scale::{ScaleProof, ScaleStatement},
};
use curve25519_dalek::{RistrettoPoint, traits::IsIdentity};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// Canonical identities for all v1 zero tests.
pub use bp52_sigma::{CANONICAL_ZERO_TESTS, ZeroTestId};

/// Number of contribution and final-card slots in a v1 deal.
pub const N_SLOTS: usize = bp52_sigma::N_SLOTS;
/// Number of encrypted zero tests in a v1 attempt.
pub const ZERO_TEST_COUNT: usize = bp52_sigma::ZERO_TEST_COUNT;

const POINT_SIZE: usize = 32;
const CIPHERTEXT_SIZE: usize = 2 * POINT_SIZE;

/// Exact canonical size of a first- or second-blinding message body.
pub const SCALE_ROUND_SIZE: usize = (ZERO_TEST_COUNT * POINT_SIZE)
    + (ZERO_TEST_COUNT * CIPHERTEXT_SIZE)
    + bp52_sigma::scale::SCALE_PROOF_SIZE;
/// Exact canonical size of a partial-decryption batch and its proof.
pub const PARTIAL_DECRYPTION_BATCH_SIZE: usize =
    (ZERO_TEST_COUNT * POINT_SIZE) + bp52_sigma::partial_decrypt::PARTIAL_DECRYPT_PROOF_SIZE;

/// The kind of locally derived ciphertext whose `R` component cancelled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivedCiphertextKind {
    /// One of the nine homomorphic card sums.
    Sum,
    /// One of the 108 difference/offset ciphertexts.
    Difference,
}

/// Errors raised by the specialized uniqueness protocol.
#[derive(Debug, thiserror::Error)]
pub enum UniquenessError {
    /// Independently valid contribution randomness cancelled in a derived
    /// ciphertext. This is a neutral retry condition, not an attributable
    /// protocol fault.
    #[error("identity R in locally derived {kind:?} ciphertext at index {index}")]
    DegenerateIdentity {
        /// The derived collection containing the cancellation.
        kind: DerivedCiphertextKind,
        /// Canonical index within that collection.
        index: usize,
    },
    /// A group value or random scalar was invalid.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// A scale or partial-decryption proof was invalid.
    #[error(transparent)]
    Sigma(#[from] SigmaError),
    /// A fixed-size collection built internally had an impossible length.
    #[error("internal fixed-size collection invariant failed")]
    InternalLength,
}

/// The nine homomorphic sums and the 108 canonical zero-test ciphertexts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedZeroTests {
    /// `C[A,i] + C[B,i]` for each fixed slot.
    pub sums: [ElGamalCiphertext; N_SLOTS],
    /// `Sum[i] - Sum[j] - Enc(t; 0)` in [`CANONICAL_ZERO_TESTS`] order.
    pub differences: [ElGamalCiphertext; ZERO_TEST_COUNT],
}

/// Public values and proof for one complete 108-entry blinding round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScaleRound {
    /// Nonidentity `factor[k] * G` points.
    pub scale_points: [RistrettoPoint; ZERO_TEST_COUNT],
    /// Component-wise scaled ciphertexts in canonical zero-test order.
    pub outputs: [ElGamalCiphertext; ZERO_TEST_COUNT],
    /// Proof that the same factor maps `G`, `R`, and `S` at every index.
    pub proof: ScaleProof,
}

/// A party's 108 same-key partial decryptions and batched DLEQ proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialDecryptionBatch {
    /// `sk * final_ciphertexts[k].R` in canonical zero-test order.
    pub shares: [RistrettoPoint; ZERO_TEST_COUNT],
    /// Proof that every share uses the secret behind the party's public key.
    pub proof: PartialDecryptionProof,
}

/// Fully evaluated public result of the uniqueness protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniquenessResult {
    /// Decrypted, doubly blinded plaintext point for every zero test.
    pub plaintexts: [RistrettoPoint; ZERO_TEST_COUNT],
    /// `true` exactly where the corresponding plaintext is the identity.
    pub collision_bitmap: [bool; ZERO_TEST_COUNT],
    /// `true` exactly when every entry in `collision_bitmap` is false.
    pub is_unique: bool,
}

/// Derives the nine public sums and all 108 difference ciphertexts.
///
/// Original contributions must already have passed their attributable
/// nonidentity-`R` checks. A cancellation introduced by addition/subtraction
/// is instead returned as [`UniquenessError::DegenerateIdentity`], which the
/// attempt state machine must treat as a neutral retry.
///
/// # Errors
///
/// Returns [`GroupError::UnexpectedIdentity`] for an invalid original
/// contribution, or [`UniquenessError::DegenerateIdentity`] if a locally
/// derived sum or difference has an identity `R` component.
pub fn derive_sums_and_zero_tests(
    contributions_a: &[ElGamalCiphertext; N_SLOTS],
    contributions_b: &[ElGamalCiphertext; N_SLOTS],
    generators: &ProtocolGenerators,
) -> Result<DerivedZeroTests, UniquenessError> {
    for contribution in contributions_a.iter().chain(contributions_b) {
        if contribution.r.is_identity() {
            return Err(GroupError::UnexpectedIdentity.into());
        }
    }

    let sums = std::array::from_fn(|index| &contributions_a[index] + &contributions_b[index]);
    reject_derived_identity(&sums, DerivedCiphertextKind::Sum)?;

    let differences = std::array::from_fn(|index| {
        let test = CANONICAL_ZERO_TESTS[index];
        let difference = &sums[usize::from(test.i)] - &sums[usize::from(test.j)];
        &difference - &ElGamalCiphertext::public_constant(test.offset(), generators)
    });
    reject_derived_identity(&differences, DerivedCiphertextKind::Difference)?;

    Ok(DerivedZeroTests { sums, differences })
}

/// Convenience wrapper returning only the 108 canonical difference
/// ciphertexts.
///
/// # Errors
///
/// Returns the same validation and neutral-retry errors as
/// [`derive_sums_and_zero_tests`].
pub fn derive_zero_test_ciphertexts(
    contributions_a: &[ElGamalCiphertext; N_SLOTS],
    contributions_b: &[ElGamalCiphertext; N_SLOTS],
    generators: &ProtocolGenerators,
) -> Result<[ElGamalCiphertext; ZERO_TEST_COUNT], UniquenessError> {
    Ok(derive_sums_and_zero_tests(contributions_a, contributions_b, generators)?.differences)
}

/// Reconstructs the complete canonical Sigma statements for a blinding round.
#[must_use]
pub fn scale_statements(
    inputs: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    round: &ScaleRound,
) -> [ScaleStatement; ZERO_TEST_COUNT] {
    build_scale_statements(inputs, &round.scale_points, &round.outputs)
}

/// Samples 108 independent nonzero factors and proves one blinding round.
///
/// The caller supplies an already framed Merlin transcript. The function adds
/// only the fixed Sigma statements and commitments defined by `bp52-sigma`.
///
/// # Errors
///
/// Returns an error if nonzero-factor sampling fails, the input statements
/// contain forbidden identities, or proof generation fails.
pub fn generate_scale_round<R>(
    transcript: &mut Transcript,
    generators: &ProtocolGenerators,
    inputs: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    rng: &mut R,
) -> Result<ScaleRound, UniquenessError>
where
    R: CryptoRng + RngCore,
{
    let mut sampled = Vec::with_capacity(ZERO_TEST_COUNT);
    for _ in 0..ZERO_TEST_COUNT {
        sampled.push(bp52_group::NonZeroScalar::random(rng)?);
    }

    let scale_points =
        std::array::from_fn(|index| sampled[index].as_scalar() * generators.blinding());
    let outputs = std::array::from_fn(|index| inputs[index].scale(sampled[index].as_scalar()));
    let statements = build_scale_statements(inputs, &scale_points, &outputs);
    let proof = ScaleProof::prove(transcript, generators, &statements, &sampled, rng)?;

    Ok(ScaleRound {
        scale_points,
        outputs,
        proof,
    })
}

/// Validates all public values and verifies a complete blinding round.
///
/// The transcript must contain exactly the same caller-supplied framing used
/// for generation.
///
/// # Errors
///
/// Returns an error if a statement is malformed or any batched proof equation
/// fails.
pub fn verify_scale_round(
    transcript: &mut Transcript,
    generators: &ProtocolGenerators,
    inputs: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    round: &ScaleRound,
) -> Result<(), UniquenessError> {
    let statements = scale_statements(inputs, round);
    round
        .proof
        .verify(transcript, generators, &statements)
        .map_err(UniquenessError::from)
}

/// Reconstructs the canonical same-key partial-decryption statements.
#[must_use]
pub fn partial_decryption_statements(
    final_ciphertexts: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    batch: &PartialDecryptionBatch,
) -> [PartialDecryptionStatement; ZERO_TEST_COUNT] {
    build_partial_decryption_statements(final_ciphertexts, &batch.shares)
}

/// Computes and proves one party's complete partial-decryption batch.
///
/// The caller supplies the role- and attempt-framed Merlin transcript.
///
/// # Errors
///
/// Returns an error if the key pair is inconsistent, a required point is the
/// identity, random nonce generation fails, or proof generation fails.
pub fn generate_partial_decryption_batch<R>(
    transcript: &mut Transcript,
    generators: &ProtocolGenerators,
    public_key: &PublicKeyShare,
    secret_key: &SecretKeyShare,
    final_ciphertexts: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    rng: &mut R,
) -> Result<PartialDecryptionBatch, UniquenessError>
where
    R: CryptoRng + RngCore,
{
    let shares = std::array::from_fn(|index| secret_key.partial_decrypt(&final_ciphertexts[index]));
    let statements = build_partial_decryption_statements(final_ciphertexts, &shares);
    let proof = PartialDecryptionProof::prove(
        transcript,
        generators,
        public_key,
        secret_key,
        &statements,
        rng,
    )?;
    Ok(PartialDecryptionBatch { shares, proof })
}

/// Validates and verifies one complete partial-decryption batch.
///
/// # Errors
///
/// Returns an error if a statement is malformed, the claimed public key does
/// not match the proof, or any batched proof equation fails.
pub fn verify_partial_decryption_batch(
    transcript: &mut Transcript,
    generators: &ProtocolGenerators,
    public_key: &PublicKeyShare,
    final_ciphertexts: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    batch: &PartialDecryptionBatch,
) -> Result<(), UniquenessError> {
    let statements = partial_decryption_statements(final_ciphertexts, batch);
    batch
        .proof
        .verify(transcript, generators, public_key, &statements)
        .map_err(UniquenessError::from)
}

/// Verifies both parties' proofs, then evaluates every plaintext and collision
/// bit without returning early from the 108 identity tests.
///
/// Both proof verifiers are invoked even if the first batch is invalid. No
/// plaintext is evaluated unless both complete batches verify.
///
/// # Errors
///
/// Returns an error after invoking both verifiers if either party's complete
/// partial-decryption batch is malformed or invalid.
#[allow(clippy::too_many_arguments)]
pub fn verify_decryption_batches(
    transcript_a: &mut Transcript,
    transcript_b: &mut Transcript,
    generators: &ProtocolGenerators,
    public_key_a: &PublicKeyShare,
    public_key_b: &PublicKeyShare,
    final_ciphertexts: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    batch_a: &PartialDecryptionBatch,
    batch_b: &PartialDecryptionBatch,
) -> Result<UniquenessResult, UniquenessError> {
    let verification_a = verify_partial_decryption_batch(
        transcript_a,
        generators,
        public_key_a,
        final_ciphertexts,
        batch_a,
    );
    let verification_b = verify_partial_decryption_batch(
        transcript_b,
        generators,
        public_key_b,
        final_ciphertexts,
        batch_b,
    );
    match (verification_a, verification_b) {
        (Err(error), _) | (Ok(()), Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }

    let plaintexts = std::array::from_fn(|index| {
        complete_decryption(
            &final_ciphertexts[index],
            &batch_a.shares[index],
            &batch_b.shares[index],
        )
    });
    let collision_bitmap = std::array::from_fn(|index| plaintexts[index].is_identity());
    let mut is_unique = true;
    for collision in collision_bitmap {
        is_unique &= !collision;
    }

    Ok(UniquenessResult {
        plaintexts,
        collision_bitmap,
        is_unique,
    })
}

impl Encode for ScaleRound {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        for point in &self.scale_points {
            encode_nonidentity_point(point, writer)?;
        }
        for output in &self.outputs {
            if output.r.is_identity() {
                return Err(CodecError::NonCanonical);
            }
            output.to_bytes().encode(writer)?;
        }
        self.proof.encode(writer)
    }
}

impl Decode for ScaleRound {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut scale_points = std::array::from_fn(|_| RistrettoPoint::default());
        for point in &mut scale_points {
            *point = decode_wire_point(reader, false)?;
        }
        let mut outputs = Vec::with_capacity(ZERO_TEST_COUNT);
        for _ in 0..ZERO_TEST_COUNT {
            let output = CiphertextBytes::decode(reader)?
                .decompress()
                .map_err(|_| CodecError::NonCanonical)?;
            if output.r.is_identity() {
                return Err(CodecError::NonCanonical);
            }
            outputs.push(output);
        }
        Ok(Self {
            scale_points,
            outputs: outputs.try_into().map_err(|_| CodecError::NonCanonical)?,
            proof: ScaleProof::decode(reader)?,
        })
    }
}

impl Encode for PartialDecryptionBatch {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        for share in &self.shares {
            encode_nonidentity_point(share, writer)?;
        }
        self.proof.encode(writer)
    }
}

impl Decode for PartialDecryptionBatch {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut shares = std::array::from_fn(|_| RistrettoPoint::default());
        for share in &mut shares {
            *share = decode_wire_point(reader, false)?;
        }
        Ok(Self {
            shares,
            proof: PartialDecryptionProof::decode(reader)?,
        })
    }
}

fn build_scale_statements(
    inputs: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    scale_points: &[RistrettoPoint; ZERO_TEST_COUNT],
    outputs: &[ElGamalCiphertext; ZERO_TEST_COUNT],
) -> [ScaleStatement; ZERO_TEST_COUNT] {
    std::array::from_fn(|index| ScaleStatement {
        test: CANONICAL_ZERO_TESTS[index],
        input: inputs[index].clone(),
        scale_point: scale_points[index],
        output: outputs[index].clone(),
    })
}

fn build_partial_decryption_statements(
    final_ciphertexts: &[ElGamalCiphertext; ZERO_TEST_COUNT],
    shares: &[RistrettoPoint; ZERO_TEST_COUNT],
) -> [PartialDecryptionStatement; ZERO_TEST_COUNT] {
    std::array::from_fn(|index| PartialDecryptionStatement {
        ciphertext_r: final_ciphertexts[index].r,
        decryption_share: shares[index],
    })
}

fn reject_derived_identity<const N: usize>(
    ciphertexts: &[ElGamalCiphertext; N],
    kind: DerivedCiphertextKind,
) -> Result<(), UniquenessError> {
    for (index, ciphertext) in ciphertexts.iter().enumerate() {
        if ciphertext.r.is_identity() {
            return Err(UniquenessError::DegenerateIdentity { kind, index });
        }
    }
    Ok(())
}

fn encode_nonidentity_point(point: &RistrettoPoint, writer: &mut Writer) -> Result<(), CodecError> {
    if point.is_identity() {
        return Err(CodecError::NonCanonical);
    }
    writer.write_bytes(point.compress().as_bytes());
    Ok(())
}

fn decode_wire_point(
    reader: &mut Reader<'_>,
    allow_identity: bool,
) -> Result<RistrettoPoint, CodecError> {
    decode_point(reader.read_array()?, allow_identity).map_err(|_| CodecError::NonCanonical)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use bp52_codec::{CodecError, Decode, Encode};
    use bp52_group::{
        ElGamalCiphertext, GroupError, JointPublicKey, NonZeroScalar, ProtocolGenerators,
        PublicKeyShare, SecretKeyShare, complete_decryption,
    };
    use curve25519_dalek::{RistrettoPoint, Scalar, traits::IsIdentity};
    use merlin::Transcript;
    use rand_core::OsRng;

    use super::{
        CANONICAL_ZERO_TESTS, DerivedCiphertextKind, DerivedZeroTests, N_SLOTS,
        PARTIAL_DECRYPTION_BATCH_SIZE, PartialDecryptionBatch, SCALE_ROUND_SIZE, ScaleRound,
        UniquenessError, UniquenessResult, ZERO_TEST_COUNT, derive_sums_and_zero_tests,
        generate_partial_decryption_batch, generate_scale_round, verify_decryption_batches,
        verify_partial_decryption_batch, verify_scale_round,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    struct Keys {
        generators: ProtocolGenerators,
        secret_a: SecretKeyShare,
        secret_b: SecretKeyShare,
        public_a: PublicKeyShare,
        public_b: PublicKeyShare,
        joint: JointPublicKey,
    }

    struct FullFixture {
        keys: Keys,
        derived: Box<DerivedZeroTests>,
        first: Box<ScaleRound>,
        second: Box<ScaleRound>,
        batch_a: Box<PartialDecryptionBatch>,
        batch_b: Box<PartialDecryptionBatch>,
    }

    fn keys() -> Result<Keys, GroupError> {
        let generators = ProtocolGenerators::derive()?;
        let secret_a = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(13_u64))?);
        let secret_b = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(29_u64))?);
        let public_a = secret_a.public_key(&generators);
        let public_b = secret_b.public_key(&generators);
        let joint = JointPublicKey::combine(&public_a, &public_b)?;
        Ok(Keys {
            generators,
            secret_a,
            secret_b,
            public_a,
            public_b,
            joint,
        })
    }

    fn encrypt_with_scalar(value: u64, randomness: Scalar, keys: &Keys) -> ElGamalCiphertext {
        ElGamalCiphertext {
            r: randomness * keys.generators.blinding(),
            s: Scalar::from(value) * keys.generators.message() + randomness * keys.joint.as_point(),
        }
    }

    fn contributions(
        raw_sums: &[u64; N_SLOTS],
        keys: &Keys,
    ) -> ([ElGamalCiphertext; N_SLOTS], [ElGamalCiphertext; N_SLOTS]) {
        const RANDOMNESS_A: [u64; N_SLOTS] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        const RANDOMNESS_B: [u64; N_SLOTS] = [97, 99, 101, 103, 105, 107, 109, 111, 113];
        let contributions_a = std::array::from_fn(|index| {
            encrypt_with_scalar(
                raw_sums[index].min(51),
                Scalar::from(RANDOMNESS_A[index]),
                keys,
            )
        });
        let contributions_b = std::array::from_fn(|index| {
            encrypt_with_scalar(
                raw_sums[index] - raw_sums[index].min(51),
                Scalar::from(RANDOMNESS_B[index]),
                keys,
            )
        });
        (contributions_a, contributions_b)
    }

    fn first_transcript() -> Transcript {
        framed_transcript(b"BP52/scale-first/v1", b"first")
    }

    fn second_transcript() -> Transcript {
        framed_transcript(b"BP52/scale-second/v1", b"second")
    }

    fn decrypt_a_transcript() -> Transcript {
        framed_transcript(b"BP52/partial-decrypt-A/v1", b"alice")
    }

    fn decrypt_b_transcript() -> Transcript {
        framed_transcript(b"BP52/partial-decrypt-B/v1", b"bob")
    }

    fn framed_transcript(domain: &'static [u8], round: &[u8]) -> Transcript {
        let mut transcript = Transcript::new(domain);
        transcript.append_message(b"game-id", &[42_u8; 32]);
        transcript.append_message(b"attempt", &7_u32.to_le_bytes());
        transcript.append_message(b"round", round);
        transcript
    }

    fn full_fixture(raw_sums: &[u64; N_SLOTS]) -> TestResult<FullFixture> {
        let keys = keys()?;
        let (contributions_a, contributions_b) = contributions(raw_sums, &keys);
        let derived = Box::new(derive_sums_and_zero_tests(
            &contributions_a,
            &contributions_b,
            &keys.generators,
        )?);
        let mut rng = OsRng;
        let first = Box::new(generate_scale_round(
            &mut first_transcript(),
            &keys.generators,
            &derived.differences,
            &mut rng,
        )?);
        verify_scale_round(
            &mut first_transcript(),
            &keys.generators,
            &derived.differences,
            &first,
        )?;
        let second = Box::new(generate_scale_round(
            &mut second_transcript(),
            &keys.generators,
            &first.outputs,
            &mut rng,
        )?);
        verify_scale_round(
            &mut second_transcript(),
            &keys.generators,
            &first.outputs,
            &second,
        )?;
        let batch_a = Box::new(generate_partial_decryption_batch(
            &mut decrypt_a_transcript(),
            &keys.generators,
            &keys.public_a,
            &keys.secret_a,
            &second.outputs,
            &mut rng,
        )?);
        let batch_b = Box::new(generate_partial_decryption_batch(
            &mut decrypt_b_transcript(),
            &keys.generators,
            &keys.public_b,
            &keys.secret_b,
            &second.outputs,
            &mut rng,
        )?);
        Ok(FullFixture {
            keys,
            derived,
            first,
            second,
            batch_a,
            batch_b,
        })
    }

    fn finish(fixture: &FullFixture) -> Result<UniquenessResult, UniquenessError> {
        verify_decryption_batches(
            &mut decrypt_a_transcript(),
            &mut decrypt_b_transcript(),
            &fixture.keys.generators,
            &fixture.keys.public_a,
            &fixture.keys.public_b,
            &fixture.second.outputs,
            &fixture.batch_a,
            &fixture.batch_b,
        )
    }

    fn signed_scalar(value: i64) -> Scalar {
        if value < 0 {
            -Scalar::from(value.unsigned_abs())
        } else {
            Scalar::from(value.unsigned_abs())
        }
    }

    fn test_index(i: u8, j: u8, offset_code: u8) -> TestResult<usize> {
        CANONICAL_ZERO_TESTS
            .iter()
            .position(|test| test.i == i && test.j == j && test.offset_code == offset_code)
            .ok_or_else(|| std::io::Error::other("missing canonical zero test").into())
    }

    fn assert_round_codecs(fixture: &FullFixture) -> TestResult {
        let first_bytes = fixture.first.encode_to_vec()?;
        assert_eq!(first_bytes.len(), SCALE_ROUND_SIZE);
        let decoded_first = ScaleRound::decode_exact(&first_bytes)?;
        assert_eq!(&decoded_first, fixture.first.as_ref());
        verify_scale_round(
            &mut first_transcript(),
            &fixture.keys.generators,
            &fixture.derived.differences,
            &decoded_first,
        )?;

        let batch_bytes = fixture.batch_a.encode_to_vec()?;
        assert_eq!(batch_bytes.len(), PARTIAL_DECRYPTION_BATCH_SIZE);
        let decoded_batch = PartialDecryptionBatch::decode_exact(&batch_bytes)?;
        assert_eq!(&decoded_batch, fixture.batch_a.as_ref());

        let mut noncanonical_scale = first_bytes;
        noncanonical_scale[..32].fill(0);
        assert_eq!(
            ScaleRound::decode_exact(&noncanonical_scale),
            Err(CodecError::NonCanonical)
        );
        let mut noncanonical_batch = batch_bytes;
        noncanonical_batch[..32].fill(0);
        assert_eq!(
            PartialDecryptionBatch::decode_exact(&noncanonical_batch),
            Err(CodecError::NonCanonical)
        );
        Ok(())
    }

    fn assert_invalid_scale(fixture: &FullFixture, mutate: impl FnOnce(&mut ScaleRound)) {
        let mut malformed = fixture.first.as_ref().clone();
        mutate(&mut malformed);
        assert!(
            verify_scale_round(
                &mut first_transcript(),
                &fixture.keys.generators,
                &fixture.derived.differences,
                &malformed,
            )
            .is_err()
        );
    }

    fn assert_invalid_batch(
        fixture: &FullFixture,
        mutate: impl FnOnce(&mut PartialDecryptionBatch),
    ) {
        let mut malformed = fixture.batch_a.as_ref().clone();
        mutate(&mut malformed);
        assert!(
            verify_partial_decryption_batch(
                &mut decrypt_a_transcript(),
                &fixture.keys.generators,
                &fixture.keys.public_a,
                &fixture.second.outputs,
                &malformed,
            )
            .is_err()
        );
    }

    #[test]
    fn derives_nine_sums_and_exact_canonical_108_tests() -> TestResult {
        let keys = keys()?;
        let raw_sums = [3, 8, 21, 34, 49, 60, 72, 91, 102];
        let (contributions_a, contributions_b) = contributions(&raw_sums, &keys);
        let derived =
            derive_sums_and_zero_tests(&contributions_a, &contributions_b, &keys.generators)?;

        assert_eq!(derived.sums.len(), N_SLOTS);
        assert_eq!(derived.differences.len(), ZERO_TEST_COUNT);
        assert_eq!(CANONICAL_ZERO_TESTS[0].offset(), -52);
        assert_eq!(CANONICAL_ZERO_TESTS[ZERO_TEST_COUNT - 1].offset(), 52);

        for (index, sum) in derived.sums.iter().enumerate() {
            let plaintext = complete_decryption(
                sum,
                &keys.secret_a.partial_decrypt(sum),
                &keys.secret_b.partial_decrypt(sum),
            );
            assert_eq!(
                plaintext,
                Scalar::from(raw_sums[index]) * keys.generators.message()
            );
        }
        for (index, difference) in derived.differences.iter().enumerate() {
            let test = CANONICAL_ZERO_TESTS[index];
            let expected = i64::try_from(raw_sums[usize::from(test.i)])?
                - i64::try_from(raw_sums[usize::from(test.j)])?
                - test.offset();
            let plaintext = complete_decryption(
                difference,
                &keys.secret_a.partial_decrypt(difference),
                &keys.secret_b.partial_decrypt(difference),
            );
            assert_eq!(
                plaintext,
                signed_scalar(expected) * keys.generators.message()
            );
        }
        Ok(())
    }

    #[test]
    fn every_signed_raw_difference_has_no_false_identity() -> TestResult {
        let keys = keys()?;
        for raw_difference in -102_i64..=102_i64 {
            let (left, right) = if raw_difference < 0 {
                (0_u64, raw_difference.unsigned_abs())
            } else {
                (raw_difference.unsigned_abs(), 0_u64)
            };
            let raw_sums = [left, right, 3, 11, 24, 39, 57, 78, 101];
            let (contributions_a, contributions_b) = contributions(&raw_sums, &keys);
            let derived =
                derive_sums_and_zero_tests(&contributions_a, &contributions_b, &keys.generators)?;

            for (offset_code, offset) in [(0_u8, -52_i64), (1, 0), (2, 52)] {
                let index = test_index(0, 1, offset_code)?;
                let difference = &derived.differences[index];
                let plaintext = complete_decryption(
                    difference,
                    &keys.secret_a.partial_decrypt(difference),
                    &keys.secret_b.partial_decrypt(difference),
                );
                let expected = raw_difference - offset;
                assert_eq!(
                    plaintext,
                    signed_scalar(expected) * keys.generators.message(),
                    "raw difference {raw_difference}, offset {offset}"
                );
                assert_eq!(
                    plaintext.is_identity(),
                    expected == 0,
                    "raw difference {raw_difference}, offset {offset}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn reordered_repeated_and_missing_test_shapes_reject() -> TestResult {
        // The public API accepts only fixed arrays and derives the test IDs
        // internally. Check that its canonical table has every required entry
        // exactly once before exercising the representable malformed shapes.
        let mut seen = [[[false; 3]; N_SLOTS]; N_SLOTS];
        for test in CANONICAL_ZERO_TESTS {
            let i = usize::from(test.i);
            let j = usize::from(test.j);
            let offset = usize::from(test.offset_code);
            assert!(i < j);
            assert!(offset < 3);
            assert!(!seen[i][j][offset]);
            seen[i][j][offset] = true;
        }
        for (i, rows) in seen.iter().enumerate() {
            for row in rows.iter().skip(i + 1) {
                assert!(row.iter().all(|present| *present));
            }
        }

        let fixture = full_fixture(&[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        let mut reordered = fixture.first.as_ref().clone();
        reordered.scale_points.swap(7, 23);
        reordered.outputs.swap(7, 23);
        assert!(
            verify_scale_round(
                &mut first_transcript(),
                &fixture.keys.generators,
                &fixture.derived.differences,
                &reordered,
            )
            .is_err()
        );

        let mut repeated = fixture.first.as_ref().clone();
        repeated.scale_points[23] = repeated.scale_points[7];
        repeated.outputs[23] = repeated.outputs[7].clone();
        assert!(
            verify_scale_round(
                &mut first_transcript(),
                &fixture.keys.generators,
                &fixture.derived.differences,
                &repeated,
            )
            .is_err()
        );

        let encoded = fixture.first.encode_to_vec()?;
        let missing = &encoded[..encoded.len() - 1];
        assert!(ScaleRound::decode_exact(missing).is_err());
        let mut repeated_trailing_entry = encoded.clone();
        repeated_trailing_entry.extend_from_slice(&encoded[..32 * 3]);
        assert!(ScaleRound::decode_exact(&repeated_trailing_entry).is_err());
        Ok(())
    }

    #[test]
    fn distinct_cards_accept_and_malformed_proofs_or_order_reject() -> TestResult {
        let fixture = full_fixture(&[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        let result = finish(&fixture)?;
        assert!(result.is_unique);
        assert!(result.collision_bitmap.iter().all(|collision| !collision));
        assert!(result.plaintexts.iter().all(|point| !point.is_identity()));

        assert_round_codecs(&fixture)?;
        assert_invalid_scale(&fixture, |round| {
            round.outputs[42].s += fixture.keys.generators.message();
        });
        assert_invalid_scale(&fixture, |round| {
            round.scale_points.swap(0, 1);
            round.outputs.swap(0, 1);
        });
        assert_invalid_scale(&fixture, |round| {
            round.scale_points[0] = RistrettoPoint::default();
        });

        let mut replay_transcript = first_transcript();
        replay_transcript.append_message(b"wrong-frame", b"different attempt");
        assert!(
            verify_scale_round(
                &mut replay_transcript,
                &fixture.keys.generators,
                &fixture.derived.differences,
                &fixture.first,
            )
            .is_err()
        );

        assert_invalid_batch(&fixture, |batch| {
            batch.shares[17] += fixture.keys.generators.message();
        });
        let mut malformed_batch = fixture.batch_a.as_ref().clone();
        malformed_batch.shares[17] += fixture.keys.generators.message();
        assert!(
            verify_decryption_batches(
                &mut decrypt_a_transcript(),
                &mut decrypt_b_transcript(),
                &fixture.keys.generators,
                &fixture.keys.public_a,
                &fixture.keys.public_b,
                &fixture.second.outputs,
                &malformed_batch,
                &fixture.batch_b,
            )
            .is_err()
        );
        assert_invalid_batch(&fixture, |batch| {
            batch.shares.swap(0, ZERO_TEST_COUNT - 1);
        });
        Ok(())
    }

    #[test]
    fn zero_plus_52_and_minus_52_collisions_are_all_reported() -> TestResult {
        // (0,1) has d=0, (2,3) differs by +52, and (4,5) differs by -52.
        let fixture = full_fixture(&[10, 10, 60, 8, 7, 59, 20, 31, 42])?;
        let result = finish(&fixture)?;
        assert!(!result.is_unique);
        assert!(result.collision_bitmap[test_index(0, 1, 1)?]);
        assert!(result.collision_bitmap[test_index(2, 3, 2)?]);
        assert!(result.collision_bitmap[test_index(4, 5, 0)?]);
        assert_eq!(
            result
                .collision_bitmap
                .iter()
                .filter(|collision| **collision)
                .count(),
            3
        );
        Ok(())
    }

    #[test]
    fn derived_r_cancellations_are_neutral_retry_errors() -> TestResult {
        const RANDOMNESS: [u64; N_SLOTS] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        const COMPLEMENTS: [u64; N_SLOTS] = [199, 198, 197, 196, 195, 194, 193, 192, 191];

        let keys = keys()?;
        let sum_cancel_a = std::array::from_fn(|index| {
            encrypt_with_scalar(0, Scalar::from(RANDOMNESS[index]), &keys)
        });
        let sum_cancel_b = std::array::from_fn(|index| {
            encrypt_with_scalar(0, -Scalar::from(RANDOMNESS[index]), &keys)
        });
        assert!(matches!(
            derive_sums_and_zero_tests(&sum_cancel_a, &sum_cancel_b, &keys.generators),
            Err(UniquenessError::DegenerateIdentity {
                kind: DerivedCiphertextKind::Sum,
                index: 0
            })
        ));

        let difference_cancel_a = std::array::from_fn(|index| {
            encrypt_with_scalar(0, Scalar::from(RANDOMNESS[index]), &keys)
        });
        let difference_cancel_b = std::array::from_fn(|index| {
            encrypt_with_scalar(0, Scalar::from(COMPLEMENTS[index]), &keys)
        });
        assert!(matches!(
            derive_sums_and_zero_tests(
                &difference_cancel_a,
                &difference_cancel_b,
                &keys.generators,
            ),
            Err(UniquenessError::DegenerateIdentity {
                kind: DerivedCiphertextKind::Difference,
                index: 0
            })
        ));
        Ok(())
    }
}
