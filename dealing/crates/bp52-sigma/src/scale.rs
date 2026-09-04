//! Batched ciphertext scale proof.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::{
    ElGamalCiphertext, GroupError, NonZeroScalar, ProtocolGenerators, decode_point, decode_scalar,
};
use curve25519_dalek::{RistrettoPoint, traits::IsIdentity};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    CANONICAL_ZERO_TESTS, SigmaError, ZERO_TEST_COUNT, ZeroTestId, append_index, append_point,
    challenge_scalar, random_nonzero,
};

/// Exact serialized size of a 108-entry scale proof.
pub const SCALE_PROOF_SIZE: usize = ZERO_TEST_COUNT * 4 * 32;

/// Public relation for one correctly scaled ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScaleStatement {
    /// Canonical `(i,j,t)` identity.
    pub test: ZeroTestId,
    /// Ciphertext before this scale round.
    pub input: ElGamalCiphertext,
    /// Public nonzero scalar commitment `alpha*G` or `beta*G`.
    pub scale_point: RistrettoPoint,
    /// Ciphertext after multiplying both components.
    pub output: ElGamalCiphertext,
}

/// One-challenge parallel proof over all 108 scaling relations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScaleProof {
    commitments: [ScaleCommitment; ZERO_TEST_COUNT],
    responses: [[u8; 32]; ZERO_TEST_COUNT],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ScaleCommitment {
    base: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
}

impl ScaleProof {
    /// Produces a proof that every statement uses its corresponding nonzero
    /// secret scale factor.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] when canonical statement ordering is violated,
    /// a witness does not match its statement, nonce sampling fails, or the
    /// challenge is zero.
    pub fn prove<R>(
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        statements: &[ScaleStatement; ZERO_TEST_COUNT],
        scale_factors: &[NonZeroScalar],
        rng: &mut R,
    ) -> Result<Self, SigmaError>
    where
        R: CryptoRng + RngCore,
    {
        if scale_factors.len() != ZERO_TEST_COUNT {
            return Err(SigmaError::VerificationFailed);
        }
        validate_and_append_statements(transcript, statements)?;
        for index in 0..ZERO_TEST_COUNT {
            if statements[index].scale_point
                != scale_factors[index].as_scalar() * generators.blinding()
                || statements[index].output
                    != statements[index]
                        .input
                        .scale(scale_factors[index].as_scalar())
            {
                return Err(SigmaError::VerificationFailed);
            }
        }

        let mut builder = transcript.build_rng();
        for scale_factor in scale_factors {
            let bytes = Zeroizing::new(scale_factor.to_bytes());
            builder = builder.rekey_with_witness_bytes(b"scale-factor", bytes.as_ref());
        }
        let mut nonce_rng = builder.finalize(rng);
        let mut nonces = Vec::with_capacity(ZERO_TEST_COUNT);
        let mut commitments = [ScaleCommitment::default(); ZERO_TEST_COUNT];
        for index in 0..ZERO_TEST_COUNT {
            let nonce = random_nonzero(&mut nonce_rng)?;
            let temporary_base = nonce.as_scalar() * generators.blinding();
            let temporary_r = nonce.as_scalar() * statements[index].input.r;
            let temporary_s = nonce.as_scalar() * statements[index].input.s;
            append_commitment(
                transcript,
                index,
                &temporary_base,
                &temporary_r,
                &temporary_s,
            );
            commitments[index] = ScaleCommitment {
                base: temporary_base.compress().to_bytes(),
                r: temporary_r.compress().to_bytes(),
                s: temporary_s.compress().to_bytes(),
            };
            nonces.push(nonce);
        }
        let challenge = challenge_scalar(transcript)?;
        let mut responses = [[0_u8; 32]; ZERO_TEST_COUNT];
        for index in 0..ZERO_TEST_COUNT {
            responses[index] = (nonces[index].as_scalar()
                + challenge * scale_factors[index].as_scalar())
            .to_bytes();
        }
        Ok(Self {
            commitments,
            responses,
        })
    }

    /// Verifies all three equations for every zero-test index.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] for malformed proof elements, noncanonical test
    /// ordering, a zero challenge, or any failed scale equation.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        statements: &[ScaleStatement; ZERO_TEST_COUNT],
    ) -> Result<(), SigmaError> {
        validate_and_append_statements(transcript, statements)?;
        let mut decoded = Vec::with_capacity(ZERO_TEST_COUNT);
        for (index, commitment) in self.commitments.iter().enumerate() {
            let temporary_base = decode_point(commitment.base, false)?;
            let temporary_r = decode_point(commitment.r, false)?;
            let temporary_s = decode_point(commitment.s, true)?;
            append_commitment(
                transcript,
                index,
                &temporary_base,
                &temporary_r,
                &temporary_s,
            );
            decoded.push((temporary_base, temporary_r, temporary_s));
        }
        let challenge = challenge_scalar(transcript)?;
        let mut valid = true;
        for index in 0..ZERO_TEST_COUNT {
            let response = decode_scalar(self.responses[index])?;
            let (temporary_base, temporary_r, temporary_s) = &decoded[index];
            let statement = &statements[index];
            valid &= response * generators.blinding()
                == temporary_base + challenge * statement.scale_point;
            valid &= response * statement.input.r == temporary_r + challenge * statement.output.r;
            valid &= response * statement.input.s == temporary_s + challenge * statement.output.s;
        }
        if valid {
            Ok(())
        } else {
            Err(SigmaError::VerificationFailed)
        }
    }
}

impl Encode for ScaleProof {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        for commitment in &self.commitments {
            writer.write_bytes(&commitment.base);
            writer.write_bytes(&commitment.r);
            writer.write_bytes(&commitment.s);
        }
        for response in &self.responses {
            writer.write_bytes(response);
        }
        Ok(())
    }
}

impl Decode for ScaleProof {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut commitments = [ScaleCommitment::default(); ZERO_TEST_COUNT];
        for commitment in &mut commitments {
            *commitment = ScaleCommitment {
                base: reader.read_array()?,
                r: reader.read_array()?,
                s: reader.read_array()?,
            };
        }
        let mut responses = [[0_u8; 32]; ZERO_TEST_COUNT];
        for response in &mut responses {
            *response = reader.read_array()?;
        }
        Ok(Self {
            commitments,
            responses,
        })
    }
}

fn validate_and_append_statements(
    transcript: &mut Transcript,
    statements: &[ScaleStatement; ZERO_TEST_COUNT],
) -> Result<(), SigmaError> {
    for (index, statement) in statements.iter().enumerate() {
        if statement.test != CANONICAL_ZERO_TESTS[index] {
            return Err(SigmaError::VerificationFailed);
        }
        if statement.scale_point.is_identity()
            || statement.input.r.is_identity()
            || statement.output.r.is_identity()
        {
            return Err(SigmaError::Group(GroupError::UnexpectedIdentity));
        }
        append_index(transcript, index);
        transcript.append_message(b"slot-i", &[statement.test.i]);
        transcript.append_message(b"slot-j", &[statement.test.j]);
        transcript.append_message(b"offset-code", &[statement.test.offset_code]);
        append_point(transcript, b"input-R", &statement.input.r);
        append_point(transcript, b"input-S", &statement.input.s);
        append_point(transcript, b"Q", &statement.scale_point);
        append_point(transcript, b"output-R", &statement.output.r);
        append_point(transcript, b"output-S", &statement.output.s);
    }
    Ok(())
}

fn append_commitment(
    transcript: &mut Transcript,
    index: usize,
    base: &RistrettoPoint,
    r: &RistrettoPoint,
    s: &RistrettoPoint,
) {
    append_index(transcript, index);
    append_point(transcript, b"T-G", base);
    append_point(transcript, b"T-R", r);
    append_point(transcript, b"T-S", s);
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use bp52_codec::{Decode, Encode};
    use bp52_group::{
        ElGamalCiphertext, JointPublicKey, NonZeroScalar, ProtocolGenerators, SecretKeyShare,
    };
    use curve25519_dalek::Scalar;
    use merlin::Transcript;
    use rand_core::OsRng;

    use super::{SCALE_PROOF_SIZE, ScaleProof, ScaleStatement};
    use crate::{CANONICAL_ZERO_TESTS, ZERO_TEST_COUNT};

    fn transcript() -> Transcript {
        let mut transcript = Transcript::new(b"BP52/scale-first/v1");
        transcript.append_message(b"test-context", b"fixed");
        transcript
    }

    fn fixture() -> (
        ProtocolGenerators,
        [ScaleStatement; ZERO_TEST_COUNT],
        [NonZeroScalar; ZERO_TEST_COUNT],
    ) {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let joint_key = JointPublicKey::combine(
            &secret_a.public_key(&generators),
            &secret_b.public_key(&generators),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut statements = Vec::with_capacity(ZERO_TEST_COUNT);
        let mut factors = Vec::with_capacity(ZERO_TEST_COUNT);
        for (index, test) in CANONICAL_ZERO_TESTS.iter().copied().enumerate() {
            let randomness =
                NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
            let input = ElGamalCiphertext::encrypt(
                Scalar::from(u64::try_from(index + 1).unwrap_or_else(|error| panic!("{error}"))),
                &randomness,
                &joint_key,
                &generators,
            );
            let factor =
                NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
            statements.push(ScaleStatement {
                test,
                input: input.clone(),
                scale_point: factor.as_scalar() * generators.blinding(),
                output: input.scale(factor.as_scalar()),
            });
            factors.push(factor);
        }
        (
            generators,
            statements
                .try_into()
                .unwrap_or_else(|_| panic!("fixed fixture length")),
            factors
                .try_into()
                .unwrap_or_else(|_| panic!("fixed fixture length")),
        )
    }

    #[test]
    fn canonical_test_order_has_expected_edges() {
        assert_eq!(CANONICAL_ZERO_TESTS[0].i, 0);
        assert_eq!(CANONICAL_ZERO_TESTS[0].j, 1);
        assert_eq!(CANONICAL_ZERO_TESTS[0].offset(), -52);
        assert_eq!(CANONICAL_ZERO_TESTS[107].i, 7);
        assert_eq!(CANONICAL_ZERO_TESTS[107].j, 8);
        assert_eq!(CANONICAL_ZERO_TESTS[107].offset(), 52);
    }

    #[test]
    fn scale_proof_round_trip_and_exact_size() {
        let (generators, statements, factors) = fixture();
        let proof = ScaleProof::prove(
            &mut transcript(),
            &generators,
            &statements,
            &factors,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let bytes = proof
            .encode_to_vec()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(bytes.len(), SCALE_PROOF_SIZE);
        let proof = ScaleProof::decode_exact(&bytes).unwrap_or_else(|error| panic!("{error}"));
        proof
            .verify(&mut transcript(), &generators, &statements)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn incorrect_component_scaling_fails() {
        let (generators, mut statements, factors) = fixture();
        let proof = ScaleProof::prove(
            &mut transcript(),
            &generators,
            &statements,
            &factors,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        statements[42].output.s += generators.message();
        assert!(
            proof
                .verify(&mut transcript(), &generators, &statements)
                .is_err()
        );
    }
}
