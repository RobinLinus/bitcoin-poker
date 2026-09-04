//! Batched same-key partial-decryption proof.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::{
    GroupError, ProtocolGenerators, PublicKeyShare, SecretKeyShare, decode_point, decode_scalar,
};
use curve25519_dalek::{RistrettoPoint, traits::IsIdentity};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    CANONICAL_ZERO_TESTS, SigmaError, ZERO_TEST_COUNT, append_index, append_point,
    challenge_scalar, random_nonzero, witness_rng,
};

/// Exact serialized size of one 108-entry partial-decryption proof.
pub const PARTIAL_DECRYPT_PROOF_SIZE: usize = (ZERO_TEST_COUNT + 2) * 32;

/// Public same-key decryption relation for one test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialDecryptionStatement {
    /// Final blinded ciphertext `R` component.
    pub ciphertext_r: RistrettoPoint,
    /// Claimed partial decryption `sk*R`.
    pub decryption_share: RistrettoPoint,
}

/// One-nonce DLEQ proof over a public key and 108 decryption shares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialDecryptionProof {
    key_commitment: [u8; 32],
    share_commitments: [[u8; 32]; ZERO_TEST_COUNT],
    response: [u8; 32],
}

impl PartialDecryptionProof {
    /// Produces the complete batch proof.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] when the key witness is inconsistent, a public
    /// statement is invalid, nonce sampling fails, or the challenge is zero.
    pub fn prove<R>(
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        public_key: &PublicKeyShare,
        secret_key: &SecretKeyShare,
        statements: &[PartialDecryptionStatement; ZERO_TEST_COUNT],
        rng: &mut R,
    ) -> Result<Self, SigmaError>
    where
        R: CryptoRng + RngCore,
    {
        if secret_key.public_key(generators) != *public_key {
            return Err(SigmaError::VerificationFailed);
        }
        validate_and_append_statements(transcript, public_key, statements)?;
        let secret_bytes = Zeroizing::new(secret_key.as_nonzero_scalar().to_bytes());
        let mut nonce_rng = witness_rng(transcript, &[secret_bytes.as_ref()], rng);
        let nonce = random_nonzero(&mut nonce_rng)?;
        let temporary_key = nonce.as_scalar() * generators.blinding();
        append_point(transcript, b"T-G", &temporary_key);
        let mut share_commitments = [[0_u8; 32]; ZERO_TEST_COUNT];
        for index in 0..ZERO_TEST_COUNT {
            let temporary = nonce.as_scalar() * statements[index].ciphertext_r;
            append_index(transcript, index);
            append_point(transcript, b"T", &temporary);
            share_commitments[index] = temporary.compress().to_bytes();
        }
        let challenge = challenge_scalar(transcript)?;
        let response = nonce.as_scalar() + challenge * secret_key.as_nonzero_scalar().as_scalar();
        Ok(Self {
            key_commitment: temporary_key.compress().to_bytes(),
            share_commitments,
            response: response.to_bytes(),
        })
    }

    /// Verifies the public-key equation and every decryption-share equation.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] for malformed elements, invalid statements, a
    /// zero challenge, or any failed batch equation.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        public_key: &PublicKeyShare,
        statements: &[PartialDecryptionStatement; ZERO_TEST_COUNT],
    ) -> Result<(), SigmaError> {
        validate_and_append_statements(transcript, public_key, statements)?;
        let temporary_key = decode_point(self.key_commitment, false)?;
        append_point(transcript, b"T-G", &temporary_key);
        let mut temporary_shares = Vec::with_capacity(ZERO_TEST_COUNT);
        for index in 0..ZERO_TEST_COUNT {
            let temporary = decode_point(self.share_commitments[index], false)?;
            append_index(transcript, index);
            append_point(transcript, b"T", &temporary);
            temporary_shares.push(temporary);
        }
        let challenge = challenge_scalar(transcript)?;
        let response = decode_scalar(self.response)?;
        let mut valid =
            response * generators.blinding() == temporary_key + challenge * public_key.as_point();
        for index in 0..ZERO_TEST_COUNT {
            valid &= response * statements[index].ciphertext_r
                == temporary_shares[index] + challenge * statements[index].decryption_share;
        }
        if valid {
            Ok(())
        } else {
            Err(SigmaError::VerificationFailed)
        }
    }
}

impl Encode for PartialDecryptionProof {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_bytes(&self.key_commitment);
        for commitment in &self.share_commitments {
            writer.write_bytes(commitment);
        }
        writer.write_bytes(&self.response);
        Ok(())
    }
}

impl Decode for PartialDecryptionProof {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let key_commitment = reader.read_array()?;
        let mut share_commitments = [[0_u8; 32]; ZERO_TEST_COUNT];
        for commitment in &mut share_commitments {
            *commitment = reader.read_array()?;
        }
        Ok(Self {
            key_commitment,
            share_commitments,
            response: reader.read_array()?,
        })
    }
}

fn validate_and_append_statements(
    transcript: &mut Transcript,
    public_key: &PublicKeyShare,
    statements: &[PartialDecryptionStatement; ZERO_TEST_COUNT],
) -> Result<(), SigmaError> {
    transcript.append_message(b"PK", &public_key.to_bytes());
    for (index, statement) in statements.iter().enumerate() {
        if statement.ciphertext_r.is_identity() || statement.decryption_share.is_identity() {
            return Err(SigmaError::Group(GroupError::UnexpectedIdentity));
        }
        let test = CANONICAL_ZERO_TESTS[index];
        append_index(transcript, index);
        transcript.append_message(b"slot-i", &[test.i]);
        transcript.append_message(b"slot-j", &[test.j]);
        transcript.append_message(b"offset-code", &[test.offset_code]);
        append_point(transcript, b"ciphertext-R", &statement.ciphertext_r);
        append_point(transcript, b"Z", &statement.decryption_share);
    }
    Ok(())
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

    use super::{PARTIAL_DECRYPT_PROOF_SIZE, PartialDecryptionProof, PartialDecryptionStatement};
    use crate::ZERO_TEST_COUNT;

    fn transcript() -> Transcript {
        let mut transcript = Transcript::new(b"BP52/partial-decrypt-A/v1");
        transcript.append_message(b"test-context", b"fixed");
        transcript
    }

    #[test]
    fn partial_decryption_proof_round_trip_and_exact_size() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public_a = secret_a.public_key(&generators);
        let joint_key = JointPublicKey::combine(&public_a, &secret_b.public_key(&generators))
            .unwrap_or_else(|error| panic!("{error}"));
        let statements: [PartialDecryptionStatement; ZERO_TEST_COUNT] =
            std::array::from_fn(|index| {
                let ciphertext = ElGamalCiphertext::encrypt(
                    Scalar::from(
                        u64::try_from(index + 1).unwrap_or_else(|error| panic!("{error}")),
                    ),
                    &NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}")),
                    &joint_key,
                    &generators,
                );
                PartialDecryptionStatement {
                    ciphertext_r: ciphertext.r,
                    decryption_share: secret_a.partial_decrypt(&ciphertext),
                }
            });
        let proof = PartialDecryptionProof::prove(
            &mut transcript(),
            &generators,
            &public_a,
            &secret_a,
            &statements,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let bytes = proof
            .encode_to_vec()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(bytes.len(), PARTIAL_DECRYPT_PROOF_SIZE);
        let proof =
            PartialDecryptionProof::decode_exact(&bytes).unwrap_or_else(|error| panic!("{error}"));
        proof
            .verify(&mut transcript(), &generators, &public_a, &statements)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn incorrect_share_fails() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public_a = secret_a.public_key(&generators);
        let joint_key = JointPublicKey::combine(&public_a, &secret_b.public_key(&generators))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut statements: [PartialDecryptionStatement; ZERO_TEST_COUNT] =
            std::array::from_fn(|index| {
                let ciphertext = ElGamalCiphertext::encrypt(
                    Scalar::from(
                        u64::try_from(index + 1).unwrap_or_else(|error| panic!("{error}")),
                    ),
                    &NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}")),
                    &joint_key,
                    &generators,
                );
                PartialDecryptionStatement {
                    ciphertext_r: ciphertext.r,
                    decryption_share: secret_a.partial_decrypt(&ciphertext),
                }
            });
        let proof = PartialDecryptionProof::prove(
            &mut transcript(),
            &generators,
            &public_a,
            &secret_a,
            &statements,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        statements[9].decryption_share += generators.message();
        assert!(
            proof
                .verify(&mut transcript(), &generators, &public_a, &statements)
                .is_err()
        );
    }
}
