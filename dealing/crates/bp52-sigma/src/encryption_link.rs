//! Batched commitment/encryption link proof.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::{
    ElGamalCiphertext, JointPublicKey, NonZeroScalar, ProtocolGenerators, decode_point,
    decode_scalar,
};
use curve25519_dalek::{RistrettoPoint, Scalar, traits::IsIdentity};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{N_SLOTS, SigmaError, append_index, append_point, challenge_scalar, random_nonzero};

/// Exact serialized size of the nine-slot v1 link proof.
pub const ENCRYPTION_LINK_PROOF_SIZE: usize = N_SLOTS * 6 * 32;

/// One public commitment/ciphertext relation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionLinkStatement {
    /// Pedersen value commitment `V`.
    pub value_commitment: RistrettoPoint,
    /// Exponential-ElGamal ciphertext `(R,S)`.
    pub ciphertext: ElGamalCiphertext,
}

/// Secret opening for one link statement.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionLinkWitness {
    value: Scalar,
    commitment_blinding: Scalar,
    encryption_randomness: NonZeroScalar,
}

impl EncryptionLinkWitness {
    /// Creates one secret relation witness.
    #[must_use]
    pub const fn new(
        value: Scalar,
        commitment_blinding: Scalar,
        encryption_randomness: NonZeroScalar,
    ) -> Self {
        Self {
            value,
            commitment_blinding,
            encryption_randomness,
        }
    }
}

/// Batched nine-slot generalized Schnorr proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionLinkProof {
    commitments: [LinkCommitment; N_SLOTS],
    responses: [LinkResponse; N_SLOTS],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LinkCommitment {
    value: [u8; 32],
    randomness: [u8; 32],
    ciphertext: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LinkResponse {
    value: [u8; 32],
    blinding: [u8; 32],
    randomness: [u8; 32],
}

impl EncryptionLinkProof {
    /// Produces one proof for all nine slots using one shared challenge.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] when a statement is invalid, a witness does not
    /// open its statement, nonce sampling fails, or the challenge is zero.
    pub fn prove<R>(
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        joint_key: &JointPublicKey,
        statements: &[EncryptionLinkStatement; N_SLOTS],
        witnesses: &[EncryptionLinkWitness],
        rng: &mut R,
    ) -> Result<Self, SigmaError>
    where
        R: CryptoRng + RngCore,
    {
        if witnesses.len() != N_SLOTS {
            return Err(SigmaError::VerificationFailed);
        }
        validate_and_append_statements(transcript, statements)?;
        for index in 0..N_SLOTS {
            let witness = &witnesses[index];
            if statements[index].value_commitment
                != witness.value * generators.message()
                    + witness.commitment_blinding * generators.blinding()
                || statements[index].ciphertext.r
                    != witness.encryption_randomness.as_scalar() * generators.blinding()
                || statements[index].ciphertext.s
                    != witness.value * generators.message()
                        + witness.encryption_randomness.as_scalar() * joint_key.as_point()
            {
                return Err(SigmaError::VerificationFailed);
            }
        }

        let mut builder = transcript.build_rng();
        for witness in witnesses {
            let value = Zeroizing::new(witness.value.to_bytes());
            let blinding = Zeroizing::new(witness.commitment_blinding.to_bytes());
            let randomness = Zeroizing::new(witness.encryption_randomness.to_bytes());
            builder = builder
                .rekey_with_witness_bytes(b"value", value.as_ref())
                .rekey_with_witness_bytes(b"commitment-blinding", blinding.as_ref())
                .rekey_with_witness_bytes(b"encryption-randomness", randomness.as_ref());
        }
        let mut nonce_rng = builder.finalize(rng);

        let mut value_nonces = Vec::with_capacity(N_SLOTS);
        let mut blinding_nonces = Vec::with_capacity(N_SLOTS);
        let mut randomness_nonces = Vec::with_capacity(N_SLOTS);
        let mut proof_commitments = [LinkCommitment::default(); N_SLOTS];
        for (index, commitment) in proof_commitments.iter_mut().enumerate() {
            let value_nonce = random_nonzero(&mut nonce_rng)?;
            let blinding_nonce = random_nonzero(&mut nonce_rng)?;
            let randomness_nonce = random_nonzero(&mut nonce_rng)?;
            let temporary_value = value_nonce.as_scalar() * generators.message()
                + blinding_nonce.as_scalar() * generators.blinding();
            let temporary_randomness = randomness_nonce.as_scalar() * generators.blinding();
            let temporary_ciphertext = value_nonce.as_scalar() * generators.message()
                + randomness_nonce.as_scalar() * joint_key.as_point();
            append_link_commitment(
                transcript,
                index,
                &temporary_value,
                &temporary_randomness,
                &temporary_ciphertext,
            );
            *commitment = LinkCommitment {
                value: temporary_value.compress().to_bytes(),
                randomness: temporary_randomness.compress().to_bytes(),
                ciphertext: temporary_ciphertext.compress().to_bytes(),
            };
            value_nonces.push(value_nonce);
            blinding_nonces.push(blinding_nonce);
            randomness_nonces.push(randomness_nonce);
        }

        let challenge = challenge_scalar(transcript)?;
        let mut responses = [LinkResponse::default(); N_SLOTS];
        for index in 0..N_SLOTS {
            responses[index] = LinkResponse {
                value: (value_nonces[index].as_scalar() + challenge * witnesses[index].value)
                    .to_bytes(),
                blinding: (blinding_nonces[index].as_scalar()
                    + challenge * witnesses[index].commitment_blinding)
                    .to_bytes(),
                randomness: (randomness_nonces[index].as_scalar()
                    + challenge * witnesses[index].encryption_randomness.as_scalar())
                .to_bytes(),
            };
        }
        Ok(Self {
            commitments: proof_commitments,
            responses,
        })
    }

    /// Verifies every equation in the nine-slot batch.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] for malformed proof elements, invalid public
    /// statements, a zero challenge, or any failed proof equation.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        joint_key: &JointPublicKey,
        statements: &[EncryptionLinkStatement; N_SLOTS],
    ) -> Result<(), SigmaError> {
        validate_and_append_statements(transcript, statements)?;
        let mut decoded_commitments = Vec::with_capacity(N_SLOTS);
        for (index, commitment) in self.commitments.iter().enumerate() {
            let temporary_value = decode_point(commitment.value, true)?;
            let temporary_randomness = decode_point(commitment.randomness, false)?;
            let temporary_ciphertext = decode_point(commitment.ciphertext, true)?;
            append_link_commitment(
                transcript,
                index,
                &temporary_value,
                &temporary_randomness,
                &temporary_ciphertext,
            );
            decoded_commitments.push((temporary_value, temporary_randomness, temporary_ciphertext));
        }
        let challenge = challenge_scalar(transcript)?;

        let mut valid = true;
        for index in 0..N_SLOTS {
            let response_value = decode_scalar(self.responses[index].value)?;
            let response_blinding = decode_scalar(self.responses[index].blinding)?;
            let response_randomness = decode_scalar(self.responses[index].randomness)?;
            let (temporary_value, temporary_randomness, temporary_ciphertext) =
                &decoded_commitments[index];
            let statement = &statements[index];

            valid &= response_value * generators.message()
                + response_blinding * generators.blinding()
                == temporary_value + challenge * statement.value_commitment;
            valid &= response_randomness * generators.blinding()
                == temporary_randomness + challenge * statement.ciphertext.r;
            valid &= response_value * generators.message()
                + response_randomness * joint_key.as_point()
                == temporary_ciphertext + challenge * statement.ciphertext.s;
        }
        if valid {
            Ok(())
        } else {
            Err(SigmaError::VerificationFailed)
        }
    }
}

impl Encode for EncryptionLinkProof {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        for commitment in &self.commitments {
            writer.write_bytes(&commitment.value);
            writer.write_bytes(&commitment.randomness);
            writer.write_bytes(&commitment.ciphertext);
        }
        for response in &self.responses {
            writer.write_bytes(&response.value);
            writer.write_bytes(&response.blinding);
            writer.write_bytes(&response.randomness);
        }
        Ok(())
    }
}

impl Decode for EncryptionLinkProof {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let mut commitments = [LinkCommitment::default(); N_SLOTS];
        for commitment in &mut commitments {
            *commitment = LinkCommitment {
                value: reader.read_array()?,
                randomness: reader.read_array()?,
                ciphertext: reader.read_array()?,
            };
        }
        let mut responses = [LinkResponse::default(); N_SLOTS];
        for response in &mut responses {
            *response = LinkResponse {
                value: reader.read_array()?,
                blinding: reader.read_array()?,
                randomness: reader.read_array()?,
            };
        }
        Ok(Self {
            commitments,
            responses,
        })
    }
}

fn validate_and_append_statements(
    transcript: &mut Transcript,
    statements: &[EncryptionLinkStatement; N_SLOTS],
) -> Result<(), SigmaError> {
    for (index, statement) in statements.iter().enumerate() {
        if statement.value_commitment.is_identity() || statement.ciphertext.r.is_identity() {
            return Err(SigmaError::Group(
                bp52_group::GroupError::UnexpectedIdentity,
            ));
        }
        append_index(transcript, index);
        append_point(transcript, b"V", &statement.value_commitment);
        append_point(transcript, b"R", &statement.ciphertext.r);
        append_point(transcript, b"S", &statement.ciphertext.s);
    }
    Ok(())
}

fn append_link_commitment(
    transcript: &mut Transcript,
    index: usize,
    value: &RistrettoPoint,
    randomness: &RistrettoPoint,
    ciphertext: &RistrettoPoint,
) {
    append_index(transcript, index);
    append_point(transcript, b"T-V", value);
    append_point(transcript, b"T-R", randomness);
    append_point(transcript, b"T-S", ciphertext);
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use bp52_codec::{Decode, Encode};
    use bp52_group::{
        ElGamalCiphertext, JointPublicKey, NonZeroScalar, ProtocolGenerators, SecretKeyShare,
        commit,
    };
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use merlin::Transcript;
    use rand_core::OsRng;

    use super::{
        ENCRYPTION_LINK_PROOF_SIZE, EncryptionLinkProof, EncryptionLinkStatement,
        EncryptionLinkWitness,
    };
    use crate::N_SLOTS;

    const GAME_ID: [u8; 32] = [42_u8; 32];
    const ATTEMPT: u32 = 7;
    const ALICE_ROLE: u8 = 0;

    fn framed_transcript(game_id: [u8; 32], attempt: u32, role: u8) -> Transcript {
        let mut transcript = Transcript::new(b"BP52/encryption-link/v1");
        transcript.append_message(b"game-id", &game_id);
        transcript.append_message(b"attempt", &attempt.to_le_bytes());
        transcript.append_message(b"role", &[role]);
        transcript
    }

    fn transcript() -> Transcript {
        framed_transcript(GAME_ID, ATTEMPT, ALICE_ROLE)
    }

    fn fixture() -> (
        ProtocolGenerators,
        JointPublicKey,
        [EncryptionLinkStatement; N_SLOTS],
        [EncryptionLinkWitness; N_SLOTS],
    ) {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::from_nonzero(
            NonZeroScalar::new(Scalar::from(101_u64)).unwrap_or_else(|error| panic!("{error}")),
        );
        let secret_b = SecretKeyShare::from_nonzero(
            NonZeroScalar::new(Scalar::from(103_u64)).unwrap_or_else(|error| panic!("{error}")),
        );
        let joint_key = JointPublicKey::combine(
            &secret_a.public_key(&generators),
            &secret_b.public_key(&generators),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut witness_values = Vec::with_capacity(N_SLOTS);
        for index in 0..N_SLOTS {
            let value =
                Scalar::from(u64::try_from(index + 1).unwrap_or_else(|error| panic!("{error}")));
            let index = u64::try_from(index).unwrap_or_else(|error| panic!("{error}"));
            let blinding = Scalar::from(1_000_u64 + index);
            let randomness = NonZeroScalar::new(Scalar::from(2_000_u64 + index))
                .unwrap_or_else(|error| panic!("{error}"));
            let statement = EncryptionLinkStatement {
                value_commitment: commit(value, blinding, &generators),
                ciphertext: ElGamalCiphertext::encrypt(value, &randomness, &joint_key, &generators),
            };
            witness_values.push((
                statement,
                EncryptionLinkWitness::new(value, blinding, randomness),
            ));
        }
        let pairs: [(EncryptionLinkStatement, EncryptionLinkWitness); N_SLOTS] = witness_values
            .try_into()
            .unwrap_or_else(|_| panic!("fixed fixture length"));
        let mut statements = Vec::with_capacity(N_SLOTS);
        let mut witnesses = Vec::with_capacity(N_SLOTS);
        for (statement, witness) in pairs {
            statements.push(statement);
            witnesses.push(witness);
        }
        (
            generators,
            joint_key,
            statements
                .try_into()
                .unwrap_or_else(|_| panic!("fixed fixture length")),
            witnesses
                .try_into()
                .unwrap_or_else(|_| panic!("fixed fixture length")),
        )
    }

    fn alternate_joint_key(generators: &ProtocolGenerators) -> JointPublicKey {
        let secret_a = SecretKeyShare::from_nonzero(
            NonZeroScalar::new(Scalar::from(107_u64)).unwrap_or_else(|error| panic!("{error}")),
        );
        let secret_b = SecretKeyShare::from_nonzero(
            NonZeroScalar::new(Scalar::from(109_u64)).unwrap_or_else(|error| panic!("{error}")),
        );
        JointPublicKey::combine(
            &secret_a.public_key(generators),
            &secret_b.public_key(generators),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn prove_fixture(
        generators: &ProtocolGenerators,
        joint_key: &JointPublicKey,
        statements: &[EncryptionLinkStatement; N_SLOTS],
        witnesses: &[EncryptionLinkWitness; N_SLOTS],
    ) -> EncryptionLinkProof {
        EncryptionLinkProof::prove(
            &mut transcript(),
            generators,
            joint_key,
            statements,
            witnesses,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn assert_statement_rejected(
        proof: &EncryptionLinkProof,
        generators: &ProtocolGenerators,
        joint_key: &JointPublicKey,
        statements: &[EncryptionLinkStatement; N_SLOTS],
    ) {
        assert!(
            proof
                .verify(&mut transcript(), generators, joint_key, statements)
                .is_err()
        );
    }

    #[test]
    fn link_proof_round_trip_and_exact_size() {
        let (generators, joint_key, statements, witnesses) = fixture();
        let proof = prove_fixture(&generators, &joint_key, &statements, &witnesses);
        let bytes = proof
            .encode_to_vec()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(bytes.len(), ENCRYPTION_LINK_PROOF_SIZE);
        let proof =
            EncryptionLinkProof::decode_exact(&bytes).unwrap_or_else(|error| panic!("{error}"));
        proof
            .verify(&mut transcript(), &generators, &joint_key, &statements)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn each_public_equation_and_joint_key_are_bound() {
        let (generators, joint_key, statements, witnesses) = fixture();
        let proof = prove_fixture(&generators, &joint_key, &statements, &witnesses);

        let mut changed_v = statements.clone();
        changed_v[3].value_commitment += generators.message();
        assert_statement_rejected(&proof, &generators, &joint_key, &changed_v);

        let mut changed_r = statements.clone();
        changed_r[3].ciphertext.r += generators.blinding();
        assert_statement_rejected(&proof, &generators, &joint_key, &changed_r);

        let mut changed_s = statements.clone();
        changed_s[3].ciphertext.s += generators.message();
        assert_statement_rejected(&proof, &generators, &joint_key, &changed_s);

        let alternate_joint_key = alternate_joint_key(&generators);
        assert_ne!(alternate_joint_key, joint_key);
        assert_statement_rejected(&proof, &generators, &alternate_joint_key, &statements);
    }

    #[test]
    fn proof_is_bound_to_role_game_attempt_and_slot_order() {
        let (generators, joint_key, statements, witnesses) = fixture();
        let proof = prove_fixture(&generators, &joint_key, &statements, &witnesses);

        for mut changed_context in [
            framed_transcript([43_u8; 32], ATTEMPT, ALICE_ROLE),
            framed_transcript(GAME_ID, ATTEMPT + 1, ALICE_ROLE),
            framed_transcript(GAME_ID, ATTEMPT, 1),
        ] {
            assert!(
                proof
                    .verify(&mut changed_context, &generators, &joint_key, &statements,)
                    .is_err()
            );
        }

        let mut reordered = statements.clone();
        reordered.swap(2, 5);
        assert_statement_rejected(&proof, &generators, &joint_key, &reordered);

        let mut repeated = statements.clone();
        repeated[5] = repeated[2].clone();
        assert_statement_rejected(&proof, &generators, &joint_key, &repeated);
    }

    #[test]
    fn identity_statements_and_malformed_proof_points_are_rejected() {
        let (generators, joint_key, statements, witnesses) = fixture();
        let proof = prove_fixture(&generators, &joint_key, &statements, &witnesses);

        let mut identity_v = statements.clone();
        identity_v[0].value_commitment = RistrettoPoint::default();
        assert_statement_rejected(&proof, &generators, &joint_key, &identity_v);

        let mut identity_r = statements.clone();
        identity_r[0].ciphertext.r = RistrettoPoint::default();
        assert_statement_rejected(&proof, &generators, &joint_key, &identity_r);

        let mut noncanonical = proof
            .encode_to_vec()
            .unwrap_or_else(|error| panic!("{error}"));
        noncanonical[..32].fill(0xff);
        let noncanonical = EncryptionLinkProof::decode_exact(&noncanonical)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_statement_rejected(&noncanonical, &generators, &joint_key, &statements);

        let mut identity_t_r = proof
            .encode_to_vec()
            .unwrap_or_else(|error| panic!("{error}"));
        identity_t_r[32..64].fill(0);
        let identity_t_r = EncryptionLinkProof::decode_exact(&identity_t_r)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_statement_rejected(&identity_t_r, &generators, &joint_key, &statements);
    }
}
