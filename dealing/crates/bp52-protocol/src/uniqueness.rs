//! Verification of the specialized uniqueness tail under authenticated inputs.
//!
//! This module deliberately does not authenticate key setup, bundle openings,
//! proof roots, or identities. Those values are preconditions supplied by the
//! complete attempt driver. Use [`crate::verify_accepted_archive`] for a
//! self-contained public verification of an accepted certificate.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, GroupError, JointPublicKey, ProtocolGenerators,
    PublicKeyShare,
};
use bp52_uniqueness::{
    PARTIAL_DECRYPTION_BATCH_SIZE, PartialDecryptionBatch, SCALE_ROUND_SIZE, ScaleRound,
    UniquenessError, UniquenessResult, derive_sums_and_zero_tests, verify_decryption_batches,
    verify_scale_round,
};

use crate::{
    N_SLOTS, Role,
    contribution::{ContributionError, prevalidate_public_bundles},
    messages::PlayerBundle,
    state::first_blinder,
    transcript::{
        AttemptContext, ProofCommonFrame, ProofDomain, TranscriptError, TranscriptHash,
        proof_transcript,
    },
};

/// Exact size of the standalone public uniqueness certificate.
pub const UNIQUENESS_TRANSCRIPT_SIZE: usize =
    (6 * 32) + (2 * SCALE_ROUND_SIZE) + (2 * PARTIAL_DECRYPTION_BATCH_SIZE);

/// Both threshold public shares and their validated joint key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JointKeyPublic {
    public_a: PublicKeyShare,
    public_b: PublicKeyShare,
    joint: JointPublicKey,
}

impl JointKeyPublic {
    /// Validates two nonidentity, distinct shares and derives their joint key.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError`] when the shares are equal or their sum is the
    /// identity.
    pub fn new(public_a: PublicKeyShare, public_b: PublicKeyShare) -> Result<Self, GroupError> {
        let joint = JointPublicKey::combine(&public_a, &public_b)?;
        Ok(Self {
            public_a,
            public_b,
            joint,
        })
    }

    /// Returns Alice's threshold public share.
    #[must_use]
    pub const fn public_a(&self) -> &PublicKeyShare {
        &self.public_a
    }

    /// Returns Bob's threshold public share.
    #[must_use]
    pub const fn public_b(&self) -> &PublicKeyShare {
        &self.public_b
    }

    /// Returns the validated joint threshold key.
    #[must_use]
    pub const fn joint(&self) -> &JointPublicKey {
        &self.joint
    }
}

/// Complete public values needed to replay both blinding and decryption rounds.
///
/// Phase roots are the authenticated hash-chain snapshots `T_10`, `T_11`, and
/// `T_12`. A full attempt verifier must derive them from signed envelopes; this
/// standalone type preserves them for deterministic public verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniquenessTranscript {
    /// Canonical Alice x-only Bitcoin identity bytes.
    pub alice_identity: [u8; 32],
    /// Canonical Bob x-only Bitcoin identity bytes.
    pub bob_identity: [u8; 32],
    /// Exact fixed hash-length circuit identifier shared by both bundles.
    pub circuit_id: [u8; 32],
    /// Shared root before the first scale message (`T_10`).
    pub scale_first_root: TranscriptHash,
    /// First blinder's complete 108-entry round.
    pub scale_first: Box<ScaleRound>,
    /// Root after the first scale message (`T_11`).
    pub scale_second_root: TranscriptHash,
    /// Other party's complete 108-entry round.
    pub scale_second: Box<ScaleRound>,
    /// Shared root before both decryption commitments (`T_12`).
    pub partial_decrypt_root: TranscriptHash,
    /// Alice's 108 partial decryptions and proof.
    pub partial_a: Box<PartialDecryptionBatch>,
    /// Bob's 108 partial decryptions and proof.
    pub partial_b: Box<PartialDecryptionBatch>,
}

/// Failures while replaying a standalone public uniqueness certificate.
#[derive(Debug, thiserror::Error)]
pub enum UniquenessTranscriptError {
    /// The caller did not anchor verification at the archived `T_10` root.
    #[error("attempt context is not anchored at the first-scale root")]
    FirstPhaseRootMismatch,
    /// A bundle claimed the wrong canonical role.
    #[error("player-bundle role mismatch")]
    BundleRoleMismatch,
    /// The bundles and public certificate did not name one circuit.
    #[error("player-bundle circuit identifier mismatch")]
    CircuitMismatch,
    /// A fixed-size internal conversion failed.
    #[error("internal fixed-size contribution conversion failed")]
    InternalShape,
    /// Public bundle prevalidation failed.
    #[error(transparent)]
    Contribution(#[from] ContributionError),
    /// A public key or ciphertext component was invalid.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// Common proof framing was invalid.
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
    /// A derivation, scale proof, decryption proof, or zero-test evaluation failed.
    #[error(transparent)]
    Uniqueness(#[from] UniquenessError),
}

/// Replays the uniqueness tail and returns all 108 results.
///
/// `attempt_context.prior_transcript` must be the authenticated `T_10` root.
/// The remaining roots must likewise come from a verified signed-envelope
/// archive; proof verification binds every round to the supplied snapshots.
/// This function does not itself authenticate those roots, the identities,
/// the key `PoPs`, either bundle commitment, or either bundle proof.
///
/// # Errors
///
/// Returns [`UniquenessTranscriptError`] for a context, role, circuit, point,
/// ordering, proof, or decryption failure. A derived-`R` cancellation remains
/// distinguishable as [`UniquenessError::DegenerateIdentity`] inside the error
/// and must be handled as a neutral retry by the attempt state machine.
pub fn verify_uniqueness_transcript_detailed(
    attempt_context: &AttemptContext,
    key_setup: &JointKeyPublic,
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
    transcript: &UniquenessTranscript,
) -> Result<UniquenessResult, UniquenessTranscriptError> {
    if attempt_context.prior_transcript != transcript.scale_first_root {
        return Err(UniquenessTranscriptError::FirstPhaseRootMismatch);
    }
    if bundle_a.role != Role::Alice || bundle_b.role != Role::Bob {
        return Err(UniquenessTranscriptError::BundleRoleMismatch);
    }
    if bundle_a.circuit_id != transcript.circuit_id || bundle_b.circuit_id != transcript.circuit_id
    {
        return Err(UniquenessTranscriptError::CircuitMismatch);
    }
    prevalidate_public_bundles(bundle_a, bundle_b)?;

    let common = ProofCommonFrame::new(
        transcript.alice_identity,
        transcript.bob_identity,
        key_setup.joint(),
        transcript.circuit_id,
    )?;
    let generators = ProtocolGenerators::derive()?;
    let contributions_a = decode_contributions(bundle_a)?;
    let contributions_b = decode_contributions(bundle_b)?;
    let derived = derive_sums_and_zero_tests(&contributions_a, &contributions_b, &generators)?;

    let first_role = first_blinder(&attempt_context.game_id, attempt_context.attempt);
    let second_role = other_role(first_role);
    let first_context = AttemptContext::with_prior_transcript(
        attempt_context.game_id,
        attempt_context.attempt,
        transcript.scale_first_root,
    );
    verify_scale_round(
        &mut proof_transcript(ProofDomain::ScaleFirst, &first_context, first_role, &common)?,
        &generators,
        &derived.differences,
        &transcript.scale_first,
    )?;

    let second_context = AttemptContext::with_prior_transcript(
        attempt_context.game_id,
        attempt_context.attempt,
        transcript.scale_second_root,
    );
    verify_scale_round(
        &mut proof_transcript(
            ProofDomain::ScaleSecond,
            &second_context,
            second_role,
            &common,
        )?,
        &generators,
        &transcript.scale_first.outputs,
        &transcript.scale_second,
    )?;

    let decrypt_context = AttemptContext::with_prior_transcript(
        attempt_context.game_id,
        attempt_context.attempt,
        transcript.partial_decrypt_root,
    );
    Ok(verify_decryption_batches(
        &mut proof_transcript(
            ProofDomain::PartialDecryptAlice,
            &decrypt_context,
            Role::Alice,
            &common,
        )?,
        &mut proof_transcript(
            ProofDomain::PartialDecryptBob,
            &decrypt_context,
            Role::Bob,
            &common,
        )?,
        &generators,
        key_setup.public_a(),
        key_setup.public_b(),
        &transcript.scale_second.outputs,
        &transcript.partial_a,
        &transcript.partial_b,
    )?)
}

/// Replays the uniqueness tail and returns only the uniqueness decision.
///
/// # Errors
///
/// Returns the same errors as [`verify_uniqueness_transcript_detailed`].
pub fn verify_uniqueness_transcript(
    attempt_context: &AttemptContext,
    key_setup: &JointKeyPublic,
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
    transcript: &UniquenessTranscript,
) -> Result<bool, UniquenessTranscriptError> {
    Ok(verify_uniqueness_transcript_detailed(
        attempt_context,
        key_setup,
        bundle_a,
        bundle_b,
        transcript,
    )?
    .is_unique)
}

impl Encode for UniquenessTranscript {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        if self.alice_identity >= self.bob_identity {
            return Err(CodecError::NonCanonical);
        }
        self.alice_identity.encode(writer)?;
        self.bob_identity.encode(writer)?;
        self.circuit_id.encode(writer)?;
        self.scale_first_root.encode(writer)?;
        self.scale_first.encode(writer)?;
        self.scale_second_root.encode(writer)?;
        self.scale_second.encode(writer)?;
        self.partial_decrypt_root.encode(writer)?;
        self.partial_a.encode(writer)?;
        self.partial_b.encode(writer)
    }
}

impl Decode for UniquenessTranscript {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let alice_identity = Decode::decode(reader)?;
        let bob_identity = Decode::decode(reader)?;
        if alice_identity >= bob_identity {
            return Err(CodecError::NonCanonical);
        }
        Ok(Self {
            alice_identity,
            bob_identity,
            circuit_id: Decode::decode(reader)?,
            scale_first_root: Decode::decode(reader)?,
            scale_first: Box::new(ScaleRound::decode(reader)?),
            scale_second_root: Decode::decode(reader)?,
            scale_second: Box::new(ScaleRound::decode(reader)?),
            partial_decrypt_root: Decode::decode(reader)?,
            partial_a: Box::new(PartialDecryptionBatch::decode(reader)?),
            partial_b: Box::new(PartialDecryptionBatch::decode(reader)?),
        })
    }
}

fn decode_contributions(
    bundle: &PlayerBundle,
) -> Result<[ElGamalCiphertext; N_SLOTS], UniquenessTranscriptError> {
    let mut contributions = Vec::with_capacity(N_SLOTS);
    for slot in &bundle.slots {
        contributions.push(CiphertextBytes::from(slot.ciphertext).decompress_contribution()?);
    }
    contributions
        .try_into()
        .map_err(|_| UniquenessTranscriptError::InternalShape)
}

const fn other_role(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use bp52_codec::{Decode, Encode};
    use bp52_group::{
        ElGamalCiphertext, NonZeroScalar, ProtocolGenerators, SecretKeyShare, commit,
    };
    use bp52_uniqueness::{generate_partial_decryption_batch, generate_scale_round};
    use curve25519_dalek::Scalar;
    use rand_core::OsRng;

    use super::{
        JointKeyPublic, UNIQUENESS_TRANSCRIPT_SIZE, UniquenessTranscript,
        verify_uniqueness_transcript, verify_uniqueness_transcript_detailed,
    };
    use crate::{
        Role,
        messages::{
            Ciphertext, ENCRYPTION_LINK_PROOF_SIZE, HASH_LENGTH_PROOF_SIZE, PlayerBundle,
            SlotPublic,
        },
        state::first_blinder,
        transcript::{AttemptContext, ProofCommonFrame, ProofDomain, proof_transcript},
    };

    struct Fixture {
        context: AttemptContext,
        keys: JointKeyPublic,
        alice: PlayerBundle,
        bob: PlayerBundle,
        transcript: UniquenessTranscript,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let generators = ProtocolGenerators::derive()?;
        let secret_a = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(13_u64))?);
        let secret_b = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(29_u64))?);
        let public_a = secret_a.public_key(&generators);
        let public_b = secret_b.public_key(&generators);
        let keys = JointKeyPublic::new(public_a, public_b)?;
        let circuit_id = [0x44_u8; 32];
        let alice = bundle(Role::Alice, 0, &keys, &generators, circuit_id);
        let bob = bundle(Role::Bob, 70, &keys, &generators, circuit_id);

        let game_id = [0x33_u8; 32];
        let attempt = 7;
        let first_root = [0x10_u8; 32];
        let second_root = [0x11_u8; 32];
        let decrypt_root = [0x12_u8; 32];
        let context = AttemptContext::with_prior_transcript(game_id, attempt, first_root);
        let common = ProofCommonFrame::new([1_u8; 32], [2_u8; 32], keys.joint(), circuit_id)?;
        let contributions_a = super::decode_contributions(&alice)?;
        let contributions_b = super::decode_contributions(&bob)?;
        let derived = bp52_uniqueness::derive_sums_and_zero_tests(
            &contributions_a,
            &contributions_b,
            &generators,
        )?;

        let first_role = first_blinder(&game_id, attempt);
        let second_role = super::other_role(first_role);
        let first_context = AttemptContext::with_prior_transcript(game_id, attempt, first_root);
        let scale_first = Box::new(generate_scale_round(
            &mut proof_transcript(ProofDomain::ScaleFirst, &first_context, first_role, &common)?,
            &generators,
            &derived.differences,
            &mut OsRng,
        )?);
        let second_context = AttemptContext::with_prior_transcript(game_id, attempt, second_root);
        let scale_second = Box::new(generate_scale_round(
            &mut proof_transcript(
                ProofDomain::ScaleSecond,
                &second_context,
                second_role,
                &common,
            )?,
            &generators,
            &scale_first.outputs,
            &mut OsRng,
        )?);
        let decrypt_context = AttemptContext::with_prior_transcript(game_id, attempt, decrypt_root);
        let partial_a = Box::new(generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &decrypt_context,
                Role::Alice,
                &common,
            )?,
            &generators,
            keys.public_a(),
            &secret_a,
            &scale_second.outputs,
            &mut OsRng,
        )?);
        let partial_b = Box::new(generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptBob,
                &decrypt_context,
                Role::Bob,
                &common,
            )?,
            &generators,
            keys.public_b(),
            &secret_b,
            &scale_second.outputs,
            &mut OsRng,
        )?);

        Ok(Fixture {
            context,
            keys,
            alice,
            bob,
            transcript: UniquenessTranscript {
                alice_identity: [1_u8; 32],
                bob_identity: [2_u8; 32],
                circuit_id,
                scale_first_root: first_root,
                scale_first,
                scale_second_root: second_root,
                scale_second,
                partial_decrypt_root: decrypt_root,
                partial_a,
                partial_b,
            },
        })
    }

    #[allow(clippy::panic)]
    fn bundle(
        role: Role,
        marker_base: u8,
        keys: &JointKeyPublic,
        generators: &ProtocolGenerators,
        circuit_id: [u8; 32],
    ) -> PlayerBundle {
        let slots = std::array::from_fn(|index| {
            let value = match role {
                Role::Alice => u8::try_from(index).unwrap_or(0),
                Role::Bob => 0,
            };
            let randomness_value = u64::from(marker_base) + u64::try_from(index).unwrap_or(0) + 1;
            let randomness = NonZeroScalar::new(Scalar::from(randomness_value))
                .unwrap_or_else(|error| panic!("fixed nonzero randomness: {error}"));
            let ciphertext = ElGamalCiphertext::encrypt(
                Scalar::from(u64::from(value)),
                &randomness,
                keys.joint(),
                generators,
            );
            SlotPublic {
                hash: [marker_base.wrapping_add(u8::try_from(index).unwrap_or(0)); 32],
                value_commitment: commit(
                    Scalar::from(u64::from(value)),
                    Scalar::from(randomness_value + 200),
                    generators,
                )
                .compress()
                .to_bytes(),
                ciphertext: Ciphertext::from(ciphertext.to_bytes()),
            }
        });
        PlayerBundle {
            role,
            slots,
            circuit_id,
            hash_length_proof: vec![0_u8; HASH_LENGTH_PROOF_SIZE],
            encryption_link_proof: vec![0_u8; ENCRYPTION_LINK_PROOF_SIZE],
        }
    }

    #[test]
    #[allow(clippy::panic)]
    fn complete_public_replay_accepts_and_is_canonically_encoded()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let result = verify_uniqueness_transcript_detailed(
            &fixture.context,
            &fixture.keys,
            &fixture.alice,
            &fixture.bob,
            &fixture.transcript,
        )?;
        assert!(result.is_unique);
        assert!(result.collision_bitmap.iter().all(|collision| !collision));
        assert!(verify_uniqueness_transcript(
            &fixture.context,
            &fixture.keys,
            &fixture.alice,
            &fixture.bob,
            &fixture.transcript,
        )?);

        let encoded = fixture.transcript.encode_to_vec()?;
        assert_eq!(encoded.len(), UNIQUENESS_TRANSCRIPT_SIZE);
        assert_eq!(
            UniquenessTranscript::decode_exact(&encoded)?,
            fixture.transcript
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::panic)]
    fn replay_rejects_wrong_phase_roots_and_tampered_rounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture()?;
        fixture.context.prior_transcript[0] ^= 1;
        assert!(
            verify_uniqueness_transcript(
                &fixture.context,
                &fixture.keys,
                &fixture.alice,
                &fixture.bob,
                &fixture.transcript,
            )
            .is_err()
        );

        fixture.context.prior_transcript = fixture.transcript.scale_first_root;
        fixture.transcript.scale_second_root[0] ^= 1;
        assert!(
            verify_uniqueness_transcript(
                &fixture.context,
                &fixture.keys,
                &fixture.alice,
                &fixture.bob,
                &fixture.transcript,
            )
            .is_err()
        );
        Ok(())
    }
}
