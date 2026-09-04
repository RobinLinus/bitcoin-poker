//! Composition of contribution statements into complete player bundles.

use bp52_circuit::hash_length::{
    AGGREGATED_SLOTS, HASH_LENGTH_PROOF_SIZE, HashLengthError, HashLengthParameters,
    HashLengthProofError, MESSAGE_BUFFER_BYTES, SLOT_HASH_LENGTH_PROOF_SIZE,
    prove_hash_length_slot, prove_hash_lengths, verify_hash_lengths, witness_buffer,
};
use bp52_codec::{CodecError, Decode, Encode};
use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, GroupError, JointPublicKey, NonZeroScalar,
    ProtocolGenerators, commit, decode_point,
};
use bp52_sigma::{
    SigmaError,
    encryption_link::{
        ENCRYPTION_LINK_PROOF_SIZE, EncryptionLinkProof, EncryptionLinkStatement,
        EncryptionLinkWitness,
    },
};
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    DECK_SIZE, N_SLOTS, PREIMAGE_BASE_LEN, Role,
    contribution::{
        ContributionError, SecretContribution, generate_contribution, prevalidate_public_bundles,
        validate_original_contribution_points,
    },
    messages::{PlayerBundle, SlotPublic},
    transcript::{
        AttemptContext, ProofCommonFrame, ProofDomain, TranscriptError, proof_transcript,
    },
};

const _: [(); N_SLOTS] = [(); AGGREGATED_SLOTS];
const _: [(); HASH_LENGTH_PROOF_SIZE] = [(); crate::messages::HASH_LENGTH_PROOF_SIZE];
const _: [(); ENCRYPTION_LINK_PROOF_SIZE] = [(); crate::messages::ENCRYPTION_LINK_PROOF_SIZE];

/// Failures while constructing or verifying a complete player bundle.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// Contribution generation or public prevalidation failed.
    #[error(transparent)]
    Contribution(#[from] ContributionError),
    /// A point or secret scalar failed group validation.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// Fixed hash-witness preparation failed.
    #[error(transparent)]
    HashWitness(#[from] HashLengthError),
    /// R1CS proof construction or verification failed.
    #[error(transparent)]
    HashLengthProof(#[from] HashLengthProofError),
    /// Encryption-link proof construction or verification failed.
    #[error(transparent)]
    EncryptionLinkProof(#[from] SigmaError),
    /// Canonical proof encoding or decoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The proof transcript frame was invalid.
    #[error(transparent)]
    Transcript(#[from] TranscriptError),
    /// The bundle role was not the authenticated prover role.
    #[error("player-bundle role mismatch: expected {expected:?}, got {actual:?}")]
    RoleMismatch {
        /// Role selected by the authenticated protocol flight.
        expected: Role,
        /// Role encoded inside the bundle.
        actual: Role,
    },
    /// The common transcript frame names another joint public key.
    #[error("proof common frame has the wrong joint public key")]
    ContextJointKeyMismatch,
    /// The common transcript frame names another hash-length circuit.
    #[error("proof common frame has the wrong circuit identifier")]
    ContextCircuitMismatch,
    /// The bundle names a circuit other than the locally compiled circuit.
    #[error("player bundle has the wrong circuit identifier")]
    BundleCircuitMismatch,
    /// The R1CS proof vector did not have the one exact manifest-derived size.
    #[error("wrong hash-length proof size: {actual} bytes")]
    HashLengthProofSize {
        /// Actual in-memory proof-vector length.
        actual: usize,
    },
    /// The encryption-link proof vector did not have its fixed profile size.
    #[error("wrong encryption-link proof size: {actual} bytes")]
    EncryptionLinkProofSize {
        /// Actual in-memory proof-vector length.
        actual: usize,
    },
    /// Supplied public slots and secret openings did not describe one relation.
    #[error("secret contribution does not open public slot {slot}")]
    SecretOpeningMismatch {
        /// First inconsistent slot.
        slot: usize,
    },
    /// An internal fixed-size conversion disagreed with the v1 profile.
    #[error("internal player-bundle shape mismatch")]
    InternalShape,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct HashWitness {
    values: [u8; N_SLOTS],
    blindings: [Scalar; N_SLOTS],
    message_buffers: [[u8; MESSAGE_BUFFER_BYTES]; N_SLOTS],
}

/// Generates fresh contributions and proves both nine-slot bundle relations.
///
/// `context` must contain the authenticated `T_6` snapshot for the player
/// bundle flight. `common` must name `joint_key` and the circuit identifier in
/// `parameters`.
///
/// # Errors
///
/// Returns an error when contribution sampling, context validation, witness
/// preparation, or either proof system fails. Secret material is zeroized on
/// every error path.
pub fn generate_player_bundle<R>(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    role: Role,
    joint_key: &JointPublicKey,
    rng: &mut R,
) -> Result<(PlayerBundle, SecretContribution), BundleError>
where
    R: CryptoRng + RngCore,
{
    validate_common_frame(parameters.circuit_id(), joint_key, common)?;
    let (slots, secrets) = generate_contribution(joint_key, &mut *rng)?;
    let bundle = prove_player_bundle(
        parameters, context, common, role, joint_key, slots, &secrets, rng,
    )?;
    Ok((bundle, secrets))
}

/// Generates the public slots and zeroizing openings before independent proof work.
pub fn generate_player_bundle_material<R>(
    joint_key: &JointPublicKey,
    rng: &mut R,
) -> Result<([SlotPublic; N_SLOTS], SecretContribution), BundleError>
where
    R: CryptoRng + RngCore,
{
    Ok(generate_contribution(joint_key, rng)?)
}

/// Proves one fixed slot so browser workers can process all nine slots concurrently.
#[allow(clippy::too_many_arguments)]
pub fn prove_player_bundle_hash_slot(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    role: Role,
    joint_key: &JointPublicKey,
    slots: &[SlotPublic; N_SLOTS],
    secrets: &SecretContribution,
    slot: usize,
) -> Result<Vec<u8>, BundleError> {
    validate_common_frame(parameters.circuit_id(), joint_key, common)?;
    validate_original_contribution_points(slots)?;
    let public = slots.get(slot).ok_or(BundleError::InternalShape)?;
    let value = *secrets
        .values()
        .get(slot)
        .ok_or(BundleError::InternalShape)?;
    let blinding = *secrets
        .commitment_blinding_values()
        .get(slot)
        .ok_or(BundleError::InternalShape)?;
    let preimage = secrets
        .preimages()
        .get(slot)
        .ok_or(BundleError::InternalShape)?;
    let message_buffer = witness_buffer(preimage)?;
    Ok(prove_hash_length_slot(
        parameters,
        proof_transcript(ProofDomain::HashLength, context, role, common)?,
        slot,
        &public.hash,
        &public.value_commitment,
        value,
        blinding,
        message_buffer.as_array(),
    )?)
}

/// Assembles nine independently generated slot proofs with the batched link proof.
#[allow(clippy::too_many_arguments)]
pub fn assemble_player_bundle<R>(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    role: Role,
    joint_key: &JointPublicKey,
    slots: [SlotPublic; N_SLOTS],
    secrets: &SecretContribution,
    slot_proofs: &[Vec<u8>],
    rng: &mut R,
) -> Result<PlayerBundle, BundleError>
where
    R: CryptoRng + RngCore,
{
    validate_common_frame(parameters.circuit_id(), joint_key, common)?;
    validate_original_contribution_points(&slots)?;
    validate_secret_openings(&slots, secrets, joint_key, &ProtocolGenerators::derive()?)?;
    if slot_proofs.len() != N_SLOTS
        || slot_proofs
            .iter()
            .any(|proof| proof.len() != SLOT_HASH_LENGTH_PROOF_SIZE)
    {
        return Err(BundleError::HashLengthProofSize {
            actual: slot_proofs.iter().map(Vec::len).sum(),
        });
    }
    let mut hash_length_proof = Vec::with_capacity(HASH_LENGTH_PROOF_SIZE);
    for proof in slot_proofs {
        hash_length_proof.extend_from_slice(proof);
    }
    let generators = ProtocolGenerators::derive()?;
    let statements = decode_link_statements(&slots)?;
    let witnesses = build_link_witnesses(secrets)?;
    let encryption_link_proof = prove_link_proof(
        context,
        common,
        role,
        joint_key,
        &generators,
        &statements,
        &witnesses,
        rng,
    )?;
    validate_link_proof_size(&encryption_link_proof)?;
    Ok(PlayerBundle {
        role,
        slots,
        circuit_id: parameters.circuit_id(),
        hash_length_proof,
        encryption_link_proof,
    })
}

/// Proves a complete bundle from an already generated contribution.
///
/// This split API is useful when contribution generation and proof production
/// occur in separate internal stages. The public slots are copied into the
/// resulting canonical bundle; the secret container is only borrowed.
///
/// # Errors
///
/// Returns an error for a mismatched transcript frame, malformed public slot,
/// inconsistent secret opening, or failure in either proof system.
#[allow(clippy::too_many_arguments)]
pub fn prove_player_bundle<R>(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    role: Role,
    joint_key: &JointPublicKey,
    slots: [SlotPublic; N_SLOTS],
    secrets: &SecretContribution,
    rng: &mut R,
) -> Result<PlayerBundle, BundleError>
where
    R: CryptoRng + RngCore,
{
    let circuit_id = parameters.circuit_id();
    validate_common_frame(circuit_id, joint_key, common)?;
    validate_original_contribution_points(&slots)?;

    let generators = ProtocolGenerators::derive()?;
    validate_secret_openings(&slots, secrets, joint_key, &generators)?;
    let (public_hashes, public_commitments) = public_hash_inputs(&slots);
    let hash_witness = prepare_hash_witness(secrets)?;
    let hash_length_proof = prove_hash_lengths(
        parameters,
        proof_transcript(ProofDomain::HashLength, context, role, common)?,
        &public_hashes,
        &public_commitments,
        &hash_witness.values,
        &hash_witness.blindings,
        &hash_witness.message_buffers,
    )?;
    validate_hash_proof_size(&hash_length_proof)?;

    let statements = decode_link_statements(&slots)?;
    let witnesses = build_link_witnesses(secrets)?;
    let encryption_link_proof = prove_link_proof(
        context,
        common,
        role,
        joint_key,
        &generators,
        &statements,
        &witnesses,
        rng,
    )?;
    validate_link_proof_size(&encryption_link_proof)?;

    Ok(PlayerBundle {
        role,
        slots,
        circuit_id,
        hash_length_proof,
        encryption_link_proof,
    })
}

/// Verifies one bundle's role, context, points, and both proofs.
///
/// This verifies every single-player relation. It cannot enforce the
/// pair-level requirement that all 18 hash locks are distinct; callers with
/// both bundles should prefer [`verify_player_bundle_pair`].
///
/// # Errors
///
/// Returns an error for any context/header mismatch, malformed original point,
/// noncanonical proof, or failed proof equation.
pub fn verify_player_bundle(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    expected_role: Role,
    joint_key: &JointPublicKey,
    bundle: &PlayerBundle,
) -> Result<(), BundleError> {
    validate_common_frame(parameters.circuit_id(), joint_key, common)?;
    validate_bundle_header(parameters.circuit_id(), expected_role, bundle)?;
    validate_original_contribution_points(&bundle.slots)?;
    verify_bundle_proofs(parameters, context, common, joint_key, bundle)
}

/// Verifies Alice and Bob's bundles with the global 18-hash requirement.
///
/// The check order is circuit/header lengths, global hash distinctness,
/// original-point validity, then Alice and Bob's two proofs.
///
/// # Errors
///
/// Returns an error when either bundle is malformed, any two hash locks are
/// equal, a transcript context is inconsistent, or any proof fails.
pub fn verify_player_bundle_pair(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    joint_key: &JointPublicKey,
    alice: &PlayerBundle,
    bob: &PlayerBundle,
) -> Result<(), BundleError> {
    let circuit_id = parameters.circuit_id();
    validate_common_frame(circuit_id, joint_key, common)?;
    validate_bundle_header(circuit_id, Role::Alice, alice)?;
    validate_bundle_header(circuit_id, Role::Bob, bob)?;
    prevalidate_public_bundles(alice, bob)?;
    verify_bundle_proofs(parameters, context, common, joint_key, alice)?;
    verify_bundle_proofs(parameters, context, common, joint_key, bob)
}

fn verify_bundle_proofs(
    parameters: &HashLengthParameters,
    context: &AttemptContext,
    common: &ProofCommonFrame,
    joint_key: &JointPublicKey,
    bundle: &PlayerBundle,
) -> Result<(), BundleError> {
    let (public_hashes, public_commitments) = public_hash_inputs(&bundle.slots);
    verify_hash_lengths(
        parameters,
        proof_transcript(ProofDomain::HashLength, context, bundle.role, common)?,
        &public_hashes,
        &public_commitments,
        &bundle.hash_length_proof,
    )?;

    let generators = ProtocolGenerators::derive()?;
    let statements = decode_link_statements(&bundle.slots)?;
    verify_link_proof(
        context,
        common,
        bundle.role,
        joint_key,
        &generators,
        &statements,
        &bundle.encryption_link_proof,
    )
}

fn validate_common_frame(
    circuit_id: [u8; 32],
    joint_key: &JointPublicKey,
    common: &ProofCommonFrame,
) -> Result<(), BundleError> {
    if common.joint_key() != &joint_key.to_bytes() {
        return Err(BundleError::ContextJointKeyMismatch);
    }
    if common.circuit_id() != &circuit_id {
        return Err(BundleError::ContextCircuitMismatch);
    }
    Ok(())
}

fn validate_bundle_header(
    circuit_id: [u8; 32],
    expected_role: Role,
    bundle: &PlayerBundle,
) -> Result<(), BundleError> {
    if bundle.role != expected_role {
        return Err(BundleError::RoleMismatch {
            expected: expected_role,
            actual: bundle.role,
        });
    }
    if bundle.circuit_id != circuit_id {
        return Err(BundleError::BundleCircuitMismatch);
    }
    validate_hash_proof_size(&bundle.hash_length_proof)?;
    validate_link_proof_size(&bundle.encryption_link_proof)
}

fn validate_hash_proof_size(proof: &[u8]) -> Result<(), BundleError> {
    if proof.len() == HASH_LENGTH_PROOF_SIZE {
        Ok(())
    } else {
        Err(BundleError::HashLengthProofSize {
            actual: proof.len(),
        })
    }
}

fn validate_link_proof_size(proof: &[u8]) -> Result<(), BundleError> {
    if proof.len() == ENCRYPTION_LINK_PROOF_SIZE {
        Ok(())
    } else {
        Err(BundleError::EncryptionLinkProofSize {
            actual: proof.len(),
        })
    }
}

fn public_hash_inputs(slots: &[SlotPublic; N_SLOTS]) -> ([[u8; 32]; N_SLOTS], [[u8; 32]; N_SLOTS]) {
    (
        core::array::from_fn(|index| slots[index].hash),
        core::array::from_fn(|index| slots[index].value_commitment),
    )
}

fn prepare_hash_witness(secrets: &SecretContribution) -> Result<HashWitness, BundleError> {
    // Install the zeroizing owner before the first fallible per-slot copy so
    // an invalid later preimage erases all buffers already prepared.
    let mut hash_witness = HashWitness {
        values: *secrets.values(),
        blindings: *secrets.commitment_blinding_values(),
        message_buffers: [[0_u8; MESSAGE_BUFFER_BYTES]; N_SLOTS],
    };
    for (index, buffer) in hash_witness.message_buffers.iter_mut().enumerate() {
        let witness = witness_buffer(secrets.preimages()[index].as_slice())?;
        buffer.copy_from_slice(witness.as_array());
    }
    Ok(hash_witness)
}

fn validate_secret_openings(
    slots: &[SlotPublic; N_SLOTS],
    secrets: &SecretContribution,
    joint_key: &JointPublicKey,
    generators: &ProtocolGenerators,
) -> Result<(), BundleError> {
    for (index, slot) in slots.iter().enumerate() {
        let value = secrets.values()[index];
        let preimage = &secrets.preimages()[index];
        let blinding = secrets.commitment_blinding_values()[index];
        let randomness = secrets.encryption_randomness_values()[index];
        if value >= DECK_SIZE
            || preimage.len() != PREIMAGE_BASE_LEN + usize::from(value)
            || <[u8; 32]>::from(Sha256::digest(preimage)) != slot.hash
            || blinding == Scalar::ZERO
        {
            return Err(BundleError::SecretOpeningMismatch { slot: index });
        }

        let value_scalar = Scalar::from(u64::from(value));
        if commit(value_scalar, blinding, generators)
            .compress()
            .to_bytes()
            != slot.value_commitment
        {
            return Err(BundleError::SecretOpeningMismatch { slot: index });
        }
        let randomness = NonZeroScalar::new(randomness)
            .map_err(|_| BundleError::SecretOpeningMismatch { slot: index })?;
        if CiphertextBytes::from(slot.ciphertext)
            != ElGamalCiphertext::encrypt(value_scalar, &randomness, joint_key, generators)
                .to_bytes()
        {
            return Err(BundleError::SecretOpeningMismatch { slot: index });
        }
    }
    Ok(())
}

fn decode_link_statements(
    slots: &[SlotPublic; N_SLOTS],
) -> Result<[EncryptionLinkStatement; N_SLOTS], BundleError> {
    let mut statements = Vec::with_capacity(N_SLOTS);
    for slot in slots {
        statements.push(EncryptionLinkStatement {
            value_commitment: decode_point(slot.value_commitment, false)?,
            ciphertext: CiphertextBytes::from(slot.ciphertext).decompress_contribution()?,
        });
    }
    statements
        .try_into()
        .map_err(|_| BundleError::InternalShape)
}

fn build_link_witnesses(
    secrets: &SecretContribution,
) -> Result<Vec<EncryptionLinkWitness>, BundleError> {
    let mut witnesses = Vec::with_capacity(N_SLOTS);
    for index in 0..N_SLOTS {
        witnesses.push(EncryptionLinkWitness::new(
            Scalar::from(u64::from(secrets.values()[index])),
            secrets.commitment_blinding_values()[index],
            NonZeroScalar::new(secrets.encryption_randomness_values()[index])?,
        ));
    }
    Ok(witnesses)
}

#[allow(clippy::too_many_arguments)]
fn prove_link_proof<R>(
    context: &AttemptContext,
    common: &ProofCommonFrame,
    role: Role,
    joint_key: &JointPublicKey,
    generators: &ProtocolGenerators,
    statements: &[EncryptionLinkStatement; N_SLOTS],
    witnesses: &[EncryptionLinkWitness],
    rng: &mut R,
) -> Result<Vec<u8>, BundleError>
where
    R: CryptoRng + RngCore,
{
    let proof = EncryptionLinkProof::prove(
        &mut proof_transcript(ProofDomain::EncryptionLink, context, role, common)?,
        generators,
        joint_key,
        statements,
        witnesses,
        rng,
    )?;
    Ok(proof.encode_to_vec()?)
}

#[allow(clippy::too_many_arguments)]
fn verify_link_proof(
    context: &AttemptContext,
    common: &ProofCommonFrame,
    role: Role,
    joint_key: &JointPublicKey,
    generators: &ProtocolGenerators,
    statements: &[EncryptionLinkStatement; N_SLOTS],
    proof_bytes: &[u8],
) -> Result<(), BundleError> {
    validate_link_proof_size(proof_bytes)?;
    let proof = EncryptionLinkProof::decode_exact(proof_bytes)?;
    proof.verify(
        &mut proof_transcript(ProofDomain::EncryptionLink, context, role, common)?,
        generators,
        joint_key,
        statements,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bp52_circuit::hash_length::HashLengthParameters;
    use bp52_group::{JointPublicKey, ProtocolGenerators};
    use curve25519_dalek::Scalar;
    use rand_core::OsRng;

    use super::{
        BundleError, build_link_witnesses, decode_link_statements, generate_player_bundle,
        prepare_hash_witness, prove_link_proof, validate_bundle_header, validate_common_frame,
        validate_secret_openings, verify_link_proof, verify_player_bundle,
    };
    use crate::{
        N_SLOTS, Role,
        contribution::generate_contribution,
        messages::{ENCRYPTION_LINK_PROOF_SIZE, HASH_LENGTH_PROOF_SIZE, PlayerBundle, SlotPublic},
        transcript::{AttemptContext, ProofCommonFrame},
    };

    fn test_joint_key(multiplier: u64) -> Result<JointPublicKey, bp52_group::GroupError> {
        let generators = ProtocolGenerators::derive()?;
        JointPublicKey::new(Scalar::from(multiplier) * generators.blinding())
    }

    fn context_and_frame(
        joint_key: &JointPublicKey,
        circuit_id: [u8; 32],
    ) -> Result<(AttemptContext, ProofCommonFrame), Box<dyn std::error::Error>> {
        let context = AttemptContext::with_prior_transcript([3_u8; 32], 11, [4_u8; 32]);
        let common = ProofCommonFrame::new([1_u8; 32], [2_u8; 32], joint_key, circuit_id)?;
        Ok((context, common))
    }

    fn placeholder_bundle(
        role: Role,
        circuit_id: [u8; 32],
        slots: &[SlotPublic; N_SLOTS],
    ) -> PlayerBundle {
        PlayerBundle {
            role,
            slots: *slots,
            circuit_id,
            hash_length_proof: vec![0_u8; HASH_LENGTH_PROOF_SIZE],
            encryption_link_proof: vec![0_u8; ENCRYPTION_LINK_PROOF_SIZE],
        }
    }

    #[test]
    fn headers_and_common_frame_are_strictly_bound() -> Result<(), Box<dyn std::error::Error>> {
        let circuit_id = [9_u8; 32];
        let joint_key = test_joint_key(17)?;
        let (_, common) = context_and_frame(&joint_key, circuit_id)?;
        let (slots, _) = generate_contribution(&joint_key, &mut OsRng)?;
        let mut bundle = placeholder_bundle(Role::Alice, circuit_id, &slots);

        validate_common_frame(circuit_id, &joint_key, &common)?;
        validate_bundle_header(circuit_id, Role::Alice, &bundle)?;

        bundle.role = Role::Bob;
        assert!(matches!(
            validate_bundle_header(circuit_id, Role::Alice, &bundle),
            Err(BundleError::RoleMismatch { .. })
        ));
        bundle.role = Role::Alice;
        bundle.circuit_id[0] ^= 1;
        assert!(matches!(
            validate_bundle_header(circuit_id, Role::Alice, &bundle),
            Err(BundleError::BundleCircuitMismatch)
        ));
        bundle.circuit_id = circuit_id;
        bundle.hash_length_proof.pop();
        assert!(matches!(
            validate_bundle_header(circuit_id, Role::Alice, &bundle),
            Err(BundleError::HashLengthProofSize { .. })
        ));

        let (_, wrong_circuit_frame) = context_and_frame(&joint_key, [8_u8; 32])?;
        assert!(matches!(
            validate_common_frame(circuit_id, &joint_key, &wrong_circuit_frame),
            Err(BundleError::ContextCircuitMismatch)
        ));
        let other_key = test_joint_key(19)?;
        assert!(matches!(
            validate_common_frame(circuit_id, &other_key, &common),
            Err(BundleError::ContextJointKeyMismatch)
        ));
        Ok(())
    }

    #[test]
    fn secret_and_hash_witness_composition_matches_all_slots()
    -> Result<(), Box<dyn std::error::Error>> {
        let joint_key = test_joint_key(23)?;
        let generators = ProtocolGenerators::derive()?;
        let (slots, secrets) = generate_contribution(&joint_key, &mut OsRng)?;
        validate_secret_openings(&slots, &secrets, &joint_key, &generators)?;
        let witness = prepare_hash_witness(&secrets)?;
        for (index, buffer) in witness.message_buffers.iter().enumerate() {
            let preimage = secrets.preimage(index).ok_or(BundleError::InternalShape)?;
            assert_eq!(&buffer[..preimage.len()], preimage);
            assert!(buffer[preimage.len()..].iter().all(|byte| *byte == 0));
            assert_eq!(
                witness.values[index],
                secrets.value(index).ok_or(BundleError::InternalShape)?
            );
        }

        let (other_slots, _) = generate_contribution(&joint_key, &mut OsRng)?;
        assert!(matches!(
            validate_secret_openings(&other_slots, &secrets, &joint_key, &generators),
            Err(BundleError::SecretOpeningMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn link_proof_is_bound_to_role_context_and_statement() -> Result<(), Box<dyn std::error::Error>>
    {
        let circuit_id = [7_u8; 32];
        let joint_key = test_joint_key(29)?;
        let generators = ProtocolGenerators::derive()?;
        let (context, common) = context_and_frame(&joint_key, circuit_id)?;
        let (slots, secrets) = generate_contribution(&joint_key, &mut OsRng)?;
        let statements = decode_link_statements(&slots)?;
        let witnesses = build_link_witnesses(&secrets)?;
        let proof = prove_link_proof(
            &context,
            &common,
            Role::Alice,
            &joint_key,
            &generators,
            &statements,
            &witnesses,
            &mut OsRng,
        )?;
        verify_link_proof(
            &context,
            &common,
            Role::Alice,
            &joint_key,
            &generators,
            &statements,
            &proof,
        )?;

        let changed_context =
            AttemptContext::with_prior_transcript(context.game_id, context.attempt, [0x55_u8; 32]);
        assert!(
            verify_link_proof(
                &changed_context,
                &common,
                Role::Alice,
                &joint_key,
                &generators,
                &statements,
                &proof,
            )
            .is_err()
        );
        assert!(
            verify_link_proof(
                &context,
                &common,
                Role::Bob,
                &joint_key,
                &generators,
                &statements,
                &proof,
            )
            .is_err()
        );

        let (mut changed_slots, _) = generate_contribution(&joint_key, &mut OsRng)?;
        changed_slots[0] = slots[0];
        changed_slots[1].hash = slots[1].hash;
        let changed_statements = decode_link_statements(&changed_slots)?;
        assert!(
            verify_link_proof(
                &context,
                &common,
                Role::Alice,
                &joint_key,
                &generators,
                &changed_statements,
                &proof,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[ignore = "resource-intensive nine-slot R1CS integration test"]
    fn full_player_bundle_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let parameters = HashLengthParameters::new()?;
        let joint_key = test_joint_key(31)?;
        let (context, common) = context_and_frame(&joint_key, parameters.circuit_id())?;
        let (bundle, _) = generate_player_bundle(
            &parameters,
            &context,
            &common,
            Role::Alice,
            &joint_key,
            &mut OsRng,
        )?;
        verify_player_bundle(
            &parameters,
            &context,
            &common,
            Role::Alice,
            &joint_key,
            &bundle,
        )?;
        Ok(())
    }
}
