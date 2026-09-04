//! Variable-length, nine-slot hash relation and circuit identity.

use bp52_codec::{CodecError, Writer};
use bp52_group::{GroupError, ProtocolGenerators, decode_point};
use bp52_proof_backend::{
    BACKEND_IDENTIFIER, BackendError, BackendParameters, CompressedRistretto, ConstraintSystem,
    LinearCombination, Prover, R1CSError, Scalar, Transcript, Variable, Verifier,
    expected_one_phase_proof_len, parse_exact_proof, required_generator_capacity,
};
#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    boolean::Bit,
    sha256::{
        BLOCK_BITS, CompressionState, MessageBlock, compress, constrain_digest, initial_state,
    },
};

/// Version of the canonical circuit-manifest schema.
pub const MANIFEST_VERSION: u16 = 1;
/// Fixed protocol version covered by this circuit.
pub const PROTOCOL_VERSION: u16 = 1;
/// Fixed number of independently proved slots.
pub const N_SLOTS: u16 = 9;
/// Minimum preimage length.
pub const PREIMAGE_BASE_LEN: u16 = 16;
/// Maximum preimage length.
pub const PREIMAGE_MAX_LEN: u16 = 67;
/// Identifier of the exact Boolean SHA-256 synthesis algorithm.
pub const SHA256_GADGET_ID: &str = "bp52-sha256-compress-msb-v2-fused-add+hash-length-padding-v1";
/// Exact vendored source revision, encoded separately in the manifest.
pub const BACKEND_SOURCE_REVISION: &str =
    "04bce4e66013ff857ed462fd4206210544101461+bp52-hardening-2";

/// Number of possible contribution values and one-hot selectors.
pub const VALUE_COUNT: usize = 52;
/// Fixed private message-buffer size.
pub const MESSAGE_BUFFER_BYTES: usize = 67;
/// Fixed private message-buffer bit count.
pub const MESSAGE_BUFFER_BITS: usize = MESSAGE_BUFFER_BYTES * 8;
/// Slot proofs concatenated into each player proof field.
pub const AGGREGATED_SLOTS: usize = 9;
/// Exact multipliers synthesized by one complete slot relation.
pub const SLOT_MULTIPLIERS: usize = 55_989;
/// Exact explicit linear constraints synthesized by one slot relation.
pub const SLOT_LINEAR_CONSTRAINTS: usize = 114_037;
/// Exact multipliers in the fixed nine-slot relation.
pub const HASH_LENGTH_MULTIPLIERS: usize = SLOT_MULTIPLIERS * AGGREGATED_SLOTS;
/// Exact explicit constraints in the fixed nine-slot relation.
pub const HASH_LENGTH_LINEAR_CONSTRAINTS: usize = SLOT_LINEAR_CONSTRAINTS * AGGREGATED_SLOTS;
/// Deterministic vector-generator capacity for one independently provable slot.
pub const HASH_LENGTH_GENERATOR_CAPACITY: usize = 65_536;
/// Exact canonical proof length for one independently provable slot.
pub const SLOT_HASH_LENGTH_PROOF_SIZE: usize = 1_441;
/// Exact concatenated size of the nine slot proofs.
pub const HASH_LENGTH_PROOF_SIZE: usize = SLOT_HASH_LENGTH_PROOF_SIZE * AGGREGATED_SLOTS;

const BASE_LEN: usize = 16;
const MAX_LEN: usize = 67;
const LONG_SHA256_THRESHOLD: usize = 56;
const SHA256_BLOCK_BYTES: usize = 64;

const MAX_GADGET_ID_LEN: usize = 64;
const MAX_BACKEND_ID_LEN: usize = 128;
const MAX_REVISION_LEN: usize = 64;

/// Locally synthesized constraint counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitMetrics {
    /// Number of multiplication gates before power-of-two padding.
    pub multipliers: u64,
    /// Number of explicit linear constraints.
    pub linear_constraints: u64,
}

impl CircuitMetrics {
    /// Converts backend `usize` metrics without permitting truncation.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::CountOverflow`] if either count cannot be
    /// represented by the manifest's canonical `u64` fields.
    pub fn from_usize(
        multipliers: usize,
        linear_constraints: usize,
    ) -> Result<Self, ManifestError> {
        Ok(Self {
            multipliers: u64::try_from(multipliers).map_err(|_| ManifestError::CountOverflow)?,
            linear_constraints: u64::try_from(linear_constraints)
                .map_err(|_| ManifestError::CountOverflow)?,
        })
    }
}

/// Exact local manifest committed by `circuit_id`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitManifest {
    metrics: CircuitMetrics,
    generator_capacity: u64,
}

impl CircuitManifest {
    /// Constructs a manifest from counts obtained from the locally compiled
    /// nine-slot circuit.
    #[cfg(test)]
    pub(crate) fn from_metrics(metrics: CircuitMetrics) -> Result<Self, ManifestError> {
        let multiplier_count =
            usize::try_from(metrics.multipliers).map_err(|_| ManifestError::CountOverflow)?;
        let capacity = required_generator_capacity(multiplier_count)?;
        Ok(Self {
            metrics,
            generator_capacity: u64::try_from(capacity)
                .map_err(|_| ManifestError::CountOverflow)?,
        })
    }

    /// Returns the single locally compiled v1 manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the compiled counts overflow their canonical
    /// fields or do not produce the fixed v1 generator capacity.
    pub fn v1() -> Result<Self, ManifestError> {
        let metrics =
            CircuitMetrics::from_usize(HASH_LENGTH_MULTIPLIERS, HASH_LENGTH_LINEAR_CONSTRAINTS)?;
        let manifest = Self {
            metrics,
            generator_capacity: u64::try_from(HASH_LENGTH_GENERATOR_CAPACITY)
                .map_err(|_| ManifestError::CountOverflow)?,
        };
        if required_generator_capacity(SLOT_MULTIPLIERS)? != HASH_LENGTH_GENERATOR_CAPACITY {
            return Err(ManifestError::CountOverflow);
        }
        Ok(manifest)
    }

    /// Returns the exact synthesized counts.
    #[must_use]
    pub const fn metrics(&self) -> CircuitMetrics {
        self.metrics
    }

    /// Returns the exact deterministic Bulletproof generator capacity.
    #[must_use]
    pub const fn generator_capacity(&self) -> u64 {
        self.generator_capacity
    }

    /// Serializes the fixed v1 manifest in canonical binary order.
    ///
    /// # Errors
    ///
    /// Returns an error if a fixed identifier is invalid or the canonical
    /// codec cannot represent a manifest field.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        validate_ascii_field(SHA256_GADGET_ID, MAX_GADGET_ID_LEN)?;
        validate_ascii_field(BACKEND_IDENTIFIER, MAX_BACKEND_ID_LEN)?;
        validate_ascii_field(BACKEND_SOURCE_REVISION, MAX_REVISION_LEN)?;

        let mut writer = Writer::new();
        writer.write_u16(MANIFEST_VERSION);
        writer.write_u16(PROTOCOL_VERSION);
        writer.write_u16(N_SLOTS);
        writer.write_u16(PREIMAGE_BASE_LEN);
        writer.write_u16(PREIMAGE_MAX_LEN);
        writer.write_byte_vector(SHA256_GADGET_ID.as_bytes())?;
        writer.write_u64(self.metrics.multipliers);
        writer.write_u64(self.metrics.linear_constraints);
        writer.write_u64(self.generator_capacity);
        writer.write_byte_vector(BACKEND_IDENTIFIER.as_bytes())?;
        writer.write_byte_vector(BACKEND_SOURCE_REVISION.as_bytes())?;
        Ok(writer.into_bytes())
    }

    /// Computes ordinary SHA-256 of the exact canonical manifest bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical manifest serialization fails.
    pub fn circuit_id(&self) -> Result<[u8; 32], ManifestError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

/// Heavy deterministic parameters for the one accepted v1 circuit.
pub struct HashLengthParameters {
    backend: BackendParameters,
    manifest: CircuitManifest,
    circuit_id: [u8; 32],
}

impl HashLengthParameters {
    /// Allocates the deterministic Dalek/Bulletproof generator vectors.
    ///
    /// This is intentionally explicit because the v1 capacity retains hundreds
    /// of megabytes of Ristretto generator points.
    ///
    /// # Errors
    ///
    /// Returns an error if protocol-generator derivation, manifest
    /// construction, or deterministic Bulletproof parameter allocation fails.
    pub fn new() -> Result<Self, HashLengthProofError> {
        let generators = ProtocolGenerators::derive()?;
        let manifest = CircuitManifest::v1()?;
        let circuit_id = manifest.circuit_id()?;
        let backend = BackendParameters::new(HASH_LENGTH_GENERATOR_CAPACITY, &generators)?;
        Ok(Self {
            backend,
            manifest,
            circuit_id,
        })
    }

    /// Returns the locally fixed manifest.
    #[must_use]
    pub const fn manifest(&self) -> &CircuitManifest {
        &self.manifest
    }

    /// Returns the only accepted v1 circuit identifier.
    #[must_use]
    pub const fn circuit_id(&self) -> [u8; 32] {
        self.circuit_id
    }
}

/// Proof composition, validation, and backend failures.
#[derive(Debug, thiserror::Error)]
pub enum HashLengthProofError {
    /// A fixed circuit witness or synthesis step was invalid.
    #[error(transparent)]
    Circuit(#[from] HashLengthError),
    /// A public commitment failed canonical or identity validation.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// The vendored proof backend rejected parameters or proof bytes.
    #[error(transparent)]
    Backend(#[from] BackendError),
    /// The locally fixed circuit manifest could not be constructed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A prover opening did not reproduce its public commitment.
    #[error("commitment opening mismatch")]
    CommitmentMismatch,
    /// A zero Pedersen blinding would expose the small committed value.
    #[error("zero Pedersen blinding")]
    ZeroBlinding,
    /// Runtime synthesis counts disagreed with the manifest.
    #[error("compiled circuit metrics disagree with manifest")]
    MetricsMismatch,
    /// The R1CS proof equation failed.
    #[error("invalid hash-length proof")]
    VerificationFailed,
}

/// Synthesizes all nine slot relations into one constraint system.
///
/// # Errors
///
/// Returns [`HashLengthError::InvalidWitness`] if prover assignments are only
/// partially supplied, or propagates a slot allocation/synthesis error.
pub fn synthesize_all_slots<CS: ConstraintSystem>(
    cs: &mut CS,
    value_variables: &[Variable; AGGREGATED_SLOTS],
    value_assignments: Option<&[u8; AGGREGATED_SLOTS]>,
    message_buffers: Option<&[[u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS]>,
    public_digests: &[[u8; 32]; AGGREGATED_SLOTS],
) -> Result<(), HashLengthError> {
    if value_assignments.is_some() != message_buffers.is_some() {
        return Err(HashLengthError::InvalidWitness);
    }
    for index in 0..AGGREGATED_SLOTS {
        drop(synthesize_slot(
            cs,
            value_variables[index],
            value_assignments.map(|values| values[index]),
            message_buffers.map(|buffers| &buffers[index]),
            &public_digests[index],
        )?);
    }
    Ok(())
}

/// Generates one canonical nine-slot R1CS proof.
///
/// # Errors
///
/// Returns an error for malformed public commitments, inconsistent commitment
/// openings or witnesses, mismatched compiled metrics, and proof-backend
/// failures.
#[allow(clippy::too_many_arguments)]
pub fn prove_hash_lengths(
    parameters: &HashLengthParameters,
    transcript: Transcript,
    public_hashes: &[[u8; 32]; AGGREGATED_SLOTS],
    public_commitments: &[[u8; 32]; AGGREGATED_SLOTS],
    values: &[u8; AGGREGATED_SLOTS],
    blindings: &[Scalar; AGGREGATED_SLOTS],
    message_buffers: &[[u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS],
) -> Result<Vec<u8>, HashLengthProofError> {
    #[cfg(not(target_arch = "wasm32"))]
    let slot_proofs = (0..AGGREGATED_SLOTS)
        .into_par_iter()
        .map(|index| {
            prove_hash_length_slot(
                parameters,
                transcript.clone(),
                index,
                &public_hashes[index],
                &public_commitments[index],
                values[index],
                blindings[index],
                &message_buffers[index],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(target_arch = "wasm32")]
    let slot_proofs = (0..AGGREGATED_SLOTS)
        .map(|index| {
            prove_hash_length_slot(
                parameters,
                transcript.clone(),
                index,
                &public_hashes[index],
                &public_commitments[index],
                values[index],
                blindings[index],
                &message_buffers[index],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut proofs = Vec::with_capacity(HASH_LENGTH_PROOF_SIZE);
    for proof in slot_proofs {
        proofs.extend_from_slice(&proof);
    }
    Ok(proofs)
}

/// Generates one independently transcript-bound slot proof.
pub fn prove_hash_length_slot(
    parameters: &HashLengthParameters,
    mut transcript: Transcript,
    index: usize,
    public_hash: &[u8; 32],
    public_commitment: &[u8; 32],
    value: u8,
    blinding: Scalar,
    message_buffer: &[u8; MESSAGE_BUFFER_BYTES],
) -> Result<Vec<u8>, HashLengthProofError> {
    if index >= AGGREGATED_SLOTS {
        return Err(HashLengthError::InternalShape.into());
    }
    if blinding == Scalar::ZERO {
        return Err(HashLengthProofError::ZeroBlinding);
    }
    append_slot_statement(&mut transcript, index, public_hash, public_commitment)?;
    let mut prover = Prover::new(parameters.backend.pedersen(), transcript);
    let (commitment, variable) = prover.commit(Scalar::from(u64::from(value)), blinding);
    if commitment.to_bytes() != *public_commitment {
        return Err(HashLengthProofError::CommitmentMismatch);
    }
    drop(synthesize_slot(
        &mut prover,
        variable,
        Some(value),
        Some(message_buffer),
        public_hash,
    )?);
    verify_slot_metrics(&prover.metrics())?;
    let bytes = prover
        .prove(parameters.backend.bulletproof())
        .map_err(BackendError::from)?
        .to_bytes();
    if bytes.len() != SLOT_HASH_LENGTH_PROOF_SIZE {
        return Err(HashLengthProofError::MetricsMismatch);
    }
    Ok(bytes)
}

/// Verifies one canonical nine-slot proof against locally compiled parameters.
///
/// # Errors
///
/// Returns an error for malformed commitments or proof bytes, a locally
/// mismatched circuit shape, or an invalid proof equation.
pub fn verify_hash_lengths(
    parameters: &HashLengthParameters,
    transcript: Transcript,
    public_hashes: &[[u8; 32]; AGGREGATED_SLOTS],
    public_commitments: &[[u8; 32]; AGGREGATED_SLOTS],
    proof_bytes: &[u8],
) -> Result<(), HashLengthProofError> {
    if proof_bytes.len() != HASH_LENGTH_PROOF_SIZE {
        return Err(BackendError::UnexpectedProofLength.into());
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        return (0..AGGREGATED_SLOTS).into_par_iter().try_for_each(|index| {
            let start = index * SLOT_HASH_LENGTH_PROOF_SIZE;
            verify_hash_length_slot(
                parameters,
                transcript.clone(),
                index,
                &public_hashes[index],
                &public_commitments[index],
                &proof_bytes[start..start + SLOT_HASH_LENGTH_PROOF_SIZE],
            )
        });
    }
    #[cfg(target_arch = "wasm32")]
    for index in 0..AGGREGATED_SLOTS {
        let start = index * SLOT_HASH_LENGTH_PROOF_SIZE;
        verify_hash_length_slot(
            parameters,
            transcript.clone(),
            index,
            &public_hashes[index],
            &public_commitments[index],
            &proof_bytes[start..start + SLOT_HASH_LENGTH_PROOF_SIZE],
        )?;
    }
    #[cfg(target_arch = "wasm32")]
    Ok(())
}

/// Verifies one independently transcript-bound slot proof.
pub fn verify_hash_length_slot(
    parameters: &HashLengthParameters,
    mut transcript: Transcript,
    index: usize,
    public_hash: &[u8; 32],
    public_commitment: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), HashLengthProofError> {
    if index >= AGGREGATED_SLOTS {
        return Err(HashLengthError::InternalShape.into());
    }
    let commitment = append_slot_statement(&mut transcript, index, public_hash, public_commitment)?;
    let mut verifier = Verifier::new(transcript);
    let variable = verifier.commit(commitment);
    drop(synthesize_slot(
        &mut verifier,
        variable,
        None,
        None,
        public_hash,
    )?);
    verify_slot_metrics(&verifier.metrics())?;
    let proof = parse_exact_proof(proof_bytes, SLOT_HASH_LENGTH_PROOF_SIZE)?;
    verifier
        .verify(
            &proof,
            parameters.backend.pedersen(),
            parameters.backend.bulletproof(),
        )
        .map_err(|_| HashLengthProofError::VerificationFailed)
}

fn append_slot_statement(
    transcript: &mut Transcript,
    index: usize,
    public_hash: &[u8; 32],
    public_commitment: &[u8; 32],
) -> Result<CompressedRistretto, HashLengthProofError> {
    let point = decode_point(*public_commitment, false)?;
    let canonical = point.compress();
    transcript.append_message(
        b"index",
        &u16::try_from(index)
            .map_err(|_| HashLengthError::InternalShape)?
            .to_le_bytes(),
    );
    transcript.append_message(b"hash", public_hash);
    transcript.append_message(b"V", canonical.as_bytes());
    Ok(canonical)
}

fn verify_slot_metrics(metrics: &bp52_proof_backend::Metrics) -> Result<(), HashLengthProofError> {
    if metrics.multipliers != SLOT_MULTIPLIERS
        || metrics.constraints != SLOT_LINEAR_CONSTRAINTS
        || metrics.phase_two_constraints != 0
        || required_generator_capacity(metrics.multipliers)? != HASH_LENGTH_GENERATOR_CAPACITY
        || expected_one_phase_proof_len(metrics.multipliers)? != SLOT_HASH_LENGTH_PROOF_SIZE
    {
        Err(HashLengthProofError::MetricsMismatch)
    } else {
        Ok(())
    }
}

/// Fixed-circuit synthesis or witness validation failure.
#[derive(Debug, thiserror::Error)]
pub enum HashLengthError {
    /// A contribution value or its zero-padded witness buffer was invalid.
    #[error("invalid hash-length witness")]
    InvalidWitness,
    /// An internal fixed-size conversion failed.
    #[error("internal fixed circuit shape mismatch")]
    InternalShape,
    /// The pinned R1CS backend rejected an allocation.
    #[error(transparent)]
    R1cs(#[from] R1CSError),
}

/// Fixed-size preimage witness buffer that is erased on drop.
///
/// The raw array is intentionally private so callers cannot accidentally
/// retain a non-zeroizing copy merely by destructuring the return value of
/// [`witness_buffer`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WitnessBuffer([u8; MESSAGE_BUFFER_BYTES]);

impl WitnessBuffer {
    /// Borrows the complete zero-padded witness array.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; MESSAGE_BUFFER_BYTES] {
        &self.0
    }
}

/// Two canonical SHA-256 blocks held in an erasing container.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CanonicalPaddedBlocks {
    first: [u8; SHA256_BLOCK_BYTES],
    second: [u8; SHA256_BLOCK_BYTES],
    is_long: bool,
}

impl CanonicalPaddedBlocks {
    /// Borrows the first compression block.
    #[must_use]
    pub const fn first(&self) -> &[u8; SHA256_BLOCK_BYTES] {
        &self.first
    }

    /// Borrows the second compression block.
    #[must_use]
    pub const fn second(&self) -> &[u8; SHA256_BLOCK_BYTES] {
        &self.second
    }

    /// Returns whether canonical SHA-256 consumes the second block.
    #[must_use]
    pub const fn is_long(&self) -> bool {
        self.is_long
    }
}

/// Copies a raw share preimage into the fixed 67-byte witness buffer.
///
/// Bytes after `preimage.len()` remain zero, as required by the circuit.
///
/// # Errors
///
/// Returns [`HashLengthError::InvalidWitness`] unless the preimage length is in
/// the inclusive range `16..=67`.
pub fn witness_buffer(preimage: &[u8]) -> Result<WitnessBuffer, HashLengthError> {
    if !(BASE_LEN..=MAX_LEN).contains(&preimage.len()) {
        return Err(HashLengthError::InvalidWitness);
    }
    let mut buffer = WitnessBuffer([0_u8; MESSAGE_BUFFER_BYTES]);
    buffer.0[..preimage.len()].copy_from_slice(preimage);
    Ok(buffer)
}

/// Builds the two canonical SHA-256 blocks for a supported raw preimage.
///
/// The second block is all zeroes when the logical length is at most 55, even
/// though ordinary SHA-256 would stop after the first compression. This is the
/// exact fixed-shape representation selected by the R1CS relation.
///
/// # Errors
///
/// Returns [`HashLengthError::InvalidWitness`] unless the preimage length is in
/// the inclusive range `16..=67` or its bit length cannot be represented.
pub fn canonical_padded_blocks(preimage: &[u8]) -> Result<CanonicalPaddedBlocks, HashLengthError> {
    if !(BASE_LEN..=MAX_LEN).contains(&preimage.len()) {
        return Err(HashLengthError::InvalidWitness);
    }
    let length = preimage.len();
    let bit_length = u64::try_from(length)
        .map_err(|_| HashLengthError::InvalidWitness)?
        .checked_mul(8)
        .ok_or(HashLengthError::InvalidWitness)?
        .to_be_bytes();
    let is_long = length >= LONG_SHA256_THRESHOLD;
    let mut blocks = CanonicalPaddedBlocks {
        first: [0_u8; SHA256_BLOCK_BYTES],
        second: [0_u8; SHA256_BLOCK_BYTES],
        is_long,
    };

    if length <= 55 {
        blocks.first[..length].copy_from_slice(preimage);
        blocks.first[length] = 0x80;
        blocks.first[56..].copy_from_slice(&bit_length);
    } else if length <= 63 {
        blocks.first[..length].copy_from_slice(preimage);
        blocks.first[length] = 0x80;
        blocks.second[56..].copy_from_slice(&bit_length);
    } else {
        blocks.first.copy_from_slice(&preimage[..64]);
        let remainder = length - 64;
        blocks.second[..remainder].copy_from_slice(&preimage[64..]);
        blocks.second[remainder] = 0x80;
        blocks.second[56..].copy_from_slice(&bit_length);
    }
    Ok(blocks)
}

/// Synthesizes one slot's complete committed-value, exact-length, and
/// two-block SHA-256 relation.
///
/// `value_assignment` and `message_buffer` are both `Some` for a prover and
/// both `None` for a verifier. The committed `value_variable` is used directly
/// by the one-hot relation; no second value witness is allocated.
///
/// # Errors
///
/// Returns an error if prover assignments are incomplete, the value is outside
/// `0..52`, a witness-buffer suffix is nonzero, or R1CS synthesis fails.
pub fn synthesize_slot<CS: ConstraintSystem>(
    cs: &mut CS,
    value_variable: Variable,
    value_assignment: Option<u8>,
    message_buffer: Option<&[u8; MESSAGE_BUFFER_BYTES]>,
    public_digest: &[u8; 32],
) -> Result<CompressionState, HashLengthError> {
    if value_assignment.is_some() != message_buffer.is_some()
        || value_assignment.is_some_and(|value| usize::from(value) >= VALUE_COUNT)
    {
        return Err(HashLengthError::InvalidWitness);
    }

    let logical_length = value_assignment.map(|value| BASE_LEN + usize::from(value));
    if let (Some(length), Some(buffer)) = (logical_length, message_buffer) {
        if buffer[length..].iter().any(|byte| *byte != 0) {
            return Err(HashLengthError::InvalidWitness);
        }
    }

    let mut selectors = Vec::with_capacity(VALUE_COUNT);
    for index in 0..VALUE_COUNT {
        selectors.push(Bit::allocate(
            cs,
            value_assignment.map(|value| usize::from(value) == index),
        )?);
    }
    let selectors: [Bit; VALUE_COUNT] = selectors
        .try_into()
        .map_err(|_| HashLengthError::InternalShape)?;

    let mut selector_sum = LinearCombination::from(-Scalar::ONE);
    let mut value_relation = LinearCombination::from(value_variable);
    for (index, selector) in selectors.iter().enumerate() {
        selector_sum = selector_sum + selector.linear_combination();
        let coefficient =
            Scalar::from(u64::try_from(index).map_err(|_| HashLengthError::InternalShape)?);
        value_relation = value_relation - selector.linear_combination() * coefficient;
    }
    cs.constrain(selector_sum);
    cs.constrain(value_relation);

    let mut message_bits = Vec::with_capacity(MESSAGE_BUFFER_BITS);
    for byte_index in 0..MESSAGE_BUFFER_BYTES {
        for bit_index in 0..8 {
            let assignment =
                message_buffer.map(|buffer| buffer[byte_index] & (1_u8 << (7 - bit_index)) != 0);
            message_bits.push(Bit::allocate(cs, assignment)?);
        }
    }
    let message_bits: [Bit; MESSAGE_BUFFER_BITS] = message_bits
        .try_into()
        .map_err(|_| HashLengthError::InternalShape)?;

    // For every byte that may be outside the selected logical length, enforce
    // each message bit times the one-hot "inactive" selector sum to be zero.
    for byte_index in BASE_LEN..MESSAGE_BUFFER_BYTES {
        let inactive = selector_linear_combination(
            &selectors,
            0..=(byte_index - BASE_LEN).min(VALUE_COUNT - 1),
        );
        for bit_index in 0..8 {
            let (_, _, product) = cs.multiply(
                message_bits[byte_index * 8 + bit_index].linear_combination(),
                inactive.clone(),
            );
            cs.constrain(product.into());
        }
    }

    let padded = match (logical_length, message_buffer) {
        (Some(length), Some(buffer)) => Some(canonical_padded_blocks(&buffer[..length])?),
        (None, None) => None,
        _ => return Err(HashLengthError::InvalidWitness),
    };
    let first_block = build_first_block(cs, &selectors, &message_bits, padded.as_ref())?;
    let second_block = build_second_block(cs, &selectors, &message_bits, padded.as_ref())?;

    let first_state = compress(cs, &initial_state(), &first_block)?;
    let second_state = compress(cs, &first_state, &second_block)?;
    let is_long_lc = selector_linear_combination(&selectors, 40..VALUE_COUNT);
    let is_long = Bit::from_linear_combination(
        cs,
        is_long_lc,
        logical_length.map(|length| length >= LONG_SHA256_THRESHOLD),
    );
    let selected_state = select_state(cs, &is_long, &second_state, &first_state)?;
    constrain_digest(cs, &selected_state, public_digest);
    Ok(selected_state)
}

fn build_first_block<CS: ConstraintSystem>(
    cs: &mut CS,
    selectors: &[Bit; VALUE_COUNT],
    message_bits: &[Bit; MESSAGE_BUFFER_BITS],
    padded: Option<&CanonicalPaddedBlocks>,
) -> Result<MessageBlock, HashLengthError> {
    let mut block = Vec::with_capacity(BLOCK_BITS);
    for byte_index in 0..SHA256_BLOCK_BYTES {
        for bit_index in 0..8 {
            let mut bit = message_bits[byte_index * 8 + bit_index].linear_combination();

            if bit_index == 0 && (BASE_LEN..=63).contains(&byte_index) {
                bit = bit + selectors[byte_index - BASE_LEN].linear_combination();
            }
            if byte_index >= 56 {
                for (value, selector) in selectors.iter().enumerate().take(40) {
                    let length = BASE_LEN + value;
                    if encoded_length_bit(length, byte_index - 56, bit_index)? {
                        bit = bit + selector.linear_combination();
                    }
                }
            }

            let assignment =
                padded.map(|blocks| blocks.first[byte_index] & (1_u8 << (7 - bit_index)) != 0);
            block.push(Bit::from_linear_combination(cs, bit, assignment));
        }
    }
    block.try_into().map_err(|_| HashLengthError::InternalShape)
}

fn build_second_block<CS: ConstraintSystem>(
    cs: &mut CS,
    selectors: &[Bit; VALUE_COUNT],
    message_bits: &[Bit; MESSAGE_BUFFER_BITS],
    padded: Option<&CanonicalPaddedBlocks>,
) -> Result<MessageBlock, HashLengthError> {
    let mut block = Vec::with_capacity(BLOCK_BITS);
    for byte_index in 0..SHA256_BLOCK_BYTES {
        for bit_index in 0..8 {
            let mut bit = if byte_index < 3 {
                message_bits[(64 + byte_index) * 8 + bit_index].linear_combination()
            } else {
                LinearCombination::from(Scalar::ZERO)
            };

            if bit_index == 0 && byte_index <= 3 {
                bit = bit + selectors[48 + byte_index].linear_combination();
            }
            if byte_index >= 56 {
                for (value, selector) in selectors.iter().enumerate().skip(40) {
                    let length = BASE_LEN + value;
                    if encoded_length_bit(length, byte_index - 56, bit_index)? {
                        bit = bit + selector.linear_combination();
                    }
                }
            }

            let assignment =
                padded.map(|blocks| blocks.second[byte_index] & (1_u8 << (7 - bit_index)) != 0);
            block.push(Bit::from_linear_combination(cs, bit, assignment));
        }
    }
    block.try_into().map_err(|_| HashLengthError::InternalShape)
}

fn selector_linear_combination(
    selectors: &[Bit; VALUE_COUNT],
    indices: impl IntoIterator<Item = usize>,
) -> LinearCombination {
    let mut result = LinearCombination::from(Scalar::ZERO);
    for index in indices {
        result = result + selectors[index].linear_combination();
    }
    result
}

fn encoded_length_bit(
    length: usize,
    byte_index: usize,
    bit_index: usize,
) -> Result<bool, HashLengthError> {
    let encoded = u64::try_from(length)
        .map_err(|_| HashLengthError::InternalShape)?
        .checked_mul(8)
        .ok_or(HashLengthError::InternalShape)?
        .to_be_bytes();
    Ok(encoded[byte_index] & (1_u8 << (7 - bit_index)) != 0)
}

fn select_state<CS: ConstraintSystem>(
    cs: &mut CS,
    selector: &Bit,
    when_true: &CompressionState,
    when_false: &CompressionState,
) -> Result<CompressionState, HashLengthError> {
    let mut state = Vec::with_capacity(8);
    for word_index in 0..8 {
        let word = std::array::from_fn(|bit_index| {
            selector.select(
                cs,
                &when_true[word_index][bit_index],
                &when_false[word_index][bit_index],
            )
        });
        state.push(word);
    }
    state.try_into().map_err(|_| HashLengthError::InternalShape)
}

/// Circuit-manifest construction errors.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// A count cannot be represented by its canonical integer width.
    #[error("circuit count overflow")]
    CountOverflow,
    /// A fixed identifier is not bounded printable ASCII.
    #[error("invalid manifest identifier")]
    InvalidIdentifier,
    /// Canonical binary encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Generator capacity derivation failed.
    #[error(transparent)]
    Backend(#[from] BackendError),
}

fn validate_ascii_field(value: &str, max_len: usize) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > max_len
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(ManifestError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bp52_group::{ProtocolGenerators, commit, decode_point};
    use bp52_proof_backend::{BackendParameters, ConstraintSystem, Prover, Scalar, Transcript};
    use sha2::{Digest, Sha256};

    use crate::sha256::assigned_state_bytes;

    use super::{
        AGGREGATED_SLOTS, BACKEND_SOURCE_REVISION, CircuitManifest, CircuitMetrics,
        HASH_LENGTH_GENERATOR_CAPACITY, HASH_LENGTH_LINEAR_CONSTRAINTS, HASH_LENGTH_MULTIPLIERS,
        HASH_LENGTH_PROOF_SIZE, HashLengthParameters, MANIFEST_VERSION, MESSAGE_BUFFER_BYTES,
        N_SLOTS, PREIMAGE_BASE_LEN, PREIMAGE_MAX_LEN, PROTOCOL_VERSION, SHA256_GADGET_ID,
        canonical_padded_blocks, prove_hash_lengths, synthesize_slot, verify_hash_lengths,
        witness_buffer,
    };

    fn synthesize_length(
        length: usize,
    ) -> Result<bp52_proof_backend::Metrics, Box<dyn std::error::Error>> {
        let generators = ProtocolGenerators::derive()?;
        let parameters = BackendParameters::new(1, &generators)?;
        let mut prover = Prover::new(
            parameters.pedersen(),
            Transcript::new(b"BP52/hash-length-shape-test/v1"),
        );
        let value = u8::try_from(
            length
                .checked_sub(16)
                .ok_or_else(|| std::io::Error::other("test length is below 16"))?,
        )?;
        let (commitment, variable) =
            prover.commit(Scalar::from(u64::from(value)), Scalar::from(19_u64));
        assert_ne!(commitment.as_bytes(), &[0_u8; 32]);
        let preimage = (0..length)
            .map(|index| u8::try_from((index * 37 + length) % 256))
            .collect::<Result<Vec<_>, _>>()?;
        let buffer = witness_buffer(&preimage)?;
        let digest: [u8; 32] = Sha256::digest(&preimage).into();
        let selected = synthesize_slot(
            &mut prover,
            variable,
            Some(value),
            Some(buffer.as_array()),
            &digest,
        )?;
        assert_eq!(assigned_state_bytes(&selected), Some(digest));
        Ok(prover.metrics())
    }

    #[test]
    fn manifest_has_fixed_order_and_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = CircuitManifest::from_metrics(CircuitMetrics {
            multipliers: 1000,
            linear_constraints: 2000,
        })?;
        assert_eq!(manifest.generator_capacity(), 1024);
        let bytes = manifest.canonical_bytes()?;
        assert_eq!(&bytes[0..2], &MANIFEST_VERSION.to_le_bytes());
        assert_eq!(&bytes[2..4], &PROTOCOL_VERSION.to_le_bytes());
        assert_eq!(&bytes[4..6], &N_SLOTS.to_le_bytes());
        assert_eq!(&bytes[6..8], &PREIMAGE_BASE_LEN.to_le_bytes());
        assert_eq!(&bytes[8..10], &PREIMAGE_MAX_LEN.to_le_bytes());
        assert!(
            bytes
                .windows(SHA256_GADGET_ID.len())
                .any(|w| w == SHA256_GADGET_ID.as_bytes())
        );
        assert!(
            bytes
                .windows(BACKEND_SOURCE_REVISION.len())
                .any(|window| window == BACKEND_SOURCE_REVISION.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn circuit_id_changes_with_exact_counts() -> Result<(), Box<dyn std::error::Error>> {
        let first = CircuitManifest::from_metrics(CircuitMetrics {
            multipliers: 1000,
            linear_constraints: 2000,
        })?;
        let second = CircuitManifest::from_metrics(CircuitMetrics {
            multipliers: 1001,
            linear_constraints: 2000,
        })?;
        assert_ne!(first.circuit_id()?, second.circuit_id()?);
        Ok(())
    }

    #[test]
    fn v1_manifest_counts_and_id_are_immutable() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = CircuitManifest::v1()?;
        assert_eq!(
            manifest.metrics().multipliers,
            u64::try_from(HASH_LENGTH_MULTIPLIERS)?
        );
        assert_eq!(
            manifest.metrics().linear_constraints,
            u64::try_from(HASH_LENGTH_LINEAR_CONSTRAINTS)?
        );
        assert_eq!(
            manifest.generator_capacity(),
            u64::try_from(HASH_LENGTH_GENERATOR_CAPACITY)?
        );
        assert_eq!(HASH_LENGTH_PROOF_SIZE, 12_969);
        assert_eq!(
            manifest.circuit_id()?,
            [
                0x50, 0x30, 0xc5, 0x1f, 0xca, 0x7b, 0x61, 0x88, 0x72, 0x7a, 0x08, 0x79, 0xde, 0xf7,
                0x26, 0x8c, 0x59, 0x7c, 0x72, 0x30, 0x6d, 0xed, 0x58, 0xa8, 0x41, 0x7a, 0x49, 0x96,
                0x5f, 0x49, 0xf9, 0xfd,
            ]
        );
        Ok(())
    }

    #[test]
    fn canonical_padding_boundaries_match_fips_layout() -> Result<(), Box<dyn std::error::Error>> {
        for length in usize::from(PREIMAGE_BASE_LEN)..=usize::from(PREIMAGE_MAX_LEN) {
            let message = vec![0x5a; length];
            let padded = canonical_padded_blocks(&message)?;
            let first = padded.first();
            let second = padded.second();
            assert_eq!(padded.is_long(), length >= 56);
            let encoded_length = (u64::try_from(length)? * 8).to_be_bytes();
            if length <= 55 {
                assert_eq!(first[length], 0x80);
                assert_eq!(&first[56..], &encoded_length);
                assert_eq!(second, &[0_u8; 64]);
            } else if length <= 63 {
                assert_eq!(first[length], 0x80);
                assert_eq!(&second[56..], &encoded_length);
            } else {
                assert_eq!(second[length - 64], 0x80);
                assert_eq!(&second[56..], &encoded_length);
            }
        }
        Ok(())
    }

    #[test]
    fn variable_length_synthesis_matches_sha256_and_has_fixed_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut expected = None;
        for length in usize::from(PREIMAGE_BASE_LEN)..=usize::from(PREIMAGE_MAX_LEN) {
            let metrics = synthesize_length(length)?;
            if let Some(expected) = &expected {
                assert_eq!(&metrics.multipliers, expected);
            } else {
                expected = Some(metrics.multipliers);
            }
            eprintln!(
                "hash-length slot metrics: {} multipliers, {} constraints",
                metrics.multipliers, metrics.constraints
            );
        }
        Ok(())
    }

    #[test]
    #[ignore = "allocates 2^19 generators and proves the full nine-slot circuit"]
    fn full_nine_slot_api_roundtrip_and_tamper_rejection() -> Result<(), Box<dyn std::error::Error>>
    {
        let setup_started = Instant::now();
        let parameters = HashLengthParameters::new()?;
        eprintln!("hash-length parameter setup: {:?}", setup_started.elapsed());

        // Cover every padding regime and both sides of the one-/two-block
        // boundaries within the fixed nine-slot API.
        let values = [0_u8, 39, 40, 47, 48, 51, 1, 23, 41];
        let blindings = [
            Scalar::from(101_u64),
            Scalar::from(102_u64),
            Scalar::from(103_u64),
            Scalar::from(104_u64),
            Scalar::from(105_u64),
            Scalar::from(106_u64),
            Scalar::from(107_u64),
            Scalar::from(108_u64),
            Scalar::from(109_u64),
        ];
        let mut message_buffers = [[0_u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS];
        let mut public_hashes = [[0_u8; 32]; AGGREGATED_SLOTS];
        let mut public_commitments = [[0_u8; 32]; AGGREGATED_SLOTS];
        let generators = ProtocolGenerators::derive()?;
        for index in 0..AGGREGATED_SLOTS {
            let length = 16 + usize::from(values[index]);
            let preimage = (0..length)
                .map(|offset| u8::try_from((index * 71 + offset * 29 + length) % 256))
                .collect::<Result<Vec<_>, _>>()?;
            let buffer = witness_buffer(&preimage)?;
            message_buffers[index].copy_from_slice(buffer.as_array());
            public_hashes[index] = Sha256::digest(&preimage).into();
            public_commitments[index] = commit(
                Scalar::from(u64::from(values[index])),
                blindings[index],
                &generators,
            )
            .compress()
            .to_bytes();
        }

        let prove_started = Instant::now();
        let proof = prove_hash_lengths(
            &parameters,
            test_transcript(parameters.circuit_id()),
            &public_hashes,
            &public_commitments,
            &values,
            &blindings,
            &message_buffers,
        )?;
        eprintln!(
            "hash-length proof: {:?}, {} bytes",
            prove_started.elapsed(),
            proof.len()
        );
        assert_eq!(proof.len(), HASH_LENGTH_PROOF_SIZE);

        let verify_started = Instant::now();
        verify_hash_lengths(
            &parameters,
            test_transcript(parameters.circuit_id()),
            &public_hashes,
            &public_commitments,
            &proof,
        )?;
        eprintln!("hash-length verification: {:?}", verify_started.elapsed());

        let tamper_started = Instant::now();
        for byte in 0..32 {
            let mut tampered_hashes = public_hashes;
            tampered_hashes[4][byte] ^= 0x01;
            assert!(
                verify_hash_lengths(
                    &parameters,
                    test_transcript(parameters.circuit_id()),
                    &tampered_hashes,
                    &public_commitments,
                    &proof,
                )
                .is_err()
            );
        }
        let mut tampered_commitments = public_commitments;
        tampered_commitments[4] = (decode_point(tampered_commitments[4], false)?
            + generators.blinding())
        .compress()
        .to_bytes();
        assert!(
            verify_hash_lengths(
                &parameters,
                test_transcript(parameters.circuit_id()),
                &public_hashes,
                &tampered_commitments,
                &proof,
            )
            .is_err()
        );
        eprintln!("tamper rejection: {:?}", tamper_started.elapsed());
        Ok(())
    }

    fn test_transcript(circuit_id: [u8; 32]) -> Transcript {
        let mut transcript = Transcript::new(b"BP52/hash-length/v1");
        transcript.append_message(b"circuit-id", &circuit_id);
        transcript
    }
}
