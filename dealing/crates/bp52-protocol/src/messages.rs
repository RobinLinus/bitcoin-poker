//! Canonical BP52-DEAL-v1 public values and authenticated message envelopes.
//!
//! The protocol encoding is deliberately implemented field-by-field. Rust
//! layout, Serde, and platform integer widths are not part of the wire format.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use curve25519_dalek::ristretto::CompressedRistretto;

use crate::{N_SLOTS, PROTOCOL_VERSION, Role};

/// Number of encrypted comparisons in the fixed v1 uniqueness test.
pub const ZERO_TEST_COUNT: usize = 108;
/// Exact size of the batched encryption-link proof defined by the v1 profile.
pub const ENCRYPTION_LINK_PROOF_SIZE: usize = 1_728;
/// Exact size of either batched ciphertext-scale proof defined by the v1 profile.
pub const SCALE_PROOF_SIZE: usize = 13_824;
/// Exact size of the batched partial-decryption proof defined by the v1 profile.
pub const PARTIAL_DECRYPT_PROOF_SIZE: usize = 3_520;

/// Exact manifest-derived length of the v1 hash-length proof.
pub const HASH_LENGTH_PROOF_SIZE: usize = bp52_circuit::hash_length::HASH_LENGTH_PROOF_SIZE;
/// Allocation cap for the hash-length proof; v1 requires this exact length.
pub const MAX_HASH_LENGTH_PROOF_SIZE: usize = HASH_LENGTH_PROOF_SIZE;

const HASH_SIZE: usize = 32;
const POINT_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const BYTE_VECTOR_PREFIX_SIZE: usize = 4;
const SLOT_PUBLIC_SIZE: usize = HASH_SIZE + POINT_SIZE + (2 * POINT_SIZE);
const PLAYER_BUNDLE_FIXED_SIZE: usize = 1
    + (N_SLOTS * SLOT_PUBLIC_SIZE)
    + HASH_SIZE
    + BYTE_VECTOR_PREFIX_SIZE
    + BYTE_VECTOR_PREFIX_SIZE;
const MIN_PLAYER_BUNDLE_SIZE: usize =
    PLAYER_BUNDLE_FIXED_SIZE + HASH_LENGTH_PROOF_SIZE + ENCRYPTION_LINK_PROOF_SIZE;
/// Maximum canonical size of an encoded [`PlayerBundle`].
pub const MAX_PLAYER_BUNDLE_SIZE: usize = MIN_PLAYER_BUNDLE_SIZE;

const KEY_COMMIT_PAYLOAD_SIZE: usize = HASH_SIZE;
const KEY_OPEN_PAYLOAD_SIZE: usize = HASH_SIZE + POINT_SIZE;
const KEY_PROOF_PAYLOAD_SIZE: usize = POINT_SIZE + 32;
const BUNDLE_COMMIT_PAYLOAD_SIZE: usize = HASH_SIZE;
const MIN_BUNDLE_OPEN_PAYLOAD_SIZE: usize = HASH_SIZE + MIN_PLAYER_BUNDLE_SIZE;
const MAX_BUNDLE_OPEN_PAYLOAD_SIZE: usize = HASH_SIZE + MAX_PLAYER_BUNDLE_SIZE;
const BLIND_PAYLOAD_SIZE: usize =
    (ZERO_TEST_COUNT * POINT_SIZE) + (ZERO_TEST_COUNT * 2 * POINT_SIZE) + SCALE_PROOF_SIZE;
const DECRYPT_COMMIT_PAYLOAD_SIZE: usize = HASH_SIZE;
const DECRYPT_OPEN_PAYLOAD_SIZE: usize =
    HASH_SIZE + (ZERO_TEST_COUNT * POINT_SIZE) + PARTIAL_DECRYPT_PROOF_SIZE;

/// Largest payload accepted by any v1 envelope.
pub const MAX_PAYLOAD_SIZE: usize = BLIND_PAYLOAD_SIZE;
const UNSIGNED_ENVELOPE_FIXED_SIZE: usize =
    2 + HASH_SIZE + 4 + 2 + 1 + 4 + HASH_SIZE + 2 + BYTE_VECTOR_PREFIX_SIZE;
/// Largest canonical unsigned v1 envelope.
pub const MAX_UNSIGNED_ENVELOPE_SIZE: usize = UNSIGNED_ENVELOPE_FIXED_SIZE + MAX_PAYLOAD_SIZE;
/// Largest canonical signed v1 envelope.
pub const MAX_ENVELOPE_SIZE: usize = MAX_UNSIGNED_ENVELOPE_SIZE + SIGNATURE_SIZE;

impl Role {
    /// Returns the single canonical role byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Alice => 0,
            Self::Bob => 1,
        }
    }
}

impl TryFrom<u8> for Role {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Alice),
            1 => Ok(Self::Bob),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for Role {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_u8(self.to_u8());
        Ok(())
    }
}

impl Decode for Role {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Self::try_from(reader.read_u8()?)
    }
}

/// Canonically compressed exponential-ElGamal ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    /// Encryption-randomness component `R`.
    pub r: [u8; POINT_SIZE],
    /// Masked-message component `S`.
    pub s: [u8; POINT_SIZE],
}

impl Encode for Ciphertext {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        validate_point(self.r)?;
        validate_point(self.s)?;
        self.r.encode(writer)?;
        self.s.encode(writer)
    }
}

impl Decode for Ciphertext {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            r: Decode::decode(reader)?,
            s: Decode::decode(reader)?,
        };
        validate_point(value.r)?;
        validate_point(value.s)?;
        Ok(value)
    }
}

impl From<bp52_group::CiphertextBytes> for Ciphertext {
    fn from(value: bp52_group::CiphertextBytes) -> Self {
        Self {
            r: value.r,
            s: value.s,
        }
    }
}

impl From<Ciphertext> for bp52_group::CiphertextBytes {
    fn from(value: Ciphertext) -> Self {
        Self {
            r: value.r,
            s: value.s,
        }
    }
}

/// Public data for one contribution slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotPublic {
    /// SHA-256 hash of the hidden share preimage.
    pub hash: [u8; HASH_SIZE],
    /// Compressed Pedersen value commitment `V`.
    pub value_commitment: [u8; POINT_SIZE],
    /// Exponential-ElGamal encryption of the same value.
    pub ciphertext: Ciphertext,
}

impl Encode for SlotPublic {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        validate_point(self.value_commitment)?;
        self.hash.encode(writer)?;
        self.value_commitment.encode(writer)?;
        self.ciphertext.encode(writer)
    }
}

impl Decode for SlotPublic {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            hash: Decode::decode(reader)?,
            value_commitment: Decode::decode(reader)?,
            ciphertext: Decode::decode(reader)?,
        };
        validate_point(value.value_commitment)?;
        Ok(value)
    }
}

/// One party's nine public card contributions and their linking proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlayerBundle {
    /// Party that generated this bundle.
    pub role: Role,
    /// Nine fixed-order public contribution slots.
    pub slots: [SlotPublic; N_SLOTS],
    /// Identifier of the exact hash-length circuit manifest.
    pub circuit_id: [u8; HASH_SIZE],
    /// Aggregated R1CS proof of all nine hash/length statements.
    pub hash_length_proof: Vec<u8>,
    /// Exact v1 batched Pedersen-to-ElGamal linking proof.
    pub encryption_link_proof: Vec<u8>,
}

impl Encode for PlayerBundle {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        validate_proof_lengths(self)?;
        self.role.encode(writer)?;
        for slot in &self.slots {
            slot.encode(writer)?;
        }
        self.circuit_id.encode(writer)?;
        writer.write_byte_vector(&self.hash_length_proof)?;
        writer.write_byte_vector(&self.encryption_link_proof)
    }
}

impl Decode for PlayerBundle {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let role = Role::decode(reader)?;
        let slots = decode_fixed_array(reader)?;
        let circuit_id = Decode::decode(reader)?;
        let hash_length_proof = reader.read_byte_vector(MAX_HASH_LENGTH_PROOF_SIZE)?;
        let encryption_link_proof = reader.read_byte_vector(ENCRYPTION_LINK_PROOF_SIZE)?;
        let value = Self {
            role,
            slots,
            circuit_id,
            hash_length_proof,
            encryption_link_proof,
        };
        validate_proof_lengths(&value)?;
        Ok(value)
    }
}

/// Fields signed by both parties when a deal is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedDealBody {
    /// Protocol wire version. It is exactly one in this codec.
    pub protocol_version: u16,
    /// Identifier of the funding/session context.
    pub game_id: [u8; HASH_SIZE],
    /// Zero-based attempt number.
    pub attempt: u32,
    /// Alice's ordered hash locks.
    pub hashes_a: [[u8; HASH_SIZE]; N_SLOTS],
    /// Bob's ordered hash locks.
    pub hashes_b: [[u8; HASH_SIZE]; N_SLOTS],
    /// Transcript state after both valid decryption openings.
    pub verification_transcript_root: [u8; HASH_SIZE],
}

impl Encode for AcceptedDealBody {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        validate_v1_version(self.protocol_version)?;
        self.protocol_version.encode(writer)?;
        self.game_id.encode(writer)?;
        self.attempt.encode(writer)?;
        encode_array(&self.hashes_a, writer)?;
        encode_array(&self.hashes_b, writer)?;
        self.verification_transcript_root.encode(writer)
    }
}

impl Decode for AcceptedDealBody {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let protocol_version = u16::decode(reader)?;
        validate_v1_version(protocol_version)?;
        Ok(Self {
            protocol_version,
            game_id: Decode::decode(reader)?,
            attempt: Decode::decode(reader)?,
            hashes_a: decode_fixed_array(reader)?,
            hashes_b: decode_fixed_array(reader)?,
            verification_transcript_root: Decode::decode(reader)?,
        })
    }
}

/// Bitcoin-facing accepted deal certificate with both BIP340 signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedDeal {
    /// Protocol wire version. It is exactly one in this codec.
    pub protocol_version: u16,
    /// Identifier of the funding/session context.
    pub game_id: [u8; HASH_SIZE],
    /// Zero-based attempt number.
    pub attempt: u32,
    /// Alice's ordered hash locks.
    pub hashes_a: [[u8; HASH_SIZE]; N_SLOTS],
    /// Bob's ordered hash locks.
    pub hashes_b: [[u8; HASH_SIZE]; N_SLOTS],
    /// Transcript state after both valid decryption openings.
    pub verification_transcript_root: [u8; HASH_SIZE],
    /// Alice's BIP340 signature of the accepted body digest.
    pub signature_a: [u8; SIGNATURE_SIZE],
    /// Bob's BIP340 signature of the accepted body digest.
    pub signature_b: [u8; SIGNATURE_SIZE],
}

impl AcceptedDeal {
    /// Copies out the exact body covered by both acceptance signatures.
    #[must_use]
    pub const fn body(&self) -> AcceptedDealBody {
        AcceptedDealBody {
            protocol_version: self.protocol_version,
            game_id: self.game_id,
            attempt: self.attempt,
            hashes_a: self.hashes_a,
            hashes_b: self.hashes_b,
            verification_transcript_root: self.verification_transcript_root,
        }
    }
}

impl Encode for AcceptedDeal {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.body().encode(writer)?;
        self.signature_a.encode(writer)?;
        self.signature_b.encode(writer)
    }
}

impl Decode for AcceptedDeal {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let body = AcceptedDealBody::decode(reader)?;
        Ok(Self {
            protocol_version: body.protocol_version,
            game_id: body.game_id,
            attempt: body.attempt,
            hashes_a: body.hashes_a,
            hashes_b: body.hashes_b,
            verification_transcript_root: body.verification_transcript_root,
            signature_a: Decode::decode(reader)?,
            signature_b: Decode::decode(reader)?,
        })
    }
}

/// Canonical v1 envelope payload identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum PayloadType {
    /// Commitment to a hidden per-attempt public-key share.
    KeyCommit = 1,
    /// Opening nonce and per-attempt public-key share.
    KeyOpen = 2,
    /// Schnorr proof of possession of a key share.
    KeyProof = 3,
    /// Commitment to a hidden player bundle.
    BundleCommit = 4,
    /// Opening nonce and player bundle.
    BundleOpen = 5,
    /// First blinding batch and scale proof.
    BlindFirst = 6,
    /// Second blinding batch and scale proof.
    BlindSecond = 7,
    /// Commitment to a hidden partial-decryption batch.
    DecryptCommit = 8,
    /// Opening nonce, partial decryptions, and proof.
    DecryptOpen = 9,
}

impl PayloadType {
    /// Returns the canonical little-endian integer identifier.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    const fn length_range(self) -> (usize, usize) {
        match self {
            Self::KeyCommit => (KEY_COMMIT_PAYLOAD_SIZE, KEY_COMMIT_PAYLOAD_SIZE),
            Self::KeyOpen => (KEY_OPEN_PAYLOAD_SIZE, KEY_OPEN_PAYLOAD_SIZE),
            Self::KeyProof => (KEY_PROOF_PAYLOAD_SIZE, KEY_PROOF_PAYLOAD_SIZE),
            Self::BundleCommit => (BUNDLE_COMMIT_PAYLOAD_SIZE, BUNDLE_COMMIT_PAYLOAD_SIZE),
            Self::BundleOpen => (MIN_BUNDLE_OPEN_PAYLOAD_SIZE, MAX_BUNDLE_OPEN_PAYLOAD_SIZE),
            Self::BlindFirst | Self::BlindSecond => (BLIND_PAYLOAD_SIZE, BLIND_PAYLOAD_SIZE),
            Self::DecryptCommit => (DECRYPT_COMMIT_PAYLOAD_SIZE, DECRYPT_COMMIT_PAYLOAD_SIZE),
            Self::DecryptOpen => (DECRYPT_OPEN_PAYLOAD_SIZE, DECRYPT_OPEN_PAYLOAD_SIZE),
        }
    }

    /// Returns the allocation cap for this payload body.
    #[must_use]
    pub const fn max_payload_len(self) -> usize {
        self.length_range().1
    }

    fn validate_payload_len(self, actual: usize) -> Result<(), CodecError> {
        let (minimum, maximum) = self.length_range();
        if actual > maximum {
            Err(CodecError::LengthLimitExceeded)
        } else if actual < minimum {
            Err(CodecError::NonCanonical)
        } else {
            Ok(())
        }
    }
}

impl TryFrom<u16> for PayloadType {
    type Error = CodecError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::KeyCommit),
            2 => Ok(Self::KeyOpen),
            3 => Ok(Self::KeyProof),
            4 => Ok(Self::BundleCommit),
            5 => Ok(Self::BundleOpen),
            6 => Ok(Self::BlindFirst),
            7 => Ok(Self::BlindSecond),
            8 => Ok(Self::DecryptCommit),
            9 => Ok(Self::DecryptOpen),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for PayloadType {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_u16(self.to_u16());
        Ok(())
    }
}

impl Decode for PayloadType {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Self::try_from(reader.read_u16()?)
    }
}

/// Every signed envelope field except the BIP340 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedEnvelope {
    /// Protocol wire version. It is exactly one in this codec.
    pub protocol_version: u16,
    /// Identifier of the funding/session context.
    pub game_id: [u8; HASH_SIZE],
    /// Zero-based attempt number.
    pub attempt: u32,
    /// Phase number from the canonical attempt schedule.
    pub round: u16,
    /// Authenticated sender.
    pub sender_role: Role,
    /// Global sequence number within this attempt.
    pub sequence: u32,
    /// Transcript state immediately before this envelope.
    pub previous_message_hash: [u8; HASH_SIZE],
    /// Type of the opaque, length-prefixed payload.
    pub payload_type: PayloadType,
    /// Canonically encoded payload body.
    pub payload: Vec<u8>,
}

impl Encode for UnsignedEnvelope {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        validate_v1_version(self.protocol_version)?;
        self.payload_type.validate_payload_len(self.payload.len())?;
        encode_unsigned_fields(self, writer)
    }
}

impl Decode for UnsignedEnvelope {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        if reader.remaining_len() > MAX_UNSIGNED_ENVELOPE_SIZE {
            return Err(CodecError::LengthLimitExceeded);
        }
        decode_unsigned_fields(reader)
    }
}

/// Signed authenticated protocol envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// All fields covered by the BIP340 envelope signature.
    pub unsigned: UnsignedEnvelope,
    /// Raw 64-byte BIP340 signature.
    pub signature: [u8; SIGNATURE_SIZE],
}

/// Structurally decoded signed envelope used by transports that authenticate
/// before applying type-specific payload validation.
///
/// Unlike [`Envelope`], this type retains the raw numeric role and payload
/// type. Its decoder enforces only the global v1 payload bound, so a bounded
/// malformed payload can be BIP340-verified and attributed before typed
/// semantic decoding. Use [`crate::history::TrackedAttempt::accept_bytes`] for
/// live protocol acceptance; ordinary application code should use [`Envelope`]
/// only for already-authenticated archives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawEnvelope {
    /// Protocol wire version.
    pub protocol_version: u16,
    /// Funding/session identifier.
    pub game_id: [u8; HASH_SIZE],
    /// Attempt number.
    pub attempt: u32,
    /// Protocol round.
    pub round: u16,
    /// Raw sender role byte; validated after signature authentication.
    pub sender_role: u8,
    /// Global envelope sequence.
    pub sequence: u32,
    /// Transcript predecessor.
    pub previous_message_hash: [u8; HASH_SIZE],
    /// Raw payload type number; validated after signature authentication.
    pub payload_type: u16,
    /// Payload bounded only by [`MAX_PAYLOAD_SIZE`].
    pub payload: Vec<u8>,
    /// BIP340 signature over the exact raw unsigned fields.
    pub signature: [u8; SIGNATURE_SIZE],
}

impl Encode for RawEnvelope {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(CodecError::LengthLimitExceeded);
        }
        encode_raw_unsigned_fields(
            self.protocol_version,
            self.game_id,
            self.attempt,
            self.round,
            self.sender_role,
            self.sequence,
            self.previous_message_hash,
            self.payload_type,
            &self.payload,
            writer,
        )?;
        self.signature.encode(writer)
    }
}

impl Decode for RawEnvelope {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        if reader.remaining_len() > MAX_ENVELOPE_SIZE {
            return Err(CodecError::LengthLimitExceeded);
        }
        let protocol_version = u16::decode(reader)?;
        let game_id = Decode::decode(reader)?;
        let attempt = u32::decode(reader)?;
        let round = u16::decode(reader)?;
        let sender_role = reader.read_u8()?;
        let sequence = u32::decode(reader)?;
        let previous_message_hash = Decode::decode(reader)?;
        let payload_type = u16::decode(reader)?;
        let payload = reader.read_byte_vector(MAX_PAYLOAD_SIZE)?;
        let signature = Decode::decode(reader)?;
        Ok(Self {
            protocol_version,
            game_id,
            attempt,
            round,
            sender_role,
            sequence,
            previous_message_hash,
            payload_type,
            payload,
            signature,
        })
    }
}

impl Encode for Envelope {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.unsigned.encode(writer)?;
        self.signature.encode(writer)
    }
}

impl Decode for Envelope {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        // This typed decoder is intentionally strict and rejects malformed
        // payload lengths before an Envelope exists. Untrusted transports
        // must use TrackedAttempt::accept_bytes when signer attribution of
        // malformed payloads is required.
        if reader.remaining_len() > MAX_ENVELOPE_SIZE {
            return Err(CodecError::LengthLimitExceeded);
        }
        Ok(Self {
            // Do not apply the standalone unsigned-envelope total cap here:
            // the reader also contains the trailing fixed-size signature.
            unsigned: decode_unsigned_fields(reader)?,
            signature: Decode::decode(reader)?,
        })
    }
}

fn encode_unsigned_fields(
    envelope: &UnsignedEnvelope,
    writer: &mut Writer,
) -> Result<(), CodecError> {
    envelope.protocol_version.encode(writer)?;
    envelope.game_id.encode(writer)?;
    envelope.attempt.encode(writer)?;
    envelope.round.encode(writer)?;
    envelope.sender_role.encode(writer)?;
    envelope.sequence.encode(writer)?;
    envelope.previous_message_hash.encode(writer)?;
    envelope.payload_type.encode(writer)?;
    writer.write_byte_vector(&envelope.payload)
}

/// Encodes the signed unsigned-envelope fields after only the global payload
/// bound has been checked. This is used solely to authenticate a raw payload
/// before the driver applies the payload-type-specific canonical length check.
///
/// Keeping this path separate from [`Encode::encode`] preserves the typed
/// canonical codec while ensuring a signer cannot evade blame by signing a
/// bounded but malformed payload.
pub(crate) fn encode_unsigned_fields_for_auth(
    envelope: &UnsignedEnvelope,
) -> Result<Vec<u8>, CodecError> {
    if envelope.payload.len() > MAX_PAYLOAD_SIZE {
        return Err(CodecError::LengthLimitExceeded);
    }
    let mut writer = Writer::with_capacity(UNSIGNED_ENVELOPE_FIXED_SIZE + envelope.payload.len());
    encode_unsigned_fields(envelope, &mut writer)?;
    Ok(writer.into_bytes())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_raw_unsigned_fields(
    protocol_version: u16,
    game_id: [u8; HASH_SIZE],
    attempt: u32,
    round: u16,
    sender_role: u8,
    sequence: u32,
    previous_message_hash: [u8; HASH_SIZE],
    payload_type: u16,
    payload: &[u8],
    writer: &mut Writer,
) -> Result<(), CodecError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(CodecError::LengthLimitExceeded);
    }
    protocol_version.encode(writer)?;
    game_id.encode(writer)?;
    attempt.encode(writer)?;
    round.encode(writer)?;
    writer.write_u8(sender_role);
    sequence.encode(writer)?;
    previous_message_hash.encode(writer)?;
    payload_type.encode(writer)?;
    writer.write_byte_vector(payload)
}

fn decode_unsigned_fields(reader: &mut Reader<'_>) -> Result<UnsignedEnvelope, CodecError> {
    let protocol_version = u16::decode(reader)?;
    validate_v1_version(protocol_version)?;
    let game_id = Decode::decode(reader)?;
    let attempt = u32::decode(reader)?;
    let round = u16::decode(reader)?;
    let sender_role = Role::decode(reader)?;
    let sequence = u32::decode(reader)?;
    let previous_message_hash = Decode::decode(reader)?;
    let payload_type = PayloadType::decode(reader)?;
    // The type-specific bound is checked before read_byte_vector allocates.
    let payload = reader.read_byte_vector(payload_type.max_payload_len())?;
    payload_type.validate_payload_len(payload.len())?;
    Ok(UnsignedEnvelope {
        protocol_version,
        game_id,
        attempt,
        round,
        sender_role,
        sequence,
        previous_message_hash,
        payload_type,
        payload,
    })
}

fn validate_v1_version(version: u16) -> Result<(), CodecError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(CodecError::NonCanonical)
    }
}

fn validate_point(bytes: [u8; POINT_SIZE]) -> Result<(), CodecError> {
    CompressedRistretto(bytes)
        .decompress()
        .map(|_| ())
        .ok_or(CodecError::NonCanonical)
}

fn validate_proof_lengths(bundle: &PlayerBundle) -> Result<(), CodecError> {
    if bundle.hash_length_proof.len() != HASH_LENGTH_PROOF_SIZE {
        return Err(CodecError::NonCanonical);
    }
    if bundle.encryption_link_proof.len() != ENCRYPTION_LINK_PROOF_SIZE {
        return Err(CodecError::NonCanonical);
    }
    Ok(())
}

fn encode_array<T: Encode, const N: usize>(
    values: &[T; N],
    writer: &mut Writer,
) -> Result<(), CodecError> {
    for value in values {
        value.encode(writer)?;
    }
    Ok(())
}

fn decode_fixed_array<T: Decode, const N: usize>(
    reader: &mut Reader<'_>,
) -> Result<[T; N], CodecError> {
    let mut values = Vec::with_capacity(N);
    for _ in 0..N {
        values.push(T::decode(reader)?);
    }
    values.try_into().map_err(|_| CodecError::NonCanonical)
}

#[cfg(test)]
mod tests {
    use bp52_codec::{CodecError, Decode, Encode, Writer};

    use super::{
        AcceptedDeal, AcceptedDealBody, Ciphertext, ENCRYPTION_LINK_PROOF_SIZE, Envelope,
        HASH_LENGTH_PROOF_SIZE, MAX_HASH_LENGTH_PROOF_SIZE, MAX_PAYLOAD_SIZE, PayloadType,
        PlayerBundle, Role, SlotPublic, UnsignedEnvelope,
    };
    use crate::{N_SLOTS, PROTOCOL_VERSION};

    const IDENTITY_POINT: [u8; 32] = [0_u8; 32];

    fn sample_slot(marker: u8) -> SlotPublic {
        SlotPublic {
            hash: [marker; 32],
            value_commitment: IDENTITY_POINT,
            ciphertext: Ciphertext {
                r: IDENTITY_POINT,
                s: IDENTITY_POINT,
            },
        }
    }

    fn sample_bundle() -> PlayerBundle {
        PlayerBundle {
            role: Role::Alice,
            slots: core::array::from_fn(|index| sample_slot(index.to_le_bytes()[0])),
            circuit_id: [0x55; 32],
            hash_length_proof: vec![0x66; HASH_LENGTH_PROOF_SIZE],
            encryption_link_proof: vec![0x77; ENCRYPTION_LINK_PROOF_SIZE],
        }
    }

    fn sample_unsigned_envelope() -> UnsignedEnvelope {
        UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x11; 32],
            attempt: 7,
            round: 0,
            sender_role: Role::Alice,
            sequence: 0,
            previous_message_hash: [0x22; 32],
            payload_type: PayloadType::KeyCommit,
            payload: vec![0x33; 32],
        }
    }

    fn sample_accepted_body() -> AcceptedDealBody {
        AcceptedDealBody {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x10; 32],
            attempt: 5,
            hashes_a: core::array::from_fn(|index| [index.to_le_bytes()[0]; 32]),
            hashes_b: core::array::from_fn(|index| [(index + N_SLOTS).to_le_bytes()[0]; 32]),
            verification_transcript_root: [0x44; 32],
        }
    }

    #[test]
    fn roles_have_one_strict_byte_encoding() -> Result<(), CodecError> {
        assert_eq!(Role::Alice.encode_to_vec()?, vec![0]);
        assert_eq!(Role::Bob.encode_to_vec()?, vec![1]);
        assert_eq!(Role::decode_exact(&[0])?, Role::Alice);
        assert_eq!(Role::decode_exact(&[1])?, Role::Bob);
        assert_eq!(Role::decode_exact(&[2]), Err(CodecError::NonCanonical));
        Ok(())
    }

    #[test]
    fn player_bundle_round_trip_uses_profile_order() -> Result<(), CodecError> {
        let bundle = sample_bundle();
        let bytes = bundle.encode_to_vec()?;
        assert_eq!(bytes[0], Role::Alice.to_u8());
        assert_eq!(&bytes[1..33], &[0_u8; 32]);
        assert_eq!(PlayerBundle::decode_exact(&bytes)?, bundle);
        Ok(())
    }

    #[test]
    fn accepted_body_and_full_deal_round_trip() -> Result<(), CodecError> {
        let body = sample_accepted_body();
        assert_eq!(
            AcceptedDealBody::decode_exact(&body.encode_to_vec()?)?,
            body
        );

        let deal = AcceptedDeal {
            protocol_version: body.protocol_version,
            game_id: body.game_id,
            attempt: body.attempt,
            hashes_a: body.hashes_a,
            hashes_b: body.hashes_b,
            verification_transcript_root: body.verification_transcript_root,
            signature_a: [0xaa; 64],
            signature_b: [0xbb; 64],
        };
        let bytes = deal.encode_to_vec()?;
        assert_eq!(AcceptedDeal::decode_exact(&bytes)?, deal);
        assert_eq!(deal.body(), body);
        Ok(())
    }

    #[test]
    fn envelope_round_trip_and_trailing_bytes_rejection() -> Result<(), CodecError> {
        let envelope = Envelope {
            unsigned: sample_unsigned_envelope(),
            signature: [0x99; 64],
        };
        let bytes = envelope.encode_to_vec()?;
        assert_eq!(Envelope::decode_exact(&bytes)?, envelope);

        let mut with_trailing = bytes;
        with_trailing.push(0);
        assert_eq!(
            Envelope::decode_exact(&with_trailing),
            Err(CodecError::TrailingBytes)
        );
        Ok(())
    }

    #[test]
    fn envelope_decoder_rejects_unknown_role_and_payload_type() {
        let mut unknown_role = raw_unsigned_prefix(2, PayloadType::KeyCommit.to_u16(), 32);
        unknown_role.extend_from_slice(&[0_u8; 32]);
        assert_eq!(
            UnsignedEnvelope::decode_exact(&unknown_role),
            Err(CodecError::NonCanonical)
        );

        let mut unknown_type = raw_unsigned_prefix(Role::Alice.to_u8(), 10, 32);
        unknown_type.extend_from_slice(&[0_u8; 32]);
        assert_eq!(
            UnsignedEnvelope::decode_exact(&unknown_type),
            Err(CodecError::NonCanonical)
        );
    }

    #[test]
    fn proof_and_payload_allocations_are_bounded() -> Result<(), CodecError> {
        let mut bundle = sample_bundle();
        bundle.hash_length_proof = vec![0; MAX_HASH_LENGTH_PROOF_SIZE + 1];
        assert_eq!(bundle.encode_to_vec(), Err(CodecError::NonCanonical));

        let mut oversized_bundle = Writer::new();
        Role::Alice.encode(&mut oversized_bundle)?;
        for slot in &sample_bundle().slots {
            slot.encode(&mut oversized_bundle)?;
        }
        [0_u8; 32].encode(&mut oversized_bundle)?;
        oversized_bundle
            .write_u32(u32::try_from(MAX_HASH_LENGTH_PROOF_SIZE + 1).unwrap_or(u32::MAX));
        assert_eq!(
            PlayerBundle::decode_exact(&oversized_bundle.into_bytes()),
            Err(CodecError::LengthLimitExceeded)
        );

        let oversized_payload = raw_unsigned_prefix(
            Role::Alice.to_u8(),
            PayloadType::BlindFirst.to_u16(),
            MAX_PAYLOAD_SIZE + 1,
        );
        assert_eq!(
            UnsignedEnvelope::decode_exact(&oversized_payload),
            Err(CodecError::LengthLimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn fixed_payload_type_rejects_short_body() {
        let mut short = sample_unsigned_envelope();
        short.payload.pop();
        assert_eq!(short.encode_to_vec(), Err(CodecError::NonCanonical));
    }

    fn raw_unsigned_prefix(role: u8, payload_type: u16, payload_len: usize) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_u16(PROTOCOL_VERSION);
        writer.write_bytes(&[0_u8; 32]);
        writer.write_u32(0);
        writer.write_u16(0);
        writer.write_u8(role);
        writer.write_u32(0);
        writer.write_bytes(&[0_u8; 32]);
        writer.write_u16(payload_type);
        writer.write_u32(u32::try_from(payload_len).unwrap_or(u32::MAX));
        writer.into_bytes()
    }
}
