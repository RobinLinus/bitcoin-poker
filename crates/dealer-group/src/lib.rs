#![forbid(unsafe_code)]
//! secp256k1 algebra and fixed DLOG52 parameters.

use dealer_codec::{Encode, Reader, put_ascii, put_u16};
use dealer_transcript::tagged_hash;
use k256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, Secp256k1,
    elliptic_curve::{
        Field, Group, PrimeField,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use thiserror::Error;

/// Number of cards.
pub const DECK_SIZE: usize = 52;
/// Number of deal slots.
pub const N_SLOTS: usize = 9;
/// Number of raw-sum candidates per slot.
pub const RAW_SUM_CANDIDATES: usize = 103;
/// Number of encrypted collision tests.
pub const ZERO_TEST_COUNT: usize = 108;
/// Fixed RFC 9380 suite identifier.
pub const H2C_SUITE: &str = "secp256k1_XMD:SHA-256_SSWU_RO_";
/// Fixed message-generator domain separation tag.
pub const MESSAGE_DST: &str = "DLOG52-DEAL-v1/message-generator/secp256k1_XMD:SHA-256_SSWU_RO_";
/// Fixed message-generator input.
pub const MESSAGE_INPUT: &str = "DLOG52-DEAL-v1/message-generator";

/// Validation failure in group-level data.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum GroupError {
    /// Scalar is not the unique big-endian integer below the group order.
    #[error("noncanonical scalar")]
    Scalar,
    /// SEC1 point encoding is malformed or forbidden in this position.
    #[error("invalid point")]
    Point,
    /// A point required to be nonidentity is the identity.
    #[error("unexpected identity")]
    Identity,
    /// A contribution is outside 0..51.
    #[error("contribution outside 0..51")]
    Contribution,
}

/// Public fixed parameters and their committed identifier.
pub struct ProtocolParameters {
    /// Standard secp256k1 generator.
    pub g: ProjectivePoint,
    /// RFC 9380-derived message generator.
    pub m: ProjectivePoint,
    /// Canonical parameter manifest.
    pub manifest: Vec<u8>,
    /// Tagged hash of the manifest.
    pub params_id: [u8; 32],
}

static PARAMETERS: std::sync::LazyLock<ProtocolParameters> = std::sync::LazyLock::new(|| {
    let g = ProjectivePoint::GENERATOR;
    let m = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[MESSAGE_INPUT.as_bytes()],
        &[MESSAGE_DST.as_bytes()],
    )
    .unwrap_or(ProjectivePoint::IDENTITY);
    assert!(
        m != ProjectivePoint::IDENTITY && m != g && m != -g,
        "invalid fixed generator"
    );
    let mut manifest = Vec::new();
    put_ascii(&mut manifest, "DLOG52-DEAL-v1");
    put_u16(&mut manifest, 1);
    put_ascii(&mut manifest, "secp256k1");
    put_ascii(&mut manifest, H2C_SUITE);
    put_ascii(&mut manifest, MESSAGE_DST);
    put_ascii(&mut manifest, MESSAGE_INPUT);
    encode_point(&g, &mut manifest);
    encode_point(&m, &mut manifest);
    manifest.extend_from_slice(&[52, 9, 6]);
    put_u16(&mut manifest, 108);
    manifest.push(102);
    for _ in 0..7 {
        put_u16(&mut manifest, 1);
    }
    let params_id = tagged_hash("DLOG52/params/v1", &manifest);
    ProtocolParameters {
        g,
        m,
        manifest,
        params_id,
    }
});

/// Return the process-wide immutable fixed parameters.
#[must_use]
pub fn protocol_parameters() -> &'static ProtocolParameters {
    &PARAMETERS
}

/// Encode a scalar as a canonical big-endian integer.
pub fn encode_scalar(scalar: &Scalar, out: &mut Vec<u8>) {
    out.extend_from_slice(&scalar.to_bytes());
}

/// Parse a canonical scalar without modular reduction.
///
/// # Errors
///
/// Rejects invalid point encodings, scalars, or card values.
pub fn decode_scalar(reader: &mut Reader<'_>) -> Result<Scalar, GroupError> {
    let bytes = reader.array::<32>().map_err(|_| GroupError::Scalar)?;
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(bytes))).ok_or(GroupError::Scalar)
}

/// Encode a full signed point, using the protocol identity sentinel where allowed.
pub fn encode_point(point: &ProjectivePoint, out: &mut Vec<u8>) {
    if bool::from(point.is_identity()) {
        out.extend_from_slice(&[0_u8; 33]);
    } else {
        out.extend_from_slice(point.to_affine().to_encoded_point(true).as_bytes());
    }
}

/// Parse a full signed point. The all-zero identity is accepted only when requested.
///
/// # Errors
///
/// Rejects invalid point encodings, scalars, or card values.
pub fn decode_point(
    reader: &mut Reader<'_>,
    allow_identity: bool,
) -> Result<ProjectivePoint, GroupError> {
    let bytes = reader.array::<33>().map_err(|_| GroupError::Point)?;
    if bytes == [0_u8; 33] {
        return if allow_identity {
            Ok(ProjectivePoint::IDENTITY)
        } else {
            Err(GroupError::Identity)
        };
    }
    if !matches!(bytes[0], 2 | 3) {
        return Err(GroupError::Point);
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| GroupError::Point)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(GroupError::Point)?;
    Ok(ProjectivePoint::from(affine))
}

/// Rejection-sample a scalar. `k256` performs canonical rejection sampling.
pub fn random_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    Scalar::random(rng)
}

/// Sample a nonzero scalar.
pub fn random_nonzero_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    loop {
        let value = random_scalar(rng);
        if !bool::from(value.is_zero()) {
            return value;
        }
    }
}

/// Sample a contribution uniformly using the specified byte rejection rule.
pub fn random_contribution(rng: &mut (impl RngCore + CryptoRng)) -> u8 {
    loop {
        let mut byte = [0_u8; 1];
        rng.fill_bytes(&mut byte);
        if byte[0] < 208 {
            return byte[0] % 52;
        }
    }
}

/// Canonical public ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    /// `ElGamal` randomness component.
    pub r: ProjectivePoint,
    /// `ElGamal` message component.
    pub s: ProjectivePoint,
}

impl Ciphertext {
    /// Componentwise addition.
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            r: self.r + rhs.r,
            s: self.s + rhs.s,
        }
    }
    /// Componentwise subtraction.
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            r: self.r - rhs.r,
            s: self.s - rhs.s,
        }
    }
    /// Componentwise scalar multiplication.
    #[must_use]
    pub fn scale(&self, scalar: &Scalar) -> Self {
        Self {
            r: self.r * scalar,
            s: self.s * scalar,
        }
    }
}

impl Encode for Ciphertext {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.r, out);
        encode_point(&self.s, out);
    }
}

/// Decode one canonical ciphertext, permitting identity components only when
/// the surrounding protocol stage does.
///
/// # Errors
///
/// Rejects invalid point encodings, scalars, or card values.
pub fn decode_ciphertext(
    reader: &mut Reader<'_>,
    allow_identity: bool,
) -> Result<Ciphertext, GroupError> {
    Ok(Ciphertext {
        r: decode_point(reader, allow_identity)?,
        s: decode_point(reader, allow_identity)?,
    })
}

/// Public data for one contribution slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotPublic {
    /// Pedersen commitment.
    pub commitment: ProjectivePoint,
    /// Linked `ElGamal` ciphertext.
    pub ciphertext: Ciphertext,
}

impl Encode for SlotPublic {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.commitment, out);
        self.ciphertext.encode(out);
    }
}

/// Decode one contribution slot with the original commitment and ciphertext-R
/// nonidentity requirements.
///
/// # Errors
///
/// Rejects invalid point encodings, scalars, or card values.
pub fn decode_slot_public(reader: &mut Reader<'_>) -> Result<SlotPublic, GroupError> {
    Ok(SlotPublic {
        commitment: decode_point(reader, false)?,
        ciphertext: Ciphertext {
            r: decode_point(reader, false)?,
            s: decode_point(reader, true)?,
        },
    })
}

/// Create the public commitment and ciphertext for one opening.
///
/// # Errors
///
/// Rejects invalid point encodings, scalars, or card values.
pub fn create_slot(
    value: u8,
    gamma: &Scalar,
    encryption_randomness: &Scalar,
    joint_key: &ProjectivePoint,
) -> Result<SlotPublic, GroupError> {
    if usize::from(value) >= DECK_SIZE {
        return Err(GroupError::Contribution);
    }
    let p = protocol_parameters();
    let v = Scalar::from(u64::from(value));
    let commitment = p.m * v + p.g * gamma;
    let r = p.g * encryption_randomness;
    if bool::from(commitment.is_identity()) || bool::from(r.is_identity()) {
        return Err(GroupError::Identity);
    }
    Ok(SlotPublic {
        commitment,
        ciphertext: Ciphertext {
            r,
            s: p.m * v + joint_key * encryption_randomness,
        },
    })
}

/// Return `W - tM` for all raw sums in canonical order.
#[must_use]
pub fn candidate_keys(
    a: &ProjectivePoint,
    b: &ProjectivePoint,
) -> [ProjectivePoint; RAW_SUM_CANDIDATES] {
    let mut current = *a + *b;
    std::array::from_fn(|_| {
        let out = current;
        current -= protocol_parameters().m;
        out
    })
}

/// Card identifier from two valid contributions.
///
/// # Errors
///
/// Rejects invalid point encodings, scalars, or card values.
pub fn card_id(a: u8, b: u8) -> Result<u8, GroupError> {
    if usize::from(a) >= DECK_SIZE || usize::from(b) >= DECK_SIZE {
        return Err(GroupError::Contribution);
    }
    u8::try_from((u16::from(a) + u16::from(b)).rem_euclid(52)).map_err(|_| GroupError::Contribution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_have_expected_sizes_and_stable_vector() {
        let p = protocol_parameters();
        assert_eq!(p.manifest.len(), 256);
        assert_eq!(
            hex::encode(p.m.to_affine().to_encoded_point(true).as_bytes()),
            "026d07c8f9da86e3d0e18300260d75bc9bb5aec1604a086ef53919050842bd916f"
        );
    }

    #[test]
    fn exhaustive_card_arithmetic() {
        for a in 0..52_u8 {
            for b in 0..52_u8 {
                assert_eq!(
                    card_id(a, b),
                    Ok(((u16::from(a) + u16::from(b)) % 52) as u8)
                );
            }
        }
        assert_eq!(card_id(52, 0), Err(GroupError::Contribution));
    }

    #[test]
    fn canonical_point_round_trip_and_identity_policy() {
        let mut bytes = Vec::new();
        encode_point(&protocol_parameters().m, &mut bytes);
        let mut reader = Reader::new(&bytes);
        assert_eq!(
            decode_point(&mut reader, false),
            Ok(protocol_parameters().m)
        );
        assert_eq!(
            decode_point(&mut Reader::new(&[0; 33]), false),
            Err(GroupError::Identity)
        );
        assert_eq!(
            decode_point(&mut Reader::new(&[0; 33]), true),
            Ok(ProjectivePoint::IDENTITY)
        );
    }
}
