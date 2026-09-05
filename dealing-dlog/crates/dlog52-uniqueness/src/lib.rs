#![forbid(unsafe_code)]
//! Candidate catalogue screening and the 108 encrypted uniqueness tests.

use std::collections::HashSet;

use dlog52_codec::{Encode, Reader};
use dlog52_group::{
    Ciphertext, N_SLOTS, RAW_SUM_CANDIDATES, SlotPublic, ZERO_TEST_COUNT, candidate_keys,
    decode_ciphertext, decode_point, decode_scalar, encode_point, encode_scalar,
    protocol_parameters, random_nonzero_scalar,
};
use dlog52_transcript::{hash_scalar, tagged_hash};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Group, sec1::ToEncodedPoint},
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

/// Screening, proof, or uniqueness failure.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum UniquenessError {
    /// A required point is the identity.
    #[error("unexpected identity")]
    Identity,
    /// Two full points collide up to sign at an x-only boundary.
    #[error("duplicate x-only key")]
    DuplicateKey,
    /// A candidate overlaps an identity/authorization key.
    #[error("candidate key overlap")]
    KeyOverlap,
    /// A scaling or decryption proof failed.
    #[error("invalid proof")]
    InvalidProof,
    /// Fiat--Shamir derivation failed.
    #[error("challenge derivation failed")]
    Challenge,
}

/// Fully screened candidate catalogue.
#[derive(Clone)]
pub struct VerifiedCatalogue {
    /// Candidate points indexed by slot then raw sum.
    pub keys: [[ProjectivePoint; RAW_SUM_CANDIDATES]; N_SLOTS],
    /// Hash binding all signed full points.
    pub hash: [u8; 32],
}

fn xonly(point: &ProjectivePoint) -> Result<[u8; 32], UniquenessError> {
    if bool::from(point.is_identity()) {
        return Err(UniquenessError::Identity);
    }
    let encoded = point.to_affine().to_encoded_point(true);
    let x = encoded.x().ok_or(UniquenessError::Identity)?;
    let mut result = [0_u8; 32];
    result.copy_from_slice(x);
    Ok(result)
}

/// Screen commitments and all 927 candidates, then hash the catalogue.
pub fn derive_candidate_catalogue(
    params_id: &[u8; 32],
    game_id: &[u8; 32],
    attempt: u32,
    a: &[SlotPublic; N_SLOTS],
    b: &[SlotPublic; N_SLOTS],
    identity_a: &[u8; 32],
    identity_b: &[u8; 32],
) -> Result<VerifiedCatalogue, UniquenessError> {
    let mut commitment_x = HashSet::with_capacity(18);
    for slot in a.iter().chain(b) {
        if !commitment_x.insert(xonly(&slot.commitment)?) {
            return Err(UniquenessError::DuplicateKey);
        }
        if bool::from(slot.ciphertext.r.is_identity()) {
            return Err(UniquenessError::Identity);
        }
    }
    let keys = std::array::from_fn(|i| candidate_keys(&a[i].commitment, &b[i].commitment));
    let mut all_x = HashSet::with_capacity(N_SLOTS * RAW_SUM_CANDIDATES);
    let mut body = Vec::with_capacity(64 + 4 + N_SLOTS * RAW_SUM_CANDIDATES * 36);
    body.extend_from_slice(params_id);
    body.extend_from_slice(game_id);
    body.extend_from_slice(&attempt.to_le_bytes());
    for (slot, candidates) in keys.iter().enumerate() {
        for (raw_sum, point) in candidates.iter().enumerate() {
            let x = xonly(point)?;
            if x == *identity_a || x == *identity_b {
                return Err(UniquenessError::KeyOverlap);
            }
            if !all_x.insert(x) {
                return Err(UniquenessError::DuplicateKey);
            }
            body.extend_from_slice(&[slot as u8, raw_sum as u8, (raw_sum % 52) as u8]);
            encode_point(point, &mut body);
        }
    }
    Ok(VerifiedCatalogue {
        keys,
        hash: tagged_hash("DLOG52/catalogue/v1", &body),
    })
}

/// Derive all encrypted tests in canonical `(i,j,[-52,0,+52])` order.
pub fn derive_zero_tests(
    a: &[SlotPublic; N_SLOTS],
    b: &[SlotPublic; N_SLOTS],
) -> Result<[Ciphertext; ZERO_TEST_COUNT], UniquenessError> {
    let sums: [Ciphertext; N_SLOTS] =
        std::array::from_fn(|i| a[i].ciphertext.add(&b[i].ciphertext));
    for sum in &sums {
        if bool::from(sum.r.is_identity()) {
            return Err(UniquenessError::Identity);
        }
    }
    let mut tests = Vec::with_capacity(ZERO_TEST_COUNT);
    for i in 0..N_SLOTS {
        for j in (i + 1)..N_SLOTS {
            let difference = sums[i].sub(&sums[j]);
            if bool::from(difference.r.is_identity()) {
                return Err(UniquenessError::Identity);
            }
            for offset in [-52_i16, 0, 52] {
                let offset_point = if offset < 0 {
                    -protocol_parameters().m * Scalar::from(offset.unsigned_abs() as u64)
                } else {
                    protocol_parameters().m * Scalar::from(offset as u64)
                };
                tests.push(Ciphertext {
                    r: difference.r,
                    s: difference.s - offset_point,
                });
            }
        }
    }
    tests.try_into().map_err(|_| UniquenessError::InvalidProof)
}

/// One exact scale-proof record.
#[derive(Clone)]
pub struct ScaleRecord {
    /// `aG` proving a nonzero generation witness.
    pub q: ProjectivePoint,
    /// Scaled ciphertext.
    pub output: Ciphertext,
    /// Nonce commitment to G.
    pub t_g: ProjectivePoint,
    /// Nonce commitment to input R.
    pub t_r: ProjectivePoint,
    /// Nonce commitment to input S.
    pub t_s: ProjectivePoint,
    /// Shared-challenge response.
    pub z: Scalar,
}

impl Encode for ScaleRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.q, out);
        self.output.encode(out);
        encode_point(&self.t_g, out);
        encode_point(&self.t_r, out);
        encode_point(&self.t_s, out);
        encode_scalar(&self.z, out);
    }
}

/// Decode one canonical scaling record.
pub fn decode_scale_record(reader: &mut Reader<'_>) -> Result<ScaleRecord, UniquenessError> {
    Ok(ScaleRecord {
        q: decode_point(reader, false).map_err(|_| UniquenessError::InvalidProof)?,
        output: decode_ciphertext(reader, true).map_err(|_| UniquenessError::InvalidProof)?,
        t_g: decode_point(reader, true).map_err(|_| UniquenessError::InvalidProof)?,
        t_r: decode_point(reader, true).map_err(|_| UniquenessError::InvalidProof)?,
        t_s: decode_point(reader, true).map_err(|_| UniquenessError::InvalidProof)?,
        z: decode_scalar(reader).map_err(|_| UniquenessError::InvalidProof)?,
    })
}

/// Exact 108-record scaling payload.
#[derive(Clone)]
pub struct ScalePayload {
    /// Canonically ordered records.
    pub records: Vec<ScaleRecord>,
}

impl Encode for ScalePayload {
    fn encode(&self, out: &mut Vec<u8>) {
        for record in &self.records {
            record.encode(out);
        }
    }
}

/// Decode the exact fixed-shape 108-record scaling payload.
pub fn decode_scale_payload(reader: &mut Reader<'_>) -> Result<ScalePayload, UniquenessError> {
    let mut records = Vec::with_capacity(ZERO_TEST_COUNT);
    for _ in 0..ZERO_TEST_COUNT {
        records.push(decode_scale_record(reader)?);
    }
    Ok(ScalePayload { records })
}

fn scale_challenge(
    label: &str,
    context: &[u8],
    joint_public: &[u8],
    input: &[Ciphertext; ZERO_TEST_COUNT],
    records: &[ScaleRecord],
) -> Result<Scalar, UniquenessError> {
    let mut body = context.to_vec();
    body.extend_from_slice(joint_public);
    for (ciphertext, record) in input.iter().zip(records) {
        ciphertext.encode(&mut body);
        encode_point(&record.q, &mut body);
        record.output.encode(&mut body);
    }
    for record in records {
        encode_point(&record.t_g, &mut body);
        encode_point(&record.t_r, &mut body);
        encode_point(&record.t_s, &mut body);
    }
    hash_scalar(label, &body).map_err(|_| UniquenessError::Challenge)
}

/// Independently blind every ciphertext and prove all three scaling equations.
pub fn create_scale_round(
    label: &str,
    context: &[u8],
    joint_public: &[u8],
    input: &[Ciphertext; ZERO_TEST_COUNT],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<ScalePayload, UniquenessError> {
    let mut factors: [Scalar; ZERO_TEST_COUNT] =
        std::array::from_fn(|_| random_nonzero_scalar(rng));
    let mut nonces: [Scalar; ZERO_TEST_COUNT] =
        std::array::from_fn(|_| dlog52_group::random_scalar(rng));
    let mut records: Vec<ScaleRecord> = input
        .iter()
        .zip(factors.iter().zip(&nonces))
        .map(|(ciphertext, (factor, nonce))| ScaleRecord {
            q: protocol_parameters().g * factor,
            output: ciphertext.scale(factor),
            t_g: protocol_parameters().g * nonce,
            t_r: ciphertext.r * nonce,
            t_s: ciphertext.s * nonce,
            z: Scalar::ZERO,
        })
        .collect();
    let e = scale_challenge(label, context, joint_public, input, &records)?;
    for ((record, factor), nonce) in records.iter_mut().zip(&factors).zip(&nonces) {
        record.z = *nonce + e * factor;
    }
    factors.zeroize();
    nonces.zeroize();
    let payload = ScalePayload { records };
    verify_scale_round(label, context, joint_public, input, &payload)?;
    Ok(payload)
}

/// Verify all equations in an exact scale round.
pub fn verify_scale_round(
    label: &str,
    context: &[u8],
    joint_public: &[u8],
    input: &[Ciphertext; ZERO_TEST_COUNT],
    payload: &ScalePayload,
) -> Result<[Ciphertext; ZERO_TEST_COUNT], UniquenessError> {
    if payload.records.len() != ZERO_TEST_COUNT {
        return Err(UniquenessError::InvalidProof);
    }
    let e = scale_challenge(label, context, joint_public, input, &payload.records)?;
    for (ciphertext, record) in input.iter().zip(&payload.records) {
        if bool::from(record.q.is_identity())
            || protocol_parameters().g * record.z != record.t_g + record.q * e
            || ciphertext.r * record.z != record.t_r + record.output.r * e
            || ciphertext.s * record.z != record.t_s + record.output.s * e
        {
            return Err(UniquenessError::InvalidProof);
        }
    }
    let outputs: Vec<_> = payload
        .records
        .iter()
        .map(|record| record.output.clone())
        .collect();
    outputs
        .try_into()
        .map_err(|_| UniquenessError::InvalidProof)
}

/// Batch same-secret partial-decryption proof.
#[derive(Clone)]
pub struct DecryptionBody {
    /// Decryption shares.
    pub shares: Vec<ProjectivePoint>,
    /// Common nonce commitment.
    pub t_g: ProjectivePoint,
    /// Per-input nonce commitments.
    pub temporaries: Vec<ProjectivePoint>,
    /// DLEQ response.
    pub z: Scalar,
}

impl Encode for DecryptionBody {
    fn encode(&self, out: &mut Vec<u8>) {
        for share in &self.shares {
            encode_point(share, out);
        }
        encode_point(&self.t_g, out);
        for temporary in &self.temporaries {
            encode_point(temporary, out);
        }
        encode_scalar(&self.z, out);
    }
}

/// Decode the exact fixed-shape batch decryption body.
pub fn decode_decryption_body(reader: &mut Reader<'_>) -> Result<DecryptionBody, UniquenessError> {
    let mut shares = Vec::with_capacity(ZERO_TEST_COUNT);
    for _ in 0..ZERO_TEST_COUNT {
        shares.push(decode_point(reader, false).map_err(|_| UniquenessError::InvalidProof)?);
    }
    let t_g = decode_point(reader, true).map_err(|_| UniquenessError::InvalidProof)?;
    let mut temporaries = Vec::with_capacity(ZERO_TEST_COUNT);
    for _ in 0..ZERO_TEST_COUNT {
        temporaries.push(decode_point(reader, true).map_err(|_| UniquenessError::InvalidProof)?);
    }
    let z = decode_scalar(reader).map_err(|_| UniquenessError::InvalidProof)?;
    Ok(DecryptionBody {
        shares,
        t_g,
        temporaries,
        z,
    })
}

fn decrypt_challenge(
    context: &[u8],
    joint_public: &[u8],
    input: &[Ciphertext; ZERO_TEST_COUNT],
    body: &DecryptionBody,
) -> Result<Scalar, UniquenessError> {
    let mut bytes = context.to_vec();
    bytes.extend_from_slice(joint_public);
    for ciphertext in input {
        ciphertext.encode(&mut bytes);
    }
    for share in &body.shares {
        encode_point(share, &mut bytes);
    }
    encode_point(&body.t_g, &mut bytes);
    for temporary in &body.temporaries {
        encode_point(temporary, &mut bytes);
    }
    hash_scalar("DLOG52/partial-decrypt/v1", &bytes).map_err(|_| UniquenessError::Challenge)
}

/// Create one exact partial-decryption body.
pub fn create_decryption(
    context: &[u8],
    joint_public: &[u8],
    input: &[Ciphertext; ZERO_TEST_COUNT],
    secret: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DecryptionBody, UniquenessError> {
    if bool::from(secret.is_zero()) {
        return Err(UniquenessError::InvalidProof);
    }
    let w = dlog52_group::random_scalar(rng);
    let shares = input
        .iter()
        .map(|ciphertext| ciphertext.r * secret)
        .collect();
    let mut body = DecryptionBody {
        shares,
        t_g: protocol_parameters().g * w,
        temporaries: input.iter().map(|ciphertext| ciphertext.r * w).collect(),
        z: Scalar::ZERO,
    };
    let e = decrypt_challenge(context, joint_public, input, &body)?;
    body.z = w + e * secret;
    Ok(body)
}

/// Verify every same-secret decryption equation.
pub fn verify_decryption(
    context: &[u8],
    joint_public: &[u8],
    input: &[Ciphertext; ZERO_TEST_COUNT],
    public_key: &ProjectivePoint,
    body: &DecryptionBody,
) -> Result<(), UniquenessError> {
    if body.shares.len() != ZERO_TEST_COUNT || body.temporaries.len() != ZERO_TEST_COUNT {
        return Err(UniquenessError::InvalidProof);
    }
    let e = decrypt_challenge(context, joint_public, input, body)?;
    if protocol_parameters().g * body.z != body.t_g + *public_key * e {
        return Err(UniquenessError::InvalidProof);
    }
    for ((ciphertext, share), temporary) in input.iter().zip(&body.shares).zip(&body.temporaries) {
        if ciphertext.r * body.z != *temporary + *share * e {
            return Err(UniquenessError::InvalidProof);
        }
    }
    Ok(())
}

/// Reveal the collision bitmap after both valid decryption shares are available.
pub fn collision_bitmap(
    input: &[Ciphertext; ZERO_TEST_COUNT],
    a: &DecryptionBody,
    b: &DecryptionBody,
) -> Result<[bool; ZERO_TEST_COUNT], UniquenessError> {
    if a.shares.len() != ZERO_TEST_COUNT || b.shares.len() != ZERO_TEST_COUNT {
        return Err(UniquenessError::InvalidProof);
    }
    Ok(std::array::from_fn(|i| {
        bool::from((input[i].s - a.shares[i] - b.shares[i]).is_identity())
    }))
}
