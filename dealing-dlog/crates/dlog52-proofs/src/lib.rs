#![forbid(unsafe_code)]
//! Exact Sigma proof profiles used by DLOG52-DEAL-v1.

use dlog52_codec::{Encode, Reader};
use dlog52_group::{
    N_SLOTS, SlotPublic, decode_point, decode_scalar, encode_point, encode_scalar,
    protocol_parameters, random_scalar,
};
use dlog52_transcript::hash_scalar;
use k256::{ProjectivePoint, Scalar, elliptic_curve::Group};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use thiserror::Error;
use zeroize::Zeroize;

/// Number of committed bit records in one player's range proof.
pub const BIT_RECORDS: usize = 108;
/// Canonical range-proof byte length.
pub const RANGE_PROOF_BYTES: usize = 13_964;
/// Canonical encryption-link proof byte length.
pub const LINK_PROOF_BYTES: usize = 1_755;

/// Proof construction or validation failure.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ProofError {
    /// A witness is outside the relation.
    #[error("invalid witness")]
    Witness,
    /// A Fiat--Shamir challenge could not be derived.
    #[error("challenge derivation failed")]
    Challenge,
    /// One or more proof equations failed.
    #[error("invalid proof")]
    Invalid,
    /// A proof has the wrong fixed shape.
    #[error("invalid proof shape")]
    Shape,
}

/// Schnorr proof of possession of a threshold secret key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPop {
    /// Nonce commitment.
    pub t: ProjectivePoint,
    /// Schnorr response.
    pub z: Scalar,
}

impl Encode for KeyPop {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.t, out);
        encode_scalar(&self.z, out);
    }
}

/// Decode an exact key proof.
pub fn decode_key_pop(reader: &mut Reader<'_>) -> Result<KeyPop, ProofError> {
    Ok(KeyPop {
        t: decode_point(reader, false).map_err(|_| ProofError::Shape)?,
        z: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
    })
}

/// Create the exact key-possession proof.
pub fn prove_key_pop(
    context: &[u8],
    secret: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<KeyPop, ProofError> {
    if bool::from(secret.is_zero()) {
        return Err(ProofError::Witness);
    }
    let g = protocol_parameters().g;
    let public = g * secret;
    let w = dlog52_group::random_nonzero_scalar(rng);
    let t = g * w;
    let mut body = context.to_vec();
    encode_point(&public, &mut body);
    encode_point(&t, &mut body);
    let e = hash_scalar("DLOG52/key-pop/v1", &body).map_err(|_| ProofError::Challenge)?;
    Ok(KeyPop {
        t,
        z: w + e * secret,
    })
}

/// Verify the exact key-possession proof.
pub fn verify_key_pop(
    context: &[u8],
    public: &ProjectivePoint,
    proof: &KeyPop,
) -> Result<(), ProofError> {
    if bool::from(public.is_identity()) || bool::from(proof.t.is_identity()) {
        return Err(ProofError::Invalid);
    }
    let mut body = context.to_vec();
    encode_point(public, &mut body);
    encode_point(&proof.t, &mut body);
    let e = hash_scalar("DLOG52/key-pop/v1", &body).map_err(|_| ProofError::Challenge)?;
    if protocol_parameters().g * proof.z == proof.t + *public * e {
        Ok(())
    } else {
        Err(ProofError::Invalid)
    }
}

/// Secret opening used only while constructing a range proof.
pub struct RangeWitness {
    /// Contribution in 0..51.
    pub value: u8,
    /// Pedersen blinder.
    pub gamma: Scalar,
}

impl Drop for RangeWitness {
    fn drop(&mut self) {
        self.value.zeroize();
        self.gamma.zeroize();
    }
}

/// Responses for one explicit two-branch OR proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitOrResponse {
    /// Branch-zero challenge.
    pub c0: Scalar,
    /// Branch-zero response.
    pub z0: Scalar,
    /// Branch-one response.
    pub z1: Scalar,
}

/// Exact fixed-shape `Range52-BitOR-v1` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Range52Proof {
    /// Bit commitments in `(slot, side, bit)` order.
    pub bit_commitments: Vec<ProjectivePoint>,
    /// One shared nonzero challenge.
    pub challenge: Scalar,
    /// OR responses in the same order.
    pub responses: Vec<BitOrResponse>,
}

impl Encode for Range52Proof {
    fn encode(&self, out: &mut Vec<u8>) {
        for point in &self.bit_commitments {
            encode_point(point, out);
        }
        encode_scalar(&self.challenge, out);
        for response in &self.responses {
            encode_scalar(&response.c0, out);
            encode_scalar(&response.z0, out);
            encode_scalar(&response.z1, out);
        }
    }
}

/// Decode the fixed 13,964-byte range proof without wire-directed allocation.
pub fn decode_range52(reader: &mut Reader<'_>) -> Result<Range52Proof, ProofError> {
    let mut bit_commitments = Vec::with_capacity(BIT_RECORDS);
    for _ in 0..BIT_RECORDS {
        bit_commitments.push(decode_point(reader, true).map_err(|_| ProofError::Shape)?);
    }
    let challenge = decode_scalar(reader).map_err(|_| ProofError::Shape)?;
    let mut responses = Vec::with_capacity(BIT_RECORDS);
    for _ in 0..BIT_RECORDS {
        responses.push(BitOrResponse {
            c0: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
            z0: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
            z1: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
        });
    }
    Ok(Range52Proof {
        bit_commitments,
        challenge,
        responses,
    })
}

struct OrWitness {
    bit: Choice,
    rho: Scalar,
    w: Scalar,
    c_fake: Scalar,
    z_fake: Scalar,
}

impl Drop for OrWitness {
    fn drop(&mut self) {
        self.rho.zeroize();
        self.w.zeroize();
        self.c_fake.zeroize();
        self.z_fake.zeroize();
    }
}

fn challenge_body(
    statement: &[u8],
    commitments: &[ProjectivePoint],
    temporaries: &[(ProjectivePoint, ProjectivePoint)],
) -> Vec<u8> {
    let mut body = statement.to_vec();
    for point in commitments {
        encode_point(point, &mut body);
    }
    for (t0, t1) in temporaries {
        encode_point(t0, &mut body);
        encode_point(t1, &mut body);
    }
    body
}

/// Construct the exact 108-record range proof.
pub fn prove_range52(
    bundle_statement: &[u8],
    slots: &[SlotPublic; N_SLOTS],
    witnesses: &[RangeWitness; N_SLOTS],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Range52Proof, ProofError> {
    let p = protocol_parameters();
    let inv_32 =
        Option::<Scalar>::from(Scalar::from(32_u64).invert()).ok_or(ProofError::Witness)?;
    let mut commitments = Vec::with_capacity(BIT_RECORDS);
    let mut or_witnesses = Vec::with_capacity(BIT_RECORDS);
    let mut temporaries = Vec::with_capacity(BIT_RECORDS);
    for (slot_index, witness) in witnesses.iter().enumerate() {
        if witness.value > 51 {
            return Err(ProofError::Witness);
        }
        let values = [witness.value, 51 - witness.value];
        let blinders = [witness.gamma, -witness.gamma];
        for side in 0..2 {
            let mut rhos = [Scalar::ZERO; 6];
            let mut weighted = Scalar::ZERO;
            for (bit, rho) in rhos.iter_mut().enumerate().take(5) {
                *rho = random_scalar(rng);
                weighted += *rho * Scalar::from(1_u64 << bit);
            }
            rhos[5] = (blinders[side] - weighted) * inv_32;
            for (bit_index, rho) in rhos.into_iter().enumerate() {
                let bit_u8 = (values[side] >> bit_index) & 1;
                let bit = Choice::from(bit_u8);
                let commitment = p.g * rho + p.m * Scalar::from(u64::from(bit_u8));
                commitments.push(commitment);
                let w = random_scalar(rng);
                let c_fake = random_scalar(rng);
                let z_fake = random_scalar(rng);
                let p0 = commitment;
                let p1 = commitment - p.m;
                let t_real = p.g * w;
                let fake_statement = ProjectivePoint::conditional_select(&p1, &p0, bit);
                let t_fake = p.g * z_fake - fake_statement * c_fake;
                let t0 = ProjectivePoint::conditional_select(&t_real, &t_fake, bit);
                let t1 = ProjectivePoint::conditional_select(&t_fake, &t_real, bit);
                temporaries.push((t0, t1));
                or_witnesses.push(OrWitness {
                    bit,
                    rho,
                    w,
                    c_fake,
                    z_fake,
                });
            }
        }
        let _ = slot_index;
    }
    let e = hash_scalar(
        "DLOG52/range52-bitor/v1",
        &challenge_body(bundle_statement, &commitments, &temporaries),
    )
    .map_err(|_| ProofError::Challenge)?;
    let responses = or_witnesses
        .iter()
        .map(|witness| {
            let c_real = e - witness.c_fake;
            let z_real = witness.w + c_real * witness.rho;
            BitOrResponse {
                c0: Scalar::conditional_select(&c_real, &witness.c_fake, witness.bit),
                z0: Scalar::conditional_select(&z_real, &witness.z_fake, witness.bit),
                z1: Scalar::conditional_select(&witness.z_fake, &z_real, witness.bit),
            }
        })
        .collect();
    let proof = Range52Proof {
        bit_commitments: commitments,
        challenge: e,
        responses,
    };
    debug_assert_eq!(proof.to_bytes().len(), RANGE_PROOF_BYTES);
    verify_range52(bundle_statement, slots, &proof)?;
    Ok(proof)
}

/// Verify every OR relation and both weighted-sum equations for every slot.
pub fn verify_range52(
    bundle_statement: &[u8],
    slots: &[SlotPublic; N_SLOTS],
    proof: &Range52Proof,
) -> Result<(), ProofError> {
    if proof.bit_commitments.len() != BIT_RECORDS
        || proof.responses.len() != BIT_RECORDS
        || bool::from(proof.challenge.is_zero())
    {
        return Err(ProofError::Shape);
    }
    let p = protocol_parameters();
    let mut temporaries = Vec::with_capacity(BIT_RECORDS);
    for (commitment, response) in proof.bit_commitments.iter().zip(&proof.responses) {
        let c1 = proof.challenge - response.c0;
        let t0 = p.g * response.z0 - *commitment * response.c0;
        let t1 = p.g * response.z1 - (*commitment - p.m) * c1;
        temporaries.push((t0, t1));
    }
    let expected = hash_scalar(
        "DLOG52/range52-bitor/v1",
        &challenge_body(bundle_statement, &proof.bit_commitments, &temporaries),
    )
    .map_err(|_| ProofError::Challenge)?;
    if expected != proof.challenge {
        return Err(ProofError::Invalid);
    }
    for (slot_index, slot) in slots.iter().enumerate() {
        let base = slot_index * 12;
        let mut value_sum = ProjectivePoint::IDENTITY;
        let mut complement_sum = ProjectivePoint::IDENTITY;
        for bit in 0..6 {
            let weight = Scalar::from(1_u64 << bit);
            value_sum += proof.bit_commitments[base + bit] * weight;
            complement_sum += proof.bit_commitments[base + 6 + bit] * weight;
        }
        if value_sum != slot.commitment
            || complement_sum != p.m * Scalar::from(51_u64) - slot.commitment
        {
            return Err(ProofError::Invalid);
        }
    }
    Ok(())
}

/// One generalized Schnorr encryption-link proof record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkProofRecord {
    /// Commitment for the Pedersen equation.
    pub t_v: ProjectivePoint,
    /// Commitment for the ciphertext-R equation.
    pub t_r: ProjectivePoint,
    /// Commitment for the ciphertext-S equation.
    pub t_s: ProjectivePoint,
    /// Value response.
    pub z_v: Scalar,
    /// Commitment-blinder response.
    pub z_gamma: Scalar,
    /// Encryption-randomness response.
    pub z_r: Scalar,
}

impl Encode for LinkProofRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.t_v, out);
        encode_point(&self.t_r, out);
        encode_point(&self.t_s, out);
        encode_scalar(&self.z_v, out);
        encode_scalar(&self.z_gamma, out);
        encode_scalar(&self.z_r, out);
    }
}

/// Decode one fixed encryption-link record.
pub fn decode_link_record(reader: &mut Reader<'_>) -> Result<LinkProofRecord, ProofError> {
    Ok(LinkProofRecord {
        t_v: decode_point(reader, true).map_err(|_| ProofError::Shape)?,
        t_r: decode_point(reader, true).map_err(|_| ProofError::Shape)?,
        t_s: decode_point(reader, true).map_err(|_| ProofError::Shape)?,
        z_v: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
        z_gamma: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
        z_r: decode_scalar(reader).map_err(|_| ProofError::Shape)?,
    })
}

/// Construct all nine encryption-link records under one shared challenge.
pub fn prove_links(
    bundle_statement: &[u8],
    range_proof: &Range52Proof,
    witnesses: &[RangeWitness; N_SLOTS],
    encryption_randomness: &[Scalar; N_SLOTS],
    joint_key: &ProjectivePoint,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<[LinkProofRecord; N_SLOTS], ProofError> {
    struct Nonce {
        av: Scalar,
        ag: Scalar,
        ar: Scalar,
        tv: ProjectivePoint,
        tr: ProjectivePoint,
        ts: ProjectivePoint,
    }
    impl Drop for Nonce {
        fn drop(&mut self) {
            self.av.zeroize();
            self.ag.zeroize();
            self.ar.zeroize();
        }
    }
    let p = protocol_parameters();
    let nonces: [Nonce; N_SLOTS] = std::array::from_fn(|_| {
        let av = random_scalar(rng);
        let ag = random_scalar(rng);
        let ar = random_scalar(rng);
        Nonce {
            av,
            ag,
            ar,
            tv: p.m * av + p.g * ag,
            tr: p.g * ar,
            ts: p.m * av + *joint_key * ar,
        }
    });
    let mut body = bundle_statement.to_vec();
    body.extend_from_slice(&dlog52_transcript::tagged_hash(
        "DLOG52/range-proof-bytes/v1",
        &range_proof.to_bytes(),
    ));
    for n in &nonces {
        encode_point(&n.tv, &mut body);
        encode_point(&n.tr, &mut body);
        encode_point(&n.ts, &mut body);
    }
    let e = hash_scalar("DLOG52/encryption-link/v1", &body).map_err(|_| ProofError::Challenge)?;
    Ok(std::array::from_fn(|i| {
        let value = Scalar::from(u64::from(witnesses[i].value));
        LinkProofRecord {
            t_v: nonces[i].tv,
            t_r: nonces[i].tr,
            t_s: nonces[i].ts,
            z_v: nonces[i].av + e * value,
            z_gamma: nonces[i].ag + e * witnesses[i].gamma,
            z_r: nonces[i].ar + e * encryption_randomness[i],
        }
    }))
}

/// Verify every equation in all nine link records.
pub fn verify_links(
    bundle_statement: &[u8],
    range_proof: &Range52Proof,
    slots: &[SlotPublic; N_SLOTS],
    joint_key: &ProjectivePoint,
    proofs: &[LinkProofRecord; N_SLOTS],
) -> Result<(), ProofError> {
    let p = protocol_parameters();
    let mut body = bundle_statement.to_vec();
    body.extend_from_slice(&dlog52_transcript::tagged_hash(
        "DLOG52/range-proof-bytes/v1",
        &range_proof.to_bytes(),
    ));
    for proof in proofs {
        encode_point(&proof.t_v, &mut body);
        encode_point(&proof.t_r, &mut body);
        encode_point(&proof.t_s, &mut body);
    }
    let e = hash_scalar("DLOG52/encryption-link/v1", &body).map_err(|_| ProofError::Challenge)?;
    for (slot, proof) in slots.iter().zip(proofs) {
        if p.m * proof.z_v + p.g * proof.z_gamma != proof.t_v + slot.commitment * e
            || p.g * proof.z_r != proof.t_r + slot.ciphertext.r * e
            || p.m * proof.z_v + *joint_key * proof.z_r != proof.t_s + slot.ciphertext.s * e
        {
            return Err(ProofError::Invalid);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use dlog52_group::create_slot;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    #[test]
    fn exact_range_and_link_proofs_validate_and_detect_mutation() {
        let mut rng = ChaCha20Rng::from_seed([7_u8; 32]);
        let joint_secret = Scalar::from(19_u64);
        let joint_key = protocol_parameters().g * joint_secret;
        let values = [0_u8, 1, 7, 15, 31, 32, 49, 50, 51];
        let gammas: [Scalar; N_SLOTS] = std::array::from_fn(|i| Scalar::from((i + 2) as u64));
        let randomness: [Scalar; N_SLOTS] = std::array::from_fn(|i| Scalar::from((i + 30) as u64));
        let slots: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
            create_slot(values[i], &gammas[i], &randomness[i], &joint_key).unwrap()
        });
        let witnesses: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
            value: values[i],
            gamma: gammas[i],
        });
        let statement = b"test-only-complete-bundle-statement";
        let proof = prove_range52(statement, &slots, &witnesses, &mut rng).unwrap();
        assert_eq!(proof.to_bytes().len(), RANGE_PROOF_BYTES);
        assert_eq!(verify_range52(statement, &slots, &proof), Ok(()));
        let links = prove_links(
            statement,
            &proof,
            &witnesses,
            &randomness,
            &joint_key,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            links.iter().flat_map(Encode::to_bytes).count(),
            LINK_PROOF_BYTES
        );
        assert_eq!(
            verify_links(statement, &proof, &slots, &joint_key, &links),
            Ok(())
        );

        let mut bad = proof.clone();
        bad.responses[44].z1 += Scalar::ONE;
        assert_eq!(
            verify_range52(statement, &slots, &bad),
            Err(ProofError::Invalid)
        );
    }

    #[test]
    fn range_rejects_out_of_range_witness() {
        let mut rng = ChaCha20Rng::from_seed([8_u8; 32]);
        let joint_key = protocol_parameters().g * Scalar::from(3_u64);
        let slots: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
            create_slot(
                0,
                &Scalar::from((i + 1) as u64),
                &Scalar::from((i + 20) as u64),
                &joint_key,
            )
            .unwrap()
        });
        let mut witnesses: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
            value: 0,
            gamma: Scalar::from((i + 1) as u64),
        });
        witnesses[3].value = 52;
        assert!(matches!(
            prove_range52(b"statement", &slots, &witnesses, &mut rng),
            Err(ProofError::Witness)
        ));
    }
}
