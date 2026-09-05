//! Canonical public setup certificates and complete successful-attempt replay.

use dlog52_codec::{Encode, Reader, put_bytes, put_u16, put_u32};
use dlog52_group::{N_SLOTS, decode_point, decode_slot_public, encode_point, protocol_parameters};
use dlog52_proofs::{decode_key_pop, decode_link_record, decode_range52};
use dlog52_transcript::tagged_hash;
use dlog52_uniqueness::{
    collision_bitmap, decode_decryption_body, decode_scale_payload, derive_zero_tests,
    verify_decryption, verify_scale_round,
};

use crate::{
    AcceptedDeal, AcceptedDealBody, GameConfig, JointPublic, KeyOpenBody, MAX_ENVELOPE_BYTES,
    MAX_SETUP_CERT_BYTES, PROTOCOL_VERSION, PlayerBundle, ProofContext, ProtocolError, Role,
    VerifiedAcceptedDeal, accepted_body_hash, derive_candidate_keys, derive_game_id,
    finalize_verified_attempt, verify_key_open, verify_player_bundle,
};

/// One signed protocol message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Wire version.
    pub version: u16,
    /// Fixed parameter identifier.
    pub params_id: [u8; 32],
    /// Game identifier.
    pub game_id: [u8; 32],
    /// Attempt number.
    pub attempt: u32,
    /// Protocol stage.
    pub stage: u16,
    /// Authenticated sender.
    pub sender_role: Role,
    /// Contiguous sender-local sequence.
    pub sender_sequence: u32,
    /// Frozen root before this stage.
    pub previous_stage_root: [u8; 32],
    /// Payload type, equal to the stage in v1.
    pub payload_type: u16,
    /// Canonical stage payload.
    pub payload: Vec<u8>,
    /// BIP340 signature over the unsigned encoding digest.
    pub signature: [u8; 64],
}

impl Envelope {
    fn encode_unsigned(&self, out: &mut Vec<u8>) {
        put_u16(out, self.version);
        out.extend_from_slice(&self.params_id);
        out.extend_from_slice(&self.game_id);
        put_u32(out, self.attempt);
        put_u16(out, self.stage);
        out.push(self.sender_role.as_u8());
        put_u32(out, self.sender_sequence);
        out.extend_from_slice(&self.previous_stage_root);
        put_u16(out, self.payload_type);
        put_bytes(out, &self.payload);
    }

    /// Digest authenticated by the sender.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(self.payload.len() + 115);
        self.encode_unsigned(&mut bytes);
        tagged_hash("DLOG52/envelope/v1", &bytes)
    }

    /// Decode one exact bounded envelope.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode_envelope(bytes)
    }

    /// Construct and authenticate one envelope over canonical payload bytes.
    pub fn signed(
        game_id: [u8; 32],
        attempt: u32,
        stage: u16,
        sender_role: Role,
        sender_sequence: u32,
        previous_stage_root: [u8; 32],
        payload: Vec<u8>,
        signing_key: &k256::schnorr::SigningKey,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<Self, ProtocolError> {
        if payload.len() + 179 > MAX_ENVELOPE_BYTES {
            return Err(ProtocolError::Wire);
        }
        let mut envelope = Self {
            version: PROTOCOL_VERSION,
            params_id: protocol_parameters().params_id,
            game_id,
            attempt,
            stage,
            sender_role,
            sender_sequence,
            previous_stage_root,
            payload_type: stage,
            payload,
            signature: [0; 64],
        };
        envelope.signature = signing_key
            .sign_prehash_with_aux_rand(&envelope.digest(), auxiliary_randomness)
            .map_err(|_| ProtocolError::AcceptedSignature)?
            .to_bytes();
        Ok(envelope)
    }
}

impl Encode for Envelope {
    fn encode(&self, out: &mut Vec<u8>) {
        self.encode_unsigned(out);
        out.extend_from_slice(&self.signature);
    }
}

/// Complete successful-attempt public certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupCertificate {
    /// Certificate version, exactly one.
    pub certificate_version: u16,
    /// Authenticated application configuration.
    pub game_config: GameConfig,
    /// Root of a discarded predecessor attempt, or zero for attempt zero.
    pub previous_attempt_root: [u8; 32],
    /// Sixteen envelopes in canonical stage/role order.
    pub envelopes: Vec<Envelope>,
    /// Descriptor signed after stage eight.
    pub accepted_deal: AcceptedDeal,
}

impl Encode for SetupCertificate {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.certificate_version);
        self.game_config.encode(out);
        out.extend_from_slice(&self.previous_attempt_root);
        for envelope in &self.envelopes {
            put_bytes(out, &envelope.to_bytes());
        }
        self.accepted_deal.body.encode(out);
        out.extend_from_slice(&self.accepted_deal.signature_a);
        out.extend_from_slice(&self.accepted_deal.signature_b);
    }
}

fn role(byte: u8) -> Result<Role, ProtocolError> {
    match byte {
        0 => Ok(Role::A),
        1 => Ok(Role::B),
        _ => Err(ProtocolError::Wire),
    }
}

fn decode_envelope(bytes: &[u8]) -> Result<Envelope, ProtocolError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(ProtocolError::Wire);
    }
    let mut reader = Reader::new(bytes);
    let envelope = Envelope {
        version: reader.u16().map_err(|_| ProtocolError::Wire)?,
        params_id: reader.array().map_err(|_| ProtocolError::Wire)?,
        game_id: reader.array().map_err(|_| ProtocolError::Wire)?,
        attempt: reader.u32().map_err(|_| ProtocolError::Wire)?,
        stage: reader.u16().map_err(|_| ProtocolError::Wire)?,
        sender_role: role(reader.u8().map_err(|_| ProtocolError::Wire)?)?,
        sender_sequence: reader.u32().map_err(|_| ProtocolError::Wire)?,
        previous_stage_root: reader.array().map_err(|_| ProtocolError::Wire)?,
        payload_type: reader.u16().map_err(|_| ProtocolError::Wire)?,
        payload: reader
            .bytes(MAX_ENVELOPE_BYTES - 179)
            .map_err(|_| ProtocolError::Wire)?
            .to_vec(),
        signature: reader.array().map_err(|_| ProtocolError::Wire)?,
    };
    reader.finish().map_err(|_| ProtocolError::Wire)?;
    if envelope.to_bytes() != bytes {
        return Err(ProtocolError::Wire);
    }
    Ok(envelope)
}

fn decode_config(reader: &mut Reader<'_>) -> Result<GameConfig, ProtocolError> {
    Ok(GameConfig {
        network_genesis: reader.array().map_err(|_| ProtocolError::Wire)?,
        session_anchor: reader.array().map_err(|_| ProtocolError::Wire)?,
        identity_a: reader.array().map_err(|_| ProtocolError::Wire)?,
        identity_b: reader.array().map_err(|_| ProtocolError::Wire)?,
        session_nonce: reader.array().map_err(|_| ProtocolError::Wire)?,
        rules_hash: reader.array().map_err(|_| ProtocolError::Wire)?,
    })
}

fn decode_accepted(reader: &mut Reader<'_>) -> Result<AcceptedDeal, ProtocolError> {
    let body = AcceptedDealBody {
        version: reader.u16().map_err(|_| ProtocolError::Wire)?,
        params_id: reader.array().map_err(|_| ProtocolError::Wire)?,
        game_id: reader.array().map_err(|_| ProtocolError::Wire)?,
        attempt: reader.u32().map_err(|_| ProtocolError::Wire)?,
        commitments_a: decode_points(reader)?,
        commitments_b: decode_points(reader)?,
        catalogue_hash: reader.array().map_err(|_| ProtocolError::Wire)?,
        verification_root: reader.array().map_err(|_| ProtocolError::Wire)?,
    };
    Ok(AcceptedDeal {
        body,
        signature_a: reader.array().map_err(|_| ProtocolError::Wire)?,
        signature_b: reader.array().map_err(|_| ProtocolError::Wire)?,
    })
}

fn decode_points(
    reader: &mut Reader<'_>,
) -> Result<[k256::ProjectivePoint; N_SLOTS], ProtocolError> {
    let mut points = Vec::with_capacity(N_SLOTS);
    for _ in 0..N_SLOTS {
        points.push(decode_point(reader, false).map_err(|_| ProtocolError::Wire)?);
    }
    points.try_into().map_err(|_| ProtocolError::Wire)
}

fn decode_certificate(bytes: &[u8]) -> Result<SetupCertificate, ProtocolError> {
    if bytes.len() > MAX_SETUP_CERT_BYTES {
        return Err(ProtocolError::Wire);
    }
    let mut reader = Reader::new(bytes);
    let certificate_version = reader.u16().map_err(|_| ProtocolError::Wire)?;
    let game_config = decode_config(&mut reader)?;
    let previous_attempt_root = reader.array().map_err(|_| ProtocolError::Wire)?;
    let mut envelopes = Vec::with_capacity(16);
    for _ in 0..16 {
        envelopes.push(decode_envelope(
            reader
                .bytes(MAX_ENVELOPE_BYTES)
                .map_err(|_| ProtocolError::Wire)?,
        )?);
    }
    let accepted_deal = decode_accepted(&mut reader)?;
    reader.finish().map_err(|_| ProtocolError::Wire)?;
    let certificate = SetupCertificate {
        certificate_version,
        game_config,
        previous_attempt_root,
        envelopes,
        accepted_deal,
    };
    if certificate.certificate_version != 1 || certificate.to_bytes() != bytes {
        return Err(ProtocolError::Wire);
    }
    Ok(certificate)
}

pub(crate) fn attempt_root(game_id: &[u8; 32], attempt: u32, previous: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(100);
    bytes.extend_from_slice(&protocol_parameters().params_id);
    bytes.extend_from_slice(game_id);
    put_u32(&mut bytes, attempt);
    bytes.extend_from_slice(previous);
    tagged_hash("DLOG52/attempt-start/v1", &bytes)
}

pub(crate) fn stage_root(previous: &[u8; 32], stage: u16, envelopes: &[&Envelope]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(previous);
    put_u16(&mut bytes, stage);
    bytes.push(u8::try_from(envelopes.len()).unwrap_or(u8::MAX));
    for envelope in envelopes {
        put_bytes(&mut bytes, &envelope.to_bytes());
    }
    tagged_hash("DLOG52/stage/v1", &bytes)
}

pub(crate) fn proof_context(
    game_id: [u8; 32],
    attempt: u32,
    stage: u16,
    role: Role,
    root: [u8; 32],
) -> ProofContext {
    ProofContext {
        game_id,
        attempt,
        proof_stage: stage,
        prover_role: role,
        frozen_anchor: root,
    }
}

pub(crate) fn commit(
    context: &ProofContext,
    open_stage: u16,
    nonce: &[u8; 32],
    body: &[u8],
) -> [u8; 32] {
    let mut bytes = context.to_bytes();
    put_u16(&mut bytes, open_stage);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(body);
    tagged_hash("DLOG52/commit/v1", &bytes)
}

fn payload_reader(envelope: &Envelope) -> Reader<'_> {
    Reader::new(&envelope.payload)
}

pub(crate) fn decode_key_open(
    envelope: &Envelope,
) -> Result<([u8; 32], KeyOpenBody), ProtocolError> {
    let mut r = payload_reader(envelope);
    let nonce = r.array().map_err(|_| ProtocolError::Wire)?;
    let body = KeyOpenBody {
        public_key: decode_point(&mut r, false).map_err(|_| ProtocolError::Wire)?,
        proof: decode_key_pop(&mut r).map_err(|_| ProtocolError::Wire)?,
    };
    r.finish().map_err(|_| ProtocolError::Wire)?;
    Ok((nonce, body))
}

pub(crate) fn decode_bundle(
    envelope: &Envelope,
) -> Result<([u8; 32], PlayerBundle), ProtocolError> {
    let mut r = payload_reader(envelope);
    let nonce = r.array().map_err(|_| ProtocolError::Wire)?;
    let bundle_role = role(r.u8().map_err(|_| ProtocolError::Wire)?)?;
    let mut slots = Vec::with_capacity(N_SLOTS);
    for _ in 0..N_SLOTS {
        slots.push(decode_slot_public(&mut r).map_err(|_| ProtocolError::Wire)?);
    }
    let slots = slots.try_into().map_err(|_| ProtocolError::Wire)?;
    let range_proof = decode_range52(&mut r).map_err(|_| ProtocolError::Wire)?;
    let mut links = Vec::with_capacity(N_SLOTS);
    for _ in 0..N_SLOTS {
        links.push(decode_link_record(&mut r).map_err(|_| ProtocolError::Wire)?);
    }
    let link_proof = links.try_into().map_err(|_| ProtocolError::Wire)?;
    r.finish().map_err(|_| ProtocolError::Wire)?;
    Ok((
        nonce,
        PlayerBundle {
            role: bundle_role,
            slots,
            range_proof,
            link_proof,
        },
    ))
}

pub(crate) fn verify_envelope(
    envelope: &Envelope,
    config: &GameConfig,
    game_id: [u8; 32],
    attempt: u32,
    stage: u16,
    expected_role: Role,
    sequence: u32,
) -> Result<(), ProtocolError> {
    if envelope.version != PROTOCOL_VERSION
        || envelope.params_id != protocol_parameters().params_id
        || envelope.game_id != game_id
        || envelope.attempt != attempt
        || envelope.stage != stage
        || envelope.payload_type != stage
        || envelope.sender_role != expected_role
        || envelope.sender_sequence != sequence
    {
        return Err(ProtocolError::Stage);
    }
    let identity = if expected_role == Role::A {
        &config.identity_a
    } else {
        &config.identity_b
    };
    super::verify_accepted_signature(identity, &envelope.digest(), &envelope.signature)
}

/// Decode and replay a complete successful setup certificate.
///
/// # Errors
///
/// Rejects noncanonical encodings, invalid authentication, wrong scheduling or
/// roots, failed openings/proofs/screens, collisions, or descriptor mismatch.
pub fn verify_setup_certificate(bytes: &[u8]) -> Result<VerifiedAcceptedDeal, ProtocolError> {
    let cert = decode_certificate(bytes)?;
    let game_id = derive_game_id(&cert.game_config)?;
    let attempt = cert.accepted_deal.body.attempt;
    if attempt == 0 && cert.previous_attempt_root != [0; 32] {
        return Err(ProtocolError::Stage);
    }
    let first = if tagged_hash(
        "DLOG52/first-blinder/v1",
        &[game_id.as_slice(), &attempt.to_le_bytes()].concat(),
    )[0] & 1
        == 0
    {
        Role::A
    } else {
        Role::B
    };
    let second = if first == Role::A { Role::B } else { Role::A };
    let schedule = [
        (1, Role::A),
        (1, Role::B),
        (2, Role::A),
        (2, Role::B),
        (3, Role::A),
        (3, Role::B),
        (4, Role::A),
        (4, Role::B),
        (5, first),
        (6, second),
        (7, Role::A),
        (7, Role::B),
        (8, Role::A),
        (8, Role::B),
        (9, Role::A),
        (9, Role::B),
    ];
    let mut sequences = [0_u32; 2];
    let mut cursor = 0;
    let mut stage_envelopes: Vec<Vec<&Envelope>> = Vec::with_capacity(9);
    for stage in 1..=9 {
        let mut entries = Vec::new();
        while cursor < schedule.len() && schedule[cursor].0 == stage {
            let expected = schedule[cursor].1;
            let envelope = &cert.envelopes[cursor];
            verify_envelope(
                envelope,
                &cert.game_config,
                game_id,
                attempt,
                stage,
                expected,
                sequences[expected as usize],
            )?;
            sequences[expected as usize] += 1;
            entries.push(envelope);
            cursor += 1;
        }
        stage_envelopes.push(entries);
    }
    // Replay semantics while reproducing the roots that proof contexts bind.
    let t0 = attempt_root(&game_id, attempt, &cert.previous_attempt_root);
    require_roots(&stage_envelopes[0], t0)?;
    let t1 = stage_root(&t0, 1, &stage_envelopes[0]);
    require_roots(&stage_envelopes[1], t1)?;
    let commits_key = [
        &stage_envelopes[0][0].payload,
        &stage_envelopes[0][1].payload,
    ];
    if commits_key.iter().any(|p| p.len() != 32) {
        return Err(ProtocolError::Wire);
    }
    let (nonce_a, key_a) = decode_key_open(stage_envelopes[1][0])?;
    let (nonce_b, key_b) = decode_key_open(stage_envelopes[1][1])?;
    for (role, nonce, body, expected) in [
        (Role::A, nonce_a, &key_a, commits_key[0]),
        (Role::B, nonce_b, &key_b, commits_key[1]),
    ] {
        let context = proof_context(game_id, attempt, 1, role, t0);
        if commit(&context, 2, &nonce, &body_bytes_key(body)) != expected.as_slice() {
            return Err(ProtocolError::Commitment);
        }
        verify_key_open(&context, body)?;
    }
    let joint = JointPublic::new(key_a.public_key, key_b.public_key)?;
    let t2 = stage_root(&t1, 2, &stage_envelopes[1]);
    require_roots(&stage_envelopes[2], t2)?;
    let t3 = stage_root(&t2, 3, &stage_envelopes[2]);
    require_roots(&stage_envelopes[3], t3)?;
    let (bundle_nonce_a, bundle_a) = decode_bundle(stage_envelopes[3][0])?;
    let (bundle_nonce_b, bundle_b) = decode_bundle(stage_envelopes[3][1])?;
    for (role, nonce, bundle, expected) in [
        (
            Role::A,
            bundle_nonce_a,
            &bundle_a,
            &stage_envelopes[2][0].payload,
        ),
        (
            Role::B,
            bundle_nonce_b,
            &bundle_b,
            &stage_envelopes[2][1].payload,
        ),
    ] {
        if expected.len() != 32 {
            return Err(ProtocolError::Wire);
        }
        let context = proof_context(game_id, attempt, 3, role, t2);
        if commit(&context, 4, &nonce, &bundle.to_bytes()) != expected.as_slice() {
            return Err(ProtocolError::Commitment);
        }
    }
    let verified_a = verify_player_bundle(
        &proof_context(game_id, attempt, 3, Role::A, t2),
        &joint,
        &bundle_a,
    )?;
    let verified_b = verify_player_bundle(
        &proof_context(game_id, attempt, 3, Role::B, t2),
        &joint,
        &bundle_b,
    )?;
    let catalogue = derive_candidate_keys(
        &game_id,
        attempt,
        (&cert.game_config.identity_a, &cert.game_config.identity_b),
        &verified_a,
        &verified_b,
    )?;
    let tests = derive_zero_tests(&bundle_a.slots, &bundle_b.slots)?;
    let t4 = stage_root(&t3, 4, &stage_envelopes[3]);
    require_roots(&stage_envelopes[4], t4)?;
    let mut r5 = payload_reader(stage_envelopes[4][0]);
    let scale1 = decode_scale_payload(&mut r5)?;
    r5.finish().map_err(|_| ProtocolError::Wire)?;
    let joint_bytes = joint.to_bytes();
    let scaled1 = verify_scale_round(
        "DLOG52/scale-first/v1",
        &proof_context(game_id, attempt, 5, first, t4).to_bytes(),
        &joint_bytes,
        &tests,
        &scale1,
    )?;
    let t5 = stage_root(&t4, 5, &stage_envelopes[4]);
    require_roots(&stage_envelopes[5], t5)?;
    let mut r6 = payload_reader(stage_envelopes[5][0]);
    let scale2 = decode_scale_payload(&mut r6)?;
    r6.finish().map_err(|_| ProtocolError::Wire)?;
    let scaled2 = verify_scale_round(
        "DLOG52/scale-second/v1",
        &proof_context(game_id, attempt, 6, second, t5).to_bytes(),
        &joint_bytes,
        &scaled1,
        &scale2,
    )?;
    let t6 = stage_root(&t5, 6, &stage_envelopes[5]);
    require_roots(&stage_envelopes[6], t6)?;
    let t7 = stage_root(&t6, 7, &stage_envelopes[6]);
    require_roots(&stage_envelopes[7], t7)?;
    let mut decryptions = Vec::new();
    for index in 0..2 {
        let role = if index == 0 { Role::A } else { Role::B };
        let mut r = payload_reader(stage_envelopes[7][index]);
        let nonce: [u8; 32] = r.array().map_err(|_| ProtocolError::Wire)?;
        let body_start = 32;
        let body = decode_decryption_body(&mut r)?;
        r.finish().map_err(|_| ProtocolError::Wire)?;
        let context = proof_context(game_id, attempt, 7, role, t6);
        let expected = &stage_envelopes[6][index].payload;
        if expected.len() != 32
            || commit(
                &context,
                8,
                &nonce,
                &stage_envelopes[7][index].payload[body_start..],
            ) != expected.as_slice()
        {
            return Err(ProtocolError::Commitment);
        }
        let public = if role == Role::A {
            &joint.pk_a
        } else {
            &joint.pk_b
        };
        verify_decryption(&context.to_bytes(), &joint_bytes, &scaled2, public, &body)?;
        decryptions.push(body);
    }
    if collision_bitmap(&scaled2, &decryptions[0], &decryptions[1])?
        .iter()
        .any(|bit| *bit)
    {
        return Err(ProtocolError::Collision);
    }
    let t8 = stage_root(&t7, 8, &stage_envelopes[7]);
    require_roots(&stage_envelopes[8], t8)?;
    if cert.accepted_deal.body.catalogue_hash != catalogue.hash {
        return Err(ProtocolError::AcceptedDescriptor);
    }
    let accepted_hash = accepted_body_hash(&cert.accepted_deal.body);
    for (index, signature) in [
        cert.accepted_deal.signature_a,
        cert.accepted_deal.signature_b,
    ]
    .iter()
    .enumerate()
    {
        let payload = &stage_envelopes[8][index].payload;
        if payload.len() != 96 || payload[..32] != accepted_hash || payload[32..] != signature[..] {
            return Err(ProtocolError::Stage);
        }
    }
    finalize_verified_attempt(
        &cert.game_config,
        &verified_a,
        &verified_b,
        t8,
        cert.accepted_deal,
    )
}

pub(crate) fn body_bytes_key(body: &KeyOpenBody) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(98);
    encode_point(&body.public_key, &mut bytes);
    body.proof.encode(&mut bytes);
    bytes
}

fn require_roots(envelopes: &[&Envelope], expected: [u8; 32]) -> Result<(), ProtocolError> {
    if envelopes
        .iter()
        .all(|envelope| envelope.previous_stage_root == expected)
    {
        Ok(())
    } else {
        Err(ProtocolError::Stage)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use dlog52_group::{SlotPublic, create_slot};
    use dlog52_proofs::{RangeWitness, prove_key_pop, prove_links, prove_range52};
    use dlog52_uniqueness::{create_decryption, create_scale_round};
    use k256::{Scalar, schnorr::SigningKey};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    fn sign_envelope(
        role: Role,
        sequence: u32,
        stage: u16,
        root: [u8; 32],
        payload: Vec<u8>,
        game_id: [u8; 32],
        signing: &SigningKey,
    ) -> Envelope {
        let mut envelope = Envelope {
            version: PROTOCOL_VERSION,
            params_id: protocol_parameters().params_id,
            game_id,
            attempt: 0,
            stage,
            sender_role: role,
            sender_sequence: sequence,
            previous_stage_root: root,
            payload_type: stage,
            payload,
            signature: [0; 64],
        };
        envelope.signature = signing
            .sign_prehash_with_aux_rand(&envelope.digest(), &[stage as u8; 32])
            .expect("envelope signature")
            .to_bytes();
        envelope
    }

    fn make_fixture() -> Vec<u8> {
        let signing_a = SigningKey::from_bytes(&[3; 32]).expect("identity A");
        let signing_b = SigningKey::from_bytes(&[5; 32]).expect("identity B");
        let mut identities = [
            (
                Into::<[u8; 32]>::into(signing_a.verifying_key().to_bytes()),
                signing_a,
            ),
            (
                Into::<[u8; 32]>::into(signing_b.verifying_key().to_bytes()),
                signing_b,
            ),
        ];
        identities.sort_by_key(|entry| entry.0);
        let config = GameConfig {
            network_genesis: [1; 32],
            session_anchor: [2; 32],
            identity_a: identities[0].0,
            identity_b: identities[1].0,
            session_nonce: [3; 32],
            rules_hash: [4; 32],
        };
        let game_id = derive_game_id(&config).expect("game id");
        let t0 = attempt_root(&game_id, 0, &[0; 32]);
        let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
        let secrets = [Scalar::from(17_u64), Scalar::from(29_u64)];
        let publics = [
            protocol_parameters().g * secrets[0],
            protocol_parameters().g * secrets[1],
        ];
        let key_bodies: [KeyOpenBody; 2] = std::array::from_fn(|index| {
            let role = if index == 0 { Role::A } else { Role::B };
            let context = proof_context(game_id, 0, 1, role, t0);
            KeyOpenBody {
                public_key: publics[index],
                proof: prove_key_pop(&context.to_bytes(), &secrets[index], &mut rng)
                    .expect("key proof"),
            }
        });
        let nonces_key = [[0x10; 32], [0x11; 32]];
        let key_commits: [[u8; 32]; 2] = std::array::from_fn(|i| {
            commit(
                &proof_context(game_id, 0, 1, if i == 0 { Role::A } else { Role::B }, t0),
                2,
                &nonces_key[i],
                &body_bytes_key(&key_bodies[i]),
            )
        });
        let mut sequence = [0_u32; 2];
        let mut envelopes = Vec::new();
        for i in 0..2 {
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                1,
                t0,
                key_commits[i].to_vec(),
                game_id,
                &identities[i].1,
            ));
            sequence[i] += 1;
        }
        let t1 = stage_root(&t0, 1, &envelopes.iter().collect::<Vec<_>>());
        for i in 0..2 {
            let mut payload = nonces_key[i].to_vec();
            payload.extend_from_slice(&body_bytes_key(&key_bodies[i]));
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                2,
                t1,
                payload,
                game_id,
                &identities[i].1,
            ));
            sequence[i] += 1;
        }
        let t2 = stage_root(&t1, 2, &envelopes[2..4].iter().collect::<Vec<_>>());
        let joint = JointPublic::new(publics[0], publics[1]).expect("joint");
        let values = [
            [0_u8, 1, 7, 15, 23, 31, 39, 47, 51],
            [2_u8, 8, 14, 20, 26, 32, 38, 44, 49],
        ];
        let gammas: [[Scalar; N_SLOTS]; 2] = std::array::from_fn(|p| {
            std::array::from_fn(|i| Scalar::from((100 + p * 20 + i) as u64))
        });
        let randomness: [[Scalar; N_SLOTS]; 2] = std::array::from_fn(|p| {
            std::array::from_fn(|i| Scalar::from((300 + p * 20 + i) as u64))
        });
        let bundles: [PlayerBundle; 2] = std::array::from_fn(|p| {
            let role = if p == 0 { Role::A } else { Role::B };
            let context = proof_context(game_id, 0, 3, role, t2);
            let slots: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
                create_slot(values[p][i], &gammas[p][i], &randomness[p][i], &joint.y).expect("slot")
            });
            let witnesses: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
                value: values[p][i],
                gamma: gammas[p][i],
            });
            let mut statement = context.to_bytes();
            joint.encode(&mut statement);
            for slot in &slots {
                slot.encode(&mut statement);
            }
            let range_proof =
                prove_range52(&statement, &slots, &witnesses, &mut rng).expect("range");
            let link_proof = prove_links(
                &statement,
                &range_proof,
                &witnesses,
                &randomness[p],
                &joint.y,
                &mut rng,
            )
            .expect("links");
            PlayerBundle {
                role,
                slots,
                range_proof,
                link_proof,
            }
        });
        let bundle_nonces = [[0x20; 32], [0x21; 32]];
        for i in 0..2 {
            let c = commit(
                &proof_context(game_id, 0, 3, if i == 0 { Role::A } else { Role::B }, t2),
                4,
                &bundle_nonces[i],
                &bundles[i].to_bytes(),
            );
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                3,
                t2,
                c.to_vec(),
                game_id,
                &identities[i].1,
            ));
            sequence[i] += 1;
        }
        let t3 = stage_root(&t2, 3, &envelopes[4..6].iter().collect::<Vec<_>>());
        for i in 0..2 {
            let mut p = bundle_nonces[i].to_vec();
            p.extend_from_slice(&bundles[i].to_bytes());
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                4,
                t3,
                p,
                game_id,
                &identities[i].1,
            ));
            sequence[i] += 1;
        }
        let t4 = stage_root(&t3, 4, &envelopes[6..8].iter().collect::<Vec<_>>());
        let tests = derive_zero_tests(&bundles[0].slots, &bundles[1].slots).expect("tests");
        let first = if tagged_hash(
            "DLOG52/first-blinder/v1",
            &[game_id.as_slice(), &0_u32.to_le_bytes()].concat(),
        )[0] & 1
            == 0
        {
            Role::A
        } else {
            Role::B
        };
        let second = if first == Role::A { Role::B } else { Role::A };
        let joint_bytes = joint.to_bytes();
        let scale1 = create_scale_round(
            "DLOG52/scale-first/v1",
            &proof_context(game_id, 0, 5, first, t4).to_bytes(),
            &joint_bytes,
            &tests,
            &mut rng,
        )
        .expect("scale1");
        let fi = first as usize;
        envelopes.push(sign_envelope(
            first,
            sequence[fi],
            5,
            t4,
            scale1.to_bytes(),
            game_id,
            &identities[fi].1,
        ));
        sequence[fi] += 1;
        let t5 = stage_root(&t4, 5, &envelopes[8..9].iter().collect::<Vec<_>>());
        let scaled1 = verify_scale_round(
            "DLOG52/scale-first/v1",
            &proof_context(game_id, 0, 5, first, t4).to_bytes(),
            &joint_bytes,
            &tests,
            &scale1,
        )
        .expect("verify scale1");
        let scale2 = create_scale_round(
            "DLOG52/scale-second/v1",
            &proof_context(game_id, 0, 6, second, t5).to_bytes(),
            &joint_bytes,
            &scaled1,
            &mut rng,
        )
        .expect("scale2");
        let si = second as usize;
        envelopes.push(sign_envelope(
            second,
            sequence[si],
            6,
            t5,
            scale2.to_bytes(),
            game_id,
            &identities[si].1,
        ));
        sequence[si] += 1;
        let t6 = stage_root(&t5, 6, &envelopes[9..10].iter().collect::<Vec<_>>());
        let scaled2 = verify_scale_round(
            "DLOG52/scale-second/v1",
            &proof_context(game_id, 0, 6, second, t5).to_bytes(),
            &joint_bytes,
            &scaled1,
            &scale2,
        )
        .expect("verify scale2");
        let decrypt: [_; 2] = std::array::from_fn(|i| {
            create_decryption(
                &proof_context(game_id, 0, 7, if i == 0 { Role::A } else { Role::B }, t6)
                    .to_bytes(),
                &joint_bytes,
                &scaled2,
                &secrets[i],
                &mut rng,
            )
            .expect("decrypt")
        });
        let decrypt_nonces = [[0x30; 32], [0x31; 32]];
        for i in 0..2 {
            let c = commit(
                &proof_context(game_id, 0, 7, if i == 0 { Role::A } else { Role::B }, t6),
                8,
                &decrypt_nonces[i],
                &decrypt[i].to_bytes(),
            );
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                7,
                t6,
                c.to_vec(),
                game_id,
                &identities[i].1,
            ));
            sequence[i] += 1;
        }
        let t7 = stage_root(&t6, 7, &envelopes[10..12].iter().collect::<Vec<_>>());
        for i in 0..2 {
            let mut p = decrypt_nonces[i].to_vec();
            p.extend_from_slice(&decrypt[i].to_bytes());
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                8,
                t7,
                p,
                game_id,
                &identities[i].1,
            ));
            sequence[i] += 1;
        }
        let t8 = stage_root(&t7, 8, &envelopes[12..14].iter().collect::<Vec<_>>());
        let va = verify_player_bundle(
            &proof_context(game_id, 0, 3, Role::A, t2),
            &joint,
            &bundles[0],
        )
        .expect("va");
        let vb = verify_player_bundle(
            &proof_context(game_id, 0, 3, Role::B, t2),
            &joint,
            &bundles[1],
        )
        .expect("vb");
        let catalogue = derive_candidate_keys(
            &game_id,
            0,
            (&config.identity_a, &config.identity_b),
            &va,
            &vb,
        )
        .expect("catalogue");
        let body = AcceptedDealBody {
            version: 1,
            params_id: protocol_parameters().params_id,
            game_id,
            attempt: 0,
            commitments_a: std::array::from_fn(|i| bundles[0].slots[i].commitment),
            commitments_b: std::array::from_fn(|i| bundles[1].slots[i].commitment),
            catalogue_hash: catalogue.hash,
            verification_root: t8,
        };
        let digest = accepted_body_hash(&body);
        let signatures: [[_; 64]; 2] = std::array::from_fn(|i| {
            identities[i]
                .1
                .sign_prehash_with_aux_rand(&digest, &[0x40 + i as u8; 32])
                .expect("accept")
                .to_bytes()
        });
        for i in 0..2 {
            let mut p = digest.to_vec();
            p.extend_from_slice(&signatures[i]);
            envelopes.push(sign_envelope(
                if i == 0 { Role::A } else { Role::B },
                sequence[i],
                9,
                t8,
                p,
                game_id,
                &identities[i].1,
            ));
        }
        SetupCertificate {
            certificate_version: 1,
            game_config: config,
            previous_attempt_root: [0; 32],
            envelopes,
            accepted_deal: AcceptedDeal {
                body,
                signature_a: signatures[0],
                signature_b: signatures[1],
            },
        }
        .to_bytes()
    }

    #[test]
    fn exact_certificate_replays_and_tampering_fails() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let bytes = make_fixture();
                assert_eq!(bytes.len(), 102_070);
                assert!(verify_setup_certificate(&bytes).is_ok());
                let mut changed = bytes;
                changed[10_000] ^= 1;
                assert!(verify_setup_certificate(&changed).is_err());
            })
            .expect("spawn")
            .join()
            .expect("join");
    }
}
