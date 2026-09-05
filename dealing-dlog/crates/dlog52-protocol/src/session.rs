//! Live two-party state machine with persist-before-send semantics.

use dlog52_codec::Encode;
use dlog52_group::{Ciphertext, ZERO_TEST_COUNT, protocol_parameters};
use dlog52_transcript::tagged_hash;
use dlog52_uniqueness::{
    DecryptionBody, ScalePayload, VerifiedCatalogue, collision_bitmap, create_decryption,
    create_scale_round, decode_decryption_body, decode_scale_payload, derive_zero_tests,
    verify_decryption, verify_scale_round,
};
use k256::{
    elliptic_curve::Group,
    schnorr::{Signature, SigningKey, VerifyingKey},
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use crate::certificate::{
    attempt_root, body_bytes_key, commit, decode_bundle, decode_key_open, proof_context,
    stage_root, verify_envelope,
};
use crate::{
    AcceptedDeal, AcceptedDealBody, Envelope, GameConfig, JointPublic, KeyOpenBody, PlayerBundle,
    ProtocolError, Role, SecretKeyShare, SetupCertificate, SetupSecrets, VerifiedAcceptedDeal,
    VerifiedBundle, accepted_body_hash, create_share_reveal, derive_candidate_keys, derive_game_id,
    finalize_verified_attempt, generate_key_open, generate_player_bundle,
    offchain_commitment_digest, verify_key_open, verify_player_bundle,
};

/// Public progress suitable for durable client orchestration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParticipantSnapshot {
    /// Current attempt.
    pub attempt: u32,
    /// Stage awaiting messages, or ten after acceptance.
    pub stage: u16,
    /// Frozen root before the current stage.
    pub stage_root: [u8; 32],
    /// Whether an outgoing envelope is waiting for durable confirmation.
    pub has_pending_outgoing: bool,
    /// Whether a verified accepted deal is available.
    pub accepted: bool,
    /// Whether the outer application must authorize a fresh attempt.
    pub retry_required: bool,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{verify_setup_certificate, verify_share_reveal};

    #[test]
    fn two_live_participants_persist_exchange_and_accept_same_certificate() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let key_a = SigningKey::from_bytes(&[3; 32]).expect("A key");
                let key_b = SigningKey::from_bytes(&[5; 32]).expect("B key");
                let mut keys = [
                    (
                        Into::<[u8; 32]>::into(key_a.verifying_key().to_bytes()),
                        [3; 32],
                    ),
                    (
                        Into::<[u8; 32]>::into(key_b.verifying_key().to_bytes()),
                        [5; 32],
                    ),
                ];
                keys.sort_by_key(|entry| entry.0);
                let config = GameConfig {
                    network_genesis: [1; 32],
                    session_anchor: [2; 32],
                    identity_a: keys[0].0,
                    identity_b: keys[1].0,
                    session_nonce: [3; 32],
                    rules_hash: [4; 32],
                };
                let mut a = LiveParticipant::new(config.clone(), Role::A, keys[0].1, [0x51; 32])
                    .expect("participant A");
                let mut b = LiveParticipant::new(config, Role::B, keys[1].1, [0x62; 32])
                    .expect("participant B");
                for _ in 0..20 {
                    if a.snapshot().accepted && b.snapshot().accepted {
                        break;
                    }
                    let outgoing_a = a.prepare_outgoing().expect("prepare A");
                    let outgoing_b = b.prepare_outgoing().expect("prepare B");
                    if let Some(bytes) = &outgoing_a {
                        assert_eq!(a.prepare_outgoing().expect("retransmit A"), outgoing_a);
                        a.confirm_persisted_outgoing(bytes).expect("persist A");
                    }
                    if let Some(bytes) = &outgoing_b {
                        b.confirm_persisted_outgoing(bytes).expect("persist B");
                    }
                    if let Some(bytes) = &outgoing_a {
                        b.accept_peer(bytes).expect("accept A");
                    }
                    if let Some(bytes) = &outgoing_b {
                        a.accept_peer(bytes).expect("accept B");
                    }
                }
                assert!(a.snapshot().accepted && b.snapshot().accepted);
                assert_eq!(
                    a.certificate().expect("cert A"),
                    b.certificate().expect("cert B")
                );
                assert_eq!(a.certificate().expect("cert").len(), 102_070);
                assert!(verify_setup_certificate(a.certificate().expect("cert replay")).is_ok());
                let commitment = [0x91; 32];
                let signature = a
                    .sign_offchain_commitment(commitment, &[0x92; 32])
                    .expect("sign off-chain commitment");
                a.verify_offchain_commitment(Role::A, commitment, signature)
                    .expect("verify own off-chain commitment");
                b.verify_offchain_commitment(Role::A, commitment, signature)
                    .expect("peer verifies off-chain commitment");
                assert!(
                    b.verify_offchain_commitment(Role::A, [0x93; 32], signature)
                        .is_err()
                );
                let reveal = a
                    .authorized_share_reveal(1, Role::B.as_u8(), 0, &[0x33; 32])
                    .expect("authorized private hole reveal");
                assert_eq!(reveal.len(), 199);
                let verified = verify_share_reveal(a.accepted().expect("accepted"), &reveal)
                    .expect("verified reveal");
                assert_eq!(
                    (
                        verified.sender(),
                        verified.recipient(),
                        verified.slot(),
                        verified.stage()
                    ),
                    (Role::A, Role::B.as_u8(), 1, 0)
                );
                assert!(
                    a.authorized_share_reveal(0, Role::B.as_u8(), 0, &[0x44; 32])
                        .is_err()
                );
                let mut tampered = reveal;
                tampered[120] ^= 1;
                assert!(verify_share_reveal(a.accepted().expect("accepted"), &tampered).is_err());
            })
            .expect("spawn")
            .join()
            .expect("join");
    }
}

/// One secret-owning participant for a single successful attempt.
pub struct LiveParticipant {
    config: GameConfig,
    game_id: [u8; 32],
    role: Role,
    signing_key: SigningKey,
    rng: ChaCha20Rng,
    attempt: u32,
    previous_attempt_root: [u8; 32],
    stage: u16,
    root: [u8; 32],
    sequences: [u32; 2],
    current: [Option<Envelope>; 2],
    transcript: Vec<Envelope>,
    pending: Option<Vec<u8>>,
    local_payload: Option<Vec<u8>>,
    key_secret: Option<SecretKeyShare>,
    key_bodies: [Option<KeyOpenBody>; 2],
    key_nonce: [u8; 32],
    joint: Option<JointPublic>,
    bundles: [Option<PlayerBundle>; 2],
    verified_bundles: [Option<VerifiedBundle>; 2],
    bundle_nonce: [u8; 32],
    setup_secrets: Option<SetupSecrets>,
    catalogue: Option<VerifiedCatalogue>,
    zero_tests: Option<[Ciphertext; ZERO_TEST_COUNT]>,
    first_scaled: Option<[Ciphertext; ZERO_TEST_COUNT]>,
    second_scaled: Option<[Ciphertext; ZERO_TEST_COUNT]>,
    decryptions: [Option<DecryptionBody>; 2],
    decrypt_nonce: [u8; 32],
    accepted_body: Option<AcceptedDealBody>,
    accepted: Option<VerifiedAcceptedDeal>,
    certificate: Option<Vec<u8>>,
    retry_required: bool,
}

impl LiveParticipant {
    /// Create a participant from an identity secret and independent 32-byte CSPRNG seed.
    ///
    /// # Errors
    ///
    /// Rejects an invalid configuration, identity secret, or role/key mismatch.
    pub fn new(
        config: GameConfig,
        role: Role,
        identity_secret: [u8; 32],
        entropy: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        let game_id = derive_game_id(&config)?;
        let signing_key =
            SigningKey::from_bytes(&identity_secret).map_err(|_| ProtocolError::Identity)?;
        let expected = if role == Role::A {
            config.identity_a
        } else {
            config.identity_b
        };
        if signing_key.verifying_key().to_bytes().as_slice() != expected {
            return Err(ProtocolError::Identity);
        }
        let mut rng = ChaCha20Rng::from_seed(entropy);
        let root = attempt_root(&game_id, 0, &[0; 32]);
        let context = proof_context(game_id, 0, 1, role, root);
        let (key_body, key_secret) = generate_key_open(&context, &mut rng)?;
        let mut key_nonce = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut key_nonce);
        let key_commit = commit(&context, 2, &key_nonce, &body_bytes_key(&key_body));
        let mut key_bodies: [Option<KeyOpenBody>; 2] = std::array::from_fn(|_| None);
        key_bodies[role as usize] = Some(key_body);
        Ok(Self {
            config,
            game_id,
            role,
            signing_key,
            rng,
            attempt: 0,
            previous_attempt_root: [0; 32],
            stage: 1,
            root,
            sequences: [0; 2],
            current: std::array::from_fn(|_| None),
            transcript: Vec::with_capacity(16),
            pending: None,
            local_payload: Some(key_commit.to_vec()),
            key_secret: Some(key_secret),
            key_bodies,
            key_nonce,
            joint: None,
            bundles: std::array::from_fn(|_| None),
            verified_bundles: std::array::from_fn(|_| None),
            bundle_nonce: [0; 32],
            setup_secrets: None,
            catalogue: None,
            zero_tests: None,
            first_scaled: None,
            second_scaled: None,
            decryptions: std::array::from_fn(|_| None),
            decrypt_nonce: [0; 32],
            accepted_body: None,
            accepted: None,
            certificate: None,
            retry_required: false,
        })
    }

    /// Return current public progress.
    #[must_use]
    pub fn snapshot(&self) -> ParticipantSnapshot {
        ParticipantSnapshot {
            attempt: self.attempt,
            stage: self.stage,
            stage_root: self.root,
            has_pending_outgoing: self.pending.is_some(),
            accepted: self.accepted.is_some(),
            retry_required: self.retry_required,
        }
    }

    /// Start the next externally approved attempt with fresh attempt secrets.
    pub fn start_retry(&mut self, next_attempt: u32) -> Result<(), ProtocolError> {
        if !self.retry_required
            || next_attempt != self.attempt.checked_add(1).ok_or(ProtocolError::Stage)?
        {
            return Err(ProtocolError::Stage);
        }
        self.attempt = next_attempt;
        self.previous_attempt_root = self.root;
        self.stage = 1;
        self.root = attempt_root(&self.game_id, self.attempt, &self.previous_attempt_root);
        self.sequences = [0; 2];
        self.current = std::array::from_fn(|_| None);
        self.transcript.clear();
        self.pending = None;
        self.local_payload = None;
        self.key_secret = None;
        self.key_bodies = std::array::from_fn(|_| None);
        self.joint = None;
        self.bundles = std::array::from_fn(|_| None);
        self.verified_bundles = std::array::from_fn(|_| None);
        self.setup_secrets = None;
        self.catalogue = None;
        self.zero_tests = None;
        self.first_scaled = None;
        self.second_scaled = None;
        self.decryptions = std::array::from_fn(|_| None);
        self.accepted_body = None;
        self.accepted = None;
        self.certificate = None;
        self.retry_required = false;
        let context = proof_context(self.game_id, self.attempt, 1, self.role, self.root);
        let (body, secret) = generate_key_open(&context, &mut self.rng)?;
        rand_core::RngCore::fill_bytes(&mut self.rng, &mut self.key_nonce);
        let commitment = commit(&context, 2, &self.key_nonce, &body_bytes_key(&body));
        self.key_bodies[self.role as usize] = Some(body);
        self.key_secret = Some(secret);
        self.local_payload = Some(commitment.to_vec());
        Ok(())
    }

    /// Prepare or retransmit the exact next signed envelope without advancing state.
    /// The caller must durably store the returned bytes before calling
    /// [`Self::confirm_persisted_outgoing`].
    pub fn prepare_outgoing(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        if let Some(bytes) = &self.pending {
            return Ok(Some(bytes.clone()));
        }
        if !self.role_required(self.role) || self.current[self.role as usize].is_some() {
            return Ok(None);
        }
        let Some(payload) = self.local_payload.clone() else {
            return Ok(None);
        };
        let mut aux = [0; 32];
        rand_core::RngCore::fill_bytes(&mut self.rng, &mut aux);
        let envelope = Envelope::signed(
            self.game_id,
            self.attempt,
            self.stage,
            self.role,
            self.sequences[self.role as usize],
            self.root,
            payload,
            &self.signing_key,
            &aux,
        )?;
        let bytes = envelope.to_bytes();
        self.pending = Some(bytes.clone());
        Ok(Some(bytes))
    }

    /// Confirm that the exact pending bytes were persisted, then process them locally.
    pub fn confirm_persisted_outgoing(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        if self.pending.as_deref() != Some(bytes) {
            return Err(ProtocolError::Stage);
        }
        let envelope = Envelope::decode_exact(bytes)?;
        self.pending = None;
        self.insert(envelope)
    }

    /// Accept one peer envelope. Byte-identical retransmission is idempotent.
    pub fn accept_peer(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let envelope = Envelope::decode_exact(bytes)?;
        if envelope.sender_role == self.role {
            return Err(ProtocolError::Stage);
        }
        if let Some(existing) = self
            .transcript
            .iter()
            .find(|item| item.stage == envelope.stage && item.sender_role == envelope.sender_role)
        {
            return if existing.to_bytes() == bytes {
                Ok(())
            } else {
                Err(ProtocolError::Stage)
            };
        }
        if let Some(existing) = &self.current[envelope.sender_role as usize] {
            return if existing.to_bytes() == bytes {
                Ok(())
            } else {
                Err(ProtocolError::Stage)
            };
        }
        self.insert(envelope)
    }

    /// Export the complete certificate only after both stage-nine messages verify.
    pub fn certificate(&self) -> Result<&[u8], ProtocolError> {
        self.certificate.as_deref().ok_or(ProtocolError::Stage)
    }

    /// Borrow the accepted deal after complete live verification.
    pub fn accepted(&self) -> Result<&VerifiedAcceptedDeal, ProtocolError> {
        self.accepted.as_ref().ok_or(ProtocolError::Stage)
    }

    /// Borrow retained local share openings for selective delivery.
    pub fn setup_secrets(&self) -> Result<&SetupSecrets, ProtocolError> {
        self.setup_secrets.as_ref().ok_or(ProtocolError::Stage)
    }

    /// Create an identity-signed reveal after the host authorizes its recipient and stage.
    pub fn authorized_share_reveal(
        &self,
        slot: u8,
        recipient: u8,
        reveal_stage: u8,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<[u8; 199], ProtocolError> {
        let accepted = self.accepted()?;
        let opening = self
            .setup_secrets()?
            .openings
            .get(usize::from(slot))
            .ok_or(ProtocolError::Stage)?;
        Ok(*create_share_reveal(
            accepted,
            self.role,
            recipient,
            slot,
            reveal_stage,
            opening.value(),
            opening.gamma(),
            &self.signing_key,
            auxiliary_randomness,
        )?
        .as_bytes())
    }

    /// Canonical local role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Sign one canonical public game-state commitment with the participant's
    /// long-lived BIP340 identity. DEAL must already be accepted so a caller
    /// cannot use this participant as an unrelated signing oracle.
    pub fn sign_offchain_commitment(
        &self,
        commitment_hash: [u8; 32],
        auxiliary_randomness: &[u8; 32],
    ) -> Result<[u8; 64], ProtocolError> {
        self.accepted()?;
        if commitment_hash == [0; 32] {
            return Err(ProtocolError::OffchainCommitment);
        }
        let digest = offchain_commitment_digest(&self.game_id, &commitment_hash);
        let signature = self
            .signing_key
            .sign_prehash_with_aux_rand(&digest, auxiliary_randomness)
            .map_err(|_| ProtocolError::OffchainCommitment)?;
        Ok(signature.to_bytes().into())
    }

    /// Verify either player's signature over one canonical public game-state
    /// commitment under the identities fixed by this DEAL session.
    pub fn verify_offchain_commitment(
        &self,
        signer: Role,
        commitment_hash: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), ProtocolError> {
        self.accepted()?;
        if commitment_hash == [0; 32] {
            return Err(ProtocolError::OffchainCommitment);
        }
        let identity = match signer {
            Role::A => self.config.identity_a,
            Role::B => self.config.identity_b,
        };
        let key =
            VerifyingKey::from_bytes(&identity).map_err(|_| ProtocolError::OffchainCommitment)?;
        let signature = Signature::try_from(signature.as_slice())
            .map_err(|_| ProtocolError::OffchainCommitment)?;
        key.verify_raw(
            &offchain_commitment_digest(&self.game_id, &commitment_hash),
            &signature,
        )
        .map_err(|_| ProtocolError::OffchainCommitment)
    }

    fn role_required(&self, role: Role) -> bool {
        match self.stage {
            1..=4 | 7..=9 => true,
            5 => role == self.first_role(),
            6 => role != self.first_role(),
            _ => false,
        }
    }

    fn first_role(&self) -> Role {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.game_id);
        bytes.extend_from_slice(&self.attempt.to_le_bytes());
        if tagged_hash("DLOG52/first-blinder/v1", &bytes)[0] & 1 == 0 {
            Role::A
        } else {
            Role::B
        }
    }

    fn insert(&mut self, envelope: Envelope) -> Result<(), ProtocolError> {
        let index = envelope.sender_role as usize;
        verify_envelope(
            &envelope,
            &self.config,
            self.game_id,
            self.attempt,
            self.stage,
            envelope.sender_role,
            self.sequences[index],
        )?;
        if envelope.previous_stage_root != self.root || !self.role_required(envelope.sender_role) {
            return Err(ProtocolError::Stage);
        }
        self.current[index] = Some(envelope);
        self.sequences[index] += 1;
        if self.stage_complete() {
            self.advance()?;
        }
        Ok(())
    }

    fn stage_complete(&self) -> bool {
        [Role::A, Role::B]
            .into_iter()
            .all(|role| !self.role_required(role) || self.current[role as usize].is_some())
    }

    fn ordered_current(&self) -> Vec<&Envelope> {
        [Role::A, Role::B]
            .into_iter()
            .filter_map(|role| self.current[role as usize].as_ref())
            .collect()
    }

    fn advance(&mut self) -> Result<(), ProtocolError> {
        self.verify_current_semantics()?;
        let entries: Vec<Envelope> = [Role::A, Role::B]
            .into_iter()
            .filter_map(|role| self.current[role as usize].clone())
            .collect();
        self.root = stage_root(&self.root, self.stage, &entries.iter().collect::<Vec<_>>());
        self.transcript.extend(entries);
        self.current = std::array::from_fn(|_| None);
        if self.retry_required {
            self.stage = 0;
            self.local_payload = None;
            return Ok(());
        }
        self.stage += 1;
        self.local_payload = None;
        self.prepare_stage_payload()
    }

    fn verify_current_semantics(&mut self) -> Result<(), ProtocolError> {
        match self.stage {
            1 | 3 | 7 => self.verify_commit_payloads(),
            2 => self.verify_key_stage(),
            4 => self.verify_bundle_stage(),
            5 => self.verify_first_scale(),
            6 => self.verify_second_scale(),
            8 => self.verify_decrypt_stage(),
            9 => self.verify_accept_stage(),
            _ => Err(ProtocolError::Stage),
        }
    }

    fn verify_commit_payloads(&self) -> Result<(), ProtocolError> {
        if self
            .ordered_current()
            .iter()
            .all(|envelope| envelope.payload.len() == 32)
        {
            Ok(())
        } else {
            Err(ProtocolError::Wire)
        }
    }

    fn verify_key_stage(&mut self) -> Result<(), ProtocolError> {
        let commit_root = self.transcript[self.transcript.len() - 2].previous_stage_root;
        for role in [Role::A, Role::B] {
            let (nonce, body) = decode_key_open(
                self.current[role as usize]
                    .as_ref()
                    .ok_or(ProtocolError::Stage)?,
            )?;
            let context = proof_context(self.game_id, self.attempt, 1, role, commit_root);
            let expected = &self.transcript[self.transcript.len() - 2 + role as usize].payload;
            if commit(&context, 2, &nonce, &body_bytes_key(&body)) != expected.as_slice() {
                return Err(ProtocolError::Commitment);
            }
            verify_key_open(&context, &body)?;
            self.key_bodies[role as usize] = Some(body);
        }
        let pk_a = self.key_bodies[0]
            .as_ref()
            .ok_or(ProtocolError::Stage)?
            .public_key;
        let pk_b = self.key_bodies[1]
            .as_ref()
            .ok_or(ProtocolError::Stage)?
            .public_key;
        if bool::from((pk_a + pk_b).is_identity()) {
            self.retry_required = true;
            return Ok(());
        }
        self.joint = Some(JointPublic::new(pk_a, pk_b)?);
        Ok(())
    }

    fn verify_bundle_stage(&mut self) -> Result<(), ProtocolError> {
        let frozen = self.transcript[self.transcript.len() - 2].previous_stage_root;
        for role in [Role::A, Role::B] {
            let (nonce, bundle) = decode_bundle(
                self.current[role as usize]
                    .as_ref()
                    .ok_or(ProtocolError::Stage)?,
            )?;
            let context = proof_context(self.game_id, self.attempt, 3, role, frozen);
            let expected = &self.transcript[self.transcript.len() - 2 + role as usize].payload;
            if commit(&context, 4, &nonce, &bundle.to_bytes()) != expected.as_slice() {
                return Err(ProtocolError::Commitment);
            }
            let verified = verify_player_bundle(
                &context,
                self.joint.as_ref().ok_or(ProtocolError::Stage)?,
                &bundle,
            )?;
            self.bundles[role as usize] = Some(bundle);
            self.verified_bundles[role as usize] = Some(verified);
        }
        let va = self.verified_bundles[0]
            .as_ref()
            .ok_or(ProtocolError::Stage)?;
        let vb = self.verified_bundles[1]
            .as_ref()
            .ok_or(ProtocolError::Stage)?;
        self.catalogue = match derive_candidate_keys(
            &self.game_id,
            self.attempt,
            (&self.config.identity_a, &self.config.identity_b),
            va,
            vb,
        ) {
            Ok(value) => Some(value),
            Err(_) => {
                self.retry_required = true;
                return Ok(());
            }
        };
        self.zero_tests = match derive_zero_tests(
            &self.bundles[0].as_ref().ok_or(ProtocolError::Stage)?.slots,
            &self.bundles[1].as_ref().ok_or(ProtocolError::Stage)?.slots,
        ) {
            Ok(value) => Some(value),
            Err(_) => {
                self.retry_required = true;
                return Ok(());
            }
        };
        Ok(())
    }

    fn decode_scale(&self, role: Role) -> Result<ScalePayload, ProtocolError> {
        let mut r = dlog52_codec::Reader::new(
            &self.current[role as usize]
                .as_ref()
                .ok_or(ProtocolError::Stage)?
                .payload,
        );
        let p = decode_scale_payload(&mut r)?;
        r.finish().map_err(|_| ProtocolError::Wire)?;
        Ok(p)
    }
    fn joint_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok(self.joint.as_ref().ok_or(ProtocolError::Stage)?.to_bytes())
    }
    fn verify_first_scale(&mut self) -> Result<(), ProtocolError> {
        let role = self.first_role();
        let p = self.decode_scale(role)?;
        self.first_scaled = Some(verify_scale_round(
            "DLOG52/scale-first/v1",
            &proof_context(self.game_id, self.attempt, 5, role, self.root).to_bytes(),
            &self.joint_bytes()?,
            self.zero_tests.as_ref().ok_or(ProtocolError::Stage)?,
            &p,
        )?);
        Ok(())
    }
    fn verify_second_scale(&mut self) -> Result<(), ProtocolError> {
        let role = if self.first_role() == Role::A {
            Role::B
        } else {
            Role::A
        };
        let p = self.decode_scale(role)?;
        self.second_scaled = Some(verify_scale_round(
            "DLOG52/scale-second/v1",
            &proof_context(self.game_id, self.attempt, 6, role, self.root).to_bytes(),
            &self.joint_bytes()?,
            self.first_scaled.as_ref().ok_or(ProtocolError::Stage)?,
            &p,
        )?);
        Ok(())
    }

    fn verify_decrypt_stage(&mut self) -> Result<(), ProtocolError> {
        let frozen = self.transcript[self.transcript.len() - 2].previous_stage_root;
        for role in [Role::A, Role::B] {
            let env = self.current[role as usize]
                .as_ref()
                .ok_or(ProtocolError::Stage)?;
            let mut r = dlog52_codec::Reader::new(&env.payload);
            let nonce = r.array().map_err(|_| ProtocolError::Wire)?;
            let body = decode_decryption_body(&mut r)?;
            r.finish().map_err(|_| ProtocolError::Wire)?;
            let context = proof_context(self.game_id, self.attempt, 7, role, frozen);
            let expected = &self.transcript[self.transcript.len() - 2 + role as usize].payload;
            if commit(&context, 8, &nonce, &env.payload[32..]) != expected.as_slice() {
                return Err(ProtocolError::Commitment);
            }
            let public = if role == Role::A {
                &self.joint.as_ref().ok_or(ProtocolError::Stage)?.pk_a
            } else {
                &self.joint.as_ref().ok_or(ProtocolError::Stage)?.pk_b
            };
            verify_decryption(
                &context.to_bytes(),
                &self.joint_bytes()?,
                self.second_scaled.as_ref().ok_or(ProtocolError::Stage)?,
                public,
                &body,
            )?;
            self.decryptions[role as usize] = Some(body);
        }
        if collision_bitmap(
            self.second_scaled.as_ref().ok_or(ProtocolError::Stage)?,
            self.decryptions[0].as_ref().ok_or(ProtocolError::Stage)?,
            self.decryptions[1].as_ref().ok_or(ProtocolError::Stage)?,
        )?
        .iter()
        .any(|v| *v)
        {
            self.retry_required = true;
        }
        Ok(())
    }

    fn verify_accept_stage(&mut self) -> Result<(), ProtocolError> {
        let body = self.accepted_body.clone().ok_or(ProtocolError::Stage)?;
        let digest = accepted_body_hash(&body);
        let mut sigs = [[0; 64]; 2];
        for role in [Role::A, Role::B] {
            let p = &self.current[role as usize]
                .as_ref()
                .ok_or(ProtocolError::Stage)?
                .payload;
            if p.len() != 96 || p[..32] != digest {
                return Err(ProtocolError::Stage);
            }
            sigs[role as usize].copy_from_slice(&p[32..]);
        }
        let deal = AcceptedDeal {
            body,
            signature_a: sigs[0],
            signature_b: sigs[1],
        };
        let accepted = finalize_verified_attempt(
            &self.config,
            self.verified_bundles[0]
                .as_ref()
                .ok_or(ProtocolError::Stage)?,
            self.verified_bundles[1]
                .as_ref()
                .ok_or(ProtocolError::Stage)?,
            self.root,
            deal.clone(),
        )?;
        let cert = SetupCertificate {
            certificate_version: 1,
            game_config: self.config.clone(),
            previous_attempt_root: self.previous_attempt_root,
            envelopes: self
                .transcript
                .iter()
                .chain(self.ordered_current())
                .cloned()
                .collect(),
            accepted_deal: deal,
        }
        .to_bytes();
        self.certificate = Some(cert);
        self.accepted = Some(accepted);
        Ok(())
    }

    fn prepare_stage_payload(&mut self) -> Result<(), ProtocolError> {
        if !self.role_required(self.role) {
            return Ok(());
        }
        match self.stage {
            2 => {
                let mut p = self.key_nonce.to_vec();
                p.extend_from_slice(&body_bytes_key(
                    self.key_bodies[self.role as usize]
                        .as_ref()
                        .ok_or(ProtocolError::Stage)?,
                ));
                self.local_payload = Some(p);
            }
            3 => {
                let joint = self.joint.as_ref().ok_or(ProtocolError::Stage)?;
                let context = proof_context(self.game_id, self.attempt, 3, self.role, self.root);
                let (bundle, secrets) = generate_player_bundle(&context, joint, &mut self.rng)?;
                rand_core::RngCore::fill_bytes(&mut self.rng, &mut self.bundle_nonce);
                let c = commit(&context, 4, &self.bundle_nonce, &bundle.to_bytes());
                self.bundles[self.role as usize] = Some(bundle);
                self.setup_secrets = Some(secrets);
                self.local_payload = Some(c.to_vec());
            }
            4 => {
                let mut p = self.bundle_nonce.to_vec();
                p.extend_from_slice(
                    &self.bundles[self.role as usize]
                        .as_ref()
                        .ok_or(ProtocolError::Stage)?
                        .to_bytes(),
                );
                self.local_payload = Some(p);
            }
            5 => {
                let p = create_scale_round(
                    "DLOG52/scale-first/v1",
                    &proof_context(self.game_id, self.attempt, 5, self.role, self.root).to_bytes(),
                    &self.joint_bytes()?,
                    self.zero_tests.as_ref().ok_or(ProtocolError::Stage)?,
                    &mut self.rng,
                )?;
                self.local_payload = Some(p.to_bytes());
            }
            6 => {
                let p = create_scale_round(
                    "DLOG52/scale-second/v1",
                    &proof_context(self.game_id, self.attempt, 6, self.role, self.root).to_bytes(),
                    &self.joint_bytes()?,
                    self.first_scaled.as_ref().ok_or(ProtocolError::Stage)?,
                    &mut self.rng,
                )?;
                self.local_payload = Some(p.to_bytes());
            }
            7 => {
                let context = proof_context(self.game_id, self.attempt, 7, self.role, self.root);
                let body = create_decryption(
                    &context.to_bytes(),
                    &self.joint_bytes()?,
                    self.second_scaled.as_ref().ok_or(ProtocolError::Stage)?,
                    self.key_secret
                        .as_ref()
                        .ok_or(ProtocolError::Stage)?
                        .expose_for_protocol(),
                    &mut self.rng,
                )?;
                rand_core::RngCore::fill_bytes(&mut self.rng, &mut self.decrypt_nonce);
                let c = commit(&context, 8, &self.decrypt_nonce, &body.to_bytes());
                self.decryptions[self.role as usize] = Some(body);
                self.local_payload = Some(c.to_vec());
            }
            8 => {
                let mut p = self.decrypt_nonce.to_vec();
                p.extend_from_slice(
                    &self.decryptions[self.role as usize]
                        .as_ref()
                        .ok_or(ProtocolError::Stage)?
                        .to_bytes(),
                );
                self.local_payload = Some(p);
            }
            9 => {
                if self.accepted_body.is_none() {
                    let catalogue = self.catalogue.as_ref().ok_or(ProtocolError::Stage)?;
                    let bundle_a = self.bundles[0].as_ref().ok_or(ProtocolError::Stage)?;
                    let bundle_b = self.bundles[1].as_ref().ok_or(ProtocolError::Stage)?;
                    self.accepted_body = Some(AcceptedDealBody {
                        version: 1,
                        params_id: protocol_parameters().params_id,
                        game_id: self.game_id,
                        attempt: self.attempt,
                        commitments_a: std::array::from_fn(|i| bundle_a.slots[i].commitment),
                        commitments_b: std::array::from_fn(|i| bundle_b.slots[i].commitment),
                        catalogue_hash: catalogue.hash,
                        verification_root: self.root,
                    });
                }
                let digest =
                    accepted_body_hash(self.accepted_body.as_ref().ok_or(ProtocolError::Stage)?);
                let mut aux = [0; 32];
                rand_core::RngCore::fill_bytes(&mut self.rng, &mut aux);
                let sig = self
                    .signing_key
                    .sign_prehash_with_aux_rand(&digest, &aux)
                    .map_err(|_| ProtocolError::AcceptedSignature)?
                    .to_bytes();
                let mut p = digest.to_vec();
                p.extend_from_slice(&sig);
                self.local_payload = Some(p);
            }
            10 => {}
            _ => return Err(ProtocolError::Stage),
        }
        Ok(())
    }
}
