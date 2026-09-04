use std::sync::OnceLock;

use bp52_circuit::hash_length::HashLengthParameters;
use bp52_codec::{Decode, Encode};
use bp52_group::{ProtocolGenerators, PublicKeyShare, SecretKeyShare};
use bp52_protocol::{
    N_SLOTS, PROTOCOL_VERSION, Role,
    archive::ArchiveProgress,
    attestation::{
        DealVerificationAttestation, DealVerificationResult, DealVerificationStatement,
        sign_deal_verification,
    },
    auth::{CanonicalIdentities, derive_game_id, sign_envelope},
    bundle::generate_player_bundle,
    commitments::{bundle_commitment, decryption_commitment, key_commitment},
    contribution::{PreimageStorageKey, RetainedPreimages, SealedRetainedPreimages},
    history::{
        PendingAcceptance, PublicAttemptHistory, RetryBoundary, TrackedAttempt, TrackedProgress,
    },
    messages::{AcceptedDeal, AcceptedDealBody, Envelope, PlayerBundle, UnsignedEnvelope},
    payloads::{
        BundleOpenPayload, CommitmentPayload, DecryptOpenPayload, KeyOpenPayload, ProtocolPayload,
    },
    secp256k1::{All, Keypair, Secp256k1, XOnlyPublicKey},
    transcript::{ProofDomain, ProofPhase, proof_transcript},
};
use bp52_sigma::schnorr::KeyProof;
use bp52_uniqueness::{
    PartialDecryptionBatch, generate_partial_decryption_batch, generate_scale_round,
};
use rand_core::RngCore;
use zeroize::Zeroize;

use rand::rngs::OsRng;

static PARAMETERS: OnceLock<HashLengthParameters> = OnceLock::new();

/// Stable worker-visible lifecycle name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    LocalEnvelope,
    PeerEnvelope,
    RetryApproval,
    LocalAcceptanceSignature,
    PeerAcceptanceSignature,
    Accepted,
    Faulted,
}

pub struct NativeDeal {
    secp: Secp256k1<All>,
    identities: CanonicalIdentities,
    local_identity: Keypair,
    pub local_role: Role,
    shared_config_hash: [u8; 32],
    session_nonce: [u8; 32],
    game_id: [u8; 32],
    rng: OsRng,
    lifecycle: Option<Lifecycle>,
    local_public: PublicKeyShare,
    key_nonce: [u8; 32],
    bundle: Option<PlayerBundle>,
    bundle_nonce: Option<[u8; 32]>,
    partial: Option<PartialDecryptionBatch>,
    decrypt_nonce: Option<[u8; 32]>,
    terminal_archive: Option<Vec<Envelope>>,
    terminal_body: Option<AcceptedDealBody>,
    terminal_result: Option<DealVerificationResult>,
    terminal_transcript_root: Option<[u8; 32]>,
    verification_attestation: Option<DealVerificationAttestation>,
    accepted_deal: Option<AcceptedDeal>,
    pub retained_preimages: Option<RetainedPreimages>,
    pub local_acceptance_signature: Option<[u8; 64]>,
    sealed_once: bool,
}

enum Lifecycle {
    Live(Box<TrackedAttempt<'static, 'static>>),
    Retry(Box<RetryBoundary<'static>>),
    Pending(Box<PendingAcceptance<'static>>),
    Accepted,
    Faulted,
}

impl NativeDeal {
    pub fn new(
        identity_keys: [[u8; 32]; 2],
        mut local_secret: [u8; 32],
        shared_config_hash: [u8; 32],
        session_nonce: [u8; 32],
        game_id: [u8; 32],
    ) -> Result<Self, String> {
        let first_identity = XOnlyPublicKey::from_slice(&identity_keys[0])
            .map_err(|_| "invalid first x-only identity".to_owned())?;
        let second_identity = XOnlyPublicKey::from_slice(&identity_keys[1])
            .map_err(|_| "invalid second x-only identity".to_owned())?;

        let secp = Secp256k1::new();
        let local_identity = Keypair::from_seckey_slice(&secp, local_secret.as_ref())
            .map_err(|_| "invalid local identity secret".to_owned())?;
        local_secret.zeroize();
        let identities = CanonicalIdentities::new(first_identity, second_identity)
            .map_err(|error| error.to_string())?;
        let local_xonly = local_identity.x_only_public_key().0;
        let local_role = identities
            .role_for_key(&local_xonly)
            .map_err(|_| "local identity secret is not one of the game identities".to_owned())?;

        let mut rng = OsRng;

        let parameters = parameters()?;
        let generators = ProtocolGenerators::derive().map_err(|error| error.to_string())?;
        let key_share = SecretKeyShare::random(&mut rng).map_err(|error| error.to_string())?;
        let local_public = key_share.public_key(&generators);
        let key_nonce = random_array(&mut rng)?;

        // A Worker owns exactly one game. Leaking the public history gives the
        // protocol's borrowing typestate a stable lifetime without unsafe
        // self-references; terminating the Worker reclaims its whole memory.
        let history: &'static mut PublicAttemptHistory =
            Box::leak(Box::new(PublicAttemptHistory::new(game_id, identities)));
        let attempt = history
            .start_attempt(parameters, local_role, key_share)
            .map_err(|error| error.to_string())?;

        Ok(Self {
            secp,
            identities,
            local_identity,
            local_role,
            shared_config_hash,
            session_nonce,
            game_id,
            rng,
            lifecycle: Some(Lifecycle::Live(Box::new(attempt))),
            local_public,
            key_nonce,
            bundle: None,
            bundle_nonce: None,
            partial: None,
            decrypt_nonce: None,
            terminal_archive: None,
            terminal_body: None,
            terminal_result: None,
            terminal_transcript_root: None,
            verification_attestation: None,
            accepted_deal: None,
            retained_preimages: None,
            local_acceptance_signature: None,
            sealed_once: false,
        })
    }

    pub fn status(&self) -> Status {
        match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => match attempt.verifier().schedule().expected() {
                Ok(expected) if expected.sender == self.local_role => Status::LocalEnvelope,
                Ok(_) => Status::PeerEnvelope,
                Err(_) => Status::Faulted,
            },
            Some(Lifecycle::Retry(_)) => Status::RetryApproval,
            Some(Lifecycle::Pending(pending)) => {
                if pending.signature(self.local_role).is_none() {
                    Status::LocalAcceptanceSignature
                } else {
                    Status::PeerAcceptanceSignature
                }
            }
            Some(Lifecycle::Accepted) => Status::Accepted,
            Some(Lifecycle::Faulted) | None => Status::Faulted,
        }
    }

    pub fn attempt_number(&self) -> u32 {
        match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => attempt.attempt(),
            Some(Lifecycle::Retry(boundary)) => boundary.next_attempt().saturating_sub(1),
            _ => self.terminal_body.map_or(0, |body| body.attempt),
        }
    }

    pub fn next_sequence(&self) -> u32 {
        match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => attempt.verifier().schedule().next_sequence(),
            _ => u32::MAX,
        }
    }

    pub fn generate_next(&mut self) -> Result<Vec<u8>, String> {
        let expected = match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => attempt
                .verifier()
                .schedule()
                .expected()
                .map_err(|error| error.to_string())?,
            _ => return Err("DEAL attempt is not accepting envelopes".to_owned()),
        };
        if expected.sender != self.local_role {
            return Err("the next DEAL envelope belongs to the peer".to_owned());
        }
        let payload = self.generate_payload(expected.sequence)?;
        if payload.payload_type() != expected.payload_type {
            return self.poison("generated payload violated the fixed DEAL schedule");
        }
        let schedule = match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => attempt.verifier().schedule(),
            _ => return Err("DEAL attempt changed state while generating".to_owned()),
        };
        let unsigned = UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: schedule.game_id(),
            attempt: schedule.attempt(),
            round: expected.round,
            sender_role: expected.sender,
            sequence: expected.sequence,
            previous_message_hash: schedule.transcript_root(),
            payload_type: expected.payload_type,
            payload: payload.encode_body().map_err(|error| error.to_string())?,
        };
        let auxiliary_randomness = random_array(&mut self.rng)?;
        let envelope = sign_envelope(
            &self.secp,
            &unsigned,
            &self.local_identity,
            &self.identities,
            &auxiliary_randomness,
        )
        .map_err(|error| error.to_string())?;
        let bytes = envelope
            .encode_to_vec()
            .map_err(|error| error.to_string())?;
        self.consume(&bytes)?;
        Ok(bytes)
    }

    #[allow(clippy::too_many_lines)]
    pub fn generate_payload(&mut self, sequence: u32) -> Result<ProtocolPayload, String> {
        match sequence {
            0 | 1 => {
                let attempt = self.live()?.attempt();
                let game_id = self.live()?.verifier().schedule().game_id();
                Ok(ProtocolPayload::KeyCommit(CommitmentPayload {
                    commitment: key_commitment(
                        &game_id,
                        attempt,
                        self.local_role,
                        &self.key_nonce,
                        &self.local_public.to_bytes(),
                    ),
                }))
            }
            2 | 3 => Ok(ProtocolPayload::KeyOpen(KeyOpenPayload {
                nonce: self.key_nonce,
                public_key: self.local_public.clone(),
            })),
            4 | 5 => {
                let Some(Lifecycle::Live(attempt)) = self.lifecycle.as_ref() else {
                    return Err("DEAL attempt is not live".to_owned());
                };
                let context = attempt
                    .verifier()
                    .phase_context(ProofPhase::KeyProof)
                    .ok_or_else(|| "missing authenticated T4 key-proof context".to_owned())?;
                let common = attempt
                    .verifier()
                    .common_frame()
                    .ok_or_else(|| "missing verified joint-key proof frame".to_owned())?
                    .clone();
                let keys = attempt
                    .verifier()
                    .key_setup()
                    .ok_or_else(|| "missing verified threshold key setup".to_owned())?
                    .clone();
                let local_secret = attempt
                    .secrets()
                    .ok_or_else(|| "missing local threshold secret owner".to_owned())?
                    .key_share();
                let generators = ProtocolGenerators::derive().map_err(|error| error.to_string())?;
                let proof = KeyProof::prove(
                    &mut proof_transcript(ProofDomain::KeyPop, &context, self.local_role, &common)
                        .map_err(|error| error.to_string())?,
                    &generators,
                    keys.public_a(),
                    keys.public_b(),
                    local_secret,
                    &mut self.rng,
                )
                .map_err(|error| error.to_string())?;
                Ok(ProtocolPayload::KeyProof(proof))
            }
            6 | 7 => {
                self.ensure_bundle()?;
                let bundle = self
                    .bundle
                    .as_ref()
                    .ok_or_else(|| "local bundle was not retained".to_owned())?;
                let nonce = self
                    .bundle_nonce
                    .ok_or_else(|| "local bundle nonce was not retained".to_owned())?;
                let schedule = self.live()?.verifier().schedule();
                let commitment = bundle_commitment(
                    &schedule.game_id(),
                    schedule.attempt(),
                    self.local_role,
                    &nonce,
                    bundle,
                )
                .map_err(|error| error.to_string())?;
                Ok(ProtocolPayload::BundleCommit(CommitmentPayload {
                    commitment,
                }))
            }
            8 | 9 => Ok(ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
                nonce: self
                    .bundle_nonce
                    .ok_or_else(|| "local bundle commitment was not generated".to_owned())?,
                bundle: self
                    .bundle
                    .clone()
                    .ok_or_else(|| "local bundle commitment was not generated".to_owned())?,
            }))),
            10 => {
                let attempt = self.live()?;
                let context = attempt
                    .verifier()
                    .phase_context(ProofPhase::ScaleFirst)
                    .ok_or_else(|| "missing authenticated T10 scale context".to_owned())?;
                let common = attempt
                    .verifier()
                    .common_frame()
                    .ok_or_else(|| "missing proof frame".to_owned())?
                    .clone();
                let inputs = attempt
                    .verifier()
                    .derived_zero_tests()
                    .ok_or_else(|| "missing verified zero-test derivation".to_owned())?
                    .differences
                    .clone();
                let generators = ProtocolGenerators::derive().map_err(|error| error.to_string())?;
                let round = generate_scale_round(
                    &mut proof_transcript(
                        ProofDomain::ScaleFirst,
                        &context,
                        self.local_role,
                        &common,
                    )
                    .map_err(|error| error.to_string())?,
                    &generators,
                    &inputs,
                    &mut self.rng,
                )
                .map_err(|error| error.to_string())?;
                Ok(ProtocolPayload::BlindFirst(Box::new(round)))
            }
            11 => {
                let attempt = self.live()?;
                let context = attempt
                    .verifier()
                    .phase_context(ProofPhase::ScaleSecond)
                    .ok_or_else(|| "missing authenticated T11 scale context".to_owned())?;
                let common = attempt
                    .verifier()
                    .common_frame()
                    .ok_or_else(|| "missing proof frame".to_owned())?
                    .clone();
                let inputs = attempt
                    .verifier()
                    .first_scale_round()
                    .ok_or_else(|| "missing verified first scale round".to_owned())?
                    .outputs
                    .clone();
                let generators = ProtocolGenerators::derive().map_err(|error| error.to_string())?;
                let round = generate_scale_round(
                    &mut proof_transcript(
                        ProofDomain::ScaleSecond,
                        &context,
                        self.local_role,
                        &common,
                    )
                    .map_err(|error| error.to_string())?,
                    &generators,
                    &inputs,
                    &mut self.rng,
                )
                .map_err(|error| error.to_string())?;
                Ok(ProtocolPayload::BlindSecond(Box::new(round)))
            }
            12 | 13 => {
                self.ensure_partial_decryption()?;
                let batch = self
                    .partial
                    .as_ref()
                    .ok_or_else(|| "local partial decryption was not retained".to_owned())?;
                let nonce = self
                    .decrypt_nonce
                    .ok_or_else(|| "local decryption nonce was not retained".to_owned())?;
                let bytes = batch.encode_to_vec().map_err(|error| error.to_string())?;
                let schedule = self.live()?.verifier().schedule();
                Ok(ProtocolPayload::DecryptCommit(CommitmentPayload {
                    commitment: decryption_commitment(
                        &schedule.game_id(),
                        schedule.attempt(),
                        self.local_role,
                        &nonce,
                        &bytes,
                    ),
                }))
            }
            14 | 15 => Ok(ProtocolPayload::DecryptOpen(Box::new(DecryptOpenPayload {
                nonce: self
                    .decrypt_nonce
                    .ok_or_else(|| "local decryption commitment was not generated".to_owned())?,
                batch: self
                    .partial
                    .clone()
                    .ok_or_else(|| "local decryption commitment was not generated".to_owned())?,
            }))),
            _ => Err("DEAL envelope schedule is complete".to_owned()),
        }
    }

    pub fn ensure_bundle(&mut self) -> Result<(), String> {
        if self.bundle.is_some() {
            return Ok(());
        }
        let Some(Lifecycle::Live(attempt)) = self.lifecycle.as_ref() else {
            return Err("DEAL attempt is not live".to_owned());
        };
        let context = attempt
            .verifier()
            .phase_context(ProofPhase::PlayerBundle)
            .ok_or_else(|| "missing authenticated T6 bundle context".to_owned())?;
        let common = attempt
            .verifier()
            .common_frame()
            .ok_or_else(|| "missing verified joint-key proof frame".to_owned())?
            .clone();
        let joint = attempt
            .verifier()
            .key_setup()
            .ok_or_else(|| "missing verified threshold key setup".to_owned())?
            .joint()
            .clone();
        let (bundle, contribution) = generate_player_bundle(
            parameters()?,
            &context,
            &common,
            self.local_role,
            &joint,
            &mut self.rng,
        )
        .map_err(|error| error.to_string())?;
        let nonce = random_array(&mut self.rng)?;
        self.live_mut()?
            .install_contribution(contribution)
            .map_err(|error| error.to_string())?;
        self.bundle = Some(bundle);
        self.bundle_nonce = Some(nonce);
        Ok(())
    }

    pub fn prepare_bundle(&mut self) -> Result<(), String> {
        if self.bundle.is_some() {
            return Ok(());
        }
        let sequence = self.live()?.verifier().schedule().next_sequence();
        if !(6..=7).contains(&sequence) {
            return Err("bundle preparation is available only at transcript height T6".to_owned());
        }
        self.ensure_bundle()?;
        Ok(())
    }

    pub fn ensure_partial_decryption(&mut self) -> Result<(), String> {
        if self.partial.is_some() {
            return Ok(());
        }
        let Some(Lifecycle::Live(attempt)) = self.lifecycle.as_ref() else {
            return Err("DEAL attempt is not live".to_owned());
        };
        let context = attempt
            .verifier()
            .phase_context(ProofPhase::PartialDecrypt)
            .ok_or_else(|| "missing authenticated T12 decryption context".to_owned())?;
        let common = attempt
            .verifier()
            .common_frame()
            .ok_or_else(|| "missing proof frame".to_owned())?
            .clone();
        let keys = attempt
            .verifier()
            .key_setup()
            .ok_or_else(|| "missing verified threshold key setup".to_owned())?
            .clone();
        let inputs = attempt
            .verifier()
            .second_scale_round()
            .ok_or_else(|| "missing verified second scale round".to_owned())?
            .outputs
            .clone();
        let secret = attempt
            .secrets()
            .ok_or_else(|| "missing local threshold secret owner".to_owned())?
            .key_share();
        let public = match self.local_role {
            Role::Alice => keys.public_a(),
            Role::Bob => keys.public_b(),
        };
        let domain = match self.local_role {
            Role::Alice => ProofDomain::PartialDecryptAlice,
            Role::Bob => ProofDomain::PartialDecryptBob,
        };
        let generators = ProtocolGenerators::derive().map_err(|error| error.to_string())?;
        let batch = generate_partial_decryption_batch(
            &mut proof_transcript(domain, &context, self.local_role, &common)
                .map_err(|error| error.to_string())?,
            &generators,
            public,
            secret,
            &inputs,
            &mut self.rng,
        )
        .map_err(|error| error.to_string())?;
        self.partial = Some(batch);
        self.decrypt_nonce = Some(random_array(&mut self.rng)?);
        Ok(())
    }

    pub fn prepare_partial_decryption(&mut self) -> Result<(), String> {
        if self.partial.is_some() {
            return Ok(());
        }
        let sequence = self.live()?.verifier().schedule().next_sequence();
        if !(12..=13).contains(&sequence) {
            return Err(
                "partial-decryption preparation is available only at transcript height T12"
                    .to_owned(),
            );
        }
        self.ensure_partial_decryption()
    }

    pub fn accept_envelope(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.is_exact_duplicate(bytes)? {
            return Ok(());
        }
        self.consume(bytes)
    }

    pub fn is_exact_duplicate(&self, bytes: &[u8]) -> Result<bool, String> {
        let Ok(candidate) = Envelope::decode_exact(bytes) else {
            return Ok(false);
        };
        let archive = match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => attempt.verifier().authenticated_archive(),
            _ => self.terminal_archive.as_deref().unwrap_or(&[]),
        };
        let Ok(index) = usize::try_from(candidate.unsigned.sequence) else {
            return Ok(false);
        };
        let Some(existing) = archive.get(index) else {
            return Ok(false);
        };
        Ok(existing
            .encode_to_vec()
            .map_err(|error| error.to_string())?
            == bytes)
    }

    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), String> {
        let progress = match self.lifecycle.as_mut() {
            Some(Lifecycle::Live(attempt)) => attempt
                .accept_bytes(&self.secp, bytes)
                .map_err(|error| error.to_string())?,
            _ => return Err("DEAL attempt is not live".to_owned()),
        };
        match progress {
            TrackedProgress::Continue { .. } => Ok(()),
            TrackedProgress::DegenerateRetry => self.finish_retry(ArchiveProgress::DegenerateRetry),
            TrackedProgress::CollisionRetry => self.finish_retry(ArchiveProgress::CollisionRetry),
            TrackedProgress::ReadyToSign => {
                let lifecycle = self
                    .lifecycle
                    .take()
                    .ok_or_else(|| "missing live attempt".to_owned())?;
                let Lifecycle::Live(attempt) = lifecycle else {
                    return self.poison("acceptance did not own a live attempt");
                };
                let transcript_root = attempt.verifier().schedule().transcript_root();
                self.terminal_archive = Some(attempt.verifier().authenticated_archive().to_vec());
                let pending = (*attempt)
                    .into_pending_acceptance()
                    .map_err(|error| error.to_string())?;
                self.terminal_body = pending.body();
                self.terminal_result = self.terminal_body.map(DealVerificationResult::Accepted);
                self.terminal_transcript_root = Some(transcript_root);
                self.verification_attestation = None;
                self.lifecycle = Some(Lifecycle::Pending(Box::new(pending)));
                Ok(())
            }
        }
    }

    pub fn finish_retry(&mut self, progress: ArchiveProgress) -> Result<(), String> {
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or_else(|| "missing live attempt".to_owned())?;
        let Lifecycle::Live(attempt) = lifecycle else {
            return self.poison("terminal retry did not own a live attempt");
        };
        let transcript_root = attempt.verifier().schedule().transcript_root();
        self.terminal_archive = Some(attempt.verifier().authenticated_archive().to_vec());
        let boundary = (*attempt).retry().map_err(|error| error.to_string())?;
        self.terminal_result = Some(match progress {
            ArchiveProgress::DegenerateRetry => DealVerificationResult::DegenerateRetry,
            ArchiveProgress::CollisionRetry => DealVerificationResult::CollisionRetry,
            ArchiveProgress::Continue => {
                return self.poison("nonterminal DEAL progress cannot authorize retry");
            }
        });
        self.terminal_transcript_root = Some(transcript_root);
        self.verification_attestation = None;
        self.lifecycle = Some(Lifecycle::Retry(Box::new(boundary)));
        Ok(())
    }

    pub fn start_retry(&mut self, approved_attempt: u32) -> Result<(), String> {
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or_else(|| "missing retry boundary".to_owned())?;
        let Lifecycle::Retry(boundary) = lifecycle else {
            self.lifecycle = Some(lifecycle);
            return Err("DEAL is not awaiting retry approval".to_owned());
        };
        if boundary.next_attempt() != approved_attempt {
            self.lifecycle = Some(Lifecycle::Retry(boundary));
            return Err("retry approval names a non-contiguous attempt".to_owned());
        }
        let generators = ProtocolGenerators::derive().map_err(|error| error.to_string())?;
        let secret = SecretKeyShare::random(&mut self.rng).map_err(|error| error.to_string())?;
        self.local_public = secret.public_key(&generators);
        self.key_nonce = random_array(&mut self.rng)?;
        let attempt = (*boundary)
            .start_next(parameters()?, self.local_role, secret)
            .map_err(|error| error.to_string())?;
        self.bundle = None;
        self.bundle_nonce = None;
        self.partial = None;
        self.decrypt_nonce = None;
        self.terminal_archive = None;
        self.terminal_body = None;
        self.terminal_result = None;
        self.terminal_transcript_root = None;
        self.verification_attestation = None;
        self.local_acceptance_signature = None;
        self.sealed_once = false;
        self.lifecycle = Some(Lifecycle::Live(Box::new(attempt)));
        Ok(())
    }

    pub fn make_acceptance_signature(
        &mut self,
        coordinator_body: &[u8],
    ) -> Result<[u8; 64], String> {
        let coordinator_body =
            AcceptedDealBody::decode_exact(coordinator_body).map_err(|error| error.to_string())?;
        let verified_body = match self.lifecycle.as_ref() {
            Some(Lifecycle::Pending(pending)) => pending
                .body()
                .ok_or_else(|| "verified accepted DEAL body is unavailable".to_owned())?,
            Some(Lifecycle::Accepted) => self
                .accepted_deal
                .map(|deal| deal.body())
                .ok_or_else(|| "accepted DEAL certificate is unavailable".to_owned())?,
            _ => return Err("DEAL is not awaiting acceptance signatures".to_owned()),
        };
        if coordinator_body != verified_body {
            return Err("coordinator accepted body differs from the Worker verifier".to_owned());
        }
        if let Some(signature) = self.local_acceptance_signature {
            return Ok(signature);
        }
        let aux = random_array(&mut self.rng)?;
        let signature = match self.lifecycle.as_mut() {
            Some(Lifecycle::Pending(pending)) => pending
                .sign(&self.secp, self.local_role, &self.local_identity, &aux)
                .map_err(|error| error.to_string())?,
            _ => return Err("DEAL is not awaiting acceptance signatures".to_owned()),
        };
        self.local_acceptance_signature = Some(signature);
        self.finalize_if_complete()?;
        Ok(signature)
    }

    pub fn accept_acceptance_signature(
        &mut self,
        role: Role,
        signature: [u8; 64],
    ) -> Result<(), String> {
        if role == self.local_role {
            if self.local_acceptance_signature == Some(signature) {
                return Ok(());
            }
            return Err("remote acceptance signature claimed the local role".to_owned());
        }
        if let Some(existing) = match self.lifecycle.as_ref() {
            Some(Lifecycle::Pending(pending)) => pending.signature(role),
            Some(Lifecycle::Accepted) => self.accepted_deal.map(|deal| match role {
                Role::Alice => deal.signature_a,
                Role::Bob => deal.signature_b,
            }),
            _ => None,
        } {
            return if existing == signature {
                Ok(())
            } else {
                Err("a different acceptance signature already occupies this role".to_owned())
            };
        }
        match self.lifecycle.as_mut() {
            Some(Lifecycle::Pending(pending)) => pending
                .record_signature(&self.secp, role, signature)
                .map_err(|error| error.to_string())?,
            Some(Lifecycle::Accepted) => {
                return Err("accepted DEAL certificate is missing its peer signature".to_owned());
            }
            _ => return Err("DEAL is not awaiting acceptance signatures".to_owned()),
        }
        self.finalize_if_complete()
    }

    pub fn finalize_if_complete(&mut self) -> Result<(), String> {
        let complete = match self.lifecycle.as_ref() {
            Some(Lifecycle::Pending(pending)) => {
                pending.signature(Role::Alice).is_some() && pending.signature(Role::Bob).is_some()
            }
            _ => false,
        };
        if !complete {
            return Ok(());
        }
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or_else(|| "missing pending acceptance".to_owned())?;
        let Lifecycle::Pending(mut pending) = lifecycle else {
            return self.poison("signature completion did not own pending acceptance");
        };
        let accepted = pending
            .finalize(&self.secp)
            .map_err(|error| error.to_string())?;
        let (deal, retained) = accepted.into_parts();
        self.accepted_deal = Some(deal);
        self.retained_preimages = Some(retained);
        self.lifecycle = Some(Lifecycle::Accepted);
        Ok(())
    }

    pub fn verification_attestation_bytes(&mut self) -> Result<Vec<u8>, String> {
        if let Some(attestation) = self.verification_attestation {
            return attestation
                .encode_to_vec()
                .map_err(|error| error.to_string());
        }
        let result = self
            .terminal_result
            .ok_or_else(|| "DEAL verification has not reached a terminal result".to_owned())?;
        let transcript_root = self
            .terminal_transcript_root
            .ok_or_else(|| "terminal DEAL transcript root is unavailable".to_owned())?;
        let statement = match result {
            DealVerificationResult::Accepted(body) => DealVerificationStatement::accepted(
                self.shared_config_hash,
                self.session_nonce,
                self.game_id,
                body.attempt,
                transcript_root,
                body,
            ),
            DealVerificationResult::DegenerateRetry => DealVerificationStatement::retry(
                self.shared_config_hash,
                self.session_nonce,
                self.game_id,
                self.attempt_number(),
                transcript_root,
                ArchiveProgress::DegenerateRetry,
            ),
            DealVerificationResult::CollisionRetry => DealVerificationStatement::retry(
                self.shared_config_hash,
                self.session_nonce,
                self.game_id,
                self.attempt_number(),
                transcript_root,
                ArchiveProgress::CollisionRetry,
            ),
        }
        .map_err(|error| error.to_string())?;
        let auxiliary_randomness = random_array(&mut self.rng)?;
        let attestation = sign_deal_verification(
            &self.secp,
            statement,
            self.local_role,
            &self.local_identity,
            &self.identities,
            &auxiliary_randomness,
        )
        .map_err(|error| error.to_string())?;
        let bytes = attestation
            .encode_to_vec()
            .map_err(|error| error.to_string())?;
        self.verification_attestation = Some(attestation);
        Ok(bytes)
    }

    pub fn accepted_body_bytes(&self) -> Result<Vec<u8>, String> {
        self.terminal_body
            .ok_or_else(|| "accepted DEAL body is not ready".to_owned())?
            .encode_to_vec()
            .map_err(|error| error.to_string())
    }

    pub fn accepted_deal_bytes(&self) -> Result<Vec<u8>, String> {
        self.accepted_deal
            .ok_or_else(|| "accepted DEAL certificate is not complete".to_owned())?
            .encode_to_vec()
            .map_err(|error| error.to_string())
    }

    /// Copy the mutually signed accepted-deal certificate.
    pub fn accepted_deal(&self) -> Result<AcceptedDeal, String> {
        self.accepted_deal
            .ok_or_else(|| "accepted DEAL certificate is not complete".to_owned())
    }

    pub fn seal_retained_preimages(&mut self, key_bytes: &mut [u8; 32]) -> Result<Vec<u8>, String> {
        if self.sealed_once {
            key_bytes.zeroize();
            return Err("retained preimages may be sealed only once per Worker".to_owned());
        }
        let deal = self
            .accepted_deal
            .ok_or_else(|| "accepted DEAL certificate is not complete".to_owned())?;
        let mut retained = self
            .retained_preimages
            .take()
            .ok_or_else(|| "accepted local preimages are not available".to_owned())?;
        let mut storage_key = PreimageStorageKey::from_bytes(*key_bytes);
        key_bytes.zeroize();
        let sealed =
            match retained.seal_at_rest(&deal, self.local_role, &mut storage_key, &mut self.rng) {
                Ok(sealed) => sealed,
                Err(error) => {
                    self.retained_preimages = Some(retained);
                    return Err(error.to_string());
                }
            };
        let bytes = sealed.as_bytes().to_vec();
        let reopened = SealedRetainedPreimages::from_bytes(&bytes)
            .and_then(|copy| copy.open(&deal, self.local_role, &storage_key))
            .map_err(|error| error.to_string())?;
        self.retained_preimages = Some(reopened);
        self.sealed_once = true;
        Ok(bytes)
    }

    #[allow(dead_code)]
    pub fn reveal_local_preimage(&self, slot: usize) -> Result<Vec<u8>, String> {
        if slot >= N_SLOTS {
            return Err("DEAL preimage slot is outside 0..9".to_owned());
        }
        self.retained_preimages
            .as_ref()
            .and_then(|retained| retained.get(slot))
            .map(ToOwned::to_owned)
            .ok_or_else(|| "accepted local preimages are not available".to_owned())
    }

    pub fn live(&self) -> Result<&TrackedAttempt<'static, 'static>, String> {
        match self.lifecycle.as_ref() {
            Some(Lifecycle::Live(attempt)) => Ok(attempt),
            _ => Err("DEAL attempt is not live".to_owned()),
        }
    }

    pub fn live_mut(&mut self) -> Result<&mut TrackedAttempt<'static, 'static>, String> {
        match self.lifecycle.as_mut() {
            Some(Lifecycle::Live(attempt)) => Ok(attempt),
            _ => Err("DEAL attempt is not live".to_owned()),
        }
    }

    pub fn poison<T>(&mut self, message: &str) -> Result<T, String> {
        self.lifecycle = Some(Lifecycle::Faulted);
        Err(message.to_owned())
    }
}

fn parameters() -> Result<&'static HashLengthParameters, String> {
    if let Some(parameters) = PARAMETERS.get() {
        return Ok(parameters);
    }
    let parameters = HashLengthParameters::new().map_err(|error| error.to_string())?;
    let _ = PARAMETERS.set(parameters);
    PARAMETERS
        .get()
        .ok_or_else(|| "failed to retain fixed DEAL proof parameters".to_owned())
}

fn random_array<const N: usize>(rng: &mut OsRng) -> Result<[u8; N], String> {
    let mut bytes = [0_u8; N];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| "local DEAL randomness failed".to_owned())?;
    Ok(bytes)
}

/// Run a complete two-participant native DEAL transcript in one process.
///
/// This is deliberately exposed as a CLI smoke test: it executes the same
/// generation, authentication, proof verification, and mutual acceptance
/// operations used when the participants are connected over libp2p.
pub fn self_test() -> Result<(), String> {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let alice_secret = bp52_protocol::secp256k1::SecretKey::new(&mut rng).secret_bytes();
    let bob_secret = bp52_protocol::secp256k1::SecretKey::new(&mut rng).secret_bytes();
    let alice_keypair =
        Keypair::from_seckey_slice(&secp, &alice_secret).map_err(|error| error.to_string())?;
    let bob_keypair =
        Keypair::from_seckey_slice(&secp, &bob_secret).map_err(|error| error.to_string())?;
    let identities = CanonicalIdentities::new(
        alice_keypair.x_only_public_key().0,
        bob_keypair.x_only_public_key().0,
    )
    .map_err(|error| error.to_string())?;
    let (alice_key, bob_key) = identities.serialized();
    let secrets = if alice_keypair.x_only_public_key().0 == *identities.alice() {
        [alice_secret, bob_secret]
    } else {
        [bob_secret, alice_secret]
    };
    let config = [0x41; 32];
    let nonce = [0x42; 32];
    let game_id = [0x43; 32];
    let mut parties = [
        NativeDeal::new([alice_key, bob_key], secrets[0], config, nonce, game_id)?,
        NativeDeal::new([alice_key, bob_key], secrets[1], config, nonce, game_id)?,
    ];

    loop {
        let sender = match parties[0].status() {
            Status::LocalEnvelope => 0,
            Status::PeerEnvelope => 1,
            Status::RetryApproval => {
                let next = parties[0].attempt_number().saturating_add(1);
                parties[0].start_retry(next)?;
                parties[1].start_retry(next)?;
                continue;
            }
            Status::LocalAcceptanceSignature | Status::PeerAcceptanceSignature => break,
            Status::Accepted => break,
            Status::Faulted => return Err("native DEAL participant faulted".to_owned()),
        };
        let bytes = parties[sender].generate_next()?;
        parties[1 - sender].accept_envelope(&bytes)?;
    }

    let body = parties[0].accepted_body_bytes()?;
    if parties[1].accepted_body_bytes()? != body {
        return Err("native DEAL participants derived different accepted bodies".to_owned());
    }
    let signature_a = parties[0].make_acceptance_signature(&body)?;
    parties[1].accept_acceptance_signature(Role::Alice, signature_a)?;
    let signature_b = parties[1].make_acceptance_signature(&body)?;
    parties[0].accept_acceptance_signature(Role::Bob, signature_b)?;
    if parties[0].status() != Status::Accepted || parties[1].status() != Status::Accepted {
        return Err("native DEAL did not reach mutual acceptance".to_owned());
    }
    if parties[0].accepted_deal_bytes()? != parties[1].accepted_deal_bytes()? {
        return Err("native DEAL certificates differ".to_owned());
    }
    Ok(())
}

/// Construct two mutually accepted native DEAL participants for local integration tests.
pub fn completed_pair(
    identity_keys: [[u8; 32]; 2],
    role_secrets: [[u8; 32]; 2],
    shared_config_hash: [u8; 32],
    session_nonce: [u8; 32],
    funding_outpoint: [u8; 36],
) -> Result<[NativeDeal; 2], String> {
    let identities = CanonicalIdentities::new(
        XOnlyPublicKey::from_slice(&identity_keys[0]).map_err(|error| error.to_string())?,
        XOnlyPublicKey::from_slice(&identity_keys[1]).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let game_id = derive_game_id(
        &shared_config_hash,
        &funding_outpoint,
        &identities,
        &session_nonce,
    );
    let mut parties = [
        NativeDeal::new(
            identity_keys,
            role_secrets[0],
            shared_config_hash,
            session_nonce,
            game_id,
        )?,
        NativeDeal::new(
            identity_keys,
            role_secrets[1],
            shared_config_hash,
            session_nonce,
            game_id,
        )?,
    ];
    loop {
        let sender = match parties[0].status() {
            Status::LocalEnvelope => 0,
            Status::PeerEnvelope => 1,
            Status::RetryApproval => {
                let next = parties[0].attempt_number().saturating_add(1);
                parties[0].start_retry(next)?;
                parties[1].start_retry(next)?;
                continue;
            }
            Status::LocalAcceptanceSignature | Status::PeerAcceptanceSignature => break,
            Status::Accepted => break,
            Status::Faulted => return Err("native DEAL participant faulted".to_owned()),
        };
        let envelope = parties[sender].generate_next()?;
        parties[1 - sender].accept_envelope(&envelope)?;
    }
    let body = parties[0].accepted_body_bytes()?;
    if parties[1].accepted_body_bytes()? != body {
        return Err("native DEAL participants derived different accepted bodies".to_owned());
    }
    let alice = parties[0].make_acceptance_signature(&body)?;
    parties[1].accept_acceptance_signature(Role::Alice, alice)?;
    let bob = parties[1].make_acceptance_signature(&body)?;
    parties[0].accept_acceptance_signature(Role::Bob, bob)?;
    if parties
        .iter()
        .any(|party| party.status() != Status::Accepted)
    {
        return Err("native DEAL did not reach mutual acceptance".to_owned());
    }
    Ok(parties)
}
