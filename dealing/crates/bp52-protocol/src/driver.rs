//! Semantic verification driver for one authenticated BP52 attempt.
//!
//! [`AttemptSchedule`](crate::state::AttemptSchedule) deliberately verifies
//! only authentication and envelope ordering.  This module layers the
//! protocol semantics on top: commit/open checks, proof verification, public
//! homomorphic derivation, both uniqueness rounds, and construction of the
//! unsigned accepted-deal body.

use bitcoin::secp256k1::{Keypair, Secp256k1, Signing, Verification};
use bp52_circuit::hash_length::HashLengthParameters;
use bp52_codec::{Decode, Encode};
use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, GroupError, ProtocolGenerators, PublicKeyShare,
};
use bp52_sigma::schnorr::KeyProof;
use bp52_uniqueness::{
    DerivedZeroTests, PartialDecryptionBatch, ScaleRound, UniquenessError,
    derive_sums_and_zero_tests, verify_partial_decryption_batch, verify_scale_round,
};

use crate::{
    N_SLOTS, PROTOCOL_VERSION, Role,
    auth::{
        AuthError, CanonicalIdentities, sign_accepted_deal, verify_accepted_deal_signature,
        verify_envelope, verify_raw_envelope,
    },
    bundle::{BundleError, verify_player_bundle},
    commitments::{
        CommitmentError, verify_bundle_commitment, verify_decryption_commitment,
        verify_key_commitment,
    },
    contribution::{
        ContributionError, validate_global_hash_uniqueness, validate_original_contribution_points,
    },
    messages::{
        AcceptedDeal, AcceptedDealBody, ENCRYPTION_LINK_PROOF_SIZE, Envelope,
        HASH_LENGTH_PROOF_SIZE, PayloadType, PlayerBundle, RawEnvelope,
    },
    outcome::{AttemptOutcome, ProtocolError},
    payloads::{DecryptOpenPayload, ProtocolPayload},
    state::{AttemptSchedule, EnvelopeAcceptanceError, authenticated_schedule_error},
    transcript::{
        AttemptContext, ProofCommonFrame, ProofDomain, ProofPhase, TranscriptHash, proof_transcript,
    },
    uniqueness::{
        JointKeyPublic, UniquenessTranscript, UniquenessTranscriptError,
        verify_uniqueness_transcript_detailed,
    },
};

/// A successful semantic transition of the attempt verifier.
#[must_use = "attempt progress may contain a non-cloneable terminal capability"]
#[derive(Debug, Eq, PartialEq)]
pub enum AttemptProgress {
    /// One valid envelope was consumed and more are required.
    Continue {
        /// New authenticated transcript root.
        transcript_root: TranscriptHash,
        /// Next global envelope sequence number.
        next_sequence: u32,
    },
    /// A negligible derived-ciphertext cancellation requires a fresh attempt.
    DegenerateRetry(Box<VerifiedDegenerateRetry>),
    /// All 16 messages and proofs verified, but a normal card collision exists.
    CollisionRetry(Box<VerifiedCollisionRetry>),
    /// All semantics verified.  Both identity signatures still need to be
    /// collected over this exact body before an [`AttemptOutcome::Accepted`]
    /// can exist.
    ReadyToSign(Box<VerifiedReadyToSign>),
}

/// Exact authenticated envelope archive emitted only by semantic verification.
///
/// The contained envelopes remain in canonical sequence order and include
/// their BIP340 signatures.  Construction is private, so the `(game, attempt,
/// root, envelopes)` tuple cannot be mixed by downstream history code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEnvelopeArchive {
    game_id: [u8; 32],
    attempt: u32,
    transcript_root: TranscriptHash,
    envelopes: Vec<Envelope>,
}

impl VerifiedEnvelopeArchive {
    /// Returns the funded game identifier authenticated by every envelope.
    #[must_use]
    pub const fn game_id(&self) -> [u8; 32] {
        self.game_id
    }

    /// Returns the attempt number authenticated by every envelope.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Returns the transcript root after the final archived envelope.
    #[must_use]
    pub const fn transcript_root(&self) -> TranscriptHash {
        self.transcript_root
    }

    /// Returns the exact signed envelopes in global sequence order.
    #[must_use]
    pub fn envelopes(&self) -> &[Envelope] {
        &self.envelopes
    }
}

/// Opaque evidence that a neutral derived-`R` cancellation was reached only
/// after both authenticated bundle openings and their proofs verified.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedDegenerateRetry {
    archive: VerifiedEnvelopeArchive,
}

impl VerifiedDegenerateRetry {
    /// Returns the funded game identifier.
    #[must_use]
    pub const fn game_id(&self) -> [u8; 32] {
        self.archive.game_id()
    }

    /// Returns the attempt that must be discarded.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.archive.attempt()
    }

    /// Returns `T_10`, after both fully verified bundle openings.
    #[must_use]
    pub const fn transcript_root(&self) -> TranscriptHash {
        self.archive.transcript_root()
    }

    /// Returns the exact ten-envelope authenticated archive through both
    /// bundle openings.
    #[must_use]
    pub const fn archive(&self) -> &VerifiedEnvelopeArchive {
        &self.archive
    }
}

/// Opaque evidence that a complete, authenticated `T_16` attempt produced at
/// least one genuine card collision.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedCollisionRetry {
    collision_bitmap: [bool; bp52_uniqueness::ZERO_TEST_COUNT],
    archive: VerifiedEnvelopeArchive,
}

impl VerifiedCollisionRetry {
    /// Returns the funded game identifier.
    #[must_use]
    pub const fn game_id(&self) -> [u8; 32] {
        self.archive.game_id()
    }

    /// Returns the attempt that must be discarded.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.archive.attempt()
    }

    /// Returns the complete canonical collision vector.
    #[must_use]
    pub const fn collision_bitmap(&self) -> &[bool; bp52_uniqueness::ZERO_TEST_COUNT] {
        &self.collision_bitmap
    }

    /// Returns the final attempt root `T_16`.
    #[must_use]
    pub const fn transcript_root(&self) -> TranscriptHash {
        self.archive.transcript_root()
    }

    /// Returns the exact complete 16-envelope authenticated archive.
    #[must_use]
    pub const fn archive(&self) -> &VerifiedEnvelopeArchive {
        &self.archive
    }

    /// Converts this verified terminal result to the public outcome taxonomy.
    #[must_use]
    pub const fn outcome(&self) -> AttemptOutcome {
        AttemptOutcome::collision(self.collision_bitmap)
    }
}

/// Opaque semantic-verification capability for acceptance signing.
///
/// Callers can inspect the body, but only a complete [`AttemptVerifier`]
/// transition can construct this token.  The low-level signer is crate-private
/// so the public API cannot accidentally sign an unverified body.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedReadyToSign {
    body: AcceptedDealBody,
    identities: CanonicalIdentities,
    archive: VerifiedEnvelopeArchive,
}

impl VerifiedReadyToSign {
    /// Returns the exact body whose transcript root is authenticated `T_16`.
    #[must_use]
    pub const fn body(&self) -> AcceptedDealBody {
        self.body
    }

    /// Returns the exact complete 16-envelope archive whose `T_16` is in the
    /// accepted body.
    #[must_use]
    pub const fn archive(&self) -> &VerifiedEnvelopeArchive {
        &self.archive
    }

    /// Signs the verified body for one canonical role.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the signing key does not own `role`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn sign<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        role: Role,
        signing_key: &Keypair,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<[u8; 64], AuthError> {
        sign_accepted_deal(
            secp,
            &self.body,
            role,
            signing_key,
            &self.identities,
            auxiliary_randomness,
        )
    }

    /// Assembles and verifies both canonical acceptance signatures.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidSignature`] if either signature is not by
    /// the role assigned in this verified attempt.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn finalize<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        signature_a: [u8; 64],
        signature_b: [u8; 64],
    ) -> Result<AcceptedDeal, AuthError> {
        verify_accepted_deal_signature(
            secp,
            &self.body,
            Role::Alice,
            &signature_a,
            &self.identities,
        )?;
        verify_accepted_deal_signature(
            secp,
            &self.body,
            Role::Bob,
            &signature_b,
            &self.identities,
        )?;
        Ok(AcceptedDeal {
            protocol_version: self.body.protocol_version,
            game_id: self.body.game_id,
            attempt: self.body.attempt,
            hashes_a: self.body.hashes_a,
            hashes_b: self.body.hashes_b,
            verification_transcript_root: self.body.verification_transcript_root,
            signature_a,
            signature_b,
        })
    }
}

/// Failure while authenticating or semantically consuming one envelope.
#[derive(Debug, thiserror::Error)]
pub enum AttemptDriverError {
    /// This driver already returned a terminal progress state.
    #[error("attempt verifier is terminal")]
    Terminal,
    /// Authentication or authenticated schedule validation failed.
    #[error(transparent)]
    Envelope(#[from] EnvelopeAcceptanceError),
    /// The valid signature covered an invalid sender-owned semantic object.
    #[error("authenticated signer {signer:?} caused semantic fault {error}")]
    SignedSemanticFault {
        /// Safely attributable signer.
        signer: Role,
        /// Public fail-closed category.
        error: ProtocolError,
    },
    /// A joint condition failed without a sound single-party attribution.
    #[error("unattributed semantic fault {error}")]
    UnattributedSemanticFault {
        /// Public fail-closed category.
        error: ProtocolError,
    },
}

impl AttemptDriverError {
    /// Returns a blamed role only when authentication makes that attribution
    /// sound.
    #[must_use]
    pub const fn blamed_role(&self) -> Option<Role> {
        match self {
            Self::Terminal | Self::UnattributedSemanticFault { .. } => None,
            Self::Envelope(error) => error.blamed_role(),
            Self::SignedSemanticFault { signer, .. } => Some(*signer),
        }
    }

    /// Converts a protocol failure to the public attempt-outcome taxonomy.
    /// A local API misuse after the driver is terminal has no protocol outcome.
    #[must_use]
    pub fn fault_outcome(&self) -> Option<AttemptOutcome> {
        match self {
            Self::Terminal => None,
            Self::Envelope(error) => error.fault_outcome(),
            Self::SignedSemanticFault { signer, error } => {
                Some(AttemptOutcome::signer_fault(*signer, *error))
            }
            Self::UnattributedSemanticFault { error } => {
                Some(AttemptOutcome::unattributed_fault(*error))
            }
        }
    }
}

/// Complete public verifier state for one attempt.
///
/// Secret keys, contribution witnesses, blinding factors, and opening
/// preimages are intentionally absent. Construction and mutation are
/// crate-private: participants receive a read-only view through
/// [`crate::history::TrackedAttempt`], while independent observers use
/// [`crate::verify_accepted_archive`].
pub struct AttemptVerifier<'parameters> {
    schedule: AttemptSchedule,
    identities: CanonicalIdentities,
    parameters: Option<&'parameters HashLengthParameters>,
    circuit_id: [u8; 32],
    terminal: bool,
    archive: Vec<Envelope>,

    key_commit_a: Option<[u8; 32]>,
    key_commit_b: Option<[u8; 32]>,
    public_a: Option<PublicKeyShare>,
    public_b: Option<PublicKeyShare>,
    keys: Option<JointKeyPublic>,
    common: Option<ProofCommonFrame>,
    key_proof_a: bool,
    key_proof_b: bool,

    bundle_commit_a: Option<[u8; 32]>,
    bundle_commit_b: Option<[u8; 32]>,
    bundle_a: Option<PlayerBundle>,
    bundle_b: Option<PlayerBundle>,
    derived: Option<Box<DerivedZeroTests>>,

    scale_first: Option<Box<ScaleRound>>,
    scale_second: Option<Box<ScaleRound>>,
    decrypt_commit_a: Option<[u8; 32]>,
    decrypt_commit_b: Option<[u8; 32]>,
    partial_a: Option<Box<PartialDecryptionBatch>>,

    root_t4: Option<TranscriptHash>,
    root_t6: Option<TranscriptHash>,
    root_t10: Option<TranscriptHash>,
    root_t11: Option<TranscriptHash>,
    root_t12: Option<TranscriptHash>,
}

impl<'parameters> AttemptVerifier<'parameters> {
    /// Starts a semantic verifier at `T_0` with locally compiled circuit
    /// parameters.
    #[must_use]
    pub(crate) fn new(
        game_id: [u8; 32],
        attempt: u32,
        identities: CanonicalIdentities,
        parameters: &'parameters HashLengthParameters,
    ) -> Self {
        Self::new_inner(
            game_id,
            attempt,
            identities,
            parameters.circuit_id(),
            Some(parameters),
        )
    }

    #[cfg(test)]
    pub(crate) fn without_hash_length_backend(
        game_id: [u8; 32],
        attempt: u32,
        identities: CanonicalIdentities,
        circuit_id: [u8; 32],
    ) -> AttemptVerifier<'static> {
        AttemptVerifier::new_inner(game_id, attempt, identities, circuit_id, None)
    }

    fn new_inner(
        game_id: [u8; 32],
        attempt: u32,
        identities: CanonicalIdentities,
        circuit_id: [u8; 32],
        parameters: Option<&'parameters HashLengthParameters>,
    ) -> Self {
        Self {
            schedule: AttemptSchedule::new(game_id, attempt),
            identities,
            parameters,
            circuit_id,
            terminal: false,
            archive: Vec::with_capacity(16),
            key_commit_a: None,
            key_commit_b: None,
            public_a: None,
            public_b: None,
            keys: None,
            common: None,
            key_proof_a: false,
            key_proof_b: false,
            bundle_commit_a: None,
            bundle_commit_b: None,
            bundle_a: None,
            bundle_b: None,
            derived: None,
            scale_first: None,
            scale_second: None,
            decrypt_commit_a: None,
            decrypt_commit_b: None,
            partial_a: None,
            root_t4: None,
            root_t6: None,
            root_t10: None,
            root_t11: None,
            root_t12: None,
        }
    }

    /// Returns the authenticated schedule cursor.
    #[must_use]
    pub const fn schedule(&self) -> &AttemptSchedule {
        &self.schedule
    }

    /// Returns whether a terminal acceptance/retry result or authenticated
    /// protocol fault has permanently closed this attempt.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Returns the semantically accepted prefix of signed envelopes.
    /// Authenticated faulting envelopes and unauthenticated traffic are never
    /// appended.
    #[must_use]
    pub fn authenticated_archive(&self) -> &[Envelope] {
        &self.archive
    }

    /// Structurally decodes, authenticates, and semantically consumes one raw
    /// wire envelope.
    ///
    /// History-owned transports reach this entry point through
    /// [`crate::history::TrackedAttempt::accept_bytes`].
    /// [`Envelope::decode_exact`] intentionally applies type-specific payload
    /// bounds before an envelope exists; [`RawEnvelope::decode_exact`] only
    /// applies the global bound, allowing a bounded malformed payload to be
    /// signature-verified and attributed to its authenticated sender first.
    /// Globally oversized payloads and bytes that verify under neither
    /// identity remain unattributed. A bounded invalid role byte is attributed
    /// by trying both fixed identity keys before semantic rejection.
    ///
    /// # Errors
    ///
    /// Returns an unattributed authentication/structural error when the raw
    /// bytes cannot be bounded or authenticated, or a signer-attributed,
    /// terminal semantic fault after a valid signature covers malformed typed
    /// fields. Successful input follows the same semantic transition rules as
    /// replay of a trusted, already-decoded envelope.
    pub(crate) fn accept_bytes<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        bytes: &[u8],
    ) -> Result<AttemptProgress, AttemptDriverError> {
        if self.terminal {
            return Err(AttemptDriverError::Terminal);
        }
        let raw = RawEnvelope::decode_exact(bytes).map_err(|error| {
            AttemptDriverError::Envelope(EnvelopeAcceptanceError::Authentication(AuthError::Codec(
                error,
            )))
        })?;
        let sender_role = verify_raw_envelope(secp, &raw, &self.identities).map_err(|error| {
            AttemptDriverError::Envelope(EnvelopeAcceptanceError::Authentication(error))
        })?;
        if let Err(source) = self.schedule.validate_context_fields(
            raw.protocol_version,
            raw.game_id,
            raw.attempt,
            raw.sequence,
            raw.previous_message_hash,
        ) {
            return Err(AttemptDriverError::Envelope(authenticated_schedule_error(
                sender_role,
                source,
            )));
        }
        if raw.sender_role != sender_role.to_u8() {
            self.terminal = true;
            return Err(signed_fault(sender_role, ProtocolError::UnexpectedMessage));
        }
        let payload_type = PayloadType::try_from(raw.payload_type).map_err(|_| {
            self.terminal = true;
            signed_fault(sender_role, ProtocolError::UnexpectedMessage)
        })?;
        self.accept(
            secp,
            &Envelope {
                unsigned: crate::messages::UnsignedEnvelope {
                    protocol_version: raw.protocol_version,
                    game_id: raw.game_id,
                    attempt: raw.attempt,
                    round: raw.round,
                    sender_role,
                    sequence: raw.sequence,
                    previous_message_hash: raw.previous_message_hash,
                    payload_type,
                    payload: raw.payload,
                },
                signature: raw.signature,
            },
        )
    }

    /// Returns the validated public key setup once both key openings pass.
    #[must_use]
    pub const fn key_setup(&self) -> Option<&JointKeyPublic> {
        self.keys.as_ref()
    }

    /// Returns the shared proof frame once the joint key has been validated.
    #[must_use]
    pub const fn common_frame(&self) -> Option<&ProofCommonFrame> {
        self.common.as_ref()
    }

    /// Returns the locally derived zero-test statements after both bundles
    /// have passed verification.
    #[must_use]
    pub fn derived_zero_tests(&self) -> Option<&DerivedZeroTests> {
        self.derived.as_deref()
    }

    /// Returns the verified first scale round once sequence 10 is consumed.
    #[must_use]
    pub fn first_scale_round(&self) -> Option<&ScaleRound> {
        self.scale_first.as_deref()
    }

    /// Returns the verified second scale round once sequence 11 is consumed.
    #[must_use]
    pub fn second_scale_round(&self) -> Option<&ScaleRound> {
        self.scale_second.as_deref()
    }

    /// Returns an authenticated proof-phase snapshot once that height has been
    /// reached.
    #[must_use]
    pub fn phase_context(&self, phase: ProofPhase) -> Option<AttemptContext> {
        let root = match phase {
            ProofPhase::KeyProof => self.root_t4,
            ProofPhase::PlayerBundle => self.root_t6,
            ProofPhase::ScaleFirst => self.root_t10,
            ProofPhase::ScaleSecond => self.root_t11,
            ProofPhase::PartialDecrypt => self.root_t12,
        }?;
        Some(AttemptContext::with_prior_transcript(
            self.schedule.game_id(),
            self.schedule.attempt(),
            root,
        ))
    }

    /// Authenticates and semantically verifies one exact next envelope.
    ///
    /// All fallible semantic work happens before the transcript or retained
    /// cryptographic state changes.  Thus every error leaves
    /// `transcript_root()` and `next_sequence()` unchanged.  A validly signed
    /// schedule or semantic fault nevertheless poisons the attempt so a
    /// corrected retry at the same sequence cannot become an oracle.  Invalid
    /// unauthenticated traffic does not poison it.
    ///
    /// # Errors
    ///
    /// Returns an unattributed authentication failure, a signer-attributed
    /// schedule/payload/proof failure, a neutral joint fault, or
    /// [`AttemptDriverError::Terminal`] after a prior terminal result.
    pub(crate) fn accept<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        envelope: &Envelope,
    ) -> Result<AttemptProgress, AttemptDriverError> {
        if self.terminal {
            return Err(AttemptDriverError::Terminal);
        }

        verify_envelope(secp, envelope, &self.identities).map_err(|error| {
            AttemptDriverError::Envelope(EnvelopeAcceptanceError::Authentication(error))
        })?;
        if let Err(source) = self.schedule.validate_header(envelope) {
            let error = authenticated_schedule_error(envelope.unsigned.sender_role, source);
            if error.blamed_role().is_some() {
                self.terminal = true;
            }
            return Err(AttemptDriverError::Envelope(error));
        }

        let signer = envelope.unsigned.sender_role;
        let Ok(payload) = ProtocolPayload::decode_exact(
            envelope.unsigned.payload_type,
            &envelope.unsigned.payload,
        ) else {
            self.terminal = true;
            return Err(signed_fault(signer, ProtocolError::MalformedEncoding));
        };
        let transition = match self.validate_transition(signer, payload) {
            Ok(transition) => transition,
            Err(error) => {
                self.terminal = true;
                return Err(error);
            }
        };

        // Revalidation and canonical full-envelope encoding are intentionally
        // the last fallible operations before mutation.
        let root = match self.schedule.advance_authenticated(envelope) {
            Ok(root) => root,
            Err(source) => {
                let error = authenticated_schedule_error(signer, source);
                if error.blamed_role().is_some() {
                    self.terminal = true;
                }
                return Err(AttemptDriverError::Envelope(error));
            }
        };
        self.archive.push(envelope.clone());
        Ok(self.apply_transition(transition, root))
    }

    /// Attributes an outer timeout to the exact sender currently scheduled.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptDriverError::Terminal`] when this attempt already
    /// reached a terminal result or a prior timeout was recorded.
    pub(crate) fn record_timeout(&mut self) -> Result<AttemptOutcome, AttemptDriverError> {
        if self.terminal {
            return Err(AttemptDriverError::Terminal);
        }
        let outcome = self
            .schedule
            .timeout_outcome()
            .map_err(|_| AttemptDriverError::Terminal)?;
        self.terminal = true;
        Ok(outcome)
    }

    #[allow(clippy::too_many_lines)]
    fn validate_transition(
        &self,
        signer: Role,
        payload: ProtocolPayload,
    ) -> Result<Transition, AttemptDriverError> {
        let sequence = self.schedule.next_sequence();
        match (sequence, payload) {
            (0, ProtocolPayload::KeyCommit(body)) => Ok(Transition::KeyCommit {
                role: Role::Alice,
                commitment: body.commitment,
            }),
            (1, ProtocolPayload::KeyCommit(body)) => Ok(Transition::KeyCommit {
                role: Role::Bob,
                commitment: body.commitment,
            }),
            (2, ProtocolPayload::KeyOpen(body)) => {
                self.verify_key_open(Role::Alice, &body.nonce, &body.public_key)?;
                Ok(Transition::KeyOpen {
                    role: Role::Alice,
                    public_key: body.public_key,
                    setup: None,
                })
            }
            (3, ProtocolPayload::KeyOpen(body)) => {
                self.verify_key_open(Role::Bob, &body.nonce, &body.public_key)?;
                let public_a = self.public_a.as_ref().ok_or_else(internal_fault)?;
                let setup = JointKeyPublic::new(public_a.clone(), body.public_key.clone())
                    .map_err(|_| unattributed_fault(ProtocolError::UnexpectedIdentity))?;
                let (alice_identity, bob_identity) = self.identities.serialized();
                let common = ProofCommonFrame::new(
                    alice_identity,
                    bob_identity,
                    setup.joint(),
                    self.circuit_id,
                )
                .map_err(|_| internal_fault())?;
                Ok(Transition::KeyOpen {
                    role: Role::Bob,
                    public_key: body.public_key,
                    setup: Some((setup, common)),
                })
            }
            (4, ProtocolPayload::KeyProof(proof)) => {
                self.verify_key_proof(Role::Alice, &proof)?;
                Ok(Transition::KeyProof(Role::Alice))
            }
            (5, ProtocolPayload::KeyProof(proof)) => {
                self.verify_key_proof(Role::Bob, &proof)?;
                Ok(Transition::KeyProof(Role::Bob))
            }
            (6, ProtocolPayload::BundleCommit(body)) => Ok(Transition::BundleCommit {
                role: Role::Alice,
                commitment: body.commitment,
            }),
            (7, ProtocolPayload::BundleCommit(body)) => Ok(Transition::BundleCommit {
                role: Role::Bob,
                commitment: body.commitment,
            }),
            (8, ProtocolPayload::BundleOpen(body)) => {
                let body = *body;
                self.verify_bundle_open(Role::Alice, &body.nonce, &body.bundle)?;
                self.verify_single_bundle(Role::Alice, &body.bundle)?;
                Ok(Transition::BundleOpen {
                    role: Role::Alice,
                    bundle: Box::new(body.bundle),
                    derived: None,
                })
            }
            (9, ProtocolPayload::BundleOpen(body)) => {
                let body = *body;
                self.verify_bundle_open(Role::Bob, &body.nonce, &body.bundle)?;
                let bundle_a = self.bundle_a.as_ref().ok_or_else(internal_fault)?;
                // Global hash distinctness has normative precedence over
                // point and proof verification once both openings are known.
                // In particular, a cross-party duplicate is unattributed even
                // if Bob's same signed bundle also contains a bad proof.
                self.verify_bundle_pair(bundle_a, &body.bundle)?;
                self.verify_single_bundle(Role::Bob, &body.bundle)?;
                let derived = match derive_bundles(bundle_a, &body.bundle) {
                    Ok(value) => Some(Box::new(value)),
                    Err(UniquenessError::DegenerateIdentity { .. }) => None,
                    Err(error) => return Err(map_derived_error(&error)),
                };
                Ok(Transition::BundleOpen {
                    role: Role::Bob,
                    bundle: Box::new(body.bundle),
                    derived,
                })
            }
            (10, ProtocolPayload::BlindFirst(round)) => {
                self.verify_scale(ProofPhase::ScaleFirst, signer, true, &round)?;
                Ok(Transition::ScaleFirst(round))
            }
            (11, ProtocolPayload::BlindSecond(round)) => {
                self.verify_scale(ProofPhase::ScaleSecond, signer, false, &round)?;
                Ok(Transition::ScaleSecond(round))
            }
            (12, ProtocolPayload::DecryptCommit(body)) => Ok(Transition::DecryptCommit {
                role: Role::Alice,
                commitment: body.commitment,
            }),
            (13, ProtocolPayload::DecryptCommit(body)) => Ok(Transition::DecryptCommit {
                role: Role::Bob,
                commitment: body.commitment,
            }),
            (14, ProtocolPayload::DecryptOpen(body)) => {
                let body = *body;
                self.verify_decrypt_open(Role::Alice, &body)?;
                self.verify_partial(Role::Alice, &body.batch)?;
                Ok(Transition::DecryptAlice(Box::new(body.batch)))
            }
            (15, ProtocolPayload::DecryptOpen(body)) => {
                let body = *body;
                self.verify_decrypt_open(Role::Bob, &body)?;
                let result = self.verify_complete_uniqueness(&body.batch)?;
                let bundle_a = self.bundle_a.as_ref().ok_or_else(internal_fault)?;
                let bundle_b = self.bundle_b.as_ref().ok_or_else(internal_fault)?;
                Ok(Transition::DecryptBob {
                    collision_bitmap: result.collision_bitmap,
                    is_unique: result.is_unique,
                    hashes_a: core::array::from_fn(|index| bundle_a.slots[index].hash),
                    hashes_b: core::array::from_fn(|index| bundle_b.slots[index].hash),
                })
            }
            _ => Err(signed_fault(signer, ProtocolError::UnexpectedMessage)),
        }
    }

    fn verify_key_open(
        &self,
        role: Role,
        nonce: &[u8; 32],
        public_key: &PublicKeyShare,
    ) -> Result<(), AttemptDriverError> {
        let expected = self.key_commitment(role).ok_or_else(internal_fault)?;
        verify_key_commitment(
            expected,
            &self.schedule.game_id(),
            self.schedule.attempt(),
            role,
            nonce,
            &public_key.to_bytes(),
        )
        .map_err(|error| map_commitment_error(role, error))
    }

    fn verify_key_proof(&self, role: Role, proof: &KeyProof) -> Result<(), AttemptDriverError> {
        let keys = self.keys.as_ref().ok_or_else(internal_fault)?;
        let common = self.common.as_ref().ok_or_else(internal_fault)?;
        let context = self
            .phase_context(ProofPhase::KeyProof)
            .ok_or_else(internal_fault)?;
        let generators = ProtocolGenerators::derive().map_err(|_| internal_fault())?;
        let mut transcript = proof_transcript(ProofDomain::KeyPop, &context, role, common)
            .map_err(|_| signed_fault(role, ProtocolError::InvalidKeyProof))?;
        proof
            .verify(
                &mut transcript,
                &generators,
                keys.public_a(),
                keys.public_b(),
                role == Role::Alice,
            )
            .map_err(|_| signed_fault(role, ProtocolError::InvalidKeyProof))
    }

    fn verify_bundle_open(
        &self,
        role: Role,
        nonce: &[u8; 32],
        bundle: &PlayerBundle,
    ) -> Result<(), AttemptDriverError> {
        let expected = self.bundle_commitment(role).ok_or_else(internal_fault)?;
        verify_bundle_commitment(
            expected,
            &self.schedule.game_id(),
            self.schedule.attempt(),
            role,
            nonce,
            bundle,
        )
        .map_err(|error| map_commitment_error(role, error))
    }

    fn verify_bundle_pair(
        &self,
        bundle_a: &PlayerBundle,
        bundle_b: &PlayerBundle,
    ) -> Result<(), AttemptDriverError> {
        if bundle_a.role != Role::Alice {
            return Err(signed_fault(Role::Alice, ProtocolError::UnexpectedMessage));
        }
        if bundle_b.role != Role::Bob {
            return Err(signed_fault(Role::Bob, ProtocolError::UnexpectedMessage));
        }
        if bundle_a.circuit_id != self.circuit_id {
            return Err(signed_fault(
                Role::Alice,
                ProtocolError::InvalidHashLengthProof,
            ));
        }
        if bundle_b.circuit_id != self.circuit_id {
            return Err(signed_fault(
                Role::Bob,
                ProtocolError::InvalidHashLengthProof,
            ));
        }
        if bundle_a.hash_length_proof.len() != HASH_LENGTH_PROOF_SIZE
            || bundle_a.encryption_link_proof.len() != ENCRYPTION_LINK_PROOF_SIZE
        {
            return Err(signed_fault(Role::Alice, ProtocolError::MalformedEncoding));
        }
        if bundle_b.hash_length_proof.len() != HASH_LENGTH_PROOF_SIZE
            || bundle_b.encryption_link_proof.len() != ENCRYPTION_LINK_PROOF_SIZE
        {
            return Err(signed_fault(Role::Bob, ProtocolError::MalformedEncoding));
        }

        validate_global_hash_uniqueness(&bundle_a.slots, &bundle_b.slots)
            .map_err(map_duplicate_hash)?;
        Ok(())
    }

    fn verify_single_bundle(
        &self,
        role: Role,
        bundle: &PlayerBundle,
    ) -> Result<(), AttemptDriverError> {
        if bundle.role != role {
            return Err(signed_fault(role, ProtocolError::UnexpectedMessage));
        }
        if bundle.circuit_id != self.circuit_id {
            return Err(signed_fault(role, ProtocolError::InvalidHashLengthProof));
        }
        if bundle.hash_length_proof.len() != HASH_LENGTH_PROOF_SIZE
            || bundle.encryption_link_proof.len() != ENCRYPTION_LINK_PROOF_SIZE
        {
            return Err(signed_fault(role, ProtocolError::MalformedEncoding));
        }
        for first in 0..N_SLOTS {
            for second in (first + 1)..N_SLOTS {
                if bundle.slots[first].hash == bundle.slots[second].hash {
                    return Err(signed_fault(role, ProtocolError::DuplicateHash));
                }
            }
        }
        validate_original_contribution_points(&bundle.slots)
            .map_err(|error| map_contribution_error(Some(role), error))?;

        if let Some(parameters) = self.parameters {
            let context = self
                .phase_context(ProofPhase::PlayerBundle)
                .ok_or_else(internal_fault)?;
            let common = self.common.as_ref().ok_or_else(internal_fault)?;
            let keys = self.keys.as_ref().ok_or_else(internal_fault)?;
            verify_player_bundle(parameters, &context, common, role, keys.joint(), bundle)
                .map_err(|error| map_bundle_error(role, &error))?;
        }
        Ok(())
    }

    fn verify_scale(
        &self,
        phase: ProofPhase,
        role: Role,
        first: bool,
        round: &ScaleRound,
    ) -> Result<(), AttemptDriverError> {
        let context = self.phase_context(phase).ok_or_else(internal_fault)?;
        let common = self.common.as_ref().ok_or_else(internal_fault)?;
        let generators = ProtocolGenerators::derive().map_err(|_| internal_fault())?;
        let (domain, inputs) = if first {
            (
                ProofDomain::ScaleFirst,
                &self
                    .derived
                    .as_ref()
                    .ok_or_else(internal_fault)?
                    .differences,
            )
        } else {
            (
                ProofDomain::ScaleSecond,
                &self
                    .scale_first
                    .as_ref()
                    .ok_or_else(internal_fault)?
                    .outputs,
            )
        };
        let mut transcript = proof_transcript(domain, &context, role, common)
            .map_err(|_| signed_fault(role, ProtocolError::InvalidScaleProof))?;
        verify_scale_round(&mut transcript, &generators, inputs, round).map_err(|error| {
            map_uniqueness_sender_error(role, &error, ProtocolError::InvalidScaleProof)
        })
    }

    fn verify_decrypt_open(
        &self,
        role: Role,
        body: &DecryptOpenPayload,
    ) -> Result<(), AttemptDriverError> {
        let expected = self.decrypt_commitment(role).ok_or_else(internal_fault)?;
        let encoded = body
            .batch
            .encode_to_vec()
            .map_err(|_| signed_fault(role, ProtocolError::MalformedEncoding))?;
        verify_decryption_commitment(
            expected,
            &self.schedule.game_id(),
            self.schedule.attempt(),
            role,
            &body.nonce,
            &encoded,
        )
        .map_err(|error| map_commitment_error(role, error))
    }

    fn verify_partial(
        &self,
        role: Role,
        batch: &PartialDecryptionBatch,
    ) -> Result<(), AttemptDriverError> {
        let context = self
            .phase_context(ProofPhase::PartialDecrypt)
            .ok_or_else(internal_fault)?;
        let common = self.common.as_ref().ok_or_else(internal_fault)?;
        let keys = self.keys.as_ref().ok_or_else(internal_fault)?;
        let final_ciphertexts = &self
            .scale_second
            .as_ref()
            .ok_or_else(internal_fault)?
            .outputs;
        let generators = ProtocolGenerators::derive().map_err(|_| internal_fault())?;
        let public_key = match role {
            Role::Alice => keys.public_a(),
            Role::Bob => keys.public_b(),
        };
        let mut transcript =
            proof_transcript(ProofDomain::partial_decrypt(role), &context, role, common)
                .map_err(|_| signed_fault(role, ProtocolError::InvalidPartialDecryptionProof))?;
        verify_partial_decryption_batch(
            &mut transcript,
            &generators,
            public_key,
            final_ciphertexts,
            batch,
        )
        .map_err(|error| {
            map_uniqueness_sender_error(role, &error, ProtocolError::InvalidPartialDecryptionProof)
        })
    }

    fn verify_complete_uniqueness(
        &self,
        partial_b: &PartialDecryptionBatch,
    ) -> Result<bp52_uniqueness::UniquenessResult, AttemptDriverError> {
        let (alice_identity, bob_identity) = self.identities.serialized();
        let root_t10 = self.root_t10.ok_or_else(internal_fault)?;
        let certificate = UniquenessTranscript {
            alice_identity,
            bob_identity,
            circuit_id: self.circuit_id,
            scale_first_root: root_t10,
            scale_first: Box::new(
                self.scale_first
                    .as_ref()
                    .ok_or_else(internal_fault)?
                    .as_ref()
                    .clone(),
            ),
            scale_second_root: self.root_t11.ok_or_else(internal_fault)?,
            scale_second: Box::new(
                self.scale_second
                    .as_ref()
                    .ok_or_else(internal_fault)?
                    .as_ref()
                    .clone(),
            ),
            partial_decrypt_root: self.root_t12.ok_or_else(internal_fault)?,
            partial_a: Box::new(
                self.partial_a
                    .as_ref()
                    .ok_or_else(internal_fault)?
                    .as_ref()
                    .clone(),
            ),
            partial_b: Box::new(partial_b.clone()),
        };
        let context = AttemptContext::with_prior_transcript(
            self.schedule.game_id(),
            self.schedule.attempt(),
            root_t10,
        );
        verify_uniqueness_transcript_detailed(
            &context,
            self.keys.as_ref().ok_or_else(internal_fault)?,
            self.bundle_a.as_ref().ok_or_else(internal_fault)?,
            self.bundle_b.as_ref().ok_or_else(internal_fault)?,
            &certificate,
        )
        .map_err(|error| map_final_uniqueness_error(&error))
    }

    fn apply_transition(
        &mut self,
        transition: Transition,
        root: TranscriptHash,
    ) -> AttemptProgress {
        match transition {
            Transition::KeyCommit { role, commitment } => {
                *role_slot_mut(role, &mut self.key_commit_a, &mut self.key_commit_b) =
                    Some(commitment);
            }
            Transition::KeyOpen {
                role,
                public_key,
                setup,
            } => {
                *role_slot_mut(role, &mut self.public_a, &mut self.public_b) = Some(public_key);
                if let Some((keys, common)) = setup {
                    self.keys = Some(keys);
                    self.common = Some(common);
                    self.root_t4 = Some(root);
                }
            }
            Transition::KeyProof(role) => match role {
                Role::Alice => self.key_proof_a = true,
                Role::Bob => {
                    self.key_proof_b = true;
                    self.root_t6 = Some(root);
                }
            },
            Transition::BundleCommit { role, commitment } => {
                *role_slot_mut(role, &mut self.bundle_commit_a, &mut self.bundle_commit_b) =
                    Some(commitment);
            }
            Transition::BundleOpen {
                role,
                bundle,
                derived,
            } => {
                *role_slot_mut(role, &mut self.bundle_a, &mut self.bundle_b) = Some(*bundle);
                if role == Role::Bob {
                    self.root_t10 = Some(root);
                    if let Some(derived) = derived {
                        self.derived = Some(derived);
                    } else {
                        self.terminal = true;
                        return AttemptProgress::DegenerateRetry(Box::new(
                            VerifiedDegenerateRetry {
                                archive: self.terminal_archive(root),
                            },
                        ));
                    }
                }
            }
            Transition::ScaleFirst(round) => {
                self.scale_first = Some(round);
                self.root_t11 = Some(root);
            }
            Transition::ScaleSecond(round) => {
                self.scale_second = Some(round);
                self.root_t12 = Some(root);
            }
            Transition::DecryptCommit { role, commitment } => {
                *role_slot_mut(role, &mut self.decrypt_commit_a, &mut self.decrypt_commit_b) =
                    Some(commitment);
            }
            Transition::DecryptAlice(batch) => self.partial_a = Some(batch),
            Transition::DecryptBob {
                collision_bitmap,
                is_unique,
                hashes_a,
                hashes_b,
            } => {
                self.terminal = true;
                if !is_unique {
                    return AttemptProgress::CollisionRetry(Box::new(VerifiedCollisionRetry {
                        collision_bitmap,
                        archive: self.terminal_archive(root),
                    }));
                }
                return AttemptProgress::ReadyToSign(Box::new(VerifiedReadyToSign {
                    body: AcceptedDealBody {
                        protocol_version: PROTOCOL_VERSION,
                        game_id: self.schedule.game_id(),
                        attempt: self.schedule.attempt(),
                        hashes_a,
                        hashes_b,
                        verification_transcript_root: root,
                    },
                    identities: self.identities,
                    archive: self.terminal_archive(root),
                }));
            }
        }
        AttemptProgress::Continue {
            transcript_root: root,
            next_sequence: self.schedule.next_sequence(),
        }
    }

    const fn key_commitment(&self, role: Role) -> Option<&[u8; 32]> {
        match role {
            Role::Alice => self.key_commit_a.as_ref(),
            Role::Bob => self.key_commit_b.as_ref(),
        }
    }

    const fn bundle_commitment(&self, role: Role) -> Option<&[u8; 32]> {
        match role {
            Role::Alice => self.bundle_commit_a.as_ref(),
            Role::Bob => self.bundle_commit_b.as_ref(),
        }
    }

    const fn decrypt_commitment(&self, role: Role) -> Option<&[u8; 32]> {
        match role {
            Role::Alice => self.decrypt_commit_a.as_ref(),
            Role::Bob => self.decrypt_commit_b.as_ref(),
        }
    }

    fn terminal_archive(&self, transcript_root: TranscriptHash) -> VerifiedEnvelopeArchive {
        VerifiedEnvelopeArchive {
            game_id: self.schedule.game_id(),
            attempt: self.schedule.attempt(),
            transcript_root,
            envelopes: self.archive.clone(),
        }
    }
}

enum Transition {
    KeyCommit {
        role: Role,
        commitment: [u8; 32],
    },
    KeyOpen {
        role: Role,
        public_key: PublicKeyShare,
        setup: Option<(JointKeyPublic, ProofCommonFrame)>,
    },
    KeyProof(Role),
    BundleCommit {
        role: Role,
        commitment: [u8; 32],
    },
    BundleOpen {
        role: Role,
        bundle: Box<PlayerBundle>,
        /// `None` is the one neutral derived-identity retry.
        derived: Option<Box<DerivedZeroTests>>,
    },
    ScaleFirst(Box<ScaleRound>),
    ScaleSecond(Box<ScaleRound>),
    DecryptCommit {
        role: Role,
        commitment: [u8; 32],
    },
    DecryptAlice(Box<PartialDecryptionBatch>),
    DecryptBob {
        collision_bitmap: [bool; bp52_uniqueness::ZERO_TEST_COUNT],
        is_unique: bool,
        hashes_a: [[u8; 32]; N_SLOTS],
        hashes_b: [[u8; 32]; N_SLOTS],
    },
}

fn derive_bundles(
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
) -> Result<DerivedZeroTests, UniquenessError> {
    let generators = ProtocolGenerators::derive()?;
    let contributions_a = decode_contributions(bundle_a)?;
    let contributions_b = decode_contributions(bundle_b)?;
    derive_sums_and_zero_tests(&contributions_a, &contributions_b, &generators)
}

fn decode_contributions(
    bundle: &PlayerBundle,
) -> Result<[ElGamalCiphertext; N_SLOTS], UniquenessError> {
    let mut decoded = Vec::with_capacity(N_SLOTS);
    for slot in &bundle.slots {
        decoded.push(CiphertextBytes::from(slot.ciphertext).decompress_contribution()?);
    }
    decoded
        .try_into()
        .map_err(|_| UniquenessError::InternalLength)
}

fn role_slot_mut<'a, T>(
    role: Role,
    alice: &'a mut Option<T>,
    bob: &'a mut Option<T>,
) -> &'a mut Option<T> {
    match role {
        Role::Alice => alice,
        Role::Bob => bob,
    }
}

fn signed_fault(signer: Role, error: ProtocolError) -> AttemptDriverError {
    AttemptDriverError::SignedSemanticFault { signer, error }
}

fn unattributed_fault(error: ProtocolError) -> AttemptDriverError {
    AttemptDriverError::UnattributedSemanticFault { error }
}

fn internal_fault() -> AttemptDriverError {
    unattributed_fault(ProtocolError::UnexpectedMessage)
}

fn map_commitment_error(role: Role, error: CommitmentError) -> AttemptDriverError {
    match error {
        CommitmentError::OpeningMismatch => signed_fault(role, ProtocolError::CommitmentMismatch),
        CommitmentError::RoleMismatch => signed_fault(role, ProtocolError::UnexpectedMessage),
        CommitmentError::Codec(_) => signed_fault(role, ProtocolError::MalformedEncoding),
    }
}

fn map_duplicate_hash(error: ContributionError) -> AttemptDriverError {
    match error {
        ContributionError::DuplicateHash { first, second }
            if first < N_SLOTS && second < N_SLOTS =>
        {
            signed_fault(Role::Alice, ProtocolError::DuplicateHash)
        }
        ContributionError::DuplicateHash { first, second }
            if first >= N_SLOTS && second >= N_SLOTS =>
        {
            signed_fault(Role::Bob, ProtocolError::DuplicateHash)
        }
        ContributionError::DuplicateHash { .. } => unattributed_fault(ProtocolError::DuplicateHash),
        other => map_contribution_error(None, other),
    }
}

fn map_contribution_error(role: Option<Role>, error: ContributionError) -> AttemptDriverError {
    let protocol_error = match error {
        ContributionError::DuplicateHash { .. } => ProtocolError::DuplicateHash,
        ContributionError::InvalidValueCommitment { source, .. }
        | ContributionError::InvalidCiphertext { source, .. }
        | ContributionError::Group(source) => map_group_error(source),
        ContributionError::PreimageRandomnessUnavailable
        | ContributionError::BlindingSamplingFailed => ProtocolError::RngFailure,
    };
    role.map_or_else(
        || unattributed_fault(protocol_error),
        |signer| signed_fault(signer, protocol_error),
    )
}

fn map_bundle_error(role: Role, error: &BundleError) -> AttemptDriverError {
    let protocol_error = match error {
        BundleError::EncryptionLinkProof(_) => ProtocolError::InvalidEncryptionLinkProof,
        BundleError::Contribution(error) => return map_contribution_error(Some(role), *error),
        BundleError::Group(error) => map_group_error(*error),
        BundleError::Codec(_) => ProtocolError::MalformedEncoding,
        BundleError::RoleMismatch { .. } => ProtocolError::UnexpectedMessage,
        BundleError::BundleCircuitMismatch | BundleError::ContextCircuitMismatch => {
            ProtocolError::InvalidHashLengthProof
        }
        BundleError::HashLengthProofSize { .. } | BundleError::EncryptionLinkProofSize { .. } => {
            ProtocolError::MalformedEncoding
        }
        BundleError::HashLengthProof(_)
        | BundleError::Transcript(_)
        | BundleError::ContextJointKeyMismatch
        | BundleError::SecretOpeningMismatch { .. }
        | BundleError::InternalShape
        | BundleError::HashWitness(_) => ProtocolError::InvalidHashLengthProof,
    };
    signed_fault(role, protocol_error)
}

fn map_group_error(error: GroupError) -> ProtocolError {
    match error {
        GroupError::InvalidPoint => ProtocolError::NonCanonicalPoint,
        GroupError::NonCanonicalScalar => ProtocolError::NonCanonicalScalar,
        GroupError::UnexpectedIdentity
        | GroupError::JointKeyIdentity
        | GroupError::DuplicateKeyShare
        | GroupError::InvalidGenerator => ProtocolError::UnexpectedIdentity,
        GroupError::ZeroScalar => ProtocolError::ZeroScaleFactor,
        GroupError::RngFailure => ProtocolError::RngFailure,
    }
}

fn map_uniqueness_sender_error(
    role: Role,
    error: &UniquenessError,
    proof_error: ProtocolError,
) -> AttemptDriverError {
    match error {
        UniquenessError::DegenerateIdentity { .. } => {
            unattributed_fault(ProtocolError::UnexpectedIdentity)
        }
        UniquenessError::Group(GroupError::ZeroScalar) => {
            signed_fault(role, ProtocolError::ZeroScaleFactor)
        }
        UniquenessError::Group(error) => signed_fault(role, map_group_error(*error)),
        UniquenessError::Sigma(_) | UniquenessError::InternalLength => {
            signed_fault(role, proof_error)
        }
    }
}

fn map_derived_error(error: &UniquenessError) -> AttemptDriverError {
    match error {
        UniquenessError::DegenerateIdentity { .. } => {
            unattributed_fault(ProtocolError::UnexpectedIdentity)
        }
        UniquenessError::Group(error) => unattributed_fault(map_group_error(*error)),
        UniquenessError::Sigma(_) | UniquenessError::InternalLength => internal_fault(),
    }
}

fn map_final_uniqueness_error(error: &UniquenessTranscriptError) -> AttemptDriverError {
    match error {
        UniquenessTranscriptError::Uniqueness(UniquenessError::DegenerateIdentity { .. }) => {
            unattributed_fault(ProtocolError::UnexpectedIdentity)
        }
        UniquenessTranscriptError::Uniqueness(UniquenessError::Sigma(_)) => {
            signed_fault(Role::Bob, ProtocolError::InvalidPartialDecryptionProof)
        }
        UniquenessTranscriptError::Uniqueness(UniquenessError::Group(error))
        | UniquenessTranscriptError::Group(error) => {
            signed_fault(Role::Bob, map_group_error(*error))
        }
        UniquenessTranscriptError::Contribution(error) => map_contribution_error(None, *error),
        UniquenessTranscriptError::FirstPhaseRootMismatch
        | UniquenessTranscriptError::BundleRoleMismatch
        | UniquenessTranscriptError::CircuitMismatch
        | UniquenessTranscriptError::InternalShape
        | UniquenessTranscriptError::Transcript(_)
        | UniquenessTranscriptError::Uniqueness(UniquenessError::InternalLength) => {
            internal_fault()
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::drop_non_drop,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::similar_names
)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bp52_codec::Encode;
    use bp52_group::{
        ElGamalCiphertext, NonZeroScalar, ProtocolGenerators, SecretKeyShare, commit,
    };
    use bp52_sigma::schnorr::KeyProof;
    use bp52_uniqueness::{generate_partial_decryption_batch, generate_scale_round};
    use curve25519_dalek::Scalar;
    use rand_core::OsRng;

    use super::{AttemptDriverError, AttemptProgress, AttemptVerifier, VerifiedEnvelopeArchive};
    use crate::{
        N_SLOTS, PROTOCOL_VERSION, Role,
        auth::{CanonicalIdentities, derive_roles, sign_envelope, sign_raw_wire_envelope_for_test},
        commitments::{bundle_commitment, decryption_commitment, key_commitment},
        messages::{
            Ciphertext, ENCRYPTION_LINK_PROOF_SIZE, Envelope, HASH_LENGTH_PROOF_SIZE, PlayerBundle,
            SlotPublic, UnsignedEnvelope,
        },
        outcome::{AttemptOutcome, ProtocolError},
        payloads::{
            BundleOpenPayload, CommitmentPayload, DecryptOpenPayload, KeyOpenPayload,
            ProtocolPayload,
        },
        transcript::{ProofDomain, ProofPhase, proof_transcript},
        uniqueness::JointKeyPublic,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct IdentityKeys {
        identities: CanonicalIdentities,
        alice: Keypair,
        bob: Keypair,
    }

    impl IdentityKeys {
        fn new() -> TestResult<Self> {
            let secp = Secp256k1::new();
            let first = keypair(&secp, 1)?;
            let second = keypair(&secp, 2)?;
            let identities =
                derive_roles(first.x_only_public_key().0, second.x_only_public_key().0)?;
            let (alice, bob) =
                if identities.role_for_key(&first.x_only_public_key().0)? == Role::Alice {
                    (first, second)
                } else {
                    (second, first)
                };
            Ok(Self {
                identities,
                alice,
                bob,
            })
        }

        const fn for_role(&self, role: Role) -> &Keypair {
            match role {
                Role::Alice => &self.alice,
                Role::Bob => &self.bob,
            }
        }
    }

    struct ThresholdKeys {
        secret_a: SecretKeyShare,
        secret_b: SecretKeyShare,
        public: JointKeyPublic,
    }

    impl ThresholdKeys {
        fn new(generators: &ProtocolGenerators) -> TestResult<Self> {
            let secret_a = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(13_u64))?);
            let secret_b = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(29_u64))?);
            let public = JointKeyPublic::new(
                secret_a.public_key(generators),
                secret_b.public_key(generators),
            )?;
            Ok(Self {
                secret_a,
                secret_b,
                public,
            })
        }
    }

    fn keypair(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        marker: u8,
    ) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let mut secret = [0_u8; 32];
        secret[31] = marker;
        Keypair::from_seckey_slice(secp, &secret)
    }

    fn bundle(
        role: Role,
        values: [u8; N_SLOTS],
        global_offset: u8,
        circuit_id: [u8; 32],
        keys: &JointKeyPublic,
        generators: &ProtocolGenerators,
    ) -> TestResult<PlayerBundle> {
        let mut slots = Vec::with_capacity(N_SLOTS);
        for (index, value) in values.into_iter().enumerate() {
            let global_index = usize::from(global_offset) + index;
            let scalar = Scalar::from(u64::from(value));
            let blinding = Scalar::from(
                1_000_u64
                    + u64::try_from(global_index)
                        .map_err(|_| std::io::Error::other("test index overflow"))?,
            );
            let randomness = NonZeroScalar::new(Scalar::from(
                2_000_u64
                    + u64::try_from(global_index)
                        .map_err(|_| std::io::Error::other("test index overflow"))?,
            ))?;
            let ciphertext =
                ElGamalCiphertext::encrypt(scalar, &randomness, keys.joint(), generators);
            let marker = u8::try_from(global_index + 1)
                .map_err(|_| std::io::Error::other("test marker overflow"))?;
            slots.push(SlotPublic {
                hash: [marker; 32],
                value_commitment: commit(scalar, blinding, generators).compress().to_bytes(),
                ciphertext: Ciphertext::from(ciphertext.to_bytes()),
            });
        }
        Ok(PlayerBundle {
            role,
            slots: slots
                .try_into()
                .map_err(|_| std::io::Error::other("test bundle shape"))?,
            circuit_id,
            hash_length_proof: vec![0x55_u8; HASH_LENGTH_PROOF_SIZE],
            encryption_link_proof: vec![0x66_u8; ENCRYPTION_LINK_PROOF_SIZE],
        })
    }

    fn signed_next(
        driver: &AttemptVerifier<'_>,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        identities: &IdentityKeys,
        payload: ProtocolPayload,
    ) -> TestResult<Envelope> {
        let expected = driver.schedule().expected()?;
        if payload.payload_type() != expected.payload_type {
            return Err(std::io::Error::other("test payload does not match schedule").into());
        }
        let unsigned = UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: driver.schedule().game_id(),
            attempt: driver.schedule().attempt(),
            round: expected.round,
            sender_role: expected.sender,
            sequence: expected.sequence,
            previous_message_hash: driver.schedule().transcript_root(),
            payload_type: payload.payload_type(),
            payload: payload.encode_body()?,
        };
        let auxiliary = [expected.sequence.to_le_bytes()[0]; 32];
        Ok(sign_envelope(
            secp,
            &unsigned,
            identities.for_role(expected.sender),
            &identities.identities,
            &auxiliary,
        )?)
    }

    fn send(
        driver: &mut AttemptVerifier<'_>,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        identities: &IdentityKeys,
        payload: ProtocolPayload,
    ) -> TestResult<AttemptProgress> {
        let envelope = signed_next(driver, secp, identities, payload)?;
        Ok(driver.accept(secp, &envelope)?)
    }

    fn verify_archive_chain(archive: &VerifiedEnvelopeArchive) -> TestResult {
        let mut root = crate::transcript::attempt_start(&archive.game_id(), archive.attempt());
        for (index, envelope) in archive.envelopes().iter().enumerate() {
            assert_eq!(
                envelope.unsigned.sequence,
                u32::try_from(index)
                    .map_err(|_| std::io::Error::other("archive index overflow"))?
            );
            assert_eq!(envelope.unsigned.previous_message_hash, root);
            root = crate::transcript::advance(&root, &envelope.encode_to_vec()?);
        }
        assert_eq!(archive.transcript_root(), root);
        Ok(())
    }

    fn key_setup_flights(
        driver: &mut AttemptVerifier<'_>,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        identities: &IdentityKeys,
        threshold: &ThresholdKeys,
        generators: &ProtocolGenerators,
    ) -> TestResult {
        let nonce_a = [0x11_u8; 32];
        let nonce_b = [0x12_u8; 32];
        let commit_a = key_commitment(
            &driver.schedule().game_id(),
            driver.schedule().attempt(),
            Role::Alice,
            &nonce_a,
            &threshold.public.public_a().to_bytes(),
        );
        let commit_b = key_commitment(
            &driver.schedule().game_id(),
            driver.schedule().attempt(),
            Role::Bob,
            &nonce_b,
            &threshold.public.public_b().to_bytes(),
        );
        drop(send(
            driver,
            secp,
            identities,
            ProtocolPayload::KeyCommit(CommitmentPayload {
                commitment: commit_a,
            }),
        )?);
        drop(send(
            driver,
            secp,
            identities,
            ProtocolPayload::KeyCommit(CommitmentPayload {
                commitment: commit_b,
            }),
        )?);
        drop(send(
            driver,
            secp,
            identities,
            ProtocolPayload::KeyOpen(KeyOpenPayload {
                nonce: nonce_a,
                public_key: threshold.public.public_a().clone(),
            }),
        )?);
        drop(send(
            driver,
            secp,
            identities,
            ProtocolPayload::KeyOpen(KeyOpenPayload {
                nonce: nonce_b,
                public_key: threshold.public.public_b().clone(),
            }),
        )?);

        let key_context = driver
            .phase_context(ProofPhase::KeyProof)
            .ok_or_else(|| std::io::Error::other("missing T4"))?;
        if key_context.prior_transcript != driver.schedule().transcript_root() {
            return Err(std::io::Error::other("key proof was not rooted at T4").into());
        }
        let common = driver
            .common_frame()
            .ok_or_else(|| std::io::Error::other("missing common frame"))?
            .clone();
        let proof_a = KeyProof::prove(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Alice, &common)?,
            generators,
            threshold.public.public_a(),
            threshold.public.public_b(),
            &threshold.secret_a,
            &mut OsRng,
        )?;
        let proof_b = KeyProof::prove(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Bob, &common)?,
            generators,
            threshold.public.public_a(),
            threshold.public.public_b(),
            &threshold.secret_b,
            &mut OsRng,
        )?;
        drop(send(
            driver,
            secp,
            identities,
            ProtocolPayload::KeyProof(proof_a),
        )?);
        drop(send(
            driver,
            secp,
            identities,
            ProtocolPayload::KeyProof(proof_b),
        )?);
        let bundle_context = driver
            .phase_context(ProofPhase::PlayerBundle)
            .ok_or_else(|| std::io::Error::other("missing T6"))?;
        if bundle_context.prior_transcript != driver.schedule().transcript_root() {
            return Err(std::io::Error::other("bundle proof was not rooted at T6").into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn run_complete(
        values_a: [u8; N_SLOTS],
        values_b: [u8; N_SLOTS],
    ) -> TestResult<(AttemptProgress, IdentityKeys)> {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let generators = ProtocolGenerators::derive()?;
        let threshold = ThresholdKeys::new(&generators)?;
        let game_id = [0x33_u8; 32];
        let circuit_id = [0x44_u8; 32];
        let mut driver = AttemptVerifier::without_hash_length_backend(
            game_id,
            7,
            identities.identities,
            circuit_id,
        );
        key_setup_flights(&mut driver, &secp, &identities, &threshold, &generators)?;

        let bundle_a = bundle(
            Role::Alice,
            values_a,
            0,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        let bundle_b = bundle(
            Role::Bob,
            values_b,
            u8::try_from(N_SLOTS).map_err(|_| std::io::Error::other("slot count overflow"))?,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        let nonce_a = [0x21_u8; 32];
        let nonce_b = [0x22_u8; 32];
        let commit_a = bundle_commitment(&game_id, 7, Role::Alice, &nonce_a, &bundle_a)?;
        let commit_b = bundle_commitment(&game_id, 7, Role::Bob, &nonce_b, &bundle_b)?;
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: commit_a,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: commit_b,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
                nonce: nonce_a,
                bundle: bundle_a,
            })),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
                nonce: nonce_b,
                bundle: bundle_b,
            })),
        )?);

        let first_context = driver
            .phase_context(ProofPhase::ScaleFirst)
            .ok_or_else(|| std::io::Error::other("missing T10"))?;
        if first_context.prior_transcript != driver.schedule().transcript_root() {
            return Err(std::io::Error::other("first scale was not rooted at T10").into());
        }
        let common = driver
            .common_frame()
            .ok_or_else(|| std::io::Error::other("missing common frame"))?
            .clone();
        let differences = driver
            .derived_zero_tests()
            .ok_or_else(|| std::io::Error::other("missing derived tests"))?
            .differences
            .clone();
        let first_role = driver.schedule().first_blinder();
        let scale_first = generate_scale_round(
            &mut proof_transcript(ProofDomain::ScaleFirst, &first_context, first_role, &common)?,
            &generators,
            &differences,
            &mut OsRng,
        )?;
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BlindFirst(Box::new(scale_first)),
        )?);

        let second_context = driver
            .phase_context(ProofPhase::ScaleSecond)
            .ok_or_else(|| std::io::Error::other("missing T11"))?;
        if second_context.prior_transcript != driver.schedule().transcript_root() {
            return Err(std::io::Error::other("second scale was not rooted at T11").into());
        }
        let second_role = match first_role {
            Role::Alice => Role::Bob,
            Role::Bob => Role::Alice,
        };
        let first_outputs = driver
            .first_scale_round()
            .ok_or_else(|| std::io::Error::other("missing first scale"))?
            .outputs
            .clone();
        let scale_second = generate_scale_round(
            &mut proof_transcript(
                ProofDomain::ScaleSecond,
                &second_context,
                second_role,
                &common,
            )?,
            &generators,
            &first_outputs,
            &mut OsRng,
        )?;
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BlindSecond(Box::new(scale_second)),
        )?);

        let decrypt_context = driver
            .phase_context(ProofPhase::PartialDecrypt)
            .ok_or_else(|| std::io::Error::other("missing T12"))?;
        if decrypt_context.prior_transcript != driver.schedule().transcript_root() {
            return Err(std::io::Error::other("decrypt proof was not rooted at T12").into());
        }
        let final_ciphertexts = driver
            .second_scale_round()
            .ok_or_else(|| std::io::Error::other("missing second scale"))?
            .outputs
            .clone();
        let partial_a = generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &decrypt_context,
                Role::Alice,
                &common,
            )?,
            &generators,
            threshold.public.public_a(),
            &threshold.secret_a,
            &final_ciphertexts,
            &mut OsRng,
        )?;
        let partial_b = generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptBob,
                &decrypt_context,
                Role::Bob,
                &common,
            )?,
            &generators,
            threshold.public.public_b(),
            &threshold.secret_b,
            &final_ciphertexts,
            &mut OsRng,
        )?;
        let nonce_da = [0x31_u8; 32];
        let nonce_db = [0x32_u8; 32];
        let commit_da = decryption_commitment(
            &game_id,
            7,
            Role::Alice,
            &nonce_da,
            &partial_a.encode_to_vec()?,
        );
        let commit_db = decryption_commitment(
            &game_id,
            7,
            Role::Bob,
            &nonce_db,
            &partial_b.encode_to_vec()?,
        );
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::DecryptCommit(CommitmentPayload {
                commitment: commit_da,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::DecryptCommit(CommitmentPayload {
                commitment: commit_db,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::DecryptOpen(Box::new(DecryptOpenPayload {
                nonce: nonce_da,
                batch: partial_a,
            })),
        )?);
        let progress = send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::DecryptOpen(Box::new(DecryptOpenPayload {
                nonce: nonce_db,
                batch: partial_b,
            })),
        )?;
        if !driver.schedule().is_complete() {
            return Err(std::io::Error::other("terminal attempt did not reach T16").into());
        }
        Ok((progress, identities))
    }

    #[test]
    fn complete_unique_attempt_yields_only_a_t16_body_ready_for_signatures() -> TestResult {
        let values_a = core::array::from_fn(|index| index.to_le_bytes()[0]);
        let values_b = [0_u8; N_SLOTS];
        let (progress, identities) = run_complete(values_a, values_b)?;
        let AttemptProgress::ReadyToSign(body_token) = progress else {
            return Err(std::io::Error::other("unique attempt did not become ready").into());
        };
        let body = body_token.body();
        assert_eq!(body_token.archive().envelopes().len(), 16);
        verify_archive_chain(body_token.archive())?;
        assert_eq!(
            body_token.archive().transcript_root(),
            body.verification_transcript_root
        );
        assert_eq!(body.protocol_version, PROTOCOL_VERSION);
        assert_eq!(body.game_id, [0x33_u8; 32]);
        assert_eq!(body.attempt, 7);
        assert_ne!(body.verification_transcript_root, [0_u8; 32]);
        assert_eq!(body.hashes_a[0], [1_u8; 32]);
        assert_eq!(body.hashes_b[N_SLOTS - 1], [18_u8; 32]);
        let secp = Secp256k1::new();
        let signature_a = body_token.sign(&secp, Role::Alice, &identities.alice, &[0xa1_u8; 32])?;
        let signature_b = body_token.sign(&secp, Role::Bob, &identities.bob, &[0xb2_u8; 32])?;
        let deal = body_token.finalize(&secp, signature_a, signature_b)?;
        assert_eq!(deal.body(), body);
        Ok(())
    }

    #[test]
    fn complete_collision_attempt_is_a_neutral_retry_not_a_fault() -> TestResult {
        let values_a = [0_u8, 0, 2, 3, 4, 5, 6, 7, 8];
        let values_b = [0_u8; N_SLOTS];
        let (progress, _) = run_complete(values_a, values_b)?;
        let AttemptProgress::CollisionRetry(retry) = progress else {
            return Err(std::io::Error::other("collision attempt did not retry").into());
        };
        assert!(retry.collision_bitmap().iter().any(|collision| *collision));
        assert_ne!(retry.transcript_root(), [0_u8; 32]);
        assert_eq!(retry.archive().envelopes().len(), 16);
        verify_archive_chain(retry.archive())?;
        Ok(())
    }

    #[test]
    fn signed_bad_commitment_opening_is_blamed_and_does_not_advance() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let generators = ProtocolGenerators::derive()?;
        let threshold = ThresholdKeys::new(&generators)?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x71_u8; 32],
            0,
            identities.identities,
            [0x72_u8; 32],
        );
        let nonce_a = [1_u8; 32];
        let nonce_b = [2_u8; 32];
        let commit_a = key_commitment(
            &driver.schedule().game_id(),
            0,
            Role::Alice,
            &nonce_a,
            &threshold.public.public_a().to_bytes(),
        );
        let commit_b = key_commitment(
            &driver.schedule().game_id(),
            0,
            Role::Bob,
            &nonce_b,
            &threshold.public.public_b().to_bytes(),
        );
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::KeyCommit(CommitmentPayload {
                commitment: commit_a,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::KeyCommit(CommitmentPayload {
                commitment: commit_b,
            }),
        )?);
        let before_root = driver.schedule().transcript_root();
        let before_sequence = driver.schedule().next_sequence();
        let bad = signed_next(
            &driver,
            &secp,
            &identities,
            ProtocolPayload::KeyOpen(KeyOpenPayload {
                nonce: [9_u8; 32],
                public_key: threshold.public.public_a().clone(),
            }),
        )?;
        let error = driver
            .accept(&secp, &bad)
            .err()
            .ok_or_else(|| std::io::Error::other("bad opening was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::SignedSemanticFault {
                signer: Role::Alice,
                error: ProtocolError::CommitmentMismatch,
            }
        ));
        assert_eq!(driver.schedule().transcript_root(), before_root);
        assert_eq!(driver.schedule().next_sequence(), before_sequence);
        assert_eq!(driver.authenticated_archive().len(), 2);
        assert!(driver.is_terminal());
        let corrected = signed_next(
            &driver,
            &secp,
            &identities,
            ProtocolPayload::KeyOpen(KeyOpenPayload {
                nonce: nonce_a,
                public_key: threshold.public.public_a().clone(),
            }),
        )?;
        assert!(matches!(
            driver.accept(&secp, &corrected),
            Err(AttemptDriverError::Terminal)
        ));
        Ok(())
    }

    #[test]
    fn alice_bundle_is_fully_checked_at_sequence_eight_before_advance() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let generators = ProtocolGenerators::derive()?;
        let threshold = ThresholdKeys::new(&generators)?;
        let game_id = [0x75_u8; 32];
        let circuit_id = [0x76_u8; 32];
        let mut driver = AttemptVerifier::without_hash_length_backend(
            game_id,
            0,
            identities.identities,
            circuit_id,
        );
        key_setup_flights(&mut driver, &secp, &identities, &threshold, &generators)?;

        let mut bundle_a = bundle(
            Role::Alice,
            [0_u8; N_SLOTS],
            0,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        bundle_a.circuit_id[0] ^= 1;
        let bundle_b = bundle(
            Role::Bob,
            [1_u8; N_SLOTS],
            u8::try_from(N_SLOTS).map_err(|_| std::io::Error::other("slot count overflow"))?,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        let nonce_a = [0x41_u8; 32];
        let nonce_b = [0x42_u8; 32];
        let commitment_a = bundle_commitment(&game_id, 0, Role::Alice, &nonce_a, &bundle_a)?;
        let commitment_b = bundle_commitment(&game_id, 0, Role::Bob, &nonce_b, &bundle_b)?;
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: commitment_a,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: commitment_b,
            }),
        )?);

        let root = driver.schedule().transcript_root();
        let opening = signed_next(
            &driver,
            &secp,
            &identities,
            ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
                nonce: nonce_a,
                bundle: bundle_a,
            })),
        )?;
        let error = driver
            .accept(&secp, &opening)
            .err()
            .ok_or_else(|| std::io::Error::other("bad Alice bundle was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::SignedSemanticFault {
                signer: Role::Alice,
                error: ProtocolError::InvalidHashLengthProof,
            }
        ));
        assert_eq!(driver.schedule().next_sequence(), 8);
        assert_eq!(driver.schedule().transcript_root(), root);
        assert_eq!(driver.authenticated_archive().len(), 8);
        assert!(driver.is_terminal());
        Ok(())
    }

    #[test]
    fn derived_randomness_cancellation_returns_opaque_neutral_t10_retry() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let generators = ProtocolGenerators::derive()?;
        let threshold = ThresholdKeys::new(&generators)?;
        let game_id = [0x77_u8; 32];
        let circuit_id = [0x78_u8; 32];
        let mut driver = AttemptVerifier::without_hash_length_backend(
            game_id,
            2,
            identities.identities,
            circuit_id,
        );
        key_setup_flights(&mut driver, &secp, &identities, &threshold, &generators)?;
        let bundle_a = bundle(
            Role::Alice,
            [0_u8; N_SLOTS],
            0,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        let mut bundle_b = bundle(
            Role::Bob,
            [1_u8; N_SLOTS],
            u8::try_from(N_SLOTS).map_err(|_| std::io::Error::other("slot count overflow"))?,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        let cancelling_randomness = NonZeroScalar::new(-Scalar::from(2_000_u64))?;
        bundle_b.slots[0].ciphertext = Ciphertext::from(
            ElGamalCiphertext::encrypt(
                Scalar::ONE,
                &cancelling_randomness,
                threshold.public.joint(),
                &generators,
            )
            .to_bytes(),
        );
        let nonce_a = [0x51_u8; 32];
        let nonce_b = [0x52_u8; 32];
        let commitment_a = bundle_commitment(&game_id, 2, Role::Alice, &nonce_a, &bundle_a)?;
        let commitment_b = bundle_commitment(&game_id, 2, Role::Bob, &nonce_b, &bundle_b)?;
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: commitment_a,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: commitment_b,
            }),
        )?);
        drop(send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
                nonce: nonce_a,
                bundle: bundle_a,
            })),
        )?);
        let progress = send(
            &mut driver,
            &secp,
            &identities,
            ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
                nonce: nonce_b,
                bundle: bundle_b,
            })),
        )?;
        let AttemptProgress::DegenerateRetry(retry) = progress else {
            return Err(std::io::Error::other("derived cancellation was not retried").into());
        };
        assert_eq!(retry.game_id(), game_id);
        assert_eq!(retry.attempt(), 2);
        assert_eq!(retry.transcript_root(), driver.schedule().transcript_root());
        assert_eq!(retry.archive().envelopes().len(), 10);
        verify_archive_chain(retry.archive())?;
        assert_eq!(driver.schedule().next_sequence(), 10);
        assert!(driver.is_terminal());
        Ok(())
    }

    #[test]
    fn invalid_signature_is_unattributed_and_does_not_advance() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x81_u8; 32],
            0,
            identities.identities,
            [0x82_u8; 32],
        );
        let expected = driver.schedule().expected()?;
        let envelope = Envelope {
            unsigned: UnsignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                game_id: driver.schedule().game_id(),
                attempt: 0,
                round: expected.round,
                sender_role: expected.sender,
                sequence: expected.sequence,
                previous_message_hash: driver.schedule().transcript_root(),
                payload_type: expected.payload_type,
                payload: ProtocolPayload::KeyCommit(CommitmentPayload {
                    commitment: [3_u8; 32],
                })
                .encode_body()?,
            },
            signature: [0_u8; 64],
        };
        let root = driver.schedule().transcript_root();
        let error = driver
            .accept(&secp, &envelope)
            .err()
            .ok_or_else(|| std::io::Error::other("bad signature was accepted"))?;
        assert_eq!(error.blamed_role(), None);
        assert!(matches!(
            error.fault_outcome(),
            Some(AttemptOutcome::Fault {
                blamed_role: None,
                error: ProtocolError::InvalidSignature,
            })
        ));
        assert_eq!(driver.schedule().transcript_root(), root);
        assert_eq!(driver.schedule().next_sequence(), 0);
        assert!(driver.authenticated_archive().is_empty());
        assert!(!driver.is_terminal());
        Ok(())
    }

    #[test]
    fn authenticated_out_of_context_replays_do_not_poison_live_attempt() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x61_u8; 32],
            7,
            identities.identities,
            [0x62_u8; 32],
        );
        let expected = driver.schedule().expected()?;
        let payload = ProtocolPayload::KeyCommit(CommitmentPayload {
            commitment: [0x63_u8; 32],
        });
        let mut unsigned = UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x64_u8; 32],
            attempt: driver.schedule().attempt(),
            round: expected.round,
            sender_role: expected.sender,
            sequence: expected.sequence,
            previous_message_hash: driver.schedule().transcript_root(),
            payload_type: payload.payload_type(),
            payload: payload.encode_body()?,
        };
        let foreign = sign_envelope(
            &secp,
            &unsigned,
            identities.for_role(expected.sender),
            &identities.identities,
            &[0x65_u8; 32],
        )?;
        let root = driver.schedule().transcript_root();
        let error = driver
            .accept(&secp, &foreign)
            .err()
            .ok_or_else(|| std::io::Error::other("foreign-game envelope was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::Envelope(crate::state::EnvelopeAcceptanceError::OutOfContext {
                source: crate::state::ScheduleError::WrongGame,
            })
        ));
        assert_eq!(error.blamed_role(), None);
        assert_eq!(error.fault_outcome(), None);
        assert_eq!(driver.schedule().transcript_root(), root);
        assert!(!driver.is_terminal());

        unsigned.game_id = driver.schedule().game_id();
        let current = sign_envelope(
            &secp,
            &unsigned,
            identities.for_role(expected.sender),
            &identities.identities,
            &[0x66_u8; 32],
        )?;
        assert!(matches!(
            driver.accept(&secp, &current)?,
            AttemptProgress::Continue {
                next_sequence: 1,
                ..
            }
        ));
        let root = driver.schedule().transcript_root();
        let error = driver
            .accept(&secp, &current)
            .err()
            .ok_or_else(|| std::io::Error::other("replayed envelope was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::Envelope(crate::state::EnvelopeAcceptanceError::OutOfContext {
                source: crate::state::ScheduleError::WrongSequence,
            })
        ));
        assert_eq!(driver.schedule().transcript_root(), root);
        assert_eq!(driver.schedule().next_sequence(), 1);
        assert!(!driver.is_terminal());
        Ok(())
    }

    #[test]
    fn raw_unknown_type_is_attributable_only_in_exact_live_context() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x67_u8; 32],
            9,
            identities.identities,
            [0x68_u8; 32],
        );
        let raw = crate::messages::RawEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x69_u8; 32],
            attempt: driver.schedule().attempt(),
            round: 0,
            sender_role: Role::Alice.to_u8(),
            sequence: 0,
            previous_message_hash: driver.schedule().transcript_root(),
            payload_type: u16::MAX,
            payload: Vec::new(),
            signature: [0_u8; 64],
        };
        let foreign = sign_raw_wire_envelope_for_test(
            &secp,
            &raw,
            identities.for_role(Role::Alice),
            &identities.identities,
            &[0x6a_u8; 32],
        )?;
        let error = driver
            .accept_bytes(&secp, &foreign.encode_to_vec()?)
            .err()
            .ok_or_else(|| std::io::Error::other("foreign raw envelope was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::Envelope(crate::state::EnvelopeAcceptanceError::OutOfContext {
                source: crate::state::ScheduleError::WrongGame,
            })
        ));
        assert!(!driver.is_terminal());

        let mut current_raw = raw;
        current_raw.game_id = driver.schedule().game_id();
        let current = sign_raw_wire_envelope_for_test(
            &secp,
            &current_raw,
            identities.for_role(Role::Alice),
            &identities.identities,
            &[0x6b_u8; 32],
        )?;
        let error = driver
            .accept_bytes(&secp, &current.encode_to_vec()?)
            .err()
            .ok_or_else(|| std::io::Error::other("unknown raw payload type was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::SignedSemanticFault {
                signer: Role::Alice,
                error: ProtocolError::UnexpectedMessage,
            }
        ));
        assert!(driver.is_terminal());
        Ok(())
    }

    #[test]
    fn raw_invalid_role_byte_is_attributed_to_actual_signer_in_live_context() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x6c_u8; 32],
            10,
            identities.identities,
            [0x6d_u8; 32],
        );
        let raw = crate::messages::RawEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x6e_u8; 32],
            attempt: driver.schedule().attempt(),
            round: 0,
            sender_role: u8::MAX,
            sequence: 0,
            previous_message_hash: driver.schedule().transcript_root(),
            payload_type: crate::messages::PayloadType::KeyCommit.to_u16(),
            payload: vec![0x6f_u8; 32],
            signature: [0_u8; 64],
        };
        let foreign = sign_raw_wire_envelope_for_test(
            &secp,
            &raw,
            identities.for_role(Role::Alice),
            &identities.identities,
            &[0x70_u8; 32],
        )?;
        let error = driver
            .accept_bytes(&secp, &foreign.encode_to_vec()?)
            .err()
            .ok_or_else(|| std::io::Error::other("foreign invalid-role envelope was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::Envelope(crate::state::EnvelopeAcceptanceError::OutOfContext {
                source: crate::state::ScheduleError::WrongGame,
            })
        ));
        assert!(!driver.is_terminal());

        let mut current_raw = raw;
        current_raw.game_id = driver.schedule().game_id();
        let current = sign_raw_wire_envelope_for_test(
            &secp,
            &current_raw,
            identities.for_role(Role::Alice),
            &identities.identities,
            &[0x71_u8; 32],
        )?;
        let error = driver
            .accept_bytes(&secp, &current.encode_to_vec()?)
            .err()
            .ok_or_else(|| std::io::Error::other("invalid sender role was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::SignedSemanticFault {
                signer: Role::Alice,
                error: ProtocolError::UnexpectedMessage,
            }
        ));
        assert!(driver.is_terminal());
        Ok(())
    }

    #[test]
    fn duplicate_hash_blame_distinguishes_owned_and_cross_party_pairs() -> TestResult {
        let identities = IdentityKeys::new()?;
        let generators = ProtocolGenerators::derive()?;
        let threshold = ThresholdKeys::new(&generators)?;
        let circuit_id = [0x91_u8; 32];
        let driver = AttemptVerifier::without_hash_length_backend(
            [0x92_u8; 32],
            0,
            identities.identities,
            circuit_id,
        );
        let alice = bundle(
            Role::Alice,
            [0_u8; N_SLOTS],
            0,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        let mut bob = bundle(
            Role::Bob,
            [1_u8; N_SLOTS],
            u8::try_from(N_SLOTS).map_err(|_| std::io::Error::other("slot count overflow"))?,
            circuit_id,
            &threshold.public,
            &generators,
        )?;
        bob.slots[0].hash = alice.slots[0].hash;
        let error = driver
            .verify_bundle_pair(&alice, &bob)
            .err()
            .ok_or_else(|| std::io::Error::other("cross-party duplicate was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::UnattributedSemanticFault {
                error: ProtocolError::DuplicateHash,
            }
        ));

        let mut alice_owned = alice;
        alice_owned.slots[1].hash = alice_owned.slots[0].hash;
        let error = driver
            .verify_bundle_pair(&alice_owned, &bob)
            .err()
            .ok_or_else(|| std::io::Error::other("owned duplicate was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::SignedSemanticFault {
                signer: Role::Alice,
                error: ProtocolError::DuplicateHash,
            }
        ));
        Ok(())
    }

    #[test]
    fn signed_bounded_malformed_payload_is_attributed_and_terminal() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x71_u8; 32],
            4,
            identities.identities,
            [0x72_u8; 32],
        );
        let raw = sign_raw_wire_envelope_for_test(
            &secp,
            &crate::messages::RawEnvelope {
                protocol_version: PROTOCOL_VERSION,
                game_id: driver.schedule().game_id(),
                attempt: driver.schedule().attempt(),
                round: 0,
                sender_role: Role::Alice.to_u8(),
                sequence: 0,
                previous_message_hash: driver.schedule().transcript_root(),
                payload_type: crate::messages::PayloadType::KeyCommit.to_u16(),
                payload: vec![0_u8; 31],
                signature: [0_u8; 64],
            },
            identities.for_role(Role::Alice),
            &identities.identities,
            &[0x73_u8; 32],
        )?;
        let bytes = raw.encode_to_vec()?;
        let root = driver.schedule().transcript_root();
        let error = driver
            .accept_bytes(&secp, &bytes)
            .err()
            .ok_or_else(|| std::io::Error::other("malformed payload was accepted"))?;
        assert!(matches!(
            error,
            AttemptDriverError::SignedSemanticFault {
                signer: Role::Alice,
                error: ProtocolError::MalformedEncoding,
            }
        ));
        assert_eq!(driver.schedule().transcript_root(), root);
        assert_eq!(driver.schedule().next_sequence(), 0);
        assert!(driver.is_terminal());
        assert!(matches!(
            driver.record_timeout(),
            Err(AttemptDriverError::Terminal)
        ));
        Ok(())
    }

    #[test]
    fn timeout_terminalizes_driver_and_rejects_later_envelopes() -> TestResult {
        let secp = Secp256k1::new();
        let identities = IdentityKeys::new()?;
        let mut driver = AttemptVerifier::without_hash_length_backend(
            [0x81_u8; 32],
            5,
            identities.identities,
            [0x82_u8; 32],
        );
        assert!(matches!(
            driver.record_timeout()?,
            AttemptOutcome::Fault {
                blamed_role: Some(Role::Alice),
                error: ProtocolError::Timeout,
            }
        ));
        assert!(driver.is_terminal());
        assert!(matches!(
            driver.record_timeout(),
            Err(AttemptDriverError::Terminal)
        ));
        let envelope = signed_next(
            &driver,
            &secp,
            &identities,
            ProtocolPayload::KeyCommit(CommitmentPayload {
                commitment: [0x83_u8; 32],
            }),
        )?;
        assert!(matches!(
            driver.accept(&secp, &envelope),
            Err(AttemptDriverError::Terminal)
        ));
        Ok(())
    }
}
