//! History-owned attempt lifecycle, freshness enforcement, and secret erasure.
//!
//! A [`TrackedAttempt`](crate::history::TrackedAttempt) owns the semantic verifier and the participant's
//! concrete per-attempt secret container. Neutral retries and acceptance are
//! reachable only from the opaque capabilities emitted by that verifier.

use std::collections::HashMap;

use bitcoin::secp256k1::{Keypair, Secp256k1, Signing, Verification};
use bp52_circuit::hash_length::{HashLengthParameters, SLOT_HASH_LENGTH_PROOF_SIZE};
use bp52_codec::{CodecError, Decode, Encode};
use bp52_group::{
    ElGamalCiphertext, JointPublicKey, NonZeroScalar, ProtocolGenerators, PublicKeyShare,
    SecretKeyShare, commit, hash::TaggedHash,
};
use curve25519_dalek::Scalar;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    N_SLOTS, Role,
    auth::{AuthError, CanonicalIdentities, verify_accepted_deal_signature, verify_envelope},
    contribution::{RetainedPreimages, SecretContribution},
    driver::{
        AttemptDriverError, AttemptProgress, AttemptVerifier, VerifiedCollisionRetry,
        VerifiedDegenerateRetry, VerifiedEnvelopeArchive, VerifiedReadyToSign,
    },
    messages::{AcceptedDeal, AcceptedDealBody, Envelope, PlayerBundle},
    outcome::{AttemptOutcome, COLLISION_TEST_COUNT, ProtocolError},
    payloads::ProtocolPayload,
    transcript::{TranscriptHash, advance, attempt_start},
};

/// Domain separating the complete public inventory of one attempt.
pub const PUBLIC_ATTEMPT_INVENTORY_TAG: &[u8] = b"BP52/attempt-public-inventory/v2";
/// Domain separating individual public components compared across attempts.
pub const PUBLIC_COMPONENT_FINGERPRINT_TAG: &[u8] = b"BP52/public-component/v2";

const DEGENERATE_ARCHIVE_LENGTH: usize = 10;
const COMPLETE_ARCHIVE_LENGTH: usize = 16;
const POINT_BYTES: usize = 32;

/// Class of public component that must be fresh across rejected attempts.
///
/// Positions and roles are deliberately absent: moving a reused value to a
/// different slot or participant does not make it fresh.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PublicComponentKind {
    /// A key, bundle, or partial-decryption commit digest.
    CommitDigest = 1,
    /// A nonce disclosed by a commit/open flight.
    OpeningNonce = 2,
    /// A threshold public-key share.
    PublicKey = 3,
    /// A SHA-256 share hash lock.
    HashLock = 4,
    /// A Pedersen value commitment.
    ValueCommitment = 5,
    /// A complete public `ElGamal` ciphertext, including original `C` and
    /// scaled `E` values.
    Ciphertext = 6,
    /// The `R` component of a public `ElGamal` ciphertext.
    CiphertextR = 7,
    /// The `S` component of a public `ElGamal` ciphertext.
    CiphertextS = 8,
    /// A complete zero-knowledge proof encoding.
    ProofBlob = 9,
    /// A commitment/base point extractable from a proof encoding.
    ProofPoint = 10,
    /// A public scale point `Q`.
    ScalePoint = 11,
    /// A public partial-decryption share `Z`.
    DecryptionShare = 12,
    /// A complete authenticated-envelope signature.
    EnvelopeSignature = 13,
    /// The public BIP340 nonce x-coordinate in an envelope signature.
    EnvelopeSignatureNonce = 14,
    /// A point known to be `scalar * G` for the protocol's standard Ristretto
    /// base. This shared class detects scalar reuse across otherwise distinct
    /// key, encryption, blinding, and proof-nonce roles.
    BaseGPoint = 15,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ComponentFingerprint {
    kind: PublicComponentKind,
    digest: [u8; 32],
}

/// Read-only digest inventory derived from a verifier-authenticated archive.
///
/// This type has no public constructor. The aggregate is useful for logging,
/// while retry safety is enforced against every individually tagged component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAttemptInventory {
    aggregate: [u8; 32],
    components: Vec<ComponentFingerprint>,
}

impl PublicAttemptInventory {
    /// Returns the aggregate tagged digest of the canonical component list.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.aggregate
    }

    /// Returns the number of independently compared public components.
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.components.len()
    }
}

/// Non-fault terminal reason authenticated by the semantic verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NeutralRetryReason {
    /// One or more canonical zero tests identified a normal card collision.
    Collision {
        /// Complete result in canonical zero-test order.
        collision_bitmap: [bool; COLLISION_TEST_COUNT],
    },
    /// Derived ciphertext randomness cancelled after both valid bundles.
    DegenerateIdentity,
}

impl NeutralRetryReason {
    /// Converts the verifier-derived retry reason to the public outcome.
    #[must_use]
    pub fn outcome(&self) -> AttemptOutcome {
        match self {
            Self::Collision { collision_bitmap } => AttemptOutcome::collision(*collision_bitmap),
            Self::DegenerateIdentity => AttemptOutcome::DegenerateRetry,
        }
    }
}

/// Immutable record of one semantically verified neutral retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedAttempt {
    archive: VerifiedEnvelopeArchive,
    inventory: PublicAttemptInventory,
    retry_reason: NeutralRetryReason,
}

impl ArchivedAttempt {
    /// Returns the discarded contiguous attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.archive.attempt()
    }

    /// Returns the terminal authenticated transcript root.
    #[must_use]
    pub const fn transcript_root(&self) -> TranscriptHash {
        self.archive.transcript_root()
    }

    /// Returns the number of authenticated envelopes in the terminal archive.
    #[must_use]
    pub fn transcript_height(&self) -> usize {
        self.archive.envelopes().len()
    }

    /// Returns the exact signed archive supplied by the semantic verifier.
    #[must_use]
    pub const fn archive(&self) -> &VerifiedEnvelopeArchive {
        &self.archive
    }

    /// Returns the component-wise public freshness inventory.
    #[must_use]
    pub const fn public_inventory(&self) -> &PublicAttemptInventory {
        &self.inventory
    }

    /// Returns the verifier-derived neutral retry reason.
    #[must_use]
    pub const fn retry_reason(&self) -> &NeutralRetryReason {
        &self.retry_reason
    }
}

/// Current lifecycle state for a funded game's local history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptHistoryState {
    /// The exact numbered attempt may be started.
    Ready {
        /// Contiguous attempt number.
        attempt: u32,
    },
    /// A tracked verifier and secret owner are live.
    Live {
        /// Contiguous attempt number.
        attempt: u32,
    },
    /// A fresh, fully verified body is collecting acceptance signatures.
    PendingAcceptance {
        /// Contiguous attempt number.
        attempt: u32,
    },
    /// Both acceptance signatures finalized and secrets were reduced to
    /// retained preimages.
    Accepted {
        /// Accepted attempt number.
        attempt: u32,
    },
    /// A live or pending value was abandoned, or an invariant failed closed.
    Faulted {
        /// Attempt that permanently faulted this local history.
        attempt: u32,
    },
}

impl AttemptHistoryState {
    const fn attempt(self) -> u32 {
        match self {
            Self::Ready { attempt }
            | Self::Live { attempt }
            | Self::PendingAcceptance { attempt }
            | Self::Accepted { attempt }
            | Self::Faulted { attempt } => attempt,
        }
    }
}

/// Errors that make a history transition fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryError {
    /// The history is not at a boundary where an attempt can start.
    #[error("history cannot start an attempt while in state {state:?}")]
    NotReady {
        /// Current terminal or borrowed lifecycle state.
        state: AttemptHistoryState,
    },
    /// A later attempt tried to switch the fixed circuit profile.
    #[error("attempt history cannot change its circuit identifier")]
    CircuitChanged,
    /// Retry was requested without a verifier-issued neutral terminal token.
    #[error("attempt did not end in a verified neutral retry")]
    RetryNotVerified,
    /// Acceptance was requested without a verifier-issued ready token.
    #[error("attempt did not end ready for acceptance signatures")]
    AcceptanceNotVerified,
    /// A supposedly verified archive failed defensive metadata or hash-chain
    /// reconstruction.
    #[error("verified terminal archive violated an internal invariant")]
    InvalidVerifiedArchive,
    /// The concrete secret owner did not match the local key and bundle in the
    /// authenticated archive.
    #[error("owned per-attempt secrets do not match authenticated public material")]
    SecretOwnerMismatch,
    /// No concrete contribution owner was installed before the attempt became
    /// terminal.
    #[error("attempt reached a terminal state without owned contribution secrets")]
    MissingContribution,
    /// A public component overlaps an earlier rejected attempt.
    #[error("attempt {attempt} reused {kind:?} material from rejected attempt {first_attempt}")]
    ReusedPublicComponent {
        /// Component class whose tagged digest matched.
        kind: PublicComponentKind,
        /// First rejected attempt containing the component.
        first_attempt: u32,
        /// Current attempt that attempted reuse.
        attempt: u32,
    },
    /// A canonical archive payload unexpectedly failed to decode or re-encode.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// No contiguous successor exists after attempt `u32::MAX`.
    #[error("attempt counter overflow")]
    CounterOverflow,
}

impl HistoryError {
    /// Converts a local fail-closed history error to a public fault category.
    #[must_use]
    pub const fn fault_outcome(self) -> AttemptOutcome {
        let error = match self {
            Self::ReusedPublicComponent { .. } => ProtocolError::ReusedPublicMaterial,
            Self::CounterOverflow => ProtocolError::CounterOverflow,
            Self::CircuitChanged => ProtocolError::InvalidHashLengthProof,
            Self::InvalidVerifiedArchive | Self::Codec(_) => ProtocolError::MalformedEncoding,
            Self::NotReady { .. }
            | Self::RetryNotVerified
            | Self::AcceptanceNotVerified
            | Self::SecretOwnerMismatch
            | Self::MissingContribution => ProtocolError::UnexpectedMessage,
        };
        AttemptOutcome::unattributed_fault(error)
    }
}

/// Errors while populating the concrete per-attempt secret owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SecretStateError {
    /// A contribution was already installed and cannot be replaced.
    #[error("attempt contribution secrets are already installed")]
    ContributionAlreadyInstalled,
    /// A terminal attempt can no longer accept secret material.
    #[error("terminal attempt cannot install contribution secrets")]
    AttemptTerminal,
}

/// Concrete local secrets owned for exactly one attempt.
///
/// The type is deliberately non-cloneable and non-serializable. It owns the
/// threshold key share immediately and the contribution once that contribution
/// can be generated after joint-key setup. Its API cannot prevent copies made
/// outside this container; callers must not retain such copies.
pub struct AttemptSecrets {
    role: Role,
    key_share: SecretKeyShare,
    contribution: Option<SecretContribution>,
}

impl AttemptSecrets {
    fn new(role: Role, key_share: SecretKeyShare) -> Self {
        Self {
            role,
            key_share,
            contribution: None,
        }
    }

    /// Returns the local participant role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Borrows the per-attempt threshold key share for proof generation.
    #[must_use]
    pub const fn key_share(&self) -> &SecretKeyShare {
        &self.key_share
    }

    /// Borrows the installed contribution openings, if generation is complete.
    #[must_use]
    pub const fn contribution(&self) -> Option<&SecretContribution> {
        self.contribution.as_ref()
    }

    fn install_contribution(
        &mut self,
        contribution: SecretContribution,
    ) -> Result<(), SecretStateError> {
        if self.contribution.is_some() {
            return Err(SecretStateError::ContributionAlreadyInstalled);
        }
        self.contribution = Some(contribution);
        Ok(())
    }

    fn into_retained_preimages(mut self) -> Result<RetainedPreimages, HistoryError> {
        self.key_share.zeroize();
        let contribution = self
            .contribution
            .take()
            .ok_or(HistoryError::MissingContribution)?;
        Ok(contribution.into_retained_preimages())
    }
}

impl Zeroize for AttemptSecrets {
    fn zeroize(&mut self) {
        self.key_share.zeroize();
        if let Some(contribution) = &mut self.contribution {
            contribution.zeroize();
        }
    }
}

impl Drop for AttemptSecrets {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AttemptSecrets {}

/// Cumulative history and lifecycle state for one funded game.
pub struct PublicAttemptHistory {
    game_id: [u8; 32],
    identities: CanonicalIdentities,
    circuit_id: Option<[u8; 32]>,
    state: AttemptHistoryState,
    archived: Vec<ArchivedAttempt>,
    component_owners: HashMap<ComponentFingerprint, u32>,
}

impl PublicAttemptHistory {
    /// Creates a history whose only startable attempt is attempt zero.
    #[must_use]
    pub fn new(game_id: [u8; 32], identities: CanonicalIdentities) -> Self {
        Self {
            game_id,
            identities,
            circuit_id: None,
            state: AttemptHistoryState::Ready { attempt: 0 },
            archived: Vec::new(),
            component_owners: HashMap::new(),
        }
    }

    /// Returns the funded game identifier fixed for the complete history.
    #[must_use]
    pub const fn game_id(&self) -> [u8; 32] {
        self.game_id
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> AttemptHistoryState {
        self.state
    }

    /// Returns every verified neutral retry in contiguous order.
    #[must_use]
    pub fn archived(&self) -> &[ArchivedAttempt] {
        &self.archived
    }

    /// Returns the exact attempt that may next be started.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::NotReady`] while an attempt is live, pending,
    /// accepted, or faulted.
    pub const fn next_attempt(&self) -> Result<u32, HistoryError> {
        match self.state {
            AttemptHistoryState::Ready { attempt } => Ok(attempt),
            state => Err(HistoryError::NotReady { state }),
        }
    }

    /// Starts and owns the one attempt currently authorized by this history.
    ///
    /// The caller moves in its fresh threshold secret share. The contribution
    /// is installed later through [`TrackedAttempt::install_contribution`],
    /// after the joint public key is available.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::NotReady`] unless the history is at a retry/start
    /// boundary, or [`HistoryError::CircuitChanged`] if a later attempt uses a
    /// different circuit profile.
    pub fn start_attempt<'history, 'parameters>(
        &'history mut self,
        parameters: &'parameters HashLengthParameters,
        local_role: Role,
        key_share: SecretKeyShare,
    ) -> Result<TrackedAttempt<'history, 'parameters>, HistoryError> {
        self.ensure_key_share_fresh(&key_share)?;
        let attempt = self.prepare_start(parameters.circuit_id())?;
        Ok(TrackedAttempt {
            verifier: AttemptVerifier::new(self.game_id, attempt, self.identities, parameters),
            history: Some(self),
            secrets: Some(AttemptSecrets::new(local_role, key_share)),
            terminal: None,
            locally_faulted: false,
        })
    }

    fn ensure_key_share_fresh(&self, key_share: &SecretKeyShare) -> Result<(), HistoryError> {
        let attempt = self.next_attempt()?;
        let generators =
            ProtocolGenerators::derive().map_err(|_| HistoryError::SecretOwnerMismatch)?;
        let public_key = key_share.public_key(&generators).to_bytes();
        self.ensure_component_fresh(
            attempt,
            component_fingerprint(PublicComponentKind::PublicKey, &public_key),
        )?;
        self.ensure_component_fresh(
            attempt,
            component_fingerprint(PublicComponentKind::BaseGPoint, &public_key),
        )
    }

    fn prepare_start(&mut self, circuit_id: [u8; 32]) -> Result<u32, HistoryError> {
        let attempt = self.next_attempt()?;
        if let Some(expected) = self.circuit_id {
            if expected != circuit_id {
                return Err(HistoryError::CircuitChanged);
            }
        } else {
            self.circuit_id = Some(circuit_id);
        }
        self.state = AttemptHistoryState::Live { attempt };
        Ok(attempt)
    }

    fn ensure_fresh(
        &self,
        attempt: u32,
        inventory: &PublicAttemptInventory,
    ) -> Result<(), HistoryError> {
        for component in &inventory.components {
            self.ensure_component_fresh(attempt, *component)?;
        }
        Ok(())
    }

    fn ensure_component_fresh(
        &self,
        attempt: u32,
        component: ComponentFingerprint,
    ) -> Result<(), HistoryError> {
        if let Some(first_attempt) = self.component_owners.get(&component) {
            return Err(HistoryError::ReusedPublicComponent {
                kind: component.kind,
                first_attempt: *first_attempt,
                attempt,
            });
        }
        Ok(())
    }

    fn archive_retry(
        &mut self,
        archive: VerifiedEnvelopeArchive,
        inventory: PublicAttemptInventory,
        retry_reason: NeutralRetryReason,
    ) -> Result<u32, HistoryError> {
        let attempt = archive.attempt();
        for component in &inventory.components {
            self.component_owners.entry(*component).or_insert(attempt);
        }
        self.archived.push(ArchivedAttempt {
            archive,
            inventory,
            retry_reason,
        });
        if let Some(next_attempt) = attempt.checked_add(1) {
            self.state = AttemptHistoryState::Ready {
                attempt: next_attempt,
            };
            Ok(next_attempt)
        } else {
            self.state = AttemptHistoryState::Faulted { attempt };
            Err(HistoryError::CounterOverflow)
        }
    }

    fn mark_faulted(&mut self, attempt: u32) {
        self.state = AttemptHistoryState::Faulted { attempt };
    }

    #[cfg(test)]
    fn start_attempt_without_backend(
        &mut self,
        circuit_id: [u8; 32],
        local_role: Role,
        key_share: SecretKeyShare,
    ) -> Result<TrackedAttempt<'_, 'static>, HistoryError> {
        self.ensure_key_share_fresh(&key_share)?;
        let attempt = self.prepare_start(circuit_id)?;
        Ok(TrackedAttempt {
            verifier: AttemptVerifier::without_hash_length_backend(
                self.game_id,
                attempt,
                self.identities,
                circuit_id,
            ),
            history: Some(self),
            secrets: Some(AttemptSecrets::new(local_role, key_share)),
            terminal: None,
            locally_faulted: false,
        })
    }
}

enum StoredTerminal {
    Degenerate(Box<VerifiedDegenerateRetry>),
    Collision(Box<VerifiedCollisionRetry>),
    Ready(Box<VerifiedReadyToSign>),
}

/// Progress reported by a history-owned semantic verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackedProgress {
    /// One valid envelope was consumed and more are required.
    Continue {
        /// New authenticated transcript root.
        transcript_root: TranscriptHash,
        /// Next global envelope sequence number.
        next_sequence: u32,
    },
    /// The verifier issued an opaque early neutral-retry capability.
    DegenerateRetry,
    /// The verifier issued an opaque complete collision-retry capability.
    CollisionRetry,
    /// The verifier issued an opaque ready-to-sign capability.
    ReadyToSign,
}

/// One exact-current attempt with its semantic verifier and concrete secrets.
///
/// Dropping this value before a verified retry or acceptance transition erases
/// its owned secrets and permanently marks the history faulted.
#[must_use = "dropping a live tracked attempt permanently faults its history"]
pub struct TrackedAttempt<'history, 'parameters> {
    verifier: AttemptVerifier<'parameters>,
    history: Option<&'history mut PublicAttemptHistory>,
    secrets: Option<AttemptSecrets>,
    terminal: Option<StoredTerminal>,
    locally_faulted: bool,
}

impl<'history, 'parameters> TrackedAttempt<'history, 'parameters> {
    /// Returns the exact contiguous attempt number selected by history.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.verifier.schedule().attempt()
    }

    /// Borrows the public semantic verifier state.
    #[must_use]
    pub const fn verifier(&self) -> &AttemptVerifier<'parameters> {
        &self.verifier
    }

    /// Borrows the concrete local secret owner.
    #[must_use]
    pub fn secrets(&self) -> Option<&AttemptSecrets> {
        self.secrets.as_ref()
    }

    /// Installs the contribution generated after joint-key setup.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStateError::ContributionAlreadyInstalled`] on a second
    /// installation or [`SecretStateError::AttemptTerminal`] after a terminal
    /// verifier transition.
    pub fn install_contribution(
        &mut self,
        contribution: SecretContribution,
    ) -> Result<(), SecretStateError> {
        if self.locally_faulted || self.terminal.is_some() || self.verifier.is_terminal() {
            return Err(SecretStateError::AttemptTerminal);
        }
        self.secrets
            .as_mut()
            .ok_or(SecretStateError::AttemptTerminal)?
            .install_contribution(contribution)
    }

    /// Authenticates and semantically consumes the exact next envelope.
    ///
    /// Opaque terminal capabilities are retained inside this value; callers
    /// receive only a disposition and therefore cannot supply their own retry
    /// reason or acceptance body.
    ///
    /// # Errors
    ///
    /// Returns the underlying authentication, schedule, or semantic verifier
    /// error. An authenticated terminal fault also permanently faults history;
    /// unauthenticated traffic leaves the tracked attempt live.
    #[cfg(test)]
    pub(crate) fn accept<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        envelope: &Envelope,
    ) -> Result<TrackedProgress, AttemptDriverError> {
        if self.locally_faulted || self.terminal.is_some() {
            return Err(AttemptDriverError::Terminal);
        }
        self.preflight_freshness(secp, envelope)?;
        let result = self.verifier.accept(secp, envelope);
        self.record_progress(result)
    }

    /// Structurally decodes and consumes an untrusted wire envelope.
    ///
    /// This preserves the driver's distinction between globally malformed
    /// unauthenticated traffic and bounded malformed fields covered by a valid
    /// sender signature.
    ///
    /// # Errors
    ///
    /// Returns authentication, attribution, schedule, and semantic errors from
    /// the integrated verifier. Authenticated terminal faults erase the owned
    /// secret container and permanently fault history.
    pub fn accept_bytes<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        bytes: &[u8],
    ) -> Result<TrackedProgress, AttemptDriverError> {
        if self.locally_faulted || self.terminal.is_some() {
            return Err(AttemptDriverError::Terminal);
        }
        if let Ok(envelope) = Envelope::decode_exact(bytes) {
            self.preflight_freshness(secp, &envelope)?;
        }
        let result = self.verifier.accept_bytes(secp, bytes);
        self.record_progress(result)
    }

    fn record_progress(
        &mut self,
        result: Result<AttemptProgress, AttemptDriverError>,
    ) -> Result<TrackedProgress, AttemptDriverError> {
        if result.is_ok() {
            if let Err(error) = self.ensure_latest_fresh() {
                return Err(self.fail_freshness(error, None));
            }
        }
        match result {
            Ok(AttemptProgress::Continue {
                transcript_root,
                next_sequence,
            }) => Ok(TrackedProgress::Continue {
                transcript_root,
                next_sequence,
            }),
            Ok(AttemptProgress::DegenerateRetry(token)) => {
                self.terminal = Some(StoredTerminal::Degenerate(token));
                Ok(TrackedProgress::DegenerateRetry)
            }
            Ok(AttemptProgress::CollisionRetry(token)) => {
                self.terminal = Some(StoredTerminal::Collision(token));
                Ok(TrackedProgress::CollisionRetry)
            }
            Ok(AttemptProgress::ReadyToSign(token)) => {
                self.terminal = Some(StoredTerminal::Ready(token));
                Ok(TrackedProgress::ReadyToSign)
            }
            Err(error) => {
                if self.verifier.is_terminal() {
                    self.locally_faulted = true;
                    self.erase_all_secrets();
                    self.mark_faulted();
                }
                Err(error)
            }
        }
    }

    /// Records a terminal timeout for the exact message currently due.
    ///
    /// # Errors
    ///
    /// Returns the driver's terminal/misuse error if a terminal disposition was
    /// already reached. A successful timeout permanently faults this history.
    pub fn record_timeout(mut self) -> Result<AttemptOutcome, AttemptDriverError> {
        if self.locally_faulted || self.terminal.is_some() {
            self.erase_all_secrets();
            self.mark_faulted();
            return Err(AttemptDriverError::Terminal);
        }
        let outcome = self.verifier.record_timeout();
        self.erase_all_secrets();
        self.mark_faulted();
        outcome
    }

    /// Consumes a verifier-issued collision or derived-identity terminal state.
    ///
    /// Freshness is derived exclusively from the authenticated archive. The
    /// concrete secret owner is explicitly zeroized and dropped before the
    /// successor boundary is returned.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::RetryNotVerified`] for a live or accepted-ready
    /// attempt, an archive/freshness/secret-owner error on invariant failure,
    /// or [`HistoryError::CounterOverflow`] after archiving attempt `u32::MAX`.
    pub fn retry(mut self) -> Result<RetryBoundary<'history>, HistoryError> {
        let terminal = self.terminal.take().ok_or(HistoryError::RetryNotVerified)?;
        let (archive, retry_reason, expected_len) = match terminal {
            StoredTerminal::Degenerate(token) => (
                token.archive().clone(),
                NeutralRetryReason::DegenerateIdentity,
                DEGENERATE_ARCHIVE_LENGTH,
            ),
            StoredTerminal::Collision(token) => (
                token.archive().clone(),
                NeutralRetryReason::Collision {
                    collision_bitmap: *token.collision_bitmap(),
                },
                COMPLETE_ARCHIVE_LENGTH,
            ),
            StoredTerminal::Ready(_) => return Err(HistoryError::RetryNotVerified),
        };

        let extraction = self.authorize_archive(&archive, expected_len)?;
        self.erase_all_secrets();
        let history = self
            .history
            .take()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        let next_attempt = history.archive_retry(archive, extraction.inventory, retry_reason)?;
        Ok(RetryBoundary {
            history,
            next_attempt,
        })
    }

    /// Converts a verifier-issued unique terminal state into the only public
    /// acceptance-signing surface.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::AcceptanceNotVerified`] unless the semantic
    /// verifier issued `ReadyToSign`, or an archive/freshness/secret-owner
    /// error if the attempt cannot safely be accepted.
    pub fn into_pending_acceptance(mut self) -> Result<PendingAcceptance<'history>, HistoryError> {
        let terminal = self
            .terminal
            .take()
            .ok_or(HistoryError::AcceptanceNotVerified)?;
        let StoredTerminal::Ready(ready) = terminal else {
            return Err(HistoryError::AcceptanceNotVerified);
        };
        let archive = ready.archive().clone();
        let extraction = self.authorize_archive(&archive, COMPLETE_ARCHIVE_LENGTH)?;
        let attempt = archive.attempt();
        let secrets = self
            .secrets
            .take()
            .ok_or(HistoryError::SecretOwnerMismatch)?;
        let history = self
            .history
            .take()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        let identities = history.identities;
        history.state = AttemptHistoryState::PendingAcceptance { attempt };
        Ok(PendingAcceptance {
            history: Some(history),
            ready: Some(ready),
            identities,
            secrets: Some(secrets),
            signature_a: None,
            signature_b: None,
            _authorized_inventory: extraction.inventory,
        })
    }

    fn authorize_archive(
        &self,
        archive: &VerifiedEnvelopeArchive,
        expected_len: usize,
    ) -> Result<ExtractedAttempt, HistoryError> {
        let history = self
            .history
            .as_deref()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        validate_verified_archive(history.game_id, self.attempt(), archive, expected_len)?;
        let extraction = extract_inventory(archive.envelopes())?;
        self.secrets
            .as_ref()
            .ok_or(HistoryError::SecretOwnerMismatch)?
            .validate_against(&extraction)?;
        history.ensure_fresh(self.attempt(), &extraction.inventory)?;
        Ok(extraction)
    }

    fn ensure_latest_fresh(&self) -> Result<(), HistoryError> {
        let history = self
            .history
            .as_deref()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        let envelope = self
            .verifier
            .authenticated_archive()
            .last()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        let extraction = extract_inventory(core::slice::from_ref(envelope))?;
        history.ensure_fresh(self.attempt(), &extraction.inventory)
    }

    fn preflight_freshness<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        envelope: &Envelope,
    ) -> Result<(), AttemptDriverError> {
        let history =
            self.history
                .as_deref()
                .ok_or(AttemptDriverError::UnattributedSemanticFault {
                    error: ProtocolError::MalformedEncoding,
                })?;
        if verify_envelope(secp, envelope, &history.identities).is_err()
            || self.verifier.schedule().validate_header(envelope).is_err()
        {
            return Ok(());
        }
        let Ok(extraction) = extract_inventory(core::slice::from_ref(envelope)) else {
            // The semantic verifier owns attribution and error precedence for
            // malformed proof encodings; freshness is checked again after any
            // successful semantic transition and over the terminal archive.
            return Ok(());
        };
        if let Err(error) = history.ensure_fresh(self.attempt(), &extraction.inventory) {
            return Err(self.fail_freshness(error, Some(envelope.unsigned.sender_role)));
        }
        Ok(())
    }

    fn fail_freshness(
        &mut self,
        error: HistoryError,
        authenticated_signer: Option<Role>,
    ) -> AttemptDriverError {
        let signer = authenticated_signer.or_else(|| {
            self.verifier
                .authenticated_archive()
                .last()
                .map(|envelope| envelope.unsigned.sender_role)
        });
        self.locally_faulted = true;
        self.erase_all_secrets();
        self.mark_faulted();
        match (signer, error) {
            (Some(signer), HistoryError::ReusedPublicComponent { .. }) => {
                AttemptDriverError::SignedSemanticFault {
                    signer,
                    error: ProtocolError::ReusedPublicMaterial,
                }
            }
            _ => AttemptDriverError::UnattributedSemanticFault {
                error: ProtocolError::MalformedEncoding,
            },
        }
    }

    fn erase_all_secrets(&mut self) {
        if let Some(mut secrets) = self.secrets.take() {
            secrets.zeroize();
            drop(secrets);
        }
    }

    fn mark_faulted(&mut self) {
        let attempt = self.attempt();
        if let Some(history) = self.history.as_deref_mut() {
            history.mark_faulted(attempt);
        }
    }
}

impl Drop for TrackedAttempt<'_, '_> {
    fn drop(&mut self) {
        self.erase_all_secrets();
        self.mark_faulted();
    }
}

/// Boundary proving that the prior attempt's owned secrets were erased.
pub struct RetryBoundary<'history> {
    history: &'history mut PublicAttemptHistory,
    next_attempt: u32,
}

impl<'history> RetryBoundary<'history> {
    /// Returns the one contiguous successor attempt.
    #[must_use]
    pub const fn next_attempt(&self) -> u32 {
        self.next_attempt
    }

    /// Borrows the updated public retry history.
    #[must_use]
    pub const fn history(&self) -> &PublicAttemptHistory {
        self.history
    }

    /// Starts the exact successor with a fresh key share.
    ///
    /// # Errors
    ///
    /// Returns the same state/circuit errors as
    /// [`PublicAttemptHistory::start_attempt`].
    pub fn start_next<'parameters>(
        self,
        parameters: &'parameters HashLengthParameters,
        local_role: Role,
        key_share: SecretKeyShare,
    ) -> Result<TrackedAttempt<'history, 'parameters>, HistoryError> {
        self.history
            .start_attempt(parameters, local_role, key_share)
    }
}

/// Errors while collecting or finalizing acceptance signatures.
#[derive(Debug, thiserror::Error)]
pub enum AcceptanceError {
    /// This role already supplied its one signature.
    #[error("acceptance signature for {role:?} is already present")]
    DuplicateSignature {
        /// Role whose slot was already occupied.
        role: Role,
    },
    /// Finalization was attempted before this role supplied a signature.
    #[error("acceptance signature for {role:?} is missing")]
    MissingSignature {
        /// Role whose signature is absent.
        role: Role,
    },
    /// Signature creation or verification failed.
    #[error(transparent)]
    Authentication(#[from] AuthError),
    /// This pending value was already finalized.
    #[error("acceptance was already finalized")]
    AlreadyFinalized,
    /// A post-authorization secret invariant failed closed.
    #[error("accepted secret owner lost its contribution")]
    SecretInvariant,
}

/// Freshness-authorized collection of exactly one signature per role.
///
/// This is the sole public acceptance-signing API. Dropping it before
/// successful finalization erases all attempt secrets and marks history
/// faulted.
#[must_use = "dropping pending acceptance permanently faults its history"]
pub struct PendingAcceptance<'history> {
    history: Option<&'history mut PublicAttemptHistory>,
    ready: Option<Box<VerifiedReadyToSign>>,
    identities: CanonicalIdentities,
    secrets: Option<AttemptSecrets>,
    signature_a: Option<[u8; 64]>,
    signature_b: Option<[u8; 64]>,
    _authorized_inventory: PublicAttemptInventory,
}

impl PendingAcceptance<'_> {
    /// Returns the exact verifier-derived body awaiting both signatures.
    #[must_use]
    pub fn body(&self) -> Option<AcceptedDealBody> {
        self.ready.as_ref().map(|ready| ready.body())
    }

    /// Signs the verified body once for `role` and records the result.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptanceError::DuplicateSignature`] if the role's slot is
    /// occupied, [`AcceptanceError::AlreadyFinalized`] after success, or the
    /// underlying authentication error if `signing_key` does not own `role`.
    pub fn sign<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        role: Role,
        signing_key: &Keypair,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<[u8; 64], AcceptanceError> {
        if self.signature(role).is_some() {
            return Err(AcceptanceError::DuplicateSignature { role });
        }
        let ready = self
            .ready
            .as_ref()
            .ok_or(AcceptanceError::AlreadyFinalized)?;
        let signature = ready.sign(secp, role, signing_key, auxiliary_randomness)?;
        self.set_signature(role, signature);
        Ok(signature)
    }

    /// Verifies and records one remotely produced signature for `role`.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptanceError::DuplicateSignature`] if the role's slot is
    /// occupied, [`AcceptanceError::AlreadyFinalized`] after success, or an
    /// authentication error for a malformed or invalid signature.
    pub fn record_signature<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        role: Role,
        signature: [u8; 64],
    ) -> Result<(), AcceptanceError> {
        if self.signature(role).is_some() {
            return Err(AcceptanceError::DuplicateSignature { role });
        }
        let body = self.body().ok_or(AcceptanceError::AlreadyFinalized)?;
        verify_accepted_deal_signature(secp, &body, role, &signature, &self.identities)?;
        self.set_signature(role, signature);
        Ok(())
    }

    /// Returns the already verified signature for `role`, if present.
    #[must_use]
    pub const fn signature(&self, role: Role) -> Option<[u8; 64]> {
        match role {
            Role::Alice => self.signature_a,
            Role::Bob => self.signature_b,
        }
    }

    /// Finalizes exactly once after both signature slots are occupied.
    ///
    /// On success the threshold key share, contribution values, encryption
    /// randomness, and commitment blindings are erased. Only the zeroizing
    /// share-preimage container is returned, and history becomes `Accepted`.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptanceError::MissingSignature`] until both roles are
    /// present, an authentication error if defensive final verification fails,
    /// or a fail-closed secret invariant error.
    pub fn finalize<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
    ) -> Result<AcceptedAttempt, AcceptanceError> {
        let signature_a = self
            .signature_a
            .ok_or(AcceptanceError::MissingSignature { role: Role::Alice })?;
        let signature_b = self
            .signature_b
            .ok_or(AcceptanceError::MissingSignature { role: Role::Bob })?;
        let ready = self
            .ready
            .as_ref()
            .ok_or(AcceptanceError::AlreadyFinalized)?;
        let deal = ready.finalize(secp, signature_a, signature_b)?;
        let secrets = self
            .secrets
            .take()
            .ok_or(AcceptanceError::SecretInvariant)?;
        let retained_preimages = secrets
            .into_retained_preimages()
            .map_err(|_| AcceptanceError::SecretInvariant)?;
        let history = self
            .history
            .take()
            .ok_or(AcceptanceError::AlreadyFinalized)?;
        history.state = AttemptHistoryState::Accepted {
            attempt: deal.attempt,
        };
        self.ready.take();
        Ok(AcceptedAttempt {
            deal,
            retained_preimages,
        })
    }

    fn set_signature(&mut self, role: Role, signature: [u8; 64]) {
        match role {
            Role::Alice => self.signature_a = Some(signature),
            Role::Bob => self.signature_b = Some(signature),
        }
    }

    fn erase_all_secrets(&mut self) {
        if let Some(mut secrets) = self.secrets.take() {
            secrets.zeroize();
            drop(secrets);
        }
    }
}

impl Drop for PendingAcceptance<'_> {
    fn drop(&mut self) {
        self.erase_all_secrets();
        if let Some(history) = self.history.as_deref_mut() {
            let attempt = history.state.attempt();
            history.mark_faulted(attempt);
        }
    }
}

/// Final accepted certificate and the local zeroizing share preimages.
pub struct AcceptedAttempt {
    deal: AcceptedDeal,
    retained_preimages: RetainedPreimages,
}

impl AcceptedAttempt {
    /// Returns the fully signed accepted-deal certificate.
    #[must_use]
    pub const fn deal(&self) -> &AcceptedDeal {
        &self.deal
    }

    /// Borrows the nine local share preimages retained for later reveal.
    #[must_use]
    pub const fn retained_preimages(&self) -> &RetainedPreimages {
        &self.retained_preimages
    }

    /// Separates the accepted certificate and zeroizing preimage owner.
    #[must_use]
    pub fn into_parts(self) -> (AcceptedDeal, RetainedPreimages) {
        (self.deal, self.retained_preimages)
    }
}

impl AttemptSecrets {
    fn validate_against(&self, extraction: &ExtractedAttempt) -> Result<(), HistoryError> {
        let contribution = self
            .contribution
            .as_ref()
            .ok_or(HistoryError::MissingContribution)?;
        let (public_key, bundle) = match self.role {
            Role::Alice => (extraction.public_a.as_ref(), extraction.bundle_a.as_ref()),
            Role::Bob => (extraction.public_b.as_ref(), extraction.bundle_b.as_ref()),
        };
        let public_key = public_key.ok_or(HistoryError::InvalidVerifiedArchive)?;
        let bundle = bundle.ok_or(HistoryError::InvalidVerifiedArchive)?;
        let public_a = extraction
            .public_a
            .as_ref()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        let public_b = extraction
            .public_b
            .as_ref()
            .ok_or(HistoryError::InvalidVerifiedArchive)?;
        let generators =
            ProtocolGenerators::derive().map_err(|_| HistoryError::SecretOwnerMismatch)?;
        if self.key_share.public_key(&generators) != *public_key {
            return Err(HistoryError::SecretOwnerMismatch);
        }
        let joint_key = JointPublicKey::combine(public_a, public_b)
            .map_err(|_| HistoryError::InvalidVerifiedArchive)?;
        for (slot, public) in bundle.slots.iter().enumerate() {
            let preimage = contribution
                .preimage(slot)
                .ok_or(HistoryError::SecretOwnerMismatch)?;
            let value = contribution
                .value(slot)
                .ok_or(HistoryError::SecretOwnerMismatch)?;
            let blinding = contribution
                .commitment_blinding(slot)
                .ok_or(HistoryError::SecretOwnerMismatch)?;
            let randomness = contribution
                .encryption_randomness(slot)
                .ok_or(HistoryError::SecretOwnerMismatch)?;
            if <[u8; 32]>::from(Sha256::digest(preimage)) != public.hash
                || commit(Scalar::from(u64::from(value)), *blinding, &generators)
                    .compress()
                    .to_bytes()
                    != public.value_commitment
            {
                return Err(HistoryError::SecretOwnerMismatch);
            }
            let randomness =
                NonZeroScalar::new(*randomness).map_err(|_| HistoryError::SecretOwnerMismatch)?;
            let ciphertext = ElGamalCiphertext::encrypt(
                Scalar::from(u64::from(value)),
                &randomness,
                &joint_key,
                &generators,
            )
            .to_bytes();
            if ciphertext.r != public.ciphertext.r || ciphertext.s != public.ciphertext.s {
                return Err(HistoryError::SecretOwnerMismatch);
            }
        }
        Ok(())
    }
}

struct ExtractedAttempt {
    inventory: PublicAttemptInventory,
    public_a: Option<PublicKeyShare>,
    public_b: Option<PublicKeyShare>,
    bundle_a: Option<PlayerBundle>,
    bundle_b: Option<PlayerBundle>,
}

fn validate_verified_archive(
    game_id: [u8; 32],
    attempt: u32,
    archive: &VerifiedEnvelopeArchive,
    expected_len: usize,
) -> Result<(), HistoryError> {
    if archive.game_id() != game_id
        || archive.attempt() != attempt
        || archive.envelopes().len() != expected_len
    {
        return Err(HistoryError::InvalidVerifiedArchive);
    }
    let mut root = attempt_start(&game_id, attempt);
    for (sequence, envelope) in archive.envelopes().iter().enumerate() {
        let sequence = u32::try_from(sequence).map_err(|_| HistoryError::InvalidVerifiedArchive)?;
        if envelope.unsigned.game_id != game_id
            || envelope.unsigned.attempt != attempt
            || envelope.unsigned.sequence != sequence
            || envelope.unsigned.previous_message_hash != root
        {
            return Err(HistoryError::InvalidVerifiedArchive);
        }
        root = advance(&root, &envelope.encode_to_vec()?);
    }
    if archive.transcript_root() != root {
        return Err(HistoryError::InvalidVerifiedArchive);
    }
    Ok(())
}

fn extract_inventory(envelopes: &[Envelope]) -> Result<ExtractedAttempt, HistoryError> {
    let mut builder = InventoryBuilder::default();
    let mut extraction = ExtractedAttempt {
        inventory: PublicAttemptInventory {
            aggregate: [0_u8; 32],
            components: Vec::new(),
        },
        public_a: None,
        public_b: None,
        bundle_a: None,
        bundle_b: None,
    };
    for envelope in envelopes {
        builder.push(PublicComponentKind::EnvelopeSignature, &envelope.signature);
        builder.push(
            PublicComponentKind::EnvelopeSignatureNonce,
            &envelope.signature[..POINT_BYTES],
        );
        let payload = ProtocolPayload::decode_exact(
            envelope.unsigned.payload_type,
            &envelope.unsigned.payload,
        )?;
        match payload {
            ProtocolPayload::KeyCommit(body)
            | ProtocolPayload::BundleCommit(body)
            | ProtocolPayload::DecryptCommit(body) => {
                builder.push(PublicComponentKind::CommitDigest, &body.commitment);
            }
            ProtocolPayload::KeyOpen(body) => {
                builder.push(PublicComponentKind::OpeningNonce, &body.nonce);
                builder.push_base_g(PublicComponentKind::PublicKey, &body.public_key.to_bytes());
                match envelope.unsigned.sender_role {
                    Role::Alice => extraction.public_a = Some(body.public_key),
                    Role::Bob => extraction.public_b = Some(body.public_key),
                }
            }
            ProtocolPayload::KeyProof(proof) => {
                let bytes = proof.encode_to_vec()?;
                builder.push(PublicComponentKind::ProofBlob, &bytes);
                builder.push_base_g(PublicComponentKind::ProofPoint, &proof.commitment);
            }
            ProtocolPayload::BundleOpen(body) => {
                let body = *body;
                builder.push(PublicComponentKind::OpeningNonce, &body.nonce);
                inventory_bundle(&mut builder, &body.bundle)?;
                match envelope.unsigned.sender_role {
                    Role::Alice => extraction.bundle_a = Some(body.bundle),
                    Role::Bob => extraction.bundle_b = Some(body.bundle),
                }
            }
            ProtocolPayload::BlindFirst(round) | ProtocolPayload::BlindSecond(round) => {
                inventory_scale_round(&mut builder, &round)?;
            }
            ProtocolPayload::DecryptOpen(body) => {
                let body = *body;
                builder.push(PublicComponentKind::OpeningNonce, &body.nonce);
                inventory_partial_batch(&mut builder, &body.batch)?;
            }
        }
    }
    extraction.inventory = builder.finish();
    Ok(extraction)
}

fn inventory_bundle(
    builder: &mut InventoryBuilder,
    bundle: &PlayerBundle,
) -> Result<(), CodecError> {
    for slot in &bundle.slots {
        builder.push(PublicComponentKind::HashLock, &slot.hash);
        builder.push(PublicComponentKind::ValueCommitment, &slot.value_commitment);
        inventory_ciphertext(builder, &slot.ciphertext.r, &slot.ciphertext.s, true);
    }
    builder.push(PublicComponentKind::ProofBlob, &bundle.hash_length_proof);
    inventory_r1cs_points(builder, &bundle.hash_length_proof)?;
    builder.push(
        PublicComponentKind::ProofBlob,
        &bundle.encryption_link_proof,
    );
    inventory_prefix_points(
        builder,
        &bundle.encryption_link_proof,
        N_SLOTS * 3,
        |index| index % 3 == 1,
    )
}

fn inventory_scale_round(
    builder: &mut InventoryBuilder,
    round: &bp52_uniqueness::ScaleRound,
) -> Result<(), CodecError> {
    for point in &round.scale_points {
        builder.push_base_g(PublicComponentKind::ScalePoint, point.compress().as_bytes());
    }
    for output in &round.outputs {
        let bytes = output.to_bytes();
        inventory_ciphertext(builder, &bytes.r, &bytes.s, false);
    }
    let proof = round.proof.encode_to_vec()?;
    builder.push(PublicComponentKind::ProofBlob, &proof);
    inventory_prefix_points(
        builder,
        &proof,
        bp52_uniqueness::ZERO_TEST_COUNT * 3,
        |index| index % 3 == 0,
    )
}

fn inventory_partial_batch(
    builder: &mut InventoryBuilder,
    batch: &bp52_uniqueness::PartialDecryptionBatch,
) -> Result<(), CodecError> {
    for share in &batch.shares {
        builder.push(
            PublicComponentKind::DecryptionShare,
            share.compress().as_bytes(),
        );
    }
    let proof = batch.proof.encode_to_vec()?;
    builder.push(PublicComponentKind::ProofBlob, &proof);
    inventory_prefix_points(
        builder,
        &proof,
        bp52_uniqueness::ZERO_TEST_COUNT + 1,
        |index| index == 0,
    )
}

fn inventory_ciphertext(
    builder: &mut InventoryBuilder,
    r: &[u8; 32],
    s: &[u8; 32],
    r_is_direct_base_g: bool,
) {
    let mut ciphertext = [0_u8; 64];
    ciphertext[..32].copy_from_slice(r);
    ciphertext[32..].copy_from_slice(s);
    builder.push(PublicComponentKind::Ciphertext, &ciphertext);
    if r_is_direct_base_g {
        builder.push_base_g(PublicComponentKind::CiphertextR, r);
    } else {
        builder.push(PublicComponentKind::CiphertextR, r);
    }
    builder.push(PublicComponentKind::CiphertextS, s);
}

fn inventory_prefix_points<F>(
    builder: &mut InventoryBuilder,
    proof: &[u8],
    count: usize,
    mut is_base_g: F,
) -> Result<(), CodecError>
where
    F: FnMut(usize) -> bool,
{
    let byte_count = count
        .checked_mul(POINT_BYTES)
        .ok_or(CodecError::LengthOverflow)?;
    let points = proof.get(..byte_count).ok_or(CodecError::UnexpectedEof)?;
    for (index, point) in points.chunks_exact(POINT_BYTES).enumerate() {
        if is_base_g(index) {
            builder.push_base_g(PublicComponentKind::ProofPoint, point);
        } else {
            builder.push(PublicComponentKind::ProofPoint, point);
        }
    }
    Ok(())
}

fn inventory_r1cs_points(builder: &mut InventoryBuilder, proof: &[u8]) -> Result<(), CodecError> {
    if proof.len() != N_SLOTS * SLOT_HASH_LENGTH_PROOF_SIZE {
        return Err(CodecError::NonCanonical);
    }
    for slot_proof in proof.chunks_exact(SLOT_HASH_LENGTH_PROOF_SIZE) {
        inventory_r1cs_slot_points(builder, slot_proof)?;
    }
    Ok(())
}

fn inventory_r1cs_slot_points(
    builder: &mut InventoryBuilder,
    proof: &[u8],
) -> Result<(), CodecError> {
    let fixed_points = match proof.first().copied() {
        Some(0) => 8,
        Some(1) => 11,
        _ => return Err(CodecError::NonCanonical),
    };
    let fixed_start = 1;
    let fixed_end = fixed_start + fixed_points * POINT_BYTES;
    let scalar_end = fixed_end + 3 * POINT_BYTES;
    let ipp_end = proof
        .len()
        .checked_sub(2 * POINT_BYTES)
        .ok_or(CodecError::UnexpectedEof)?;
    if ipp_end < scalar_end || (ipp_end - scalar_end) % (2 * POINT_BYTES) != 0 {
        return Err(CodecError::NonCanonical);
    }
    for point in proof[fixed_start..fixed_end]
        .chunks_exact(POINT_BYTES)
        .chain(proof[scalar_end..ipp_end].chunks_exact(POINT_BYTES))
    {
        builder.push(PublicComponentKind::ProofPoint, point);
    }
    Ok(())
}

#[derive(Default)]
struct InventoryBuilder {
    components: Vec<ComponentFingerprint>,
}

impl InventoryBuilder {
    fn push(&mut self, kind: PublicComponentKind, bytes: &[u8]) {
        self.components.push(component_fingerprint(kind, bytes));
    }

    fn push_base_g(&mut self, semantic_kind: PublicComponentKind, bytes: &[u8]) {
        self.push(semantic_kind, bytes);
        self.push(PublicComponentKind::BaseGPoint, bytes);
    }

    fn finish(self) -> PublicAttemptInventory {
        let mut aggregate = TaggedHash::new(PUBLIC_ATTEMPT_INVENTORY_TAG);
        for component in &self.components {
            aggregate.update([component.kind as u8]);
            aggregate.update(component.digest);
        }
        PublicAttemptInventory {
            aggregate: aggregate.finalize(),
            components: self.components,
        }
    }
}

fn component_fingerprint(kind: PublicComponentKind, bytes: &[u8]) -> ComponentFingerprint {
    let mut hash = TaggedHash::new(PUBLIC_COMPONENT_FINGERPRINT_TAG);
    hash.update([kind as u8]);
    hash.update(bytes);
    ComponentFingerprint {
        kind,
        digest: hash.finalize(),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bp52_group::{NonZeroScalar, ProtocolGenerators, SecretKeyShare};
    use curve25519_dalek::Scalar;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        AttemptHistoryState, AttemptSecrets, HistoryError, InventoryBuilder, PublicAttemptHistory,
        PublicComponentKind, SLOT_HASH_LENGTH_PROOF_SIZE, component_fingerprint,
        inventory_r1cs_points,
    };
    use crate::{
        N_SLOTS, PROTOCOL_VERSION, Role,
        auth::{CanonicalIdentities, sign_envelope},
        driver::AttemptDriverError,
        messages::UnsignedEnvelope,
        outcome::{AttemptOutcome, ProtocolError},
        payloads::{CommitmentPayload, ProtocolPayload},
    };

    fn identities() -> Result<CanonicalIdentities, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let first = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3_u8; 32])?);
        let second = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7_u8; 32])?);
        let (first, _) = first.x_only_public_key();
        let (second, _) = second.x_only_public_key();
        Ok(CanonicalIdentities::new(first, second)?)
    }

    fn key_share(value: u64) -> Result<SecretKeyShare, bp52_group::GroupError> {
        Ok(SecretKeyShare::from_nonzero(NonZeroScalar::new(
            Scalar::from(value),
        )?))
    }

    #[test]
    fn inventories_each_hash_length_slot_proof_independently() {
        let mut aggregate = vec![0_u8; N_SLOTS * SLOT_HASH_LENGTH_PROOF_SIZE];
        for slot in aggregate.chunks_exact_mut(SLOT_HASH_LENGTH_PROOF_SIZE) {
            // The current backend's canonical proof encoding starts with the
            // eight-fixed-point shape tag. The remaining bytes need not be
            // valid points for structural inventory extraction.
            slot[0] = 0;
        }
        assert!(inventory_r1cs_points(&mut InventoryBuilder::default(), &aggregate).is_ok());

        aggregate.pop();
        assert_eq!(
            inventory_r1cs_points(&mut InventoryBuilder::default(), &aggregate),
            Err(bp52_codec::CodecError::NonCanonical)
        );
    }

    #[test]
    fn dropping_live_attempt_faults_and_prevents_restart() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut history = PublicAttemptHistory::new([9_u8; 32], identities()?);
        {
            let attempt =
                history.start_attempt_without_backend([4_u8; 32], Role::Alice, key_share(11)?)?;
            assert_eq!(attempt.attempt(), 0);
        }
        assert_eq!(history.state(), AttemptHistoryState::Faulted { attempt: 0 });
        assert!(matches!(
            history.start_attempt_without_backend([4_u8; 32], Role::Alice, key_share(13)?),
            Err(HistoryError::NotReady { .. })
        ));
        Ok(())
    }

    #[test]
    fn timeout_consumes_live_attempt_and_faults_history() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut history = PublicAttemptHistory::new([10_u8; 32], identities()?);
        let attempt =
            history.start_attempt_without_backend([5_u8; 32], Role::Alice, key_share(19)?)?;
        assert_eq!(
            attempt.record_timeout()?,
            AttemptOutcome::Fault {
                blamed_role: Some(Role::Alice),
                error: ProtocolError::Timeout,
            }
        );
        assert_eq!(history.state(), AttemptHistoryState::Faulted { attempt: 0 });
        Ok(())
    }

    #[test]
    fn retry_without_verified_terminal_faults_history() -> Result<(), Box<dyn std::error::Error>> {
        let mut history = PublicAttemptHistory::new([11_u8; 32], identities()?);
        let attempt =
            history.start_attempt_without_backend([6_u8; 32], Role::Bob, key_share(23)?)?;
        assert!(matches!(
            attempt.retry(),
            Err(HistoryError::RetryNotVerified)
        ));
        assert_eq!(history.state(), AttemptHistoryState::Faulted { attempt: 0 });
        assert!(matches!(
            history.start_attempt_without_backend([6_u8; 32], Role::Bob, key_share(29)?),
            Err(HistoryError::NotReady { .. })
        ));
        Ok(())
    }

    #[test]
    fn authenticated_reuse_is_rejected_before_transcript_advance()
    -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let first = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3_u8; 32])?);
        let second = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7_u8; 32])?);
        let (first_public, _) = first.x_only_public_key();
        let (second_public, _) = second.x_only_public_key();
        let identities = CanonicalIdentities::new(first_public, second_public)?;
        let alice_key = if first_public == *identities.alice() {
            &first
        } else {
            &second
        };

        let game_id = [12_u8; 32];
        let circuit_id = [7_u8; 32];
        let reused_commitment = [42_u8; 32];
        let mut history = PublicAttemptHistory::new(game_id, identities);
        history.state = AttemptHistoryState::Ready { attempt: 1 };
        history.circuit_id = Some(circuit_id);
        history.component_owners.insert(
            component_fingerprint(PublicComponentKind::CommitDigest, &reused_commitment),
            0,
        );

        let mut attempt =
            history.start_attempt_without_backend(circuit_id, Role::Alice, key_share(31)?)?;
        let expected = attempt.verifier().schedule().expected()?;
        let root_before = attempt.verifier().schedule().transcript_root();
        let payload = ProtocolPayload::KeyCommit(CommitmentPayload {
            commitment: reused_commitment,
        });
        let envelope = sign_envelope(
            &secp,
            &UnsignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                game_id,
                attempt: 1,
                round: expected.round,
                sender_role: expected.sender,
                sequence: expected.sequence,
                previous_message_hash: root_before,
                payload_type: payload.payload_type(),
                payload: payload.encode_body()?,
            },
            alice_key,
            &identities,
            &[9_u8; 32],
        )?;
        let result = attempt.accept(&secp, &envelope);
        assert!(
            matches!(
                result,
                Err(AttemptDriverError::SignedSemanticFault {
                    signer: Role::Alice,
                    error: ProtocolError::ReusedPublicMaterial,
                })
            ),
            "{result:?}"
        );
        assert_eq!(attempt.verifier().schedule().next_sequence(), 0);
        assert_eq!(attempt.verifier().schedule().transcript_root(), root_before);
        assert!(attempt.verifier().authenticated_archive().is_empty());
        assert!(attempt.secrets().is_none());
        drop(attempt);
        assert_eq!(history.state(), AttemptHistoryState::Faulted { attempt: 1 });
        Ok(())
    }

    #[test]
    fn rejected_attempt_material_reuse_is_rejected_even_after_reordering()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = InventoryBuilder::default();
        first.push(PublicComponentKind::HashLock, &[1_u8; 32]);
        first.push(PublicComponentKind::ValueCommitment, &[2_u8; 32]);
        let first = first.finish();

        let mut second = InventoryBuilder::default();
        second.push(PublicComponentKind::ValueCommitment, &[3_u8; 32]);
        second.push(PublicComponentKind::HashLock, &[1_u8; 32]);
        let second = second.finish();

        let mut history = PublicAttemptHistory::new([8_u8; 32], identities()?);
        for component in &first.components {
            history.component_owners.insert(*component, 0);
        }
        assert_eq!(
            history.ensure_fresh(1, &second),
            Err(HistoryError::ReusedPublicComponent {
                kind: PublicComponentKind::HashLock,
                first_attempt: 0,
                attempt: 1,
            })
        );
        Ok(())
    }

    #[test]
    fn base_g_fingerprint_detects_cross_role_scalar_reuse() -> Result<(), Box<dyn std::error::Error>>
    {
        let generators = ProtocolGenerators::derive()?;
        let point = (Scalar::from(37_u64) * generators.blinding())
            .compress()
            .to_bytes();
        let semantic_kinds = [
            PublicComponentKind::PublicKey,
            PublicComponentKind::CiphertextR,
            PublicComponentKind::ScalePoint,
            PublicComponentKind::ProofPoint,
        ];

        for pair in semantic_kinds.windows(2) {
            let mut rejected = InventoryBuilder::default();
            rejected.push_base_g(pair[0], &point);
            let rejected = rejected.finish();
            let mut current = InventoryBuilder::default();
            current.push_base_g(pair[1], &point);
            let current = current.finish();

            let mut history = PublicAttemptHistory::new([13_u8; 32], identities()?);
            for component in &rejected.components {
                history.component_owners.insert(*component, 0);
            }
            assert_eq!(
                history.ensure_fresh(1, &current),
                Err(HistoryError::ReusedPublicComponent {
                    kind: PublicComponentKind::BaseGPoint,
                    first_attempt: 0,
                    attempt: 1,
                })
            );
        }
        Ok(())
    }

    #[test]
    fn concrete_secret_owner_is_zeroize_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        fn require_traits<T: Zeroize + ZeroizeOnDrop>() {}
        require_traits::<AttemptSecrets>();
        let generators = ProtocolGenerators::derive()?;
        let secrets = AttemptSecrets::new(Role::Bob, key_share(17)?);
        assert_eq!(
            secrets.key_share().public_key(&generators),
            key_share(17)?.public_key(&generators)
        );
        assert!(secrets.contribution().is_none());
        Ok(())
    }
}
