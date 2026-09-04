//! Canonical authenticated-envelope schedule for one protocol attempt.

#[cfg(test)]
use bitcoin::secp256k1::{Secp256k1, Verification};
use bp52_codec::{CodecError, Encode};
use bp52_group::hash::TaggedHash;

use crate::{
    PROTOCOL_VERSION, Role,
    auth::AuthError,
    messages::{Envelope, PayloadType},
    outcome::{AttemptOutcome, ProtocolError},
    transcript::{AttemptContext, TranscriptHash},
};

/// Number of signed envelopes hashed into one accepted attempt transcript.
pub const ATTEMPT_ENVELOPE_COUNT: u32 = 16;

/// Tagged-hash domain used to select the first uniqueness blinder.
pub const FIRST_BLINDER_TAG: &[u8] = b"BP52/first-blinder/v1";

/// Metadata fixed for one position in the v1 attempt schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedEnvelope {
    /// Global zero-based envelope sequence.
    pub sequence: u32,
    /// Protocol round identifier.
    pub round: u16,
    /// Required authenticated sender.
    pub sender: Role,
    /// Required payload type.
    pub payload_type: PayloadType,
}

/// Errors raised before an envelope can advance the transcript.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    /// The attempt has already consumed its 16 protocol envelopes.
    #[error("attempt envelope schedule is complete")]
    Complete,
    /// The envelope was encoded under another protocol version.
    #[error("wrong protocol version")]
    WrongProtocolVersion,
    /// The envelope belongs to another game.
    #[error("wrong game identifier")]
    WrongGame,
    /// The envelope belongs to another attempt.
    #[error("wrong attempt number")]
    WrongAttempt,
    /// The sequence was stale, repeated, skipped, or otherwise unexpected.
    #[error("wrong envelope sequence")]
    WrongSequence,
    /// The round did not match the canonical sequence entry.
    #[error("wrong protocol round")]
    WrongRound,
    /// The authenticated sender was not scheduled at this sequence.
    #[error("wrong envelope sender")]
    WrongSender,
    /// The payload type did not match the canonical sequence entry.
    #[error("wrong envelope payload type")]
    WrongPayloadType,
    /// The predecessor did not equal the current transcript root.
    #[error("transcript predecessor mismatch")]
    TranscriptMismatch,
    /// Canonical envelope encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
}

impl ScheduleError {
    /// Returns whether this error only says that an authenticated envelope is
    /// outside the exact live attempt cursor.
    ///
    /// Such traffic can be a replay or an envelope routed from another game,
    /// attempt, protocol version, or transcript fork. It cannot soundly be
    /// blamed on its signer and must not poison the live attempt.
    pub(crate) const fn is_out_of_context(&self) -> bool {
        matches!(
            self,
            Self::Complete
                | Self::WrongProtocolVersion
                | Self::WrongGame
                | Self::WrongAttempt
                | Self::WrongSequence
                | Self::TranscriptMismatch
        )
    }
}

/// Authentication or schedule failure while consuming an envelope.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeAcceptanceError {
    /// BIP340 authentication or canonical signed encoding failed.
    #[error(transparent)]
    Authentication(#[from] AuthError),
    /// The signature was valid, but the envelope was not addressed to the
    /// exact live attempt cursor. This is a routing/filtering result, not a
    /// protocol fault attributable to the signer.
    #[error("authenticated envelope is outside the live attempt context: {source}")]
    OutOfContext {
        /// Exact context field that did not match.
        #[source]
        source: ScheduleError,
    },
    /// Authenticated metadata was invalid for the current attempt state. Since
    /// signature verification precedes schedule validation, `signer` is safe
    /// to use for fault attribution.
    #[error("authenticated signer {signer:?} violated the envelope schedule: {source}")]
    SignedProtocolFault {
        /// Role whose valid signature covered the invalid metadata.
        signer: Role,
        /// Exact schedule failure covered by the valid signature.
        #[source]
        source: ScheduleError,
    },
}

impl EnvelopeAcceptanceError {
    /// Returns the authenticated signer when blame assignment is sound.
    #[must_use]
    pub const fn blamed_role(&self) -> Option<Role> {
        match self {
            Self::Authentication(_) | Self::OutOfContext { .. } => None,
            Self::SignedProtocolFault { signer, .. } => Some(*signer),
        }
    }

    /// Converts a genuine protocol failure to the public outcome taxonomy.
    ///
    /// Out-of-context traffic has no outcome for the live attempt.
    #[must_use]
    pub fn fault_outcome(&self) -> Option<AttemptOutcome> {
        match self {
            Self::Authentication(error) => Some(AttemptOutcome::unattributed_fault(
                protocol_error_from_auth(*error),
            )),
            Self::SignedProtocolFault { signer, source } => Some(AttemptOutcome::signer_fault(
                *signer,
                protocol_error_from_schedule(source),
            )),
            Self::OutOfContext { .. } => None,
        }
    }
}

/// Public hash-chain cursor for a single attempt.
///
/// Signature verification is deliberately kept outside this type. The only
/// state-mutating acceptance method is crate-private so the eventual protocol
/// driver must authenticate an envelope before calling it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptSchedule {
    context: AttemptContext,
    next_sequence: u32,
    first_blinder: Role,
}

impl AttemptSchedule {
    /// Starts at `T_0`, sequence zero.
    #[must_use]
    pub fn new(game_id: [u8; 32], attempt: u32) -> Self {
        Self {
            context: AttemptContext::new(game_id, attempt),
            next_sequence: 0,
            first_blinder: first_blinder(&game_id, attempt),
        }
    }

    /// Returns the funded game identifier for this attempt.
    #[must_use]
    pub const fn game_id(&self) -> [u8; 32] {
        self.context.game_id
    }

    /// Returns the zero-based attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.context.attempt
    }

    /// Returns the current transcript root before the next envelope.
    #[must_use]
    pub const fn transcript_root(&self) -> TranscriptHash {
        self.context.prior_transcript
    }

    /// Returns the next global sequence number.
    #[must_use]
    pub const fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    /// Returns `true` only after all 16 exact scheduled envelopes were
    /// authenticated and hashed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.next_sequence == ATTEMPT_ENVELOPE_COUNT
    }

    /// Returns `T_16` only for a fully consumed attempt schedule.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::WrongSequence`] before all 16 envelopes have
    /// been consumed.
    pub const fn completed_transcript_root(&self) -> Result<TranscriptHash, ScheduleError> {
        if self.is_complete() {
            Ok(self.context.prior_transcript)
        } else {
            Err(ScheduleError::WrongSequence)
        }
    }

    /// Returns the deterministic first blinder for this attempt.
    #[must_use]
    pub const fn first_blinder(&self) -> Role {
        self.first_blinder
    }

    /// Returns the next required sender/round/type tuple.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::Complete`] after all 16 envelopes were
    /// consumed.
    pub fn expected(&self) -> Result<ExpectedEnvelope, ScheduleError> {
        expected_envelope(self.next_sequence, self.first_blinder).ok_or(ScheduleError::Complete)
    }

    /// Validates every schedule and transcript header field without mutating.
    ///
    /// # Errors
    ///
    /// Returns the precise version, game, attempt, sequence, transcript,
    /// round, signer, payload, or completion mismatch.
    pub fn validate_header(&self, envelope: &Envelope) -> Result<(), ScheduleError> {
        let unsigned = &envelope.unsigned;
        self.validate_context_fields(
            unsigned.protocol_version,
            unsigned.game_id,
            unsigned.attempt,
            unsigned.sequence,
            unsigned.previous_message_hash,
        )?;
        let expected = self.expected()?;
        if unsigned.round != expected.round {
            return Err(ScheduleError::WrongRound);
        }
        if unsigned.sender_role != expected.sender {
            return Err(ScheduleError::WrongSender);
        }
        if unsigned.payload_type != expected.payload_type {
            return Err(ScheduleError::WrongPayloadType);
        }
        Ok(())
    }

    pub(crate) fn validate_context_fields(
        &self,
        protocol_version: u16,
        game_id: [u8; 32],
        attempt: u32,
        sequence: u32,
        previous_message_hash: TranscriptHash,
    ) -> Result<(), ScheduleError> {
        if protocol_version != PROTOCOL_VERSION {
            return Err(ScheduleError::WrongProtocolVersion);
        }
        if game_id != self.context.game_id {
            return Err(ScheduleError::WrongGame);
        }
        if attempt != self.context.attempt {
            return Err(ScheduleError::WrongAttempt);
        }
        if sequence != self.next_sequence {
            return Err(ScheduleError::WrongSequence);
        }
        if previous_message_hash != self.context.prior_transcript {
            return Err(ScheduleError::TranscriptMismatch);
        }
        Ok(())
    }

    /// Authenticates, schedule-checks, canonically encodes, and hashes one
    /// envelope in that order.
    ///
    /// The transcript is unchanged on every error path.
    ///
    /// # Errors
    ///
    /// Returns an unattributed authentication error if the signature cannot be
    /// trusted, or a signer-attributed schedule error after authentication.
    #[cfg(test)]
    pub(crate) fn accept_envelope<C: Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        identities: &crate::auth::CanonicalIdentities,
        envelope: &Envelope,
    ) -> Result<TranscriptHash, EnvelopeAcceptanceError> {
        crate::auth::verify_envelope(secp, envelope, identities)?;
        self.advance_authenticated(envelope)
            .map_err(|source| authenticated_schedule_error(envelope.unsigned.sender_role, source))
    }

    /// Attributes a timeout to the role whose exact envelope is currently due.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::Complete`] when no message remains due after
    /// the complete 16-envelope lifecycle.
    pub fn timeout_outcome(&self) -> Result<AttemptOutcome, ScheduleError> {
        Ok(AttemptOutcome::timeout(self.expected()?.sender))
    }

    pub(crate) fn advance_authenticated(
        &mut self,
        envelope: &Envelope,
    ) -> Result<TranscriptHash, ScheduleError> {
        self.validate_header(envelope)?;
        let encoded = envelope.encode_to_vec()?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ScheduleError::WrongSequence)?;
        let root = self.context.advance(&encoded);
        self.next_sequence = next_sequence;
        Ok(root)
    }

    /// Advances an already-authenticated envelope during state-machine fuzzing.
    ///
    /// This hook is excluded from normal builds. Production callers must use
    /// [`crate::history::TrackedAttempt::accept_bytes`], which performs
    /// authentication, semantic validation, and retry-freshness checks before
    /// advancing the transcript.
    ///
    /// # Errors
    ///
    /// Returns a schedule or canonical-encoding error without changing the
    /// transcript cursor.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzzing_advance_authenticated(
        &mut self,
        envelope: &Envelope,
    ) -> Result<TranscriptHash, ScheduleError> {
        self.advance_authenticated(envelope)
    }
}

pub(crate) fn authenticated_schedule_error(
    signer: Role,
    source: ScheduleError,
) -> EnvelopeAcceptanceError {
    if source.is_out_of_context() {
        EnvelopeAcceptanceError::OutOfContext { source }
    } else {
        EnvelopeAcceptanceError::SignedProtocolFault { signer, source }
    }
}

fn protocol_error_from_auth(error: AuthError) -> ProtocolError {
    match error {
        AuthError::Codec(_) => ProtocolError::MalformedEncoding,
        AuthError::DuplicateIdentityKeys
        | AuthError::UnknownIdentityKey
        | AuthError::UnknownSenderRole
        | AuthError::RoleKeyMismatch
        | AuthError::InvalidSignature => ProtocolError::InvalidSignature,
    }
}

fn protocol_error_from_schedule(error: &ScheduleError) -> ProtocolError {
    match error {
        ScheduleError::Complete | ScheduleError::WrongSender | ScheduleError::WrongPayloadType => {
            ProtocolError::UnexpectedMessage
        }
        ScheduleError::WrongProtocolVersion => ProtocolError::WrongProtocolVersion,
        ScheduleError::WrongGame => ProtocolError::WrongGame,
        ScheduleError::WrongAttempt => ProtocolError::WrongAttempt,
        ScheduleError::WrongRound => ProtocolError::WrongRound,
        ScheduleError::WrongSequence | ScheduleError::TranscriptMismatch => {
            ProtocolError::TranscriptMismatch
        }
        ScheduleError::Codec(_) => ProtocolError::MalformedEncoding,
    }
}

/// Selects the first blinder from the low bit of the tagged digest.
#[must_use]
pub fn first_blinder(game_id: &[u8; 32], attempt: u32) -> Role {
    let mut hash = TaggedHash::new(FIRST_BLINDER_TAG);
    hash.update(game_id);
    hash.update(attempt.to_le_bytes());
    if hash.finalize()[0] & 1 == 0 {
        Role::Alice
    } else {
        Role::Bob
    }
}

/// Returns one canonical schedule entry, or `None` after sequence 15.
#[must_use]
pub const fn expected_envelope(sequence: u32, first_blinder: Role) -> Option<ExpectedEnvelope> {
    let other_blinder = match first_blinder {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    };
    let (round, sender, payload_type) = match sequence {
        0 => (0, Role::Alice, PayloadType::KeyCommit),
        1 => (0, Role::Bob, PayloadType::KeyCommit),
        2 => (1, Role::Alice, PayloadType::KeyOpen),
        3 => (1, Role::Bob, PayloadType::KeyOpen),
        4 => (2, Role::Alice, PayloadType::KeyProof),
        5 => (2, Role::Bob, PayloadType::KeyProof),
        6 => (3, Role::Alice, PayloadType::BundleCommit),
        7 => (3, Role::Bob, PayloadType::BundleCommit),
        8 => (4, Role::Alice, PayloadType::BundleOpen),
        9 => (4, Role::Bob, PayloadType::BundleOpen),
        10 => (5, first_blinder, PayloadType::BlindFirst),
        11 => (6, other_blinder, PayloadType::BlindSecond),
        12 => (7, Role::Alice, PayloadType::DecryptCommit),
        13 => (7, Role::Bob, PayloadType::DecryptCommit),
        14 => (8, Role::Alice, PayloadType::DecryptOpen),
        15 => (8, Role::Bob, PayloadType::DecryptOpen),
        _ => return None,
    };
    Some(ExpectedEnvelope {
        sequence,
        round,
        sender,
        payload_type,
    })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    use crate::{
        Role,
        auth::{derive_roles, sign_envelope},
        messages::{Envelope, UnsignedEnvelope},
        outcome::{AttemptOutcome, ProtocolError},
    };

    use super::{
        ATTEMPT_ENVELOPE_COUNT, AttemptSchedule, EnvelopeAcceptanceError, ScheduleError,
        expected_envelope, first_blinder,
    };

    fn scheduled_envelope(schedule: &AttemptSchedule) -> Result<Envelope, ScheduleError> {
        let expected = schedule.expected()?;
        Ok(Envelope {
            unsigned: UnsignedEnvelope {
                protocol_version: crate::PROTOCOL_VERSION,
                game_id: schedule.game_id(),
                attempt: schedule.attempt(),
                round: expected.round,
                sender_role: expected.sender,
                sequence: expected.sequence,
                previous_message_hash: schedule.transcript_root(),
                payload_type: expected.payload_type,
                payload: vec![0_u8; expected.payload_type.max_payload_len()],
            },
            signature: [1_u8; 64],
        })
    }

    fn keypair(secret_number: u8) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let mut secret = [0_u8; 32];
        secret[31] = secret_number;
        Keypair::from_seckey_slice(&secp, &secret)
    }

    #[test]
    fn all_sixteen_schedule_entries_are_fixed() {
        let first = first_blinder(&[7_u8; 32], 3);
        for sequence in 0..ATTEMPT_ENVELOPE_COUNT {
            let expected = expected_envelope(sequence, first);
            assert!(expected.is_some(), "missing sequence {sequence}");
            assert_eq!(expected.map(|entry| entry.sequence), Some(sequence));
        }
        assert_eq!(expected_envelope(ATTEMPT_ENVELOPE_COUNT, first), None);
    }

    #[test]
    fn cursor_rejects_reorder_replay_and_wrong_predecessor() {
        let game_id = [9_u8; 32];
        let mut schedule = AttemptSchedule::new(game_id, 0);
        let expected = schedule
            .expected()
            .unwrap_or_else(|error| panic!("{error}"));
        let valid = Envelope {
            unsigned: UnsignedEnvelope {
                protocol_version: crate::PROTOCOL_VERSION,
                game_id,
                attempt: 0,
                round: expected.round,
                sender_role: expected.sender,
                sequence: expected.sequence,
                previous_message_hash: schedule.transcript_root(),
                payload_type: expected.payload_type,
                payload: vec![0_u8; expected.payload_type.max_payload_len()],
            },
            signature: [1_u8; 64],
        };
        schedule
            .advance_authenticated(&valid)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            schedule.validate_header(&valid),
            Err(ScheduleError::WrongSequence)
        ));

        let expected = schedule
            .expected()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut reordered = valid;
        reordered.unsigned.sequence = expected.sequence + 1;
        assert!(matches!(
            schedule.validate_header(&reordered),
            Err(ScheduleError::WrongSequence)
        ));

        reordered.unsigned.sequence = expected.sequence;
        reordered.unsigned.round = expected.round;
        reordered.unsigned.sender_role = expected.sender;
        reordered.unsigned.payload_type = expected.payload_type;
        reordered.unsigned.previous_message_hash = [0_u8; 32];
        assert!(matches!(
            schedule.validate_header(&reordered),
            Err(ScheduleError::TranscriptMismatch)
        ));
    }

    #[test]
    fn t16_exists_only_after_the_exact_complete_lifecycle() -> Result<(), ScheduleError> {
        let mut schedule = AttemptSchedule::new([10_u8; 32], 4);
        assert!(!schedule.is_complete());
        assert!(matches!(
            schedule.completed_transcript_root(),
            Err(ScheduleError::WrongSequence)
        ));

        for sequence in 0..ATTEMPT_ENVELOPE_COUNT {
            assert_eq!(schedule.next_sequence(), sequence);
            let envelope = scheduled_envelope(&schedule)?;
            schedule.advance_authenticated(&envelope)?;
        }
        assert!(schedule.is_complete());
        assert_eq!(
            schedule.completed_transcript_root()?,
            schedule.transcript_root()
        );
        assert!(matches!(schedule.expected(), Err(ScheduleError::Complete)));

        let mut seventeenth = scheduled_envelope(&AttemptSchedule::new([10_u8; 32], 4))?;
        seventeenth.unsigned.sequence = ATTEMPT_ENVELOPE_COUNT;
        seventeenth.unsigned.previous_message_hash = schedule.transcript_root();
        assert!(matches!(
            schedule.advance_authenticated(&seventeenth),
            Err(ScheduleError::Complete)
        ));
        Ok(())
    }

    #[test]
    fn valid_signer_faults_and_timeouts_have_sound_blame() -> Result<(), Box<dyn std::error::Error>>
    {
        let secp = Secp256k1::new();
        let first = keypair(1)?;
        let second = keypair(2)?;
        let identities = derive_roles(first.x_only_public_key().0, second.x_only_public_key().0)?;
        let alice_key = if identities.role_for_key(&first.x_only_public_key().0)? == Role::Alice {
            &first
        } else {
            &second
        };
        let schedule = &mut AttemptSchedule::new([11_u8; 32], 0);
        assert!(matches!(
            schedule.timeout_outcome()?,
            AttemptOutcome::Fault {
                blamed_role: Some(Role::Alice),
                error: ProtocolError::Timeout,
            }
        ));

        let mut unsigned = scheduled_envelope(schedule)?.unsigned;
        unsigned.round = unsigned.round.saturating_add(1);
        let signed = sign_envelope(&secp, &unsigned, alice_key, &identities, &[3_u8; 32])?;
        let error = schedule
            .accept_envelope(&secp, &identities, &signed)
            .err()
            .ok_or_else(|| std::io::Error::other("wrong signed round was accepted"))?;
        assert_eq!(error.blamed_role(), Some(Role::Alice));
        assert!(matches!(
            &error,
            EnvelopeAcceptanceError::SignedProtocolFault {
                signer: Role::Alice,
                source: ScheduleError::WrongRound,
            }
        ));
        assert!(matches!(
            error.fault_outcome(),
            Some(AttemptOutcome::Fault {
                blamed_role: Some(Role::Alice),
                error: ProtocolError::WrongRound,
            })
        ));

        let unsigned = scheduled_envelope(schedule)?.unsigned;
        let invalid_signature = Envelope {
            unsigned,
            signature: [0_u8; 64],
        };
        let error = schedule
            .accept_envelope(&secp, &identities, &invalid_signature)
            .err()
            .ok_or_else(|| std::io::Error::other("invalid signature was accepted"))?;
        assert_eq!(error.blamed_role(), None);
        assert!(matches!(
            error.fault_outcome(),
            Some(AttemptOutcome::Fault {
                blamed_role: None,
                error: ProtocolError::InvalidSignature,
            })
        ));
        Ok(())
    }
}
