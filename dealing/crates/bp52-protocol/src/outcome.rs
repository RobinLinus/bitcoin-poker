//! Public attempt outcomes and fault attribution.

use crate::{Role, messages::AcceptedDeal};

/// Number of collision predicates reported for a rejected attempt.
pub const COLLISION_TEST_COUNT: usize = 108;

/// High-level protocol faults. Normal collisions and neutral cryptographic
/// retries are represented separately by [`AttemptOutcome`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    /// Canonical message decoding failed.
    #[error("malformed canonical encoding")]
    MalformedEncoding,
    /// A compressed Ristretto point was invalid.
    #[error("noncanonical Ristretto point")]
    NonCanonicalPoint,
    /// A scalar encoding was not canonical.
    #[error("noncanonical scalar")]
    NonCanonicalScalar,
    /// A message used another protocol version.
    #[error("wrong protocol version")]
    WrongProtocolVersion,
    /// A message belongs to another funded game.
    #[error("wrong game")]
    WrongGame,
    /// A message belongs to another attempt.
    #[error("wrong attempt")]
    WrongAttempt,
    /// A message was sent in another round.
    #[error("wrong round")]
    WrongRound,
    /// A signed envelope had an unexpected sequence, sender, or payload type.
    #[error("unexpected authenticated protocol message")]
    UnexpectedMessage,
    /// BIP340 authentication failed.
    #[error("invalid signature")]
    InvalidSignature,
    /// Sequence or transcript-predecessor validation failed.
    #[error("transcript mismatch")]
    TranscriptMismatch,
    /// A commit/open digest did not match.
    #[error("bundle or batch commitment mismatch")]
    CommitmentMismatch,
    /// Two hash locks were equal where global distinctness is required.
    #[error("duplicate SHA-256 hash lock")]
    DuplicateHash,
    /// A threshold-key proof failed.
    #[error("invalid threshold key proof")]
    InvalidKeyProof,
    /// The SHA-256/preimage-length proof failed.
    #[error("invalid hash-length proof")]
    InvalidHashLengthProof,
    /// The Pedersen-to-ElGamal link proof failed.
    #[error("invalid encryption-link proof")]
    InvalidEncryptionLinkProof,
    /// A ciphertext scale proof failed.
    #[error("invalid scale proof")]
    InvalidScaleProof,
    /// A zero scale factor was supplied.
    #[error("zero scale factor")]
    ZeroScaleFactor,
    /// A same-key partial-decryption proof failed.
    #[error("invalid partial-decryption proof")]
    InvalidPartialDecryptionProof,
    /// A contextually forbidden identity point occurred.
    #[error("unexpected identity point")]
    UnexpectedIdentity,
    /// A declared payload or proof exceeded its compile-time bound.
    #[error("message too large")]
    MessageTooLarge,
    /// A scheduled message did not arrive before the outer deadline.
    #[error("protocol timeout")]
    Timeout,
    /// A bounded RNG rejection loop was exhausted.
    #[error("random source failure")]
    RngFailure,
    /// Ephemeral public material matched an earlier attempt fingerprint.
    #[error("reused public attempt material")]
    ReusedPublicMaterial,
    /// An integer sequence or attempt number would overflow.
    #[error("protocol counter overflow")]
    CounterOverflow,
}

/// Terminal disposition of one attempt.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    /// All proofs and zero tests verified, and both acceptance signatures exist.
    Accepted(AcceptedDeal),
    /// At least one of the 108 plaintext differences was zero.
    CollisionRetry {
        /// Canonical `(i,j,t)` collision result vector.
        collision_bitmap: [bool; COLLISION_TEST_COUNT],
    },
    /// A negligible derived-randomness cancellation requires a fresh attempt
    /// without blaming either party.
    DegenerateRetry,
    /// An authenticated protocol fault. `blamed_role=None` denotes a setup
    /// failure that cannot safely be attributed to one participant.
    Fault {
        /// Authenticated role at fault, if attribution is sound.
        blamed_role: Option<Role>,
        /// Fail-closed fault category.
        error: ProtocolError,
    },
}

impl AttemptOutcome {
    /// Constructs a normal collision retry without misclassifying it as fraud.
    #[must_use]
    pub const fn collision(bitmap: [bool; COLLISION_TEST_COUNT]) -> Self {
        Self::CollisionRetry {
            collision_bitmap: bitmap,
        }
    }

    /// Constructs a fault attributed to a validly authenticated sender.
    #[must_use]
    pub const fn sender_fault(role: Role, error: ProtocolError) -> Self {
        Self::Fault {
            blamed_role: Some(role),
            error,
        }
    }

    /// Constructs a fault attributed to the role whose valid signature covered
    /// the invalid protocol message.
    #[must_use]
    pub const fn signer_fault(role: Role, error: ProtocolError) -> Self {
        Self::sender_fault(role, error)
    }

    /// Constructs a timeout fault attributed to the role whose scheduled
    /// envelope did not arrive.
    #[must_use]
    pub const fn timeout(waiting_for: Role) -> Self {
        Self::sender_fault(waiting_for, ProtocolError::Timeout)
    }

    /// Constructs a fault or invalid setup with no safe blame assignment.
    #[must_use]
    pub const fn unattributed_fault(error: ProtocolError) -> Self {
        Self::Fault {
            blamed_role: None,
            error,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Role;

    use super::{AttemptOutcome, COLLISION_TEST_COUNT, ProtocolError};

    #[test]
    fn collisions_and_degenerate_retries_are_not_faults() {
        let mut bitmap = [false; COLLISION_TEST_COUNT];
        bitmap[17] = true;
        assert!(matches!(
            AttemptOutcome::collision(bitmap),
            AttemptOutcome::CollisionRetry { .. }
        ));
        assert!(matches!(
            AttemptOutcome::DegenerateRetry,
            AttemptOutcome::DegenerateRetry
        ));
        assert!(matches!(
            AttemptOutcome::unattributed_fault(ProtocolError::UnexpectedIdentity),
            AttemptOutcome::Fault {
                blamed_role: None,
                ..
            }
        ));
        assert!(matches!(
            AttemptOutcome::signer_fault(Role::Bob, ProtocolError::WrongRound),
            AttemptOutcome::Fault {
                blamed_role: Some(Role::Bob),
                error: ProtocolError::WrongRound,
            }
        ));
        assert!(matches!(
            AttemptOutcome::timeout(Role::Alice),
            AttemptOutcome::Fault {
                blamed_role: Some(Role::Alice),
                error: ProtocolError::Timeout,
            }
        ));
    }
}
