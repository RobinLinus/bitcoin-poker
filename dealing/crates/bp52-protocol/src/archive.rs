//! Replay and verification of complete accepted-deal archives.
//!
//! This module is intentionally independent of [`crate::history`]. An archive
//! verifier checks one self-contained certificate; it does not decide whether
//! an attempt may be started, retried, or accepted in a caller's local
//! history.

use bitcoin::secp256k1::{Secp256k1, Verification};
use bp52_circuit::hash_length::HashLengthParameters;

use crate::{
    auth::{AuthError, CanonicalIdentities},
    driver::{AttemptDriverError, AttemptProgress, AttemptVerifier},
    messages::{AcceptedDeal, AcceptedDealBody, Envelope},
};

/// The exact number of signed envelopes in a complete v1 attempt.
pub const ACCEPTED_ARCHIVE_LENGTH: usize = 16;

/// Precise failures returned by [`verify_accepted_archive`].
#[derive(Debug, thiserror::Error)]
pub enum AcceptedArchiveError {
    /// The supplied archive was not exactly one complete v1 attempt.
    #[error("accepted archive must contain exactly {expected} envelopes (got {actual})")]
    WrongEnvelopeCount {
        /// Required number of envelopes.
        expected: usize,
        /// Number supplied by the caller.
        actual: usize,
    },
    /// One signed envelope failed authentication, scheduling, or semantic
    /// verification. The index is zero based in canonical archive order.
    #[error("archive replay failed at envelope {sequence}: {source}")]
    Replay {
        /// Zero-based envelope index being replayed.
        sequence: usize,
        /// Exact driver failure.
        #[source]
        source: AttemptDriverError,
    },
    /// The final replay result was not a unique accepted attempt.
    #[error("archive replay ended in {progress}, not ReadyToSign")]
    NotReady {
        /// Terminal/nonterminal progress reached by the replay.
        progress: ArchiveProgress,
    },
    /// The certificate body did not equal the body derived by semantic replay.
    #[error("accepted deal body does not match the replayed body")]
    BodyMismatch {
        /// Body derived from all sixteen verified envelopes.
        expected: Box<AcceptedDealBody>,
        /// Body carried by the supplied accepted certificate.
        actual: Box<AcceptedDealBody>,
    },
    /// One of the two acceptance signatures was malformed or invalid.
    #[error("accepted-deal signature verification failed: {0}")]
    Signatures(#[from] AuthError),
}

/// The progress states that can be observed at the end of archive replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArchiveProgress {
    /// A complete replay unexpectedly still requested another envelope.
    #[error("Continue")]
    Continue,
    /// The derived `R` was the neutral identity and the attempt requires a
    /// fresh attempt number.
    #[error("DegenerateRetry")]
    DegenerateRetry,
    /// One of the fixed zero tests found a card collision.
    #[error("CollisionRetry")]
    CollisionRetry,
}

/// Opaque evidence that an accepted certificate was authenticated and its
/// complete sixteen-envelope archive was semantically replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedAcceptedDeal {
    deal: AcceptedDeal,
}

impl VerifiedAcceptedDeal {
    pub(crate) const fn from_authenticated_deal(deal: AcceptedDeal) -> Self {
        Self { deal }
    }

    /// Borrows the exact accepted certificate that was verified.
    #[must_use]
    pub const fn as_deal(&self) -> &AcceptedDeal {
        &self.deal
    }

    /// Returns the exact accepted certificate that was verified.
    #[must_use]
    pub const fn deal(&self) -> AcceptedDeal {
        self.deal
    }

    /// Returns the exact body covered by both verified acceptance signatures.
    #[must_use]
    pub const fn body(&self) -> AcceptedDealBody {
        self.deal.body()
    }
}

/// Replays a complete signed archive and verifies an accepted-deal certificate.
///
/// The verifier constructs a fresh semantic [`AttemptVerifier`] for the
/// certificate's `(game_id, attempt)` pair, consumes exactly sixteen
/// authenticated envelopes in order, requires the final transition to be
/// [`AttemptProgress::ReadyToSign`], compares every field of the derived body
/// (including `T_16`) with `deal`, and finally verifies both canonical BIP340
/// acceptance signatures. No history or retry policy is consulted.
///
/// # Errors
///
/// Returns [`AcceptedArchiveError::WrongEnvelopeCount`] for a short or extra
/// archive, [`AcceptedArchiveError::Replay`] for any authentication, schedule,
/// or semantic failure, [`AcceptedArchiveError::NotReady`] for a terminal
/// retry/collision result, [`AcceptedArchiveError::BodyMismatch`] when the
/// certificate is not the one derived by replay, or
/// [`AcceptedArchiveError::Signatures`] for invalid acceptance signatures.
pub fn verify_accepted_archive<C: Verification>(
    secp: &Secp256k1<C>,
    identities: &CanonicalIdentities,
    parameters: &HashLengthParameters,
    deal: &AcceptedDeal,
    envelopes: &[Envelope],
) -> Result<VerifiedAcceptedDeal, AcceptedArchiveError> {
    if envelopes.len() != ACCEPTED_ARCHIVE_LENGTH {
        return Err(AcceptedArchiveError::WrongEnvelopeCount {
            expected: ACCEPTED_ARCHIVE_LENGTH,
            actual: envelopes.len(),
        });
    }

    let mut replay = AttemptVerifier::new(deal.game_id, deal.attempt, *identities, parameters);
    let mut final_progress = None;
    for (sequence, envelope) in envelopes.iter().enumerate() {
        let progress = replay
            .accept(secp, envelope)
            .map_err(|source| AcceptedArchiveError::Replay { sequence, source })?;
        final_progress = Some(progress);
    }

    let token = match final_progress {
        Some(AttemptProgress::ReadyToSign(token)) => token,
        Some(AttemptProgress::Continue { .. }) | None => {
            return Err(AcceptedArchiveError::NotReady {
                progress: ArchiveProgress::Continue,
            });
        }
        Some(AttemptProgress::DegenerateRetry(_)) => {
            return Err(AcceptedArchiveError::NotReady {
                progress: ArchiveProgress::DegenerateRetry,
            });
        }
        Some(AttemptProgress::CollisionRetry(_)) => {
            return Err(AcceptedArchiveError::NotReady {
                progress: ArchiveProgress::CollisionRetry,
            });
        }
    };

    let expected = token.body();
    let actual = deal.body();
    if expected != actual {
        return Err(AcceptedArchiveError::BodyMismatch {
            expected: Box::new(expected),
            actual: Box::new(actual),
        });
    }

    // `finalize` checks Alice and Bob against the exact body produced by the
    // semantic replay. Its returned value is therefore the authenticated
    // certificate, not merely an unchecked copy of caller input.
    let checked_deal = token.finalize(secp, deal.signature_a, deal.signature_b)?;
    Ok(VerifiedAcceptedDeal::from_authenticated_deal(checked_deal))
}
