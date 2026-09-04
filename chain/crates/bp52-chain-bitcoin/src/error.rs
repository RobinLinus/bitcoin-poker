//! Fail-closed errors for Bitcoin program and transaction construction.

use bp52_bitcoin::OpeningError;
use bp52_lamport::LamportError;
use bp52_poker::PokerError;
use thiserror::Error;

/// Failure while constructing or evaluating the Bitcoin enforcement layer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum BitcoinBackendError {
    /// A share or card opening failed for one fixed deal slot.
    #[error("invalid card opening at slot {slot}: {source}")]
    InvalidOpening {
        /// Canonical deal slot whose opening failed.
        slot: u8,
        /// Exact native BP52 opening error.
        source: OpeningError,
    },
    /// A pure poker predicate rejected a hand or score.
    #[error(transparent)]
    Poker(#[from] PokerError),
    /// A Lamport key, signature, or context was invalid.
    #[error(transparent)]
    Lamport(#[from] LamportError),
    /// A fixed reveal contained the wrong number of preimages.
    #[error("reveal requires {expected} preimages, got {actual}")]
    WrongRevealCount {
        /// Required count for the reveal phase.
        expected: usize,
        /// Supplied count.
        actual: usize,
    },
    /// A script-path witness contained the wrong number of program elements.
    #[error("script-path witness requires {expected} program elements, got {actual}")]
    WrongWitnessElementCount {
        /// Required number of elements before the script and control block.
        expected: usize,
        /// Supplied number of elements.
        actual: usize,
    },
    /// A card-opening witness named a slot outside the nine-card deal.
    #[error("invalid deal slot {slot}; expected 0..=8")]
    InvalidDealSlot {
        /// Rejected slot number.
        slot: u8,
    },
    /// A showdown opening appeared at the wrong position.
    #[error("showdown opening {position} must be slot {expected}, got {actual}")]
    WrongShowdownSlot {
        /// Position in the ordered seven-card witness.
        position: usize,
        /// Slot fixed by the player's seven-card ordering.
        expected: u8,
        /// Supplied slot.
        actual: u8,
    },
    /// Alice's signed score differed from her selected-hand score.
    #[error("Alice certificate score {certificate} differs from hand score {hand}")]
    AliceCertificateMismatch {
        /// Score covered by the certificate.
        certificate: u32,
        /// Score witnessed by Alice's selected cards.
        hand: u32,
    },
    /// Bob's signed score differed from his selected-hand score.
    #[error("Bob certificate score {certificate} differs from hand score {hand}")]
    BobCertificateMismatch {
        /// Score covered by the certificate.
        certificate: u32,
        /// Score witnessed by Bob's selected cards.
        hand: u32,
    },
    /// Scores did not satisfy the selected payout branch.
    #[error("scores A={score_a:#08x}, B={score_b:#08x} do not satisfy {outcome}")]
    WrongShowdownOutcome {
        /// Alice's verified canonical score.
        score_a: u32,
        /// Bob's verified canonical score.
        score_b: u32,
        /// Stable branch name.
        outcome: &'static str,
    },
    /// A serialized x-only public key was invalid.
    #[error("invalid x-only public key for {purpose}")]
    InvalidXOnlyPublicKey {
        /// Stable key purpose.
        purpose: &'static str,
    },
    /// A required game or node identifier was all zero.
    #[error("{field} must not be the all-zero identifier")]
    ZeroIdentifier {
        /// Stable identifier field name.
        field: &'static str,
    },
    /// A Taproot signature was not the exact implicit-DEFAULT encoding.
    #[error("Taproot SIGHASH_DEFAULT signature must be exactly 64 bytes")]
    NonDefaultSighashEncoding,
    /// A BIP340 signature failed verification.
    #[error("invalid BIP340 signature")]
    InvalidBitcoinSignature,
    /// A Taproot tree or control block could not be constructed.
    #[error("failed to construct deterministic Taproot tree")]
    TaprootConstruction,
    /// A state output was requested without any spend leaf.
    #[error("Taproot state requires at least one spend leaf")]
    EmptyTaprootTree,
    /// Too many leaves were requested for the bounded v1 state profile.
    #[error("Taproot state has {actual} executable leaves, exceeding {maximum}")]
    TooManyTaprootLeaves {
        /// Supplied number of leaves.
        actual: usize,
        /// Defensive implementation maximum.
        maximum: usize,
    },
    /// Two logical leaves compiled to the same predicate identifier.
    #[error("duplicate Taproot predicate identifier")]
    DuplicatePredicateId,
    /// A generated consensus script exceeded Bitcoin's script-size limit.
    #[error("consensus script has {actual} bytes, exceeding {maximum}")]
    OversizedConsensusScript {
        /// Generated script length.
        actual: usize,
        /// Enforced maximum.
        maximum: usize,
    },
    /// A witness item exceeded Bitcoin's stack-element limit.
    #[error("witness element has {actual} bytes, exceeding {maximum}")]
    OversizedWitnessElement {
        /// Supplied element length.
        actual: usize,
        /// Enforced maximum.
        maximum: usize,
    },
    /// The requested semantic predicate has no reviewed consensus compiler.
    #[error("unsupported consensus predicate: {kind}")]
    UnsupportedConsensusProgram {
        /// Predicate class deliberately rejected rather than weakened.
        kind: &'static str,
    },
    /// A version-2 transaction template violated a structural invariant.
    #[error("invalid transaction template: {reason}")]
    InvalidTransactionTemplate {
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// Input or output amount arithmetic failed or exceeded Bitcoin's cap.
    #[error("transaction amount arithmetic is invalid")]
    InvalidTransactionAmount,
    /// A BIP341 sighash could not be computed for the transaction and prevouts.
    #[error("failed to compute BIP341 SIGHASH_DEFAULT digest")]
    SighashComputation,
    /// Real-funds mainnet use is disabled by the prototype.
    #[error("BP52-CHAIN-v1 mainnet construction is disabled")]
    MainnetDisabled,
    /// A descriptor named neither a supported standard genesis nor a
    /// recognized challenge-bound custom signet identifier.
    #[error("unknown Bitcoin network identifier")]
    UnknownNetworkGenesis,
    /// The exact network identifier contradicts the configured Bitcoin
    /// transaction/address parameter family.
    #[error("Bitcoin network identifier does not match the configured network")]
    NetworkIdentityMismatch,
}
