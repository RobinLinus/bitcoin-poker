//! Terminal outcomes and settlement accounting.

use crate::{
    ChainError,
    descriptor::{Role, TimeoutSettlementPolicy},
    state::{AmountState, TimeoutKind},
};

/// Branch selected by the comparison of Bob's verified score to Alice's.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ShowdownOutcome {
    /// Alice's score is greater than Bob's score.
    AliceWin = 0,
    /// Bob's score is greater than Alice's score.
    BobWin = 1,
    /// Both canonical packed scores are equal.
    Split = 2,
}

impl ShowdownOutcome {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Human- and manifest-visible reason for a terminal settlement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SettlementReason {
    /// A player selected the fold action.
    Fold = 0,
    /// The active player missed an action deadline.
    ActionTimeout = 1,
    /// A designated player missed a share-reveal deadline.
    RevealTimeout = 2,
    /// Alice or Bob missed a showdown deadline.
    ShowdownTimeout = 3,
    /// Both showdown claims were supplied and compared.
    Showdown = 4,
}

impl SettlementReason {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Complete semantic outcome of a terminal branch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TerminalOutcome {
    /// One player explicitly folded.
    Fold {
        /// Player surrendering the pot.
        folded: Role,
    },
    /// One player failed a node-specific deadline.
    Timeout {
        /// Class of missed obligation.
        kind: TimeoutKind,
        /// Player who failed the obligation.
        defaulting: Role,
    },
    /// Both verified hand scores selected a terminal comparison branch.
    Showdown(ShowdownOutcome),
}

impl TerminalOutcome {
    /// Returns the settlement reason independent of winner.
    #[must_use]
    pub const fn reason(self) -> SettlementReason {
        match self {
            Self::Fold { .. } => SettlementReason::Fold,
            Self::Timeout {
                kind: TimeoutKind::Action,
                ..
            } => SettlementReason::ActionTimeout,
            Self::Timeout {
                kind: TimeoutKind::Reveal,
                ..
            } => SettlementReason::RevealTimeout,
            Self::Timeout {
                kind: TimeoutKind::Showdown,
                ..
            } => SettlementReason::ShowdownTimeout,
            Self::Showdown(_) => SettlementReason::Showdown,
        }
    }

    /// Returns the single winner or `None` for a split.
    #[must_use]
    pub const fn winner(self) -> Option<Role> {
        match self {
            Self::Fold { folded } => Some(folded.other()),
            Self::Timeout { defaulting, .. } => Some(defaulting.other()),
            Self::Showdown(ShowdownOutcome::AliceWin) => Some(Role::Alice),
            Self::Showdown(ShowdownOutcome::BobWin) => Some(Role::Bob),
            Self::Showdown(ShowdownOutcome::Split) => None,
        }
    }
}

/// Checked terminal player amounts before fee-reserve disposition.
///
/// The exact fee policy consumes or assigns `fee_reserve_remaining` when it
/// builds terminal outputs. Keeping that amount explicit prevents this pure
/// poker-accounting layer from silently assigning a reserve whose disposition
/// is identified only by `fee_policy_id`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TerminalAccounting {
    /// Value due to Alice before fee-reserve disposition.
    pub alice_sat: u64,
    /// Value due to Bob before fee-reserve disposition.
    pub bob_sat: u64,
    /// Dedicated reserve still requiring deterministic fee-policy treatment.
    pub fee_reserve_remaining: u64,
    /// Semantic reason for the payout.
    pub reason: SettlementReason,
}

impl TerminalAccounting {
    /// Computes the full tracked value across players and unresolved reserve.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ArithmeticOverflow`] if the total is not a `u64`.
    pub fn total(self) -> Result<u64, ChainError> {
        self.alice_sat
            .checked_add(self.bob_sat)
            .and_then(|value| value.checked_add(self.fee_reserve_remaining))
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

/// Computes normal poker, split, or timeout payouts with checked arithmetic.
///
/// Player payouts conserve `alice_remaining + bob_remaining + pot` exactly.
/// The fee reserve remains separately visible for the descriptor-selected fee
/// policy. The v1 profile permits only `PotOnly`: every outcome returns each
/// player's uncommitted remainder and distributes only the pot.
///
/// # Errors
///
/// Returns [`ChainError::UnsupportedTimeoutSettlementPolicy`] for the reserved
/// slashing discriminant, an arithmetic error, or
/// [`ChainError::ValueNotConserved`].
pub fn terminal_accounting(
    amounts: AmountState,
    outcome: TerminalOutcome,
    timeout_policy: TimeoutSettlementPolicy,
    split_remainder_recipient: Role,
) -> Result<TerminalAccounting, ChainError> {
    if timeout_policy != TimeoutSettlementPolicy::PotOnly {
        return Err(ChainError::UnsupportedTimeoutSettlementPolicy {
            actual: timeout_policy,
        });
    }
    let reason = outcome.reason();
    let (alice_sat, bob_sat) = match outcome {
        TerminalOutcome::Showdown(ShowdownOutcome::Split) => {
            split_amounts(amounts, split_remainder_recipient)?
        }
        _ => winner_amounts(
            amounts,
            outcome.winner().ok_or(ChainError::InvalidLogicalRecord {
                reason: "split outcome did not select split accounting",
            })?,
        )?,
    };
    let accounting = TerminalAccounting {
        alice_sat,
        bob_sat,
        fee_reserve_remaining: amounts.fee_reserve_remaining,
        reason,
    };
    if accounting.total()? == amounts.game_value()? {
        Ok(accounting)
    } else {
        Err(ChainError::ValueNotConserved)
    }
}

fn winner_amounts(amounts: AmountState, winner: Role) -> Result<(u64, u64), ChainError> {
    match winner {
        Role::Alice => Ok((
            amounts
                .alice_remaining
                .checked_add(amounts.pot)
                .ok_or(ChainError::ArithmeticOverflow)?,
            amounts.bob_remaining,
        )),
        Role::Bob => Ok((
            amounts.alice_remaining,
            amounts
                .bob_remaining
                .checked_add(amounts.pot)
                .ok_or(ChainError::ArithmeticOverflow)?,
        )),
    }
}

fn split_amounts(
    amounts: AmountState,
    remainder_recipient: Role,
) -> Result<(u64, u64), ChainError> {
    let half = amounts.pot / 2;
    let remainder = amounts.pot % 2;
    let alice_share = half
        .checked_add(u64::from(remainder_recipient == Role::Alice) * remainder)
        .ok_or(ChainError::ArithmeticOverflow)?;
    let bob_share = half
        .checked_add(u64::from(remainder_recipient == Role::Bob) * remainder)
        .ok_or(ChainError::ArithmeticOverflow)?;
    Ok((
        amounts
            .alice_remaining
            .checked_add(alice_share)
            .ok_or(ChainError::ArithmeticOverflow)?,
        amounts
            .bob_remaining
            .checked_add(bob_share)
            .ok_or(ChainError::ArithmeticOverflow)?,
    ))
}
