//! Checked fold, timeout, and showdown settlement helpers.

use poker_settlement_types::{
    AmountState, ChainError, PokerRules, Role, ShowdownOutcome, TerminalAccounting,
    TerminalOutcome, TimeoutKind, TimeoutSpec, terminal_accounting,
};

/// One of the three exact Bob terminal comparison branches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShowdownBranch {
    /// Comparison enforced by this branch's predicate.
    pub outcome: ShowdownOutcome,
    /// Exact terminal accounting before fee-reserve disposition.
    pub accounting: TerminalAccounting,
}

/// Return the Alice-showdown timeout attached to a river-complete state.
///
/// # Errors
///
/// Rejects a zero rules delay.
pub fn alice_showdown_timeout(rules: impl Into<PokerRules>) -> Result<TimeoutSpec, ChainError> {
    let rules = &rules.into();
    TimeoutSpec::new(
        TimeoutKind::Showdown,
        rules.showdown_csv,
        Role::Alice,
        Role::Bob,
    )
}

/// Return the Bob-showdown timeout attached to the final showdown state.
///
/// # Errors
///
/// Rejects a zero rules delay.
pub fn bob_showdown_timeout(rules: impl Into<PokerRules>) -> Result<TimeoutSpec, ChainError> {
    let rules = &rules.into();
    TimeoutSpec::new(
        TimeoutKind::Showdown,
        rules.showdown_csv,
        Role::Bob,
        Role::Alice,
    )
}

/// Compute all three exact normal showdown settlements in canonical order.
///
/// # Errors
///
/// Propagates checked terminal-accounting failures.
pub fn showdown_branches(
    rules: impl Into<PokerRules>,
    amounts: AmountState,
) -> Result<[ShowdownBranch; 3], ChainError> {
    let rules = &rules.into();
    let make = |outcome| -> Result<ShowdownBranch, ChainError> {
        Ok(ShowdownBranch {
            outcome,
            accounting: terminal_accounting(
                amounts,
                TerminalOutcome::Showdown(outcome),
                rules.timeout_policy,
                rules.split_remainder_recipient,
            )?,
        })
    };
    Ok([
        make(ShowdownOutcome::AliceWin)?,
        make(ShowdownOutcome::BobWin)?,
        make(ShowdownOutcome::Split)?,
    ])
}

/// Compute a fold settlement.
///
/// # Errors
///
/// Propagates checked terminal-accounting failures.
pub fn fold_accounting(
    rules: impl Into<PokerRules>,
    amounts: AmountState,
    folded: Role,
) -> Result<TerminalAccounting, ChainError> {
    let rules = &rules.into();
    terminal_accounting(
        amounts,
        TerminalOutcome::Fold { folded },
        rules.timeout_policy,
        rules.split_remainder_recipient,
    )
}

/// Compute one pot-only timeout settlement under the signed v1 policy.
///
/// # Errors
///
/// Propagates checked terminal-accounting failures.
pub fn timeout_accounting(
    rules: impl Into<PokerRules>,
    amounts: AmountState,
    kind: TimeoutKind,
    defaulting: Role,
) -> Result<TerminalAccounting, ChainError> {
    let rules = &rules.into();
    terminal_accounting(
        amounts,
        TerminalOutcome::Timeout { kind, defaulting },
        rules.timeout_policy,
        rules.split_remainder_recipient,
    )
}

#[cfg(test)]
mod tests {
    use poker_bitcoin::{FeePolicy, FixedFeePolicy};
    use poker_settlement_types::{
        AmountState, Role, SettlementReason, ShowdownOutcome, TerminalOutcome, TimeoutKind,
        TimeoutSettlementPolicy, terminal_accounting,
    };

    use super::{showdown_branches, timeout_accounting};
    use crate::test_support::rules_fixture;

    #[test]
    fn branches_are_canonical_and_conserve_value() -> Result<(), Box<dyn std::error::Error>> {
        let rules = rules_fixture();
        let amounts = AmountState {
            alice_remaining: 1_000,
            bob_remaining: 2_000,
            pot: 500,
            fee_reserve_remaining: 6_600,
        };
        let branches = showdown_branches(rules, amounts)?;
        assert_eq!(branches[0].outcome, ShowdownOutcome::AliceWin);
        assert_eq!(branches[1].outcome, ShowdownOutcome::BobWin);
        assert_eq!(branches[2].outcome, ShowdownOutcome::Split);
        for branch in branches {
            assert_eq!(branch.accounting.total()?, amounts.game_value()?);
        }
        let timeout = timeout_accounting(
            rules,
            amounts,
            poker_settlement_types::TimeoutKind::Showdown,
            Role::Bob,
        )?;
        assert_eq!(timeout.reason, SettlementReason::ShowdownTimeout);
        assert_eq!(timeout.total()?, amounts.game_value()?);
        Ok(())
    }

    #[test]
    fn every_terminal_outcome_refunds_remainders_and_only_distributes_pot_and_reserve()
    -> Result<(), Box<dyn std::error::Error>> {
        let amounts = AmountState {
            alice_remaining: 1_001,
            bob_remaining: 2_003,
            pot: 501,
            fee_reserve_remaining: 601,
        };
        let outcomes = [
            TerminalOutcome::Fold {
                folded: Role::Alice,
            },
            TerminalOutcome::Fold { folded: Role::Bob },
            TerminalOutcome::Timeout {
                kind: TimeoutKind::Action,
                defaulting: Role::Alice,
            },
            TerminalOutcome::Timeout {
                kind: TimeoutKind::Action,
                defaulting: Role::Bob,
            },
            TerminalOutcome::Timeout {
                kind: TimeoutKind::Reveal,
                defaulting: Role::Alice,
            },
            TerminalOutcome::Timeout {
                kind: TimeoutKind::Reveal,
                defaulting: Role::Bob,
            },
            TerminalOutcome::Timeout {
                kind: TimeoutKind::Showdown,
                defaulting: Role::Alice,
            },
            TerminalOutcome::Timeout {
                kind: TimeoutKind::Showdown,
                defaulting: Role::Bob,
            },
            TerminalOutcome::Showdown(ShowdownOutcome::AliceWin),
            TerminalOutcome::Showdown(ShowdownOutcome::BobWin),
            TerminalOutcome::Showdown(ShowdownOutcome::Split),
        ];
        let fee_policy = FixedFeePolicy::new(200, 330)?;
        let (alice_reserve, bob_reserve) =
            fee_policy.split_unused_reserve(amounts.fee_reserve_remaining, Role::Alice);

        for outcome in outcomes {
            let accounting = terminal_accounting(
                amounts,
                outcome,
                TimeoutSettlementPolicy::PotOnly,
                Role::Alice,
            )?;
            assert_eq!(
                accounting.fee_reserve_remaining,
                amounts.fee_reserve_remaining
            );
            assert!(accounting.alice_sat >= amounts.alice_remaining);
            assert!(accounting.bob_sat >= amounts.bob_remaining);

            let alice_pot_award = accounting.alice_sat - amounts.alice_remaining;
            let bob_pot_award = accounting.bob_sat - amounts.bob_remaining;
            assert_eq!(alice_pot_award + bob_pot_award, amounts.pot);

            let alice_output = accounting.alice_sat + alice_reserve;
            let bob_output = accounting.bob_sat + bob_reserve;
            assert_eq!(
                alice_output - amounts.alice_remaining,
                alice_pot_award + alice_reserve
            );
            assert_eq!(
                bob_output - amounts.bob_remaining,
                bob_pot_award + bob_reserve
            );
            assert_eq!(alice_output + bob_output, amounts.game_value()?);
        }
        Ok(())
    }
}
