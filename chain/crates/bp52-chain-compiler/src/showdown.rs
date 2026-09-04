//! Checked fold, timeout, and showdown settlement helpers.

use bp52_chain_types::{
    AmountState, ChainError, ChainGameDescriptor, Role, ShowdownOutcome, TerminalAccounting,
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
/// Rejects a zero descriptor delay.
pub fn alice_showdown_timeout(descriptor: &ChainGameDescriptor) -> Result<TimeoutSpec, ChainError> {
    TimeoutSpec::new(
        TimeoutKind::Showdown,
        descriptor.showdown_csv,
        Role::Alice,
        Role::Bob,
    )
}

/// Return the Bob-showdown timeout attached to the final showdown state.
///
/// # Errors
///
/// Rejects a zero descriptor delay.
pub fn bob_showdown_timeout(descriptor: &ChainGameDescriptor) -> Result<TimeoutSpec, ChainError> {
    TimeoutSpec::new(
        TimeoutKind::Showdown,
        descriptor.showdown_csv,
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
    descriptor: &ChainGameDescriptor,
    amounts: AmountState,
) -> Result<[ShowdownBranch; 3], ChainError> {
    let make = |outcome| -> Result<ShowdownBranch, ChainError> {
        Ok(ShowdownBranch {
            outcome,
            accounting: terminal_accounting(
                amounts,
                TerminalOutcome::Showdown(outcome),
                descriptor.timeout_policy,
                descriptor.split_remainder_recipient,
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
    descriptor: &ChainGameDescriptor,
    amounts: AmountState,
    folded: Role,
) -> Result<TerminalAccounting, ChainError> {
    terminal_accounting(
        amounts,
        TerminalOutcome::Fold { folded },
        descriptor.timeout_policy,
        descriptor.split_remainder_recipient,
    )
}

/// Compute one pot-only timeout settlement under the signed v1 policy.
///
/// # Errors
///
/// Propagates checked terminal-accounting failures.
pub fn timeout_accounting(
    descriptor: &ChainGameDescriptor,
    amounts: AmountState,
    kind: TimeoutKind,
    defaulting: Role,
) -> Result<TerminalAccounting, ChainError> {
    terminal_accounting(
        amounts,
        TerminalOutcome::Timeout { kind, defaulting },
        descriptor.timeout_policy,
        descriptor.split_remainder_recipient,
    )
}

#[cfg(test)]
mod tests {
    use bp52_chain_bitcoin::{FeePolicy, FixedFeePolicy};
    use bp52_chain_types::{
        AmountState, ChainError, Role, SettlementReason, ShowdownOutcome, TerminalOutcome,
        TimeoutKind, TimeoutSettlementPolicy, terminal_accounting,
    };

    use super::{showdown_branches, timeout_accounting};
    use crate::{
        CompilerError, graph::compile_logical_graph_descriptor, reference_compiler_id,
        test_support::descriptor_fixture,
    };

    #[test]
    fn branches_are_canonical_and_conserve_value() -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = descriptor_fixture()?;
        let amounts = AmountState {
            alice_remaining: 1_000,
            bob_remaining: 2_000,
            pot: 500,
            fee_reserve_remaining: 6_600,
        };
        let branches = showdown_branches(&descriptor, amounts)?;
        assert_eq!(branches[0].outcome, ShowdownOutcome::AliceWin);
        assert_eq!(branches[1].outcome, ShowdownOutcome::BobWin);
        assert_eq!(branches[2].outcome, ShowdownOutcome::Split);
        for branch in branches {
            assert_eq!(branch.accounting.total()?, amounts.game_value()?);
        }
        let timeout = timeout_accounting(
            &descriptor,
            amounts,
            bp52_chain_types::TimeoutKind::Showdown,
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

    #[test]
    fn compiler_rejects_reserved_stack_slashing_policy() -> Result<(), Box<dyn std::error::Error>> {
        let fee_policy = FixedFeePolicy::new(200, 330)?;
        let mut descriptor = descriptor_fixture()?;
        descriptor.fee_policy_id = fee_policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();
        descriptor.timeout_policy = TimeoutSettlementPolicy::SlashRemainingStack;

        assert!(matches!(
            compile_logical_graph_descriptor(&descriptor, &descriptor.deal, &fee_policy),
            Err(CompilerError::Chain(
                ChainError::UnsupportedTimeoutSettlementPolicy {
                    actual: TimeoutSettlementPolicy::SlashRemainingStack
                }
            ))
        ));
        Ok(())
    }
}
