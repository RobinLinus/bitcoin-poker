use std::error::Error;

use super::{Action, AmountState, BettingState, BettingTransition, Street};
use crate::{ChainError, PokerRules, RevealOrder, Role, TimeoutSettlementPolicy};

fn rules(alice_stack: u64, bob_stack: u64, button: Role) -> PokerRules {
    PokerRules {
        button,
        unit_sat: 100,
        max_bets_per_street: crate::MAX_BETS_PER_STREET,
        alice_starting_stack_sat: alice_stack,
        bob_starting_stack_sat: bob_stack,
        fee_reserve_sat: 10_000,
        action_csv: 1,
        reveal_csv: 1,
        showdown_csv: 1,
        reveal_order: RevealOrder {
            flop_first: Role::Alice,
            turn_first: Role::Bob,
            river_first: Role::Alice,
        },
        timeout_policy: TimeoutSettlementPolicy::PotOnly,
        split_remainder_recipient: Role::Alice,
    }
}

fn assert_tree_conserves_value(
    rules: &PokerRules,
    state: BettingState,
    depth: usize,
) -> Result<(), ChainError> {
    assert!(depth <= 8, "fixed-limit decision tree did not terminate");
    state.validate(rules)?;
    let actions = state.legal_actions(rules)?;
    assert!(!actions.is_empty());
    for action in actions {
        let transition = state.apply_action(rules, action)?;
        state.amounts.verify_transition(transition.amounts(), 0)?;
        if let BettingTransition::Continue(next) = transition {
            assert_tree_conserves_value(rules, next, depth + 1)?;
        }
    }
    Ok(())
}

#[test]
fn minimum_stacks_post_full_blinds_and_skip_big_blind_option() -> Result<(), Box<dyn Error>> {
    for (alice_stack, bob_stack) in [(200, 200), (500, 200), (200, 500)] {
        let rules = rules(alice_stack, bob_stack, Role::Alice);
        let initial = BettingState::initial_preflop(rules)?;
        assert_eq!(initial.amounts.pot, 300);
        assert_eq!(
            initial.legal_actions(rules)?,
            vec![Action::Fold, Action::Call]
        );

        let BettingTransition::StreetComplete { street, amounts } =
            initial.apply_action(rules, Action::Call)?
        else {
            return Err("an all-in blind call exposed the big-blind option".into());
        };
        assert_eq!(street, Street::Preflop);
        assert_eq!(amounts.pot, 400);
        assert!(amounts.alice_remaining == 0 || amounts.bob_remaining == 0);
        initial.amounts.verify_transition(amounts, 0)?;
    }
    Ok(())
}

#[test]
fn bet_is_capped_by_opponents_effective_stack_without_unmatched_chips() -> Result<(), Box<dyn Error>>
{
    let rules = rules(250, 1_000, Role::Alice);
    let before = AmountState {
        alice_remaining: 150,
        bob_remaining: 900,
        pot: 200,
        fee_reserve_remaining: rules.fee_reserve_sat,
    };
    let state = BettingState::start_postflop(Street::Flop, rules, before)?;
    let BettingTransition::Continue(response) = state.apply_action(rules, Action::Bet)? else {
        return Err("bet did not expose an all-in response".into());
    };
    assert_eq!(response.current_wager, 150);
    assert_eq!(response.bob_committed_this_street, 150);
    assert_eq!(response.amounts.bob_remaining, 750);
    assert_eq!(
        response.legal_actions(rules)?,
        vec![Action::Fold, Action::Call]
    );
    before.verify_transition(response.amounts, 0)?;

    let BettingTransition::StreetComplete { amounts, .. } =
        response.apply_action(rules, Action::Call)?
    else {
        return Err("effective-stack call did not complete the street".into());
    };
    assert_eq!(amounts.alice_remaining, 0);
    assert_eq!(amounts.bob_remaining, 750);
    assert_eq!(amounts.pot, 500);
    assert_eq!(response.committed(Role::Bob), 150);
    response.amounts.verify_transition(amounts, 0)?;
    Ok(())
}

#[test]
fn bettor_can_commit_own_short_stack_without_exposing_a_raise() -> Result<(), Box<dyn Error>> {
    let rules = rules(1_000, 500, Role::Alice);
    let before = AmountState {
        alice_remaining: 575,
        bob_remaining: 75,
        pot: 850,
        fee_reserve_remaining: rules.fee_reserve_sat,
    };
    let state = BettingState::start_postflop(Street::Turn, rules, before)?;
    let BettingTransition::Continue(response) = state.apply_action(rules, Action::Bet)? else {
        return Err("short-stack bet did not expose a response".into());
    };
    assert_eq!(response.current_wager, 75);
    assert_eq!(response.amounts.bob_remaining, 0);
    assert_eq!(
        response.legal_actions(rules)?,
        vec![Action::Fold, Action::Call]
    );

    let BettingTransition::StreetComplete { amounts, .. } =
        response.apply_action(rules, Action::Call)?
    else {
        return Err("call of short-stack bet did not complete the street".into());
    };
    assert_eq!(amounts.alice_remaining, 500);
    assert_eq!(amounts.bob_remaining, 0);
    assert_eq!(amounts.pot, 1_000);
    before.verify_transition(amounts, 0)?;
    Ok(())
}

#[test]
fn short_and_exact_all_in_raises_allow_only_fold_or_call() -> Result<(), Box<dyn Error>> {
    for (alice_stack, expected_wager) in [(250, 250), (400, 400)] {
        let rules = rules(alice_stack, 1_000, Role::Alice);
        let flop = BettingState::start_postflop(Street::Flop, rules, AmountState::funded(rules))?;
        let BettingTransition::Continue(after_bet) = flop.apply_action(rules, Action::Bet)? else {
            return Err("opening bet completed unexpectedly".into());
        };
        let BettingTransition::Continue(after_raise) =
            after_bet.apply_action(rules, Action::Raise)?
        else {
            return Err("all-in raise completed unexpectedly".into());
        };

        assert_eq!(after_raise.current_wager, expected_wager);
        assert_eq!(after_raise.alice_committed_this_street, expected_wager);
        assert_eq!(after_raise.amounts.alice_remaining, 0);
        assert_eq!(
            after_raise.legal_actions(rules)?,
            vec![Action::Fold, Action::Call]
        );
        assert!(matches!(
            after_raise.apply_action(rules, Action::Raise),
            Err(ChainError::IllegalAction {
                action: Action::Raise
            })
        ));

        let to_call = expected_wager - 200;
        let before_call = after_raise.amounts;
        let BettingTransition::StreetComplete { amounts, .. } =
            after_raise.apply_action(rules, Action::Call)?
        else {
            return Err("all-in raise call did not complete the street".into());
        };
        assert_eq!(amounts.bob_remaining, 800 - to_call);
        assert_eq!(amounts.pot, expected_wager * 2);
        before_call.verify_transition(amounts, 0)?;
    }
    Ok(())
}

#[test]
fn malformed_short_or_uncallable_wagers_are_rejected() -> Result<(), Box<dyn Error>> {
    let rules = rules(250, 1_000, Role::Alice);
    let before = AmountState {
        alice_remaining: 150,
        bob_remaining: 900,
        pot: 200,
        fee_reserve_remaining: rules.fee_reserve_sat,
    };
    let flop = BettingState::start_postflop(Street::Flop, rules, before)?;
    let BettingTransition::Continue(valid_short) = flop.apply_action(rules, Action::Bet)? else {
        return Err("capped bet did not continue".into());
    };

    let mut not_capped = valid_short;
    not_capped.amounts.alice_remaining += 1;
    not_capped.amounts.bob_remaining += 1;
    not_capped.amounts.pot -= 2;
    assert!(matches!(
        not_capped.validate(rules),
        Err(ChainError::InvalidBettingState {
            reason: "short wager is not effective-stack capped"
        })
    ));

    let mut uncallable = valid_short;
    uncallable.amounts.alice_remaining -= 1;
    uncallable.amounts.bob_remaining -= 1;
    uncallable.amounts.pot += 2;
    assert!(matches!(
        uncallable.validate(rules),
        Err(ChainError::InvalidBettingState {
            reason: "current wager exceeds effective stack"
        })
    ));

    let unequal_prior = AmountState {
        alice_remaining: 149,
        bob_remaining: 900,
        pot: 201,
        fee_reserve_remaining: rules.fee_reserve_sat,
    };
    assert!(matches!(
        BettingState::start_postflop(Street::Flop, rules, unequal_prior),
        Err(ChainError::InvalidBettingState {
            reason: "prior-street contributions are unequal"
        })
    ));

    let all_in_amounts = AmountState {
        alice_remaining: 0,
        bob_remaining: 850,
        pot: 400,
        fee_reserve_remaining: rules.fee_reserve_sat,
    };
    assert!(matches!(
        BettingState::start_postflop(Street::Turn, rules, all_in_amounts),
        Err(ChainError::InvalidBettingState {
            reason: "postflop betting cannot start after an all-in"
        })
    ));
    Ok(())
}

#[test]
fn small_stack_decision_trees_are_finite_valid_and_conservative() -> Result<(), Box<dyn Error>> {
    let stack_sizes = [200, 201, 250, 399, 400, 401, 800];
    for button in [Role::Alice, Role::Bob] {
        for alice_stack in stack_sizes {
            for bob_stack in stack_sizes {
                let rules = rules(alice_stack, bob_stack, button);
                assert_tree_conserves_value(&rules, BettingState::initial_preflop(rules)?, 0)?;
                for street in [Street::Flop, Street::Turn, Street::River] {
                    assert_tree_conserves_value(
                        &rules,
                        BettingState::start_postflop(street, rules, AmountState::funded(rules))?,
                        0,
                    )?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn descriptor_cap_one_retains_real_betting_without_raises() -> Result<(), Box<dyn Error>> {
    let mut rules = rules(4_566, 4_566, Role::Alice);
    rules.max_bets_per_street = 1;

    let small_blind = BettingState::initial_preflop(rules)?;
    assert_eq!(
        small_blind.legal_actions(rules)?,
        vec![Action::Fold, Action::Call]
    );
    let BettingTransition::Continue(big_blind) = small_blind.apply_action(rules, Action::Call)?
    else {
        return Err("deep-stack small-blind call completed preflop".into());
    };
    assert_eq!(big_blind.legal_actions(rules)?, vec![Action::Check]);
    assert!(matches!(
        big_blind.apply_action(rules, Action::Check)?,
        BettingTransition::StreetComplete {
            street: Street::Preflop,
            ..
        }
    ));

    let flop = BettingState::start_postflop(Street::Flop, rules, AmountState::funded(rules))?;
    assert_eq!(flop.legal_actions(rules)?, vec![Action::Check, Action::Bet]);
    let BettingTransition::Continue(response) = flop.apply_action(rules, Action::Bet)? else {
        return Err("opening flop bet completed the street".into());
    };
    assert_eq!(
        response.legal_actions(rules)?,
        vec![Action::Fold, Action::Call]
    );
    assert!(matches!(
        response.apply_action(rules, Action::Raise),
        Err(ChainError::IllegalAction {
            action: Action::Raise
        })
    ));
    Ok(())
}
