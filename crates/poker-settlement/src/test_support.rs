//! Deal-independent poker fixtures.
use poker_settlement_types::{PokerRules, RevealOrder, Role, TimeoutSettlementPolicy};
pub(crate) fn rules_fixture() -> PokerRules {
    PokerRules {
        button: Role::Alice,
        unit_sat: 100,
        max_bets_per_street: poker_settlement_types::MAX_BETS_PER_STREET,
        alice_starting_stack_sat: 10_000,
        bob_starting_stack_sat: 12_000,
        fee_reserve_sat: 6_600,
        action_csv: 12,
        reveal_csv: 18,
        showdown_csv: 24,
        reveal_order: RevealOrder {
            flop_first: Role::Bob,
            turn_first: Role::Alice,
            river_first: Role::Bob,
        },
        timeout_policy: TimeoutSettlementPolicy::PotOnly,
        split_remainder_recipient: Role::Alice,
    }
}
