use super::verify::{
    verify_betting_action_set, verify_child_semantics, verify_exact_outgoing_kinds,
    verify_terminal_intrinsic, verify_transition_against_rules,
};
use std::collections::HashSet;

use poker_bitcoin::{FeeClass, FeeError, FeePolicy, FixedFeePolicy, RevealPattern};
use poker_score_ots::LamportPurpose;
use poker_settlement_types::{
    Action, AuthorizationPolicy, BettingState, EdgeKind, NodeKind, Phase, Role, ShowdownOutcome,
    Street, TerminalOutcome, TimeoutKind, terminal_accounting,
};

use super::{
    LiveFeeSemantics, LogicalGraphPlan, PlannedNode, PlannedState, PlannedTerminal,
    REFERENCE_ALICE_LAMPORT_ENTRIES, REFERENCE_BOB_LAMPORT_ENTRIES, compile_rules_graph,
};
use crate::{
    CompilerError, REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT,
    REFERENCE_TRANSACTION_COUNT, test_support::rules_fixture,
};

const REFERENCE_ALICE_PREAUTHORIZATIONS: usize = 24_877;
const REFERENCE_BOB_PREAUTHORIZATIONS: usize = 14_671;
const REFERENCE_ALICE_RUNTIME_SIGNATURES: usize = 8_930;
const REFERENCE_BOB_RUNTIME_SIGNATURES: usize = 24_239;
#[derive(Clone, Copy)]
struct ZeroFeePolicy;

impl FeePolicy for ZeroFeePolicy {
    fn policy_id(&self) -> [u8; 32] {
        [0x52; 32]
    }

    fn fee_for(&self, _class: FeeClass) -> Result<u64, FeeError> {
        Ok(0)
    }

    fn dust_threshold(&self) -> u64 {
        330
    }

    fn split_unused_reserve(&self, remaining: u64, remainder_recipient: Role) -> (u64, u64) {
        let half = remaining / 2;
        match remainder_recipient {
            Role::Alice => (half + remaining % 2, half),
            Role::Bob => (half, half + remaining % 2),
        }
    }
}

fn graph_fixture() -> Result<LogicalGraphPlan, Box<dyn std::error::Error>> {
    let policy = FixedFeePolicy::new(200, 330)?;
    let rules = rules_fixture();
    Ok(compile_rules_graph(&rules, [7; 32], &policy)?)
}

fn stack_graph_fixture(
    alice_units: u64,
    bob_units: u64,
) -> Result<(poker_settlement_types::PokerRules, LogicalGraphPlan), Box<dyn std::error::Error>> {
    let policy = FixedFeePolicy::new(200, 330)?;
    let mut rules = rules_fixture();
    rules.alice_starting_stack_sat = rules.unit_sat * alice_units;
    rules.bob_starting_stack_sat = rules.unit_sat * bob_units;
    let plan = compile_rules_graph(&rules, [7; 32], &policy)?;
    Ok((rules, plan))
}

fn child_for<'a>(
    plan: &'a LogicalGraphPlan,
    node: &PlannedNode,
    kind: EdgeKind,
) -> Result<&'a PlannedNode, &'static str> {
    let edge = node
        .edges
        .iter()
        .find(|edge| edge.kind == kind)
        .ok_or("missing expected edge")?;
    plan.node(&edge.child_node_id).ok_or("missing edge child")
}

fn normal_reveal_child<'a>(
    plan: &'a LogicalGraphPlan,
    node: &PlannedNode,
) -> Result<&'a PlannedNode, &'static str> {
    let edge = node
        .edges
        .iter()
        .find(|edge| {
            matches!(
                edge.kind,
                EdgeKind::HoleCardReveal { .. } | EdgeKind::CommunityReveal { .. }
            )
        })
        .ok_or("missing normal reveal edge")?;
    plan.node(&edge.child_node_id)
        .ok_or("missing normal reveal child")
}

fn preflop_node(plan: &LogicalGraphPlan) -> Result<&PlannedNode, &'static str> {
    let deal_bob = normal_reveal_child(plan, &plan.nodes[0])?;
    normal_reveal_child(plan, deal_bob)
}

fn reveal_pair<'a>(
    plan: &'a LogicalGraphPlan,
    first: &PlannedNode,
) -> Result<&'a PlannedNode, &'static str> {
    let second = normal_reveal_child(plan, first)?;
    normal_reveal_child(plan, second)
}

fn action_child<'a>(
    plan: &'a LogicalGraphPlan,
    node: &PlannedNode,
    action: Action,
) -> Result<&'a PlannedNode, &'static str> {
    child_for(plan, node, EdgeKind::Action(action))
}

fn assert_reveal_timeout(plan: &LogicalGraphPlan, node: &PlannedNode) -> Result<(), &'static str> {
    let edge = node
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Timeout(TimeoutKind::Reveal))
        .ok_or("forced-runout reveal lacks timeout")?;
    assert!(matches!(
        edge.authorization,
        AuthorizationPolicy::Timeout { .. }
    ));
    let child = plan
        .node(&edge.child_node_id)
        .ok_or("forced-runout reveal timeout lacks terminal")?;
    let PlannedState::Reveal { pattern, .. } = node.state else {
        return Err("reveal-timeout assertion used on a non-reveal node");
    };
    assert!(matches!(
        child.state,
        PlannedState::Terminal(PlannedTerminal {
            outcome: TerminalOutcome::Timeout {
                kind: TimeoutKind::Reveal,
                defaulting,
            },
            ..
        }) if defaulting == pattern.revealer()
    ));
    Ok(())
}

#[test]
fn whole_tree_matches_corrected_profile() -> Result<(), Box<dyn std::error::Error>> {
    let plan = graph_fixture()?;
    plan.verify()?;
    assert_eq!(plan.nodes.len(), REFERENCE_TOTAL_NODE_COUNT);
    assert_eq!(plan.transaction_count(), REFERENCE_TRANSACTION_COUNT);
    assert_eq!(plan.maximum_path_length, REFERENCE_MAX_PATH_LENGTH);
    assert_eq!(plan.maximum_path_fee_sat, 6_600);
    assert_eq!(
        plan.expected_alice_lamport.len(),
        REFERENCE_ALICE_LAMPORT_ENTRIES
    );
    assert_eq!(
        plan.expected_bob_lamport.len(),
        REFERENCE_BOB_LAMPORT_ENTRIES
    );

    let mut funded = 0;
    let mut deal_alice = 0;
    let mut deal_bob = 0;
    let mut betting = 0;
    let mut reveal_first = 0;
    let mut reveal_second = 0;
    let mut alice_showdown = 0;
    let mut bob_terminal = 0;
    let mut terminal = 0;
    for node in &plan.nodes {
        match node.node_kind {
            NodeKind::Funded => funded += 1,
            NodeKind::DealAlice => deal_alice += 1,
            NodeKind::DealBob => deal_bob += 1,
            NodeKind::Betting => betting += 1,
            NodeKind::CommunityRevealFirst => reveal_first += 1,
            NodeKind::CommunityRevealSecond => reveal_second += 1,
            NodeKind::AliceShowdown => alice_showdown += 1,
            NodeKind::BobTerminal => bob_terminal += 1,
            NodeKind::Terminal => terminal += 1,
        }
    }
    assert_eq!(funded, 1);
    assert_eq!(deal_alice, 0);
    assert_eq!(deal_bob, 1);
    assert_eq!(betting, 6_378);
    assert_eq!(reveal_first, 637);
    assert_eq!(reveal_second, 637);
    assert_eq!(alice_showdown, 5_103);
    assert_eq!(bob_terminal, 5_103);
    assert_eq!(terminal, 38_272);

    let root = &plan.nodes[0];
    assert_eq!(root.node_kind, NodeKind::Funded);
    assert!(matches!(
        root.state,
        PlannedState::Reveal {
            phase: Phase::DealAlice,
            ..
        }
    ));
    assert_eq!(root.depth, 0);
    assert_eq!(
        plan.nodes.iter().map(|node| node.depth).max(),
        Some(REFERENCE_MAX_PATH_LENGTH)
    );
    Ok(())
}

#[test]
fn preflop_all_in_call_forces_every_remaining_reveal_pair() -> Result<(), Box<dyn std::error::Error>>
{
    let (rules, plan) = stack_graph_fixture(2, 2)?;
    plan.verify()?;
    assert!(plan.nodes.len() < REFERENCE_TOTAL_NODE_COUNT);
    assert_eq!(plan.transaction_count(), plan.nodes.len() - 1);
    assert!(plan.maximum_path_length < REFERENCE_MAX_PATH_LENGTH);
    assert!(plan.maximum_path_fee_sat < 6_600);
    assert_eq!(
        plan.expected_alice_lamport.len(),
        plan.expected_bob_lamport.len()
    );
    let mut wrong_maximum_fee = plan.clone();
    wrong_maximum_fee.maximum_path_fee_sat += 1;
    assert!(wrong_maximum_fee.verify().is_err());

    let preflop = preflop_node(&plan)?;
    let action_kinds: Vec<_> = preflop
        .edges
        .iter()
        .filter_map(|edge| match edge.kind {
            EdgeKind::Action(action) => Some(action),
            _ => None,
        })
        .collect();
    assert_eq!(action_kinds, vec![Action::Fold, Action::Call]);
    let flop_first = action_child(&plan, preflop, Action::Call)?;
    assert!(matches!(
        flop_first.state,
        PlannedState::Reveal {
            phase: Phase::FlopRevealFirst,
            ..
        }
    ));
    assert_eq!(flop_first.state.amounts().alice_remaining, 0);
    assert_eq!(flop_first.state.amounts().bob_remaining, 0);

    assert_reveal_timeout(&plan, flop_first)?;
    let turn_first = reveal_pair(&plan, flop_first)?;
    assert!(matches!(
        turn_first.state,
        PlannedState::Reveal {
            phase: Phase::TurnRevealFirst,
            ..
        }
    ));
    assert_reveal_timeout(&plan, turn_first)?;
    let river_first = reveal_pair(&plan, turn_first)?;
    assert!(matches!(
        river_first.state,
        PlannedState::Reveal {
            phase: Phase::RiverRevealFirst,
            ..
        }
    ));
    assert_reveal_timeout(&plan, river_first)?;
    let showdown = reveal_pair(&plan, river_first)?;
    assert!(matches!(showdown.state, PlannedState::AliceShowdown { .. }));
    for node in plan.nodes.iter().filter(|node| {
        node.state.amounts().alice_remaining == 0 || node.state.amounts().bob_remaining == 0
    }) {
        if let PlannedState::Betting { state, .. } = node.state {
            assert!(state.to_call()? > 0);
            assert_eq!(
                state.legal_actions(rules)?,
                vec![Action::Fold, Action::Call]
            );
        }
    }
    Ok(())
}

#[test]
fn called_all_in_on_each_postflop_street_forces_only_the_remaining_board()
-> Result<(), Box<dyn std::error::Error>> {
    for (stack_units, all_in_street) in [(4, Street::Flop), (8, Street::Turn), (12, Street::River)]
    {
        let (_descriptor, plan) = stack_graph_fixture(stack_units, stack_units)?;
        let initial = preflop_node(&plan)?;
        let big_blind_option = action_child(&plan, initial, Action::Call)?;
        let mut next = action_child(&plan, big_blind_option, Action::Check)?;

        for street in [Street::Flop, Street::Turn, Street::River] {
            let betting = reveal_pair(&plan, next)?;
            assert!(matches!(
                betting.state,
                PlannedState::Betting { state, .. } if state.street == street
            ));
            let response = action_child(&plan, betting, Action::Bet)?;
            let response_actions: Vec<_> = response
                .edges
                .iter()
                .filter_map(|edge| match edge.kind {
                    EdgeKind::Action(action) => Some(action),
                    _ => None,
                })
                .collect();
            if street == all_in_street {
                assert_eq!(response_actions, vec![Action::Fold, Action::Call]);
            } else {
                assert!(response_actions.starts_with(&[Action::Fold, Action::Call]));
            }
            next = action_child(&plan, response, Action::Call)?;

            if street == all_in_street {
                assert!(
                    next.state.amounts().alice_remaining == 0
                        || next.state.amounts().bob_remaining == 0
                );
                match street {
                    Street::Flop => assert!(matches!(
                        next.state,
                        PlannedState::Reveal {
                            phase: Phase::TurnRevealFirst,
                            ..
                        }
                    )),
                    Street::Turn => assert!(matches!(
                        next.state,
                        PlannedState::Reveal {
                            phase: Phase::RiverRevealFirst,
                            ..
                        }
                    )),
                    Street::River => {
                        assert!(matches!(next.state, PlannedState::AliceShowdown { .. }));
                    }
                    Street::Preflop => unreachable!(),
                }
                break;
            }
        }

        while matches!(next.state, PlannedState::Reveal { .. }) {
            assert_reveal_timeout(&plan, next)?;
            next = reveal_pair(&plan, next)?;
        }
        assert!(matches!(next.state, PlannedState::AliceShowdown { .. }));
        plan.verify()?;
    }
    Ok(())
}

#[test]
fn short_effective_stack_bet_preserves_larger_remainder_at_showdown()
-> Result<(), Box<dyn std::error::Error>> {
    let (rules, plan) = stack_graph_fixture(3, 10)?;
    let initial = preflop_node(&plan)?;
    let big_blind_option = action_child(&plan, initial, Action::Call)?;
    let flop_first = action_child(&plan, big_blind_option, Action::Check)?;
    let flop_betting = reveal_pair(&plan, flop_first)?;
    let response = action_child(&plan, flop_betting, Action::Bet)?;
    let PlannedState::Betting { state, .. } = response.state else {
        return Err("all-in bet did not leave a response decision".into());
    };
    assert_eq!(state.current_wager, rules.unit_sat);
    assert_eq!(state.amounts.bob_remaining, rules.unit_sat * 7);
    assert_eq!(
        state.legal_actions(rules)?,
        vec![Action::Fold, Action::Call]
    );
    let fold = action_child(&plan, response, Action::Fold)?;
    let PlannedState::Terminal(fold) = fold.state else {
        return Err("all-in response fold is not terminal".into());
    };
    assert_eq!(
        fold.outcome,
        TerminalOutcome::Fold {
            folded: Role::Alice
        }
    );
    assert_eq!(fold.accounting.alice_sat, rules.unit_sat);
    assert_eq!(fold.accounting.bob_sat, rules.unit_sat * 12);

    let mut node = action_child(&plan, response, Action::Call)?;
    assert_eq!(node.state.amounts().alice_remaining, 0);
    assert_eq!(node.state.amounts().bob_remaining, rules.unit_sat * 7);
    assert_eq!(node.state.amounts().pot, rules.unit_sat * 6);
    while matches!(node.state, PlannedState::Reveal { .. }) {
        node = reveal_pair(&plan, node)?;
    }
    let bob_terminal = child_for(&plan, node, EdgeKind::AliceShowdown)?;
    let alice_wins = child_for(
        &plan,
        bob_terminal,
        EdgeKind::BobPayout(ShowdownOutcome::AliceWin),
    )?;
    let PlannedState::Terminal(terminal) = alice_wins.state else {
        return Err("Alice-win payout is not terminal".into());
    };
    assert_eq!(terminal.accounting.alice_sat, rules.unit_sat * 6);
    assert_eq!(terminal.accounting.bob_sat, rules.unit_sat * 7);
    assert_eq!(
        terminal.accounting.alice_sat + terminal.accounting.bob_sat,
        rules.alice_starting_stack_sat + rules.bob_starting_stack_sat
    );
    plan.verify()?;
    Ok(())
}

#[test]
fn exact_outgoing_sets_reject_pruned_missing_and_extra_edges()
-> Result<(), Box<dyn std::error::Error>> {
    let (rules, plan) = stack_graph_fixture(2, 2)?;

    let root = &plan.nodes[0];
    let mut missing_reveal_success = root.clone();
    missing_reveal_success
        .edges
        .retain(|edge| edge.kind.is_timeout());
    assert!(verify_exact_outgoing_kinds(&missing_reveal_success).is_err());

    let mut extra_reveal_edge = root.clone();
    let mut impossible = extra_reveal_edge.edges[0];
    impossible.kind = EdgeKind::Action(Action::Check);
    let timeout_index = extra_reveal_edge.edges.len() - 1;
    extra_reveal_edge.edges.insert(timeout_index, impossible);
    assert!(verify_exact_outgoing_kinds(&extra_reveal_edge).is_err());

    let betting = preflop_node(&plan)?;
    let mut missing_action = betting.clone();
    missing_action
        .edges
        .retain(|edge| edge.kind != EdgeKind::Action(Action::Call));
    assert!(verify_betting_action_set(&missing_action, rules).is_err());

    let mut extra_non_action = betting.clone();
    let mut impossible = extra_non_action.edges[0];
    impossible.kind = EdgeKind::AliceShowdown;
    let timeout_index = extra_non_action.edges.len() - 1;
    extra_non_action.edges.insert(timeout_index, impossible);
    assert!(verify_exact_outgoing_kinds(&extra_non_action).is_err());
    assert!(verify_betting_action_set(&extra_non_action, rules).is_err());

    let alice_showdown = plan
        .nodes
        .iter()
        .find(|node| matches!(node.state, PlannedState::AliceShowdown { .. }))
        .ok_or("short graph has no Alice-showdown node")?;
    let mut missing_alice_success = alice_showdown.clone();
    missing_alice_success
        .edges
        .retain(|edge| edge.kind.is_timeout());
    assert!(verify_exact_outgoing_kinds(&missing_alice_success).is_err());

    let bob_terminal = plan
        .nodes
        .iter()
        .find(|node| matches!(node.state, PlannedState::BobTerminal { .. }))
        .ok_or("short graph has no Bob-terminal node")?;
    let mut missing_split = bob_terminal.clone();
    missing_split
        .edges
        .retain(|edge| edge.kind != EdgeKind::BobPayout(ShowdownOutcome::Split));
    assert!(verify_exact_outgoing_kinds(&missing_split).is_err());

    let timeout_edge = root
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Timeout(TimeoutKind::Reveal))
        .copied()
        .ok_or("root has no reveal timeout")?;
    let timeout_child = plan
        .node(&timeout_edge.child_node_id)
        .cloned()
        .ok_or("root reveal timeout has no child")?;
    let mut timeout_only_root = root.clone();
    timeout_only_root.edges = vec![timeout_edge];
    let mut pruned = plan.clone();
    pruned.nodes = vec![timeout_only_root, timeout_child];
    pruned.expected_alice_lamport.clear();
    pruned.expected_bob_lamport.clear();
    pruned.maximum_path_length = 1;
    pruned.maximum_path_fee_sat = timeout_edge.fee_sat;
    assert!(matches!(
        pruned.verify(),
        Err(CompilerError::ProfileMismatch {
            reason: "node does not contain its exact required outgoing edge-kind set"
        })
    ));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn edge_and_lamport_multiplicities_are_exact() -> Result<(), Box<dyn std::error::Error>> {
    let plan = graph_fixture()?;
    let mut hole = 0;
    let mut community = 0;
    let mut action = 0;
    let mut action_timeout = 0;
    let mut reveal_timeout = 0;
    let mut alice_showdown = 0;
    let mut bob_payout = 0;
    let mut showdown_timeout = 0;
    let mut advance = 0;
    let mut alice_action = 0;
    let mut bob_action = 0;
    let mut alice_timeout = 0;
    let mut bob_timeout = 0;
    let mut alice_preauthorizations = 0;
    let mut bob_preauthorizations = 0;
    let mut both_presigned = 0;
    let mut alice_runtime_signatures = 0;
    let mut bob_runtime_signatures = 0;
    for node in &plan.nodes {
        for edge in &node.edges {
            match edge.authorization {
                AuthorizationPolicy::BothPresigned => {
                    both_presigned += 1;
                    alice_preauthorizations += 1;
                    bob_preauthorizations += 1;
                }
                AuthorizationPolicy::RevealOpenings { revealer } => match revealer {
                    Role::Alice => bob_preauthorizations += 1,
                    Role::Bob => alice_preauthorizations += 1,
                },
                AuthorizationPolicy::AliceScore => bob_preauthorizations += 1,
                AuthorizationPolicy::BettingAction { .. } => {}
                AuthorizationPolicy::BobLivePayout => {
                    alice_preauthorizations += 1;
                    bob_runtime_signatures += 1;
                }
                AuthorizationPolicy::Timeout { beneficiary } => match beneficiary {
                    Role::Alice => {
                        bob_preauthorizations += 1;
                        alice_runtime_signatures += 1;
                    }
                    Role::Bob => {
                        alice_preauthorizations += 1;
                        bob_runtime_signatures += 1;
                    }
                },
            }
            if let AuthorizationPolicy::Timeout { beneficiary } = edge.authorization {
                match beneficiary {
                    Role::Alice => alice_timeout += 1,
                    Role::Bob => bob_timeout += 1,
                }
            }
            match edge.kind {
                EdgeKind::HoleCardReveal { .. } => hole += 1,
                EdgeKind::CommunityReveal { .. } => community += 1,
                EdgeKind::Action(_) => {
                    action += 1;
                    match node.state {
                        PlannedState::Betting { state, .. } => match state.actor {
                            Role::Alice => alice_action += 1,
                            Role::Bob => bob_action += 1,
                        },
                        _ => return Err("action edge leaves a non-betting node".into()),
                    }
                }
                EdgeKind::Timeout(poker_settlement_types::TimeoutKind::Action) => {
                    action_timeout += 1;
                }
                EdgeKind::Timeout(poker_settlement_types::TimeoutKind::Reveal) => {
                    reveal_timeout += 1;
                }
                EdgeKind::AliceShowdown => alice_showdown += 1,
                EdgeKind::BobPayout(_) => bob_payout += 1,
                EdgeKind::Timeout(poker_settlement_types::TimeoutKind::Showdown) => {
                    showdown_timeout += 1;
                }
                EdgeKind::Advance { .. } => advance += 1,
            }
        }
    }
    assert_eq!(hole, 2);
    assert_eq!(community, 1_274);
    assert_eq!(action, 16_583);
    assert_eq!(alice_action, 8_292);
    assert_eq!(bob_action, 8_291);
    assert_eq!(action_timeout, 6_378);
    assert_eq!(reveal_timeout, 1_276);
    assert_eq!(alice_showdown, 5_103);
    assert_eq!(bob_payout, 15_309);
    assert_eq!(showdown_timeout, 10_206);
    assert_eq!(alice_timeout, 8_930);
    assert_eq!(bob_timeout, 8_930);
    assert_eq!(both_presigned, 0);
    assert_eq!(alice_preauthorizations, REFERENCE_ALICE_PREAUTHORIZATIONS);
    assert_eq!(bob_preauthorizations, REFERENCE_BOB_PREAUTHORIZATIONS);
    assert_eq!(
        alice_preauthorizations + bob_preauthorizations + action,
        REFERENCE_TRANSACTION_COUNT
    );
    assert_eq!(alice_runtime_signatures, REFERENCE_ALICE_RUNTIME_SIGNATURES);
    assert_eq!(bob_runtime_signatures, REFERENCE_BOB_RUNTIME_SIGNATURES);
    assert_eq!(advance, 0);

    let alice_score = plan
        .expected_alice_lamport
        .iter()
        .filter(|entry| entry.purpose == LamportPurpose::AliceScore24Bit)
        .count();
    assert_eq!(alice_score, REFERENCE_ALICE_LAMPORT_ENTRIES);
    assert!(
        plan.expected_alice_lamport
            .iter()
            .all(|entry| entry.purpose == LamportPurpose::AliceScore24Bit)
    );
    assert_eq!(
        plan.expected_bob_lamport
            .iter()
            .filter(|entry| entry.purpose == LamportPurpose::BobScore24Bit)
            .count(),
        REFERENCE_BOB_LAMPORT_ENTRIES
    );
    assert!(
        plan.expected_bob_lamport
            .iter()
            .all(|entry| entry.purpose == LamportPurpose::BobScore24Bit)
    );
    let unique_ids: HashSet<_> = plan.nodes.iter().map(|node| node.node_id).collect();
    assert_eq!(unique_ids.len(), plan.nodes.len());
    Ok(())
}

#[test]
fn graph_is_byte_for_byte_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let first = graph_fixture()?;
    let second = graph_fixture()?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn funded_root_posts_blinds_before_hole_reveal_timeouts() -> Result<(), Box<dyn std::error::Error>>
{
    let policy = FixedFeePolicy::new(200, 330)?;
    let rules = rules_fixture();
    let plan = compile_rules_graph(&rules, [7; 32], &policy)?;
    let initial = BettingState::initial_preflop(rules)?;
    let root = &plan.nodes[0];

    assert_eq!(root.state.amounts(), initial.amounts);
    assert_eq!(initial.amounts.pot, rules.unit_sat * 3);
    assert_eq!(
        initial.amounts.alice_remaining,
        rules.alice_starting_stack_sat - rules.unit_sat
    );
    assert_eq!(
        initial.amounts.bob_remaining,
        rules.bob_starting_stack_sat - rules.unit_sat * 2
    );

    let deal_bob_edge = root
        .edges
        .iter()
        .find(|edge| matches!(edge.kind, EdgeKind::HoleCardReveal { .. }))
        .ok_or("missing Deal-Alice reveal edge")?;
    let deal_bob = plan
        .node(&deal_bob_edge.child_node_id)
        .ok_or("missing Deal-Bob node")?;
    let mut after_first_reveal = initial.amounts;
    after_first_reveal.fee_reserve_remaining -= 200;
    assert_eq!(deal_bob.state.amounts(), after_first_reveal);

    let preflop_edge = deal_bob
        .edges
        .iter()
        .find(|edge| matches!(edge.kind, EdgeKind::HoleCardReveal { .. }))
        .ok_or("missing Deal-Bob reveal edge")?;
    let preflop = plan
        .node(&preflop_edge.child_node_id)
        .ok_or("missing preflop node")?;
    let PlannedState::Betting { state, .. } = preflop.state else {
        return Err("Deal-Bob reveal did not create preflop betting".into());
    };
    let mut expected_preflop = initial;
    expected_preflop.amounts.fee_reserve_remaining -= 400;
    assert_eq!(state, expected_preflop);

    let timeout_edge = root
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Timeout(TimeoutKind::Reveal))
        .ok_or("missing Deal-Alice timeout edge")?;
    let timeout = plan
        .node(&timeout_edge.child_node_id)
        .ok_or("missing Deal-Alice timeout terminal")?;
    let PlannedState::Terminal(timeout) = timeout.state else {
        return Err("Deal-Alice timeout did not settle".into());
    };
    let timeout_amounts = initial.amounts.charge_fee(200)?;
    let outcome = TerminalOutcome::Timeout {
        kind: TimeoutKind::Reveal,
        defaulting: Role::Bob,
    };
    assert_eq!(
        timeout.accounting,
        terminal_accounting(
            timeout_amounts,
            outcome,
            rules.timeout_policy,
            rules.split_remainder_recipient,
        )?
    );
    assert_eq!(
        timeout.accounting.alice_sat,
        initial.amounts.alice_remaining + initial.amounts.pot
    );
    assert_eq!(timeout.accounting.bob_sat, initial.amounts.bob_remaining);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn descriptor_verifier_rejects_semantic_mutations() -> Result<(), Box<dyn std::error::Error>> {
    let policy = FixedFeePolicy::new(200, 330)?;
    let fee_semantics = LiveFeeSemantics(&policy);
    let rules = rules_fixture();
    let plan = compile_rules_graph(&rules, [7; 32], &policy)?;

    let betting = plan
        .nodes
        .iter()
        .find(|node| {
            node.edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::Action(Action::Call))
                && node
                    .edges
                    .iter()
                    .any(|edge| edge.kind == EdgeKind::Action(Action::Raise))
        })
        .ok_or("missing call/raise betting node")?;
    let call_edge = betting
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Action(Action::Call))
        .ok_or("missing call edge")?;
    let call_child = plan
        .node(&call_edge.child_node_id)
        .ok_or("missing call child")?;
    let mut relabeled = *call_edge;
    relabeled.kind = EdgeKind::Action(Action::Raise);
    assert!(
        verify_transition_against_rules(betting, &relabeled, call_child, rules, &fee_semantics,)
            .is_err()
    );

    let mut missing_action = betting.clone();
    missing_action
        .edges
        .retain(|edge| edge.kind != EdgeKind::Action(Action::Raise));
    assert!(verify_betting_action_set(&missing_action, rules).is_err());

    let reveal_first = plan
        .nodes
        .iter()
        .find(|node| {
            matches!(
                node.state,
                PlannedState::Reveal {
                    phase: Phase::FlopRevealFirst,
                    ..
                }
            )
        })
        .ok_or("missing first flop reveal")?;
    let reveal_edge = reveal_first
        .edges
        .iter()
        .find(|edge| matches!(edge.kind, EdgeKind::CommunityReveal { .. }))
        .ok_or("missing community reveal edge")?;
    let mut repeated_revealer = plan
        .node(&reveal_edge.child_node_id)
        .ok_or("missing second community reveal")?
        .clone();
    let PlannedState::Reveal { pattern, .. } = &mut repeated_revealer.state else {
        return Err("first reveal did not lead to another reveal".into());
    };
    let parent_revealer = match reveal_first.state {
        PlannedState::Reveal { pattern, .. } => pattern.revealer(),
        _ => unreachable!(),
    };
    *pattern = RevealPattern::Flop(parent_revealer);
    assert!(verify_child_semantics(reveal_first, reveal_edge, &repeated_revealer).is_err());
    assert!(
        verify_transition_against_rules(
            reveal_first,
            reveal_edge,
            &repeated_revealer,
            rules,
            &fee_semantics,
        )
        .is_err()
    );

    let terminal_edge = plan.nodes[0]
        .edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Timeout(TimeoutKind::Reveal))
        .ok_or("missing root timeout")?;
    let mut shifted_terminal = plan
        .node(&terminal_edge.child_node_id)
        .ok_or("missing timeout terminal")?
        .clone();
    let PlannedState::Terminal(terminal) = &mut shifted_terminal.state else {
        return Err("root timeout child is not terminal".into());
    };
    terminal.alice_output_sat += 1;
    terminal.bob_output_sat -= 1;
    verify_terminal_intrinsic(*terminal)?;
    assert!(
        verify_transition_against_rules(
            &plan.nodes[0],
            terminal_edge,
            &shifted_terminal,
            rules,
            &fee_semantics,
        )
        .is_err()
    );

    let mut shifted_accounting = plan
        .node(&terminal_edge.child_node_id)
        .ok_or("missing timeout terminal")?
        .clone();
    let PlannedState::Terminal(terminal) = &mut shifted_accounting.state else {
        return Err("root timeout child is not terminal".into());
    };
    terminal.accounting.alice_sat += 1;
    terminal.accounting.bob_sat -= 1;
    terminal.alice_output_sat += 1;
    terminal.bob_output_sat -= 1;
    verify_terminal_intrinsic(*terminal)?;
    assert!(
        verify_transition_against_rules(
            &plan.nodes[0],
            terminal_edge,
            &shifted_accounting,
            rules,
            &fee_semantics,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn all_zero_fee_logical_graph_is_supported() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ZeroFeePolicy;
    let rules = rules_fixture();
    let initial_reserve = rules.fee_reserve_sat;

    let plan = compile_rules_graph(&rules, [7; 32], &policy)?;
    assert_eq!(plan.maximum_path_fee_sat, 0);
    assert!(
        plan.nodes
            .iter()
            .flat_map(|node| &node.edges)
            .all(|edge| edge.fee_sat == 0)
    );
    assert!(plan.nodes.iter().all(|node| match &node.state {
        PlannedState::Reveal { amounts, .. }
        | PlannedState::AliceShowdown { amounts }
        | PlannedState::BobTerminal { amounts } => {
            amounts.fee_reserve_remaining == initial_reserve
        }
        PlannedState::Betting { state, .. } => {
            state.amounts.fee_reserve_remaining == initial_reserve
        }
        PlannedState::Terminal(terminal) => {
            terminal.amounts.fee_reserve_remaining == initial_reserve
        }
    }));
    Ok(())
}
