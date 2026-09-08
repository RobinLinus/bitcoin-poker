//! Verify.

use super::{
    Action, AmountState, AuthorizationPolicy, BettingState, BettingTransition, ChainError,
    CompilerError, EdgeKind, ExpectedLamportEntry, FeeClass, FeeError, FeeSemantics, HashMap,
    LogicalGraphPlan, NodeKind, Phase, PlannedEdge, PlannedNode, PlannedState, PlannedTerminal,
    PokerRules, REFERENCE_ALICE_LAMPORT_ENTRIES, REFERENCE_BOB_LAMPORT_ENTRIES,
    REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT, REFERENCE_TRANSACTION_COUNT,
    RevealPattern, Role, ShowdownOutcome, Street, TerminalOutcome, TimeoutKind, TimeoutSpec,
    alice_showdown_timeout, betting_phase, bob_showdown_timeout, path_node_id,
    community_reveal_steps, hole_reveal_steps, is_all_in, next_depth, planned_state_digest,
    profile, record_expected, reveal_edge_kind, reveal_phase_street, reveal_step_for_phase,
    root_node_id, sort_lamport_entries, state_after_completed_street, terminal_accounting,
    valid_reveal_phase,
};

pub(super) fn verify_rules_plan(
    plan: &LogicalGraphPlan,
    rules: &PokerRules,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    rules.validate()?;
    plan.verify()?;
    let schedule = fee_policy.schedule()?;
    let reference_maximum_path_fee_sat = schedule.maximum_path_fee()?;
    if plan.maximum_path_fee_sat > reference_maximum_path_fee_sat {
        return Err(profile(
            "rules-derived maximum path fee exceeds the profile maximum",
        ));
    }
    if rules.fee_reserve_sat < plan.maximum_path_fee_sat {
        return Err(CompilerError::InsufficientMaximumPathReserve {
            available: rules.fee_reserve_sat,
            required: plan.maximum_path_fee_sat,
        });
    }
    let root = plan
        .nodes
        .first()
        .ok_or_else(|| profile("logical graph is empty"))?;
    if root.state.amounts() != BettingState::initial_preflop(rules)?.amounts {
        return Err(profile("funded root amounts disagree with the rules"));
    }
    let by_id: HashMap<_, _> = plan.nodes.iter().map(|node| (node.node_id, node)).collect();
    for node in &plan.nodes {
        verify_node_against_rules(node, rules)?;
        verify_betting_action_set(node, rules)?;
        for edge in &node.edges {
            if edge.fee_sat != schedule.for_class(edge.fee_class) {
                return Err(profile("edge fee disagrees with the fee policy"));
            }
            let child = by_id
                .get(&edge.child_node_id)
                .copied()
                .ok_or(CompilerError::DanglingNode)?;
            verify_transition_against_rules(node, edge, child, rules, fee_policy)?;
        }
    }
    Ok(())
}

pub(super) fn verify_betting_action_set(
    node: &PlannedNode,
    rules: impl Into<PokerRules>,
) -> Result<(), CompilerError> {
    let rules = &rules.into();
    let PlannedState::Betting { state, .. } = node.state else {
        return Ok(());
    };
    let expected_actions = state.legal_actions(rules)?;
    let Some((timeout, action_edges)) = node.edges.split_last() else {
        return Err(profile("betting node has no outgoing edges"));
    };
    if timeout.kind == EdgeKind::Timeout(TimeoutKind::Action)
        && action_edges.len() == expected_actions.len()
        && action_edges
            .iter()
            .zip(expected_actions)
            .all(|(edge, action)| edge.kind == EdgeKind::Action(action))
    {
        Ok(())
    } else {
        Err(profile(
            "betting edges are not exactly the legal action set",
        ))
    }
}

pub(super) fn verify_node_against_rules(
    node: &PlannedNode,
    rules: impl Into<PokerRules>,
) -> Result<(), CompilerError> {
    let rules = &rules.into();
    verify_exact_outgoing_kinds(node)?;
    let expected_timeout = match node.state {
        PlannedState::Reveal { phase, pattern, .. } => {
            let step = reveal_step_for_phase(rules, phase)?;
            if pattern != step.pattern {
                return Err(profile("reveal obligation disagrees with rules order"));
            }
            Some(step.timeout)
        }
        PlannedState::Betting { phase, state } => {
            if phase != betting_phase(state.street) {
                return Err(profile("betting phase disagrees with its street"));
            }
            state.validate(rules)?;
            Some(TimeoutSpec::new(
                TimeoutKind::Action,
                rules.action_csv,
                state.actor,
                state.actor.other(),
            )?)
        }
        PlannedState::AliceShowdown { .. } => Some(alice_showdown_timeout(rules)?),
        PlannedState::BobTerminal { .. } => Some(bob_showdown_timeout(rules)?),
        PlannedState::Terminal(_) => None,
    };
    if node.timeout != expected_timeout {
        return Err(profile("node timeout disagrees with the rules"));
    }
    Ok(())
}

pub(super) fn verify_transition_against_rules(
    parent: &PlannedNode,
    edge: &PlannedEdge,
    child: &PlannedNode,
    rules: impl Into<PokerRules>,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    let rules = &rules.into();
    if let EdgeKind::Timeout(kind) = edge.kind {
        let timeout = parent
            .timeout
            .ok_or_else(|| profile("timeout edge has no parent timeout"))?;
        if kind != timeout.kind {
            return Err(profile("timeout edge kind disagrees with its obligation"));
        }
        let amounts = parent.state.amounts().charge_fee(edge.fee_sat)?;
        let outcome = TerminalOutcome::Timeout {
            kind,
            defaulting: timeout.defaulting,
        };
        return verify_terminal_child(child, amounts, outcome, rules, fee_policy);
    }

    match (&parent.state, edge.kind) {
        (
            PlannedState::Reveal {
                phase,
                pattern,
                amounts,
            },
            kind,
        ) if kind == reveal_edge_kind(*pattern) => {
            verify_reveal_transition(*phase, *amounts, edge, child, rules)
        }
        (PlannedState::Betting { state, .. }, EdgeKind::Action(action)) => {
            verify_betting_transition(*state, action, edge, child, rules, fee_policy)
        }
        (PlannedState::AliceShowdown { amounts }, EdgeKind::AliceShowdown) => {
            let expected = PlannedState::BobTerminal {
                amounts: amounts.charge_fee(edge.fee_sat)?,
            };
            require_state(child, &expected)
        }
        (PlannedState::BobTerminal { amounts }, EdgeKind::BobPayout(outcome)) => {
            verify_terminal_child(
                child,
                amounts.charge_fee(edge.fee_sat)?,
                TerminalOutcome::Showdown(outcome),
                rules,
                fee_policy,
            )
        }
        _ => Err(profile("edge is not a legal rules-bound transition")),
    }
}

pub(super) fn verify_reveal_transition(
    phase: Phase,
    amounts: AmountState,
    edge: &PlannedEdge,
    child: &PlannedNode,
    rules: impl Into<PokerRules>,
) -> Result<(), CompilerError> {
    let rules = &rules.into();
    let after_fee = amounts.charge_fee(edge.fee_sat)?;
    let expected = match phase {
        Phase::DealAlice => {
            let step = hole_reveal_steps(rules)?[1];
            PlannedState::Reveal {
                phase: step.phase,
                pattern: step.pattern,
                amounts: after_fee,
            }
        }
        Phase::DealBob => {
            let mut state = BettingState::initial_preflop(rules)?;
            state.amounts.fee_reserve_remaining = after_fee.fee_reserve_remaining;
            PlannedState::Betting {
                phase: Phase::PreflopBetting,
                state,
            }
        }
        Phase::FlopRevealFirst | Phase::TurnRevealFirst | Phase::RiverRevealFirst => {
            let street = reveal_phase_street(phase)?;
            let step = community_reveal_steps(rules, street)?[1];
            PlannedState::Reveal {
                phase: step.phase,
                pattern: step.pattern,
                amounts: after_fee,
            }
        }
        Phase::FlopRevealSecond | Phase::TurnRevealSecond | Phase::RiverRevealSecond => {
            let street = reveal_phase_street(phase)?;
            if is_all_in(after_fee) {
                state_after_completed_street(rules, street, after_fee)?
            } else {
                PlannedState::Betting {
                    phase: betting_phase(street),
                    state: BettingState::start_postflop(street, rules, after_fee)?,
                }
            }
        }
        _ => return Err(profile("non-reveal phase used as reveal parent")),
    };
    require_state(child, &expected)
}

pub(super) fn verify_betting_transition(
    state: BettingState,
    action: Action,
    edge: &PlannedEdge,
    child: &PlannedNode,
    rules: impl Into<PokerRules>,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    let rules = &rules.into();
    match state
        .apply_action(rules, action)?
        .charge_fee(edge.fee_sat)?
    {
        BettingTransition::Continue(next) => require_state(
            child,
            &PlannedState::Betting {
                phase: betting_phase(next.street),
                state: next,
            },
        ),
        BettingTransition::StreetComplete { street, amounts } => {
            let expected = state_after_completed_street(rules, street, amounts)?;
            require_state(child, &expected)
        }
        BettingTransition::Fold {
            folded,
            winner,
            amounts,
        } => {
            if winner != folded.other() {
                return Err(profile("fold transition names the wrong winner"));
            }
            verify_terminal_child(
                child,
                amounts,
                TerminalOutcome::Fold { folded },
                rules,
                fee_policy,
            )
        }
    }
}

pub(super) fn verify_terminal_child(
    child: &PlannedNode,
    amounts: AmountState,
    outcome: TerminalOutcome,
    rules: impl Into<PokerRules>,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    let rules = &rules.into();
    let accounting = terminal_accounting(
        amounts,
        outcome,
        rules.timeout_policy,
        rules.split_remainder_recipient,
    )?;
    let (alice_reserve, bob_reserve) = fee_policy.reserve_split(
        accounting.fee_reserve_remaining,
        rules.split_remainder_recipient,
    )?;
    let alice_output_sat = accounting
        .alice_sat
        .checked_add(alice_reserve)
        .ok_or(ChainError::ArithmeticOverflow)?;
    let bob_output_sat = accounting
        .bob_sat
        .checked_add(bob_reserve)
        .ok_or(ChainError::ArithmeticOverflow)?;
    verify_non_dust(alice_output_sat, fee_policy.dust_threshold())?;
    verify_non_dust(bob_output_sat, fee_policy.dust_threshold())?;
    require_state(
        child,
        &PlannedState::Terminal(PlannedTerminal {
            outcome,
            amounts,
            accounting,
            alice_output_sat,
            bob_output_sat,
        }),
    )
}

pub(super) fn require_state(
    child: &PlannedNode,
    expected: &PlannedState,
) -> Result<(), CompilerError> {
    if &child.state == expected {
        Ok(())
    } else {
        Err(profile("child state disagrees with recomputed transition"))
    }
}

pub(super) fn verify_reserve_split(remaining: u64, split: (u64, u64)) -> Result<(), CompilerError> {
    if split
        .0
        .checked_add(split.1)
        .ok_or(ChainError::ArithmeticOverflow)?
        == remaining
    {
        Ok(())
    } else {
        Err(ChainError::ValueNotConserved.into())
    }
}

pub(super) fn verify_non_dust(value: u64, dust_threshold: u64) -> Result<(), CompilerError> {
    if value != 0 && value < dust_threshold {
        Err(FeeError::DustOutput {
            value,
            dust_threshold,
        }
        .into())
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn verify_plan(plan: &LogicalGraphPlan) -> Result<(), CompilerError> {
    verify_plan_header(plan)?;
    let mut by_id = HashMap::with_capacity(plan.nodes.len());
    for (index, node) in plan.nodes.iter().enumerate() {
        if by_id.insert(node.node_id, index).is_some() {
            return Err(profile("duplicate planned node identifier"));
        }
    }
    let mut child_owners = HashMap::with_capacity(plan.transaction_count());
    let mut cumulative_fees = HashMap::with_capacity(plan.nodes.len());
    cumulative_fees.insert(plan.root_node_id, 0_u64);
    let mut maximum_depth = 0_u16;
    let mut maximum_fee = 0_u64;
    let mut actual_alice = Vec::with_capacity(REFERENCE_ALICE_LAMPORT_ENTRIES);
    let mut actual_bob = Vec::with_capacity(REFERENCE_BOB_LAMPORT_ENTRIES);
    let mut edge_count = 0_usize;

    for (parent_index, node) in plan.nodes.iter().enumerate() {
        if planned_state_digest(&node.state)? != node.logical_state_digest {
            return Err(profile("logical state digest mismatch"));
        }
        if parent_index == 0 {
            if node.node_kind != NodeKind::Funded {
                return Err(profile("root node kind is not Funded"));
            }
        } else if node.node_kind != node.state.node_kind() {
            return Err(profile("node kind disagrees with planned state"));
        }
        maximum_depth = maximum_depth.max(node.depth);
        verify_node_obligation(node)?;
        verify_exact_outgoing_kinds(node)?;
        if let PlannedState::Terminal(terminal) = node.state {
            verify_terminal_intrinsic(terminal)?;
        }
        record_expected(node, plan.root_node_id, &mut actual_alice, &mut actual_bob);

        if matches!(node.state, PlannedState::Terminal(_)) {
            if !node.edges.is_empty() || node.timeout.is_some() {
                return Err(profile("terminal planned node has edges or timeout"));
            }
        } else if node.edges.is_empty() || node.timeout.is_none() {
            return Err(profile("obligation node lacks children or timeout"));
        }

        let parent_fee = *cumulative_fees
            .get(&node.node_id)
            .ok_or(CompilerError::DanglingNode)?;
        let mut timeout_edges = 0_usize;
        for (edge_index, edge) in node.edges.iter().enumerate() {
            edge_count = edge_count
                .checked_add(1)
                .ok_or(ChainError::ArithmeticOverflow)?;
            if edge_index > 0
                && node.edges[edge_index - 1].kind.path_code() >= edge.kind.path_code()
            {
                return Err(profile("planned edges are not in strict path-code order"));
            }
            if matches!(edge.kind, EdgeKind::Advance { .. }) {
                return Err(profile("corrected profile contains an Advance edge"));
            }
            verify_edge_semantics(node, edge)?;
            if edge.kind.is_timeout() {
                timeout_edges += 1;
                if edge_index + 1 != node.edges.len() {
                    return Err(profile("timeout edge is not last"));
                }
            }
            let child_index = *by_id
                .get(&edge.child_node_id)
                .ok_or(CompilerError::DanglingNode)?;
            if child_index <= parent_index {
                return Err(profile("plan is not in parent-before-child order"));
            }
            let child = &plan.nodes[child_index];
            if child.parent_node_id != Some(node.node_id)
                || child.depth != next_depth(node.depth)?
                || child.node_id
                    != path_node_id(&node.node_id, edge.kind)
            {
                return Err(profile("planned parent/child linkage is inconsistent"));
            }
            verify_child_semantics(node, edge, child)?;
            if child_owners.insert(child.node_id, node.node_id).is_some() {
                return Err(profile("planned child is owned by more than one parent"));
            }
            node.state
                .amounts()
                .verify_transition(child.state.amounts(), edge.fee_sat)?;
            let child_fee = parent_fee
                .checked_add(edge.fee_sat)
                .ok_or(ChainError::ArithmeticOverflow)?;
            if cumulative_fees.insert(child.node_id, child_fee).is_some() {
                return Err(profile("planned child has multiple cumulative fees"));
            }
            if let PlannedState::Terminal(terminal) = child.state {
                if terminal.output_total()? != terminal.amounts.game_value()? {
                    return Err(ChainError::ValueNotConserved.into());
                }
                maximum_fee = maximum_fee.max(child_fee);
            }
        }
        if !matches!(node.state, PlannedState::Terminal(_)) && timeout_edges != 1 {
            return Err(profile(
                "nonterminal node does not have exactly one timeout edge",
            ));
        }
    }
    verify_plan_totals(
        plan,
        edge_count,
        child_owners.len(),
        cumulative_fees.len(),
        maximum_depth,
        maximum_fee,
        actual_alice,
        actual_bob,
    )
}

pub(super) fn verify_plan_header(plan: &LogicalGraphPlan) -> Result<(), CompilerError> {
    if plan.nodes.is_empty()
        || plan.nodes.len() > REFERENCE_TOTAL_NODE_COUNT
        || plan.transaction_count() > REFERENCE_TRANSACTION_COUNT
        || plan.maximum_path_length > REFERENCE_MAX_PATH_LENGTH
    {
        return Err(profile("logical graph has an invalid rules-derived shape"));
    }
    let Some(root) = plan.nodes.first() else {
        return Err(profile("logical graph is empty"));
    };
    if root.node_id != plan.root_node_id
        || root.node_id != root_node_id(&plan.chain_game_id)
        || root.parent_node_id.is_some()
        || root.node_kind != NodeKind::Funded
        || root.depth != 0
        || !matches!(
            root.state,
            PlannedState::Reveal {
                phase: Phase::DealAlice,
                pattern: RevealPattern::DealAlice,
                ..
            }
        )
    {
        return Err(profile("funded root is not the Deal-Alice obligation"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_plan_totals(
    plan: &LogicalGraphPlan,
    edge_count: usize,
    child_owner_count: usize,
    reached_node_count: usize,
    maximum_depth: u16,
    maximum_fee: u64,
    mut actual_alice: Vec<ExpectedLamportEntry>,
    mut actual_bob: Vec<ExpectedLamportEntry>,
) -> Result<(), CompilerError> {
    if edge_count != plan.transaction_count()
        || child_owner_count != plan.transaction_count()
        || reached_node_count != plan.nodes.len()
    {
        return Err(profile(
            "logical graph is disconnected or has the wrong edge count",
        ));
    }
    if maximum_depth != plan.maximum_path_length || maximum_fee != plan.maximum_path_fee_sat {
        return Err(profile("declared maximum path depth or fee is incorrect"));
    }
    sort_lamport_entries(&mut actual_alice);
    sort_lamport_entries(&mut actual_bob);
    if actual_alice != plan.expected_alice_lamport
        || actual_bob != plan.expected_bob_lamport
        || !strictly_sorted_lamport(&actual_alice)
        || !strictly_sorted_lamport(&actual_bob)
    {
        return Err(profile(
            "Lamport expectations do not match graph-controlled nodes",
        ));
    }
    Ok(())
}

pub(super) fn verify_node_obligation(node: &PlannedNode) -> Result<(), CompilerError> {
    match (&node.state, node.timeout) {
        (
            PlannedState::Reveal { phase, pattern, .. },
            Some(TimeoutSpec {
                kind: TimeoutKind::Reveal,
                defaulting,
                beneficiary,
                ..
            }),
        ) if valid_reveal_phase(*phase, *pattern)
            && defaulting == pattern.revealer()
            && beneficiary == defaulting.other() =>
        {
            Ok(())
        }
        (
            PlannedState::Betting { state, .. },
            Some(TimeoutSpec {
                kind: TimeoutKind::Action,
                defaulting,
                beneficiary,
                ..
            }),
        ) if defaulting == state.actor && beneficiary == defaulting.other() => Ok(()),
        (
            PlannedState::AliceShowdown { .. },
            Some(TimeoutSpec {
                kind: TimeoutKind::Showdown,
                defaulting: Role::Alice,
                beneficiary: Role::Bob,
                ..
            }),
        )
        | (
            PlannedState::BobTerminal { .. },
            Some(TimeoutSpec {
                kind: TimeoutKind::Showdown,
                defaulting: Role::Bob,
                beneficiary: Role::Alice,
                ..
            }),
        )
        | (PlannedState::Terminal(_), None) => Ok(()),
        _ => Err(profile("planned state has the wrong timeout obligation")),
    }
}

pub(super) fn verify_exact_outgoing_kinds(node: &PlannedNode) -> Result<(), CompilerError> {
    let valid = match node.state {
        PlannedState::Reveal { pattern, .. } => edge_kinds_equal(
            &node.edges,
            [
                reveal_edge_kind(pattern),
                EdgeKind::Timeout(TimeoutKind::Reveal),
            ],
        ),
        PlannedState::Betting { .. } => {
            let Some((timeout, actions)) = node.edges.split_last() else {
                return Err(profile("betting node has no outgoing edges"));
            };
            actions
                .iter()
                .all(|edge| matches!(edge.kind, EdgeKind::Action(_)))
                && !actions.is_empty()
                && timeout.kind == EdgeKind::Timeout(TimeoutKind::Action)
        }
        PlannedState::AliceShowdown { .. } => edge_kinds_equal(
            &node.edges,
            [
                EdgeKind::AliceShowdown,
                EdgeKind::Timeout(TimeoutKind::Showdown),
            ],
        ),
        PlannedState::BobTerminal { .. } => edge_kinds_equal(
            &node.edges,
            [
                EdgeKind::BobPayout(ShowdownOutcome::AliceWin),
                EdgeKind::BobPayout(ShowdownOutcome::BobWin),
                EdgeKind::BobPayout(ShowdownOutcome::Split),
                EdgeKind::Timeout(TimeoutKind::Showdown),
            ],
        ),
        PlannedState::Terminal(_) => node.edges.is_empty(),
    };
    if valid {
        Ok(())
    } else {
        Err(profile(
            "node does not contain its exact required outgoing edge-kind set",
        ))
    }
}

pub(super) fn edge_kinds_equal<const N: usize>(
    edges: &[PlannedEdge],
    expected: [EdgeKind; N],
) -> bool {
    edges.len() == N
        && edges
            .iter()
            .zip(expected)
            .all(|(edge, kind)| edge.kind == kind)
}

pub(super) fn verify_child_semantics(
    parent: &PlannedNode,
    edge: &PlannedEdge,
    child: &PlannedNode,
) -> Result<(), CompilerError> {
    let valid = if let EdgeKind::Timeout(kind) = edge.kind {
        matches!(&child.state, PlannedState::Terminal(terminal) if parent.timeout.is_some_and(|timeout| {
            terminal.outcome == TerminalOutcome::Timeout {
                kind,
                defaulting: timeout.defaulting,
            }
        }))
    } else {
        match &parent.state {
            PlannedState::Reveal {
                phase,
                pattern,
                amounts,
            } => valid_reveal_successor(*phase, *pattern, *amounts, edge.kind, &child.state),
            PlannedState::Betting { state, .. } => match (edge.kind, &child.state) {
                (
                    EdgeKind::Action(poker_settlement_types::Action::Fold),
                    PlannedState::Terminal(terminal),
                ) => {
                    terminal.outcome
                        == TerminalOutcome::Fold {
                            folded: state.actor,
                        }
                }
                (EdgeKind::Action(action), child_state) => {
                    action != poker_settlement_types::Action::Fold
                        && !matches!(child_state, PlannedState::Terminal(_))
                }
                _ => false,
            },
            PlannedState::AliceShowdown { .. } => {
                edge.kind == EdgeKind::AliceShowdown
                    && matches!(child.state, PlannedState::BobTerminal { .. })
            }
            PlannedState::BobTerminal { .. } => {
                matches!(
                    (edge.kind, &child.state),
                    (EdgeKind::BobPayout(outcome), PlannedState::Terminal(terminal))
                        if terminal.outcome == TerminalOutcome::Showdown(outcome)
                )
            }
            PlannedState::Terminal(_) => false,
        }
    };
    if valid {
        Ok(())
    } else {
        Err(profile(
            "edge does not create the required next semantic phase",
        ))
    }
}

pub(super) fn valid_reveal_successor(
    phase: Phase,
    pattern: RevealPattern,
    amounts: AmountState,
    edge_kind: EdgeKind,
    child: &PlannedState,
) -> bool {
    match phase {
        Phase::DealAlice => {
            edge_kind
                == EdgeKind::HoleCardReveal {
                    revealer: Role::Bob,
                }
                && matches!(
                    child,
                    PlannedState::Reveal {
                        phase: Phase::DealBob,
                        pattern: RevealPattern::DealBob,
                        ..
                    }
                )
        }
        Phase::DealBob => {
            edge_kind
                == EdgeKind::HoleCardReveal {
                    revealer: Role::Alice,
                }
                && matches!(
                    child,
                    PlannedState::Betting {
                        phase: Phase::PreflopBetting,
                        ..
                    }
                )
        }
        _ => valid_community_reveal_successor(phase, pattern, amounts, edge_kind, child),
    }
}

pub(super) fn valid_community_reveal_successor(
    phase: Phase,
    pattern: RevealPattern,
    amounts: AmountState,
    edge_kind: EdgeKind,
    child: &PlannedState,
) -> bool {
    let (street, next_phase, next_is_reveal) = match phase {
        Phase::FlopRevealFirst => (Street::Flop, Phase::FlopRevealSecond, true),
        Phase::FlopRevealSecond => (Street::Flop, Phase::FlopBetting, false),
        Phase::TurnRevealFirst => (Street::Turn, Phase::TurnRevealSecond, true),
        Phase::TurnRevealSecond => (Street::Turn, Phase::TurnBetting, false),
        Phase::RiverRevealFirst => (Street::River, Phase::RiverRevealSecond, true),
        Phase::RiverRevealSecond => (Street::River, Phase::RiverBetting, false),
        _ => return false,
    };
    if !matches!(edge_kind, EdgeKind::CommunityReveal { street: actual, .. } if actual == street) {
        return false;
    }
    if next_is_reveal {
        matches!(child, PlannedState::Reveal { phase, pattern: next_pattern, .. }
            if *phase == next_phase
                && next_pattern.revealer() == pattern.revealer().other())
    } else if is_all_in(amounts) {
        match street {
            Street::Flop => matches!(
                child,
                PlannedState::Reveal {
                    phase: Phase::TurnRevealFirst,
                    ..
                }
            ),
            Street::Turn => matches!(
                child,
                PlannedState::Reveal {
                    phase: Phase::RiverRevealFirst,
                    ..
                }
            ),
            Street::River => matches!(child, PlannedState::AliceShowdown { .. }),
            Street::Preflop => false,
        }
    } else {
        matches!(child, PlannedState::Betting { phase, .. } if *phase == next_phase)
    }
}

pub(super) fn verify_terminal_intrinsic(terminal: PlannedTerminal) -> Result<(), CompilerError> {
    if terminal.accounting.reason != terminal.outcome.reason()
        || terminal.accounting.fee_reserve_remaining != terminal.amounts.fee_reserve_remaining
        || terminal.accounting.total()? != terminal.amounts.game_value()?
        || terminal.output_total()? != terminal.amounts.game_value()?
    {
        return Err(ChainError::ValueNotConserved.into());
    }
    let alice_reserve = terminal
        .alice_output_sat
        .checked_sub(terminal.accounting.alice_sat)
        .ok_or(ChainError::ValueNotConserved)?;
    let bob_reserve = terminal
        .bob_output_sat
        .checked_sub(terminal.accounting.bob_sat)
        .ok_or(ChainError::ValueNotConserved)?;
    verify_reserve_split(
        terminal.accounting.fee_reserve_remaining,
        (alice_reserve, bob_reserve),
    )
}

pub(super) fn verify_edge_semantics(
    parent: &PlannedNode,
    edge: &PlannedEdge,
) -> Result<(), CompilerError> {
    let fee_class_is_valid = match edge.kind {
        EdgeKind::Action(_) => edge.fee_class == FeeClass::Betting,
        EdgeKind::HoleCardReveal { .. } | EdgeKind::CommunityReveal { .. } => {
            edge.fee_class == FeeClass::Reveal
        }
        EdgeKind::AliceShowdown => edge.fee_class == FeeClass::AliceShowdown,
        EdgeKind::BobPayout(_) => edge.fee_class == FeeClass::BobPayout,
        EdgeKind::Timeout(_) => edge.fee_class == FeeClass::Timeout,
        EdgeKind::Advance { .. } => false,
    };
    if !fee_class_is_valid {
        return Err(profile("edge kind has the wrong fee class"));
    }
    match (edge.kind, edge.authorization, edge.timeout) {
        (EdgeKind::Action(_), AuthorizationPolicy::BettingAction { actor }, None) if matches!(&parent.state, PlannedState::Betting { state, .. } if state.actor == actor) => {
            Ok(())
        }
        (
            EdgeKind::HoleCardReveal {
                revealer: edge_role,
            }
            | EdgeKind::CommunityReveal {
                revealer: edge_role,
                ..
            },
            AuthorizationPolicy::RevealOpenings {
                revealer: authorization_role,
            },
            None,
        ) if edge_role == authorization_role
            && matches!(&parent.state, PlannedState::Reveal { pattern, .. }
                if pattern.revealer() == edge_role && reveal_edge_kind(*pattern) == edge.kind) =>
        {
            Ok(())
        }
        (EdgeKind::AliceShowdown, AuthorizationPolicy::AliceScore, None)
            if matches!(parent.state, PlannedState::AliceShowdown { .. }) =>
        {
            Ok(())
        }
        (EdgeKind::BobPayout(_), AuthorizationPolicy::BobLivePayout, None)
            if matches!(parent.state, PlannedState::BobTerminal { .. }) =>
        {
            Ok(())
        }
        (EdgeKind::Timeout(kind), AuthorizationPolicy::Timeout { beneficiary }, Some(timeout))
            if parent.timeout == Some(timeout)
                && timeout.kind == kind
                && timeout.beneficiary == beneficiary =>
        {
            timeout.validate()?;
            Ok(())
        }
        _ => Err(profile(
            "edge authorization or timeout metadata is inconsistent",
        )),
    }
}

pub(super) fn strictly_sorted_lamport(entries: &[ExpectedLamportEntry]) -> bool {
    entries
        .windows(2)
        .all(|pair| (pair[0].node_id, pair[0].purpose) < (pair[1].node_id, pair[1].purpose))
}
