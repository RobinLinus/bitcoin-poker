//! Deterministic semantic planning for the complete literal transaction tree.
//!
//! This module deliberately stops before Taproot/script and Bitcoin transaction
//! materialization. [`LogicalGraphPlan`] retains every semantic fact required
//! by that later top-down pass without fabricating executable scripts or txids.

use std::collections::{HashMap, HashSet};

use poker_bitcoin::{FeeClass, FeeError, FeePolicy, RevealPattern};
use poker_codec::{CodecError, Encode, Writer};
use poker_score_ots::{ExpectedLamportEntry, LamportPurpose};
use poker_settlement_types::{
    Action, AmountState, AuthorizationPolicy, BettingState, BettingTransition, ChainError,
    EdgeKind, NodeId, NodeKind, Phase, PokerRules, Role, ShowdownOutcome, StateDigest, Street,
    TerminalAccounting, TerminalOutcome, TimeoutKind, TimeoutSpec, child_node_id,
    logical_state_digest, root_node_id, terminal_accounting,
};

use crate::{
    CompilerError,
    betting::{BettingTree, expand_postflop, expand_preflop},
    manifest::{
        REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT, REFERENCE_TRANSACTION_COUNT,
    },
    reveals::{RevealStep, community_reveal_steps, hole_reveal_steps},
    showdown::{
        alice_showdown_timeout, bob_showdown_timeout, fold_accounting, showdown_branches,
        timeout_accounting,
    },
};

/// Exact number of Alice-controlled score Lamport keys in one game.
pub const REFERENCE_ALICE_LAMPORT_ENTRIES: usize = 1;
/// Exact number of Bob-controlled score Lamport keys in one game.
pub const REFERENCE_BOB_LAMPORT_ENTRIES: usize = 1;

/// Stable logical state committed by one planned node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannedState {
    /// A player must publish the exact committed card shares for this phase.
    Reveal {
        /// Exact protocol phase.
        phase: Phase,
        /// Revealer and ordered deal slots.
        pattern: RevealPattern,
        /// Complete value state before the outgoing transaction.
        amounts: AmountState,
    },
    /// One fixed-limit action decision.
    Betting {
        /// Explicit phase, redundantly checked against `state.street`.
        phase: Phase,
        /// Exact betting decision state.
        state: BettingState,
    },
    /// Alice must reveal her hole shares and certify her packed score.
    AliceShowdown {
        /// Complete value state before Alice's transition.
        amounts: AmountState,
    },
    /// Bob must prove one hand claim and select a signed payout template.
    BobTerminal {
        /// Complete value state before Bob's terminal transition.
        amounts: AmountState,
    },
    /// Fully settled semantic leaf.
    Terminal(PlannedTerminal),
}

impl PlannedState {
    /// Returns the complete amount state at this node.
    #[must_use]
    pub const fn amounts(&self) -> AmountState {
        match self {
            Self::Reveal { amounts, .. }
            | Self::AliceShowdown { amounts }
            | Self::BobTerminal { amounts } => *amounts,
            Self::Betting { state, .. } => state.amounts,
            Self::Terminal(terminal) => terminal.amounts,
        }
    }

    /// Returns the semantic phase, absent only for terminal leaves.
    #[must_use]
    pub const fn phase(&self) -> Option<Phase> {
        match self {
            Self::Reveal { phase, .. } | Self::Betting { phase, .. } => Some(*phase),
            Self::AliceShowdown { .. } => Some(Phase::AliceShowdown),
            Self::BobTerminal { .. } => Some(Phase::BobTerminal),
            Self::Terminal(_) => None,
        }
    }

    fn node_kind(&self) -> NodeKind {
        match self {
            Self::Reveal { phase, .. } => match phase {
                Phase::DealAlice => NodeKind::DealAlice,
                Phase::DealBob => NodeKind::DealBob,
                Phase::FlopRevealFirst | Phase::TurnRevealFirst | Phase::RiverRevealFirst => {
                    NodeKind::CommunityRevealFirst
                }
                Phase::FlopRevealSecond | Phase::TurnRevealSecond | Phase::RiverRevealSecond => {
                    NodeKind::CommunityRevealSecond
                }
                _ => NodeKind::Betting,
            },
            Self::Betting { .. } => NodeKind::Betting,
            Self::AliceShowdown { .. } => NodeKind::AliceShowdown,
            Self::BobTerminal { .. } => NodeKind::BobTerminal,
            Self::Terminal(_) => NodeKind::Terminal,
        }
    }
}

impl Encode for PlannedState {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        match self {
            Self::Reveal {
                phase,
                pattern,
                amounts,
            } => {
                0_u8.encode(writer)?;
                phase.encode(writer)?;
                pattern.code().encode(writer)?;
                amounts.encode(writer)
            }
            Self::Betting { phase, state } => {
                if *phase != betting_phase(state.street) {
                    return Err(CodecError::NonCanonical);
                }
                1_u8.encode(writer)?;
                phase.encode(writer)?;
                state.encode(writer)
            }
            Self::AliceShowdown { amounts } => {
                2_u8.encode(writer)?;
                amounts.encode(writer)
            }
            Self::BobTerminal { amounts } => {
                3_u8.encode(writer)?;
                amounts.encode(writer)
            }
            Self::Terminal(terminal) => {
                4_u8.encode(writer)?;
                terminal.encode(writer)
            }
        }
    }
}

/// Deterministic terminal accounting after fee-reserve disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedTerminal {
    /// Fold, timeout, or showdown outcome selecting this leaf.
    pub outcome: TerminalOutcome,
    /// Amount state after this leaf transaction's fixed fee.
    pub amounts: AmountState,
    /// Poker accounting before unused reserve is assigned.
    pub accounting: TerminalAccounting,
    /// Final value assigned to Alice's independently spendable output(s).
    pub alice_output_sat: u64,
    /// Final value assigned to Bob's independently spendable output(s).
    pub bob_output_sat: u64,
}

impl PlannedTerminal {
    /// Returns the total terminal output value.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic error if the two outputs overflow `u64`.
    pub fn output_total(self) -> Result<u64, ChainError> {
        self.alice_output_sat
            .checked_add(self.bob_output_sat)
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

impl Encode for PlannedTerminal {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.outcome.encode(writer)?;
        self.amounts.encode(writer)?;
        self.accounting.encode(writer)?;
        self.alice_output_sat.encode(writer)?;
        self.bob_output_sat.encode(writer)
    }
}

/// One ordered semantic edge awaiting Bitcoin materialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedEdge {
    /// Semantic branch label and path-code source.
    pub kind: EdgeKind,
    /// Exact pre-exchange/runtime authorization class.
    pub authorization: AuthorizationPolicy,
    /// Child node created by the future transaction.
    pub child_node_id: NodeId,
    /// Fee-policy class used for this transaction.
    pub fee_class: FeeClass,
    /// Exact fee already debited in the child state.
    pub fee_sat: u64,
    /// Relative timeout metadata, present only for timeout edges.
    pub timeout: Option<TimeoutSpec>,
}

/// One semantic state in deterministic parent-before-child order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedNode {
    /// Path-dependent identifier.
    pub node_id: NodeId,
    /// Parent identifier, absent only for the post-activation gameplay root.
    pub parent_node_id: Option<NodeId>,
    /// Root/state/terminal class used by later record materialization.
    pub node_kind: NodeKind,
    /// Canonical semantic state.
    pub state: PlannedState,
    /// SHA-256 of `state`'s canonical encoding.
    pub logical_state_digest: StateDigest,
    /// Number of post-activation gameplay transactions from the root.
    pub depth: u16,
    /// Node-specific deadline for its defaulting actor/revealer.
    pub timeout: Option<TimeoutSpec>,
    /// Children in strict path-code order; timeout is last.
    pub edges: Vec<PlannedEdge>,
}

/// Complete deterministic semantic graph prior to Bitcoin materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalGraphPlan {
    /// Identifier of the signed rules.
    pub chain_game_id: [u8; 32],
    /// Funded Deal-Alice obligation root.
    pub root_node_id: NodeId,
    /// Stable preorder: each parent appears before every child.
    pub nodes: Vec<PlannedNode>,
    /// Strictly sorted Alice node/purpose requirements.
    pub expected_alice_lamport: Vec<ExpectedLamportEntry>,
    /// Strictly sorted Bob node/purpose requirements.
    pub expected_bob_lamport: Vec<ExpectedLamportEntry>,
    /// Exact largest fee sum over any root-to-terminal path.
    pub maximum_path_fee_sat: u64,
    /// Exact largest post-activation gameplay path depth.
    pub maximum_path_length: u16,
}

impl LogicalGraphPlan {
    /// Returns the number of future post-activation gameplay transactions.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    /// Finds one node by identifier.
    #[must_use]
    pub fn node(&self, node_id: &NodeId) -> Option<&PlannedNode> {
        self.nodes.iter().find(|node| &node.node_id == node_id)
    }

    /// Rechecks topology, identifiers, accounting, ordering, and profile counts.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed compiler error on the first discrepancy.
    pub fn verify(&self) -> Result<(), CompilerError> {
        verify_plan(self)
    }
}

/// Shared complete poker topology; callers must authenticate the profile ID.
pub(crate) fn compile_rules_graph(
    rules: &PokerRules,
    chain_id: [u8; 32],
    fee_policy: &dyn FeePolicy,
) -> Result<LogicalGraphPlan, CompilerError> {
    rules.validate()?;
    let fees = FeeSchedule::new(fee_policy)?;
    // The effective-stack graph can be much shorter than the deep-stack
    // 33-transaction deep-stack tree. Graph construction debits every edge of
    // the actual rules-derived tree and therefore fails closed if any
    // branch exhausts the reserve; requiring the reference bound here would make
    // small all-in profiles needlessly unspendable.

    let root_id = root_node_id(&chain_id);
    let mut builder = GraphBuilder::new(rules, fee_policy, fees, root_id);
    builder.build()?;
    let mut expected_alice_lamport = builder.expected_alice_lamport;
    let mut expected_bob_lamport = builder.expected_bob_lamport;
    sort_lamport_entries(&mut expected_alice_lamport);
    sort_lamport_entries(&mut expected_bob_lamport);
    let maximum_path_length = builder
        .nodes
        .iter()
        .map(|node| node.depth)
        .max()
        .unwrap_or(0);
    let maximum_path_fee_sat = exact_maximum_path_fee(rules, &builder.nodes)?;
    if rules.fee_reserve_sat < maximum_path_fee_sat {
        return Err(CompilerError::InsufficientMaximumPathReserve {
            available: rules.fee_reserve_sat,
            required: maximum_path_fee_sat,
        });
    }
    let plan = LogicalGraphPlan {
        chain_game_id: chain_id,
        root_node_id: root_id,
        nodes: builder.nodes,
        expected_alice_lamport,
        expected_bob_lamport,
        maximum_path_fee_sat,
        maximum_path_length,
    };
    verify_rules_plan(&plan, rules, &LiveFeeSemantics(fee_policy))?;
    Ok(plan)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FeeSchedule {
    betting: u64,
    reveal: u64,
    alice_showdown: u64,
    bob_payout: u64,
    timeout: u64,
}

trait FeeSemantics {
    fn schedule(&self) -> Result<FeeSchedule, CompilerError>;
    fn dust_threshold(&self) -> u64;
    fn reserve_split(
        &self,
        remaining: u64,
        remainder_recipient: Role,
    ) -> Result<(u64, u64), CompilerError>;
}

struct LiveFeeSemantics<'a>(&'a dyn FeePolicy);

impl FeeSemantics for LiveFeeSemantics<'_> {
    fn schedule(&self) -> Result<FeeSchedule, CompilerError> {
        FeeSchedule::new(self.0)
    }

    fn dust_threshold(&self) -> u64 {
        self.0.dust_threshold()
    }

    fn reserve_split(
        &self,
        remaining: u64,
        remainder_recipient: Role,
    ) -> Result<(u64, u64), CompilerError> {
        let split = self.0.split_unused_reserve(remaining, remainder_recipient);
        verify_reserve_split(remaining, split)?;
        Ok(split)
    }
}

impl FeeSchedule {
    fn new(policy: &dyn FeePolicy) -> Result<Self, CompilerError> {
        if policy.dust_threshold() == 0 {
            return Err(FeeError::ZeroDustThreshold.into());
        }
        let schedule = Self {
            betting: policy.fee_for(FeeClass::Betting)?,
            reveal: policy.fee_for(FeeClass::Reveal)?,
            alice_showdown: policy.fee_for(FeeClass::AliceShowdown)?,
            bob_payout: policy.fee_for(FeeClass::BobPayout)?,
            timeout: policy.fee_for(FeeClass::Timeout)?,
        };
        Ok(schedule)
    }

    const fn for_class(self, class: FeeClass) -> u64 {
        match class {
            FeeClass::Betting => self.betting,
            FeeClass::Reveal => self.reveal,
            FeeClass::AliceShowdown => self.alice_showdown,
            FeeClass::BobPayout => self.bob_payout,
            FeeClass::Timeout => self.timeout,
            FeeClass::Transition => 0,
        }
    }

    fn maximum_path_fee(self) -> Result<u64, CompilerError> {
        let betting = self
            .betting
            .checked_mul(23)
            .ok_or(FeeError::ArithmeticOverflow)?;
        let reveals = self
            .reveal
            .checked_mul(8)
            .ok_or(FeeError::ArithmeticOverflow)?;
        betting
            .checked_add(reveals)
            .and_then(|total| total.checked_add(self.alice_showdown))
            .and_then(|total| total.checked_add(self.bob_payout.max(self.timeout)))
            .ok_or_else(|| CompilerError::from(FeeError::ArithmeticOverflow))
    }
}

struct GraphBuilder<'a> {
    rules: &'a PokerRules,
    fee_policy: &'a dyn FeePolicy,
    fees: FeeSchedule,
    root_node_id: NodeId,
    nodes: Vec<PlannedNode>,
    seen_node_ids: HashSet<NodeId>,
    expected_alice_lamport: Vec<ExpectedLamportEntry>,
    expected_bob_lamport: Vec<ExpectedLamportEntry>,
}

impl<'a> GraphBuilder<'a> {
    fn new(
        rules: &'a PokerRules,
        fee_policy: &'a dyn FeePolicy,
        fees: FeeSchedule,
        root_node_id: NodeId,
    ) -> Self {
        Self {
            rules,
            fee_policy,
            fees,
            root_node_id,
            nodes: Vec::with_capacity(REFERENCE_TOTAL_NODE_COUNT),
            seen_node_ids: HashSet::with_capacity(REFERENCE_TOTAL_NODE_COUNT),
            expected_alice_lamport: Vec::with_capacity(REFERENCE_ALICE_LAMPORT_ENTRIES),
            expected_bob_lamport: Vec::with_capacity(REFERENCE_BOB_LAMPORT_ENTRIES),
        }
    }

    fn build(&mut self) -> Result<(), CompilerError> {
        let [deal_alice, deal_bob] = hole_reveal_steps(self.rules)?;
        if deal_alice.phase != Phase::DealAlice
            || deal_alice.pattern != RevealPattern::DealAlice
            || deal_bob.phase != Phase::DealBob
            || deal_bob.pattern != RevealPattern::DealBob
        {
            return Err(profile("hole-card reveal helper returned the wrong phases"));
        }
        let root_state = PlannedState::Reveal {
            phase: deal_alice.phase,
            pattern: deal_alice.pattern,
            // Forced blinds are part of the first protocol state, before any
            // reveal obligation or timeout can be exercised.
            amounts: BettingState::initial_preflop(self.rules)?.amounts,
        };
        let root_index = self.insert_root(root_state, deal_alice.timeout)?;
        self.populate_deal_alice(root_index, deal_alice, deal_bob)
    }

    fn populate_deal_alice(
        &mut self,
        root_index: usize,
        step: RevealStep,
        next_step: RevealStep,
    ) -> Result<(), CompilerError> {
        let root_id = self.nodes[root_index].node_id;
        let amounts = self.nodes[root_index].state.amounts();
        let normal_kind = reveal_edge_kind(step.pattern);
        let normal_amounts = self.charge(amounts, FeeClass::Reveal)?;
        let normal_child =
            self.build_deal_bob(root_id, normal_kind, normal_amounts, 1, next_step)?;
        let normal = self.edge(
            normal_kind,
            AuthorizationPolicy::RevealOpenings {
                revealer: step.pattern.revealer(),
            },
            normal_child,
            FeeClass::Reveal,
            None,
        );
        let timeout = self.build_timeout_edge(root_id, 1, amounts, step.timeout)?;
        self.finish_edges(root_index, vec![normal, timeout])
    }

    fn build_deal_bob(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        amounts: AmountState,
        depth: u16,
        step: RevealStep,
    ) -> Result<NodeId, CompilerError> {
        let state = PlannedState::Reveal {
            phase: step.phase,
            pattern: step.pattern,
            amounts,
        };
        let node_index = self.insert_child(
            parent_node_id,
            incoming_kind,
            state,
            depth,
            Some(step.timeout),
        )?;
        let node_id = self.nodes[node_index].node_id;
        let normal_kind = reveal_edge_kind(step.pattern);
        let after_fee = self.charge(amounts, FeeClass::Reveal)?;
        let mut preflop = BettingState::initial_preflop(self.rules)?;
        preflop.amounts.fee_reserve_remaining = after_fee.fee_reserve_remaining;
        preflop.validate(self.rules)?;
        let tree = expand_preflop(self.rules, preflop)?;
        let normal_child =
            self.build_betting_tree(node_id, normal_kind, &tree, preflop, next_depth(depth)?)?;
        let normal = self.edge(
            normal_kind,
            AuthorizationPolicy::RevealOpenings {
                revealer: step.pattern.revealer(),
            },
            normal_child,
            FeeClass::Reveal,
            None,
        );
        let timeout =
            self.build_timeout_edge(node_id, next_depth(depth)?, amounts, step.timeout)?;
        self.finish_edges(node_index, vec![normal, timeout])?;
        Ok(node_id)
    }

    fn build_betting_tree(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        tree: &BettingTree,
        actual_state: BettingState,
        depth: u16,
    ) -> Result<NodeId, CompilerError> {
        let BettingTree::Decision {
            state: tree_state,
            timeout_beneficiary,
            actions,
        } = tree
        else {
            return Err(profile("betting subtree root is not a decision"));
        };
        let mut expected_state = *tree_state;
        expected_state.amounts.fee_reserve_remaining = actual_state.amounts.fee_reserve_remaining;
        if expected_state != actual_state || *timeout_beneficiary != actual_state.actor.other() {
            return Err(profile(
                "betting-tree state disagrees with fee-adjusted state",
            ));
        }
        actual_state.validate(self.rules)?;
        let timeout = TimeoutSpec::new(
            TimeoutKind::Action,
            self.rules.action_csv,
            actual_state.actor,
            actual_state.actor.other(),
        )?;
        let state = PlannedState::Betting {
            phase: betting_phase(actual_state.street),
            state: actual_state,
        };
        let node_index =
            self.insert_child(parent_node_id, incoming_kind, state, depth, Some(timeout))?;
        let node_id = self.nodes[node_index].node_id;
        let child_depth = next_depth(depth)?;
        let mut edges = Vec::with_capacity(actions.len() + 1);
        for action_edge in actions {
            let edge_kind = EdgeKind::Action(action_edge.action);
            let child_node_id = match action_edge.child.as_ref() {
                BettingTree::Decision {
                    state: child_state, ..
                } => {
                    let mut child_state = *child_state;
                    child_state.amounts.fee_reserve_remaining =
                        actual_state.amounts.fee_reserve_remaining;
                    child_state.amounts = self.charge(child_state.amounts, FeeClass::Betting)?;
                    self.build_betting_tree(
                        node_id,
                        edge_kind,
                        action_edge.child.as_ref(),
                        child_state,
                        child_depth,
                    )?
                }
                BettingTree::Fold {
                    folded,
                    winner,
                    amounts,
                } => {
                    if *winner != folded.other() {
                        return Err(profile("betting fold winner is not the other player"));
                    }
                    let after_fee = self.charge(
                        with_fee_reserve(*amounts, actual_state.amounts.fee_reserve_remaining),
                        FeeClass::Betting,
                    )?;
                    let outcome = TerminalOutcome::Fold { folded: *folded };
                    let accounting = fold_accounting(self.rules, after_fee, *folded)?;
                    self.insert_terminal(
                        node_id,
                        edge_kind,
                        child_depth,
                        after_fee,
                        outcome,
                        accounting,
                    )?
                }
                BettingTree::Continuation { street, amounts } => {
                    let after_fee = self.charge(
                        with_fee_reserve(*amounts, actual_state.amounts.fee_reserve_remaining),
                        FeeClass::Betting,
                    )?;
                    self.build_after_street(node_id, edge_kind, *street, after_fee, child_depth)?
                }
            };
            edges.push(self.edge(
                edge_kind,
                AuthorizationPolicy::BettingAction {
                    actor: actual_state.actor,
                },
                child_node_id,
                FeeClass::Betting,
                None,
            ));
        }
        edges.push(self.build_timeout_edge(node_id, child_depth, actual_state.amounts, timeout)?);
        self.finish_edges(node_index, edges)?;
        Ok(node_id)
    }

    fn build_after_street(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        street: Street,
        amounts: AmountState,
        depth: u16,
    ) -> Result<NodeId, CompilerError> {
        match street {
            Street::Preflop => self.build_community_first(
                parent_node_id,
                incoming_kind,
                Street::Flop,
                amounts,
                depth,
            ),
            Street::Flop => self.build_community_first(
                parent_node_id,
                incoming_kind,
                Street::Turn,
                amounts,
                depth,
            ),
            Street::Turn => self.build_community_first(
                parent_node_id,
                incoming_kind,
                Street::River,
                amounts,
                depth,
            ),
            Street::River => {
                self.build_alice_showdown(parent_node_id, incoming_kind, amounts, depth)
            }
        }
    }

    fn build_community_first(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        street: Street,
        amounts: AmountState,
        depth: u16,
    ) -> Result<NodeId, CompilerError> {
        let [first, second] = community_reveal_steps(self.rules, street)?;
        let state = PlannedState::Reveal {
            phase: first.phase,
            pattern: first.pattern,
            amounts,
        };
        let node_index = self.insert_child(
            parent_node_id,
            incoming_kind,
            state,
            depth,
            Some(first.timeout),
        )?;
        let node_id = self.nodes[node_index].node_id;
        let child_depth = next_depth(depth)?;
        let normal_kind = reveal_edge_kind(first.pattern);
        let normal_amounts = self.charge(amounts, FeeClass::Reveal)?;
        let normal_child = self.build_community_second(
            node_id,
            normal_kind,
            street,
            normal_amounts,
            child_depth,
            second,
        )?;
        let normal = self.edge(
            normal_kind,
            AuthorizationPolicy::RevealOpenings {
                revealer: first.pattern.revealer(),
            },
            normal_child,
            FeeClass::Reveal,
            None,
        );
        let timeout = self.build_timeout_edge(node_id, child_depth, amounts, first.timeout)?;
        self.finish_edges(node_index, vec![normal, timeout])?;
        Ok(node_id)
    }

    fn build_community_second(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        street: Street,
        amounts: AmountState,
        depth: u16,
        step: RevealStep,
    ) -> Result<NodeId, CompilerError> {
        let state = PlannedState::Reveal {
            phase: step.phase,
            pattern: step.pattern,
            amounts,
        };
        let node_index = self.insert_child(
            parent_node_id,
            incoming_kind,
            state,
            depth,
            Some(step.timeout),
        )?;
        let node_id = self.nodes[node_index].node_id;
        let child_depth = next_depth(depth)?;
        let normal_kind = reveal_edge_kind(step.pattern);
        let normal_amounts = self.charge(amounts, FeeClass::Reveal)?;
        let normal_child = if is_all_in(normal_amounts) {
            self.build_after_street(node_id, normal_kind, street, normal_amounts, child_depth)?
        } else {
            let betting_state = BettingState::start_postflop(street, self.rules, normal_amounts)?;
            let tree = expand_postflop(self.rules, betting_state)?;
            self.build_betting_tree(node_id, normal_kind, &tree, betting_state, child_depth)?
        };
        let normal = self.edge(
            normal_kind,
            AuthorizationPolicy::RevealOpenings {
                revealer: step.pattern.revealer(),
            },
            normal_child,
            FeeClass::Reveal,
            None,
        );
        let timeout = self.build_timeout_edge(node_id, child_depth, amounts, step.timeout)?;
        self.finish_edges(node_index, vec![normal, timeout])?;
        Ok(node_id)
    }

    fn build_alice_showdown(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        amounts: AmountState,
        depth: u16,
    ) -> Result<NodeId, CompilerError> {
        let timeout = alice_showdown_timeout(self.rules)?;
        let state = PlannedState::AliceShowdown { amounts };
        let node_index =
            self.insert_child(parent_node_id, incoming_kind, state, depth, Some(timeout))?;
        let node_id = self.nodes[node_index].node_id;
        let child_depth = next_depth(depth)?;
        let after_fee = self.charge(amounts, FeeClass::AliceShowdown)?;
        let normal_child =
            self.build_bob_terminal(node_id, EdgeKind::AliceShowdown, after_fee, child_depth)?;
        let normal = self.edge(
            EdgeKind::AliceShowdown,
            AuthorizationPolicy::AliceScore,
            normal_child,
            FeeClass::AliceShowdown,
            None,
        );
        let timeout_edge = self.build_timeout_edge(node_id, child_depth, amounts, timeout)?;
        self.finish_edges(node_index, vec![normal, timeout_edge])?;
        Ok(node_id)
    }

    fn build_bob_terminal(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        amounts: AmountState,
        depth: u16,
    ) -> Result<NodeId, CompilerError> {
        let timeout = bob_showdown_timeout(self.rules)?;
        let state = PlannedState::BobTerminal { amounts };
        let node_index =
            self.insert_child(parent_node_id, incoming_kind, state, depth, Some(timeout))?;
        let node_id = self.nodes[node_index].node_id;
        let child_depth = next_depth(depth)?;
        let payout_amounts = self.charge(amounts, FeeClass::BobPayout)?;
        let branches = showdown_branches(self.rules, payout_amounts)?;
        let mut edges = Vec::with_capacity(4);
        for branch in branches {
            let kind = EdgeKind::BobPayout(branch.outcome);
            let outcome = TerminalOutcome::Showdown(branch.outcome);
            let child = self.insert_terminal(
                node_id,
                kind,
                child_depth,
                payout_amounts,
                outcome,
                branch.accounting,
            )?;
            edges.push(self.edge(
                kind,
                AuthorizationPolicy::BobLivePayout,
                child,
                FeeClass::BobPayout,
                None,
            ));
        }
        edges.push(self.build_timeout_edge(node_id, child_depth, amounts, timeout)?);
        self.finish_edges(node_index, edges)?;
        Ok(node_id)
    }

    fn build_timeout_edge(
        &mut self,
        parent_node_id: NodeId,
        depth: u16,
        amounts: AmountState,
        timeout: TimeoutSpec,
    ) -> Result<PlannedEdge, CompilerError> {
        timeout.validate()?;
        let after_fee = self.charge(amounts, FeeClass::Timeout)?;
        let outcome = TerminalOutcome::Timeout {
            kind: timeout.kind,
            defaulting: timeout.defaulting,
        };
        let accounting =
            timeout_accounting(self.rules, after_fee, timeout.kind, timeout.defaulting)?;
        let kind = EdgeKind::Timeout(timeout.kind);
        let child =
            self.insert_terminal(parent_node_id, kind, depth, after_fee, outcome, accounting)?;
        Ok(self.edge(
            kind,
            AuthorizationPolicy::Timeout {
                beneficiary: timeout.beneficiary,
            },
            child,
            FeeClass::Timeout,
            Some(timeout),
        ))
    }

    fn insert_terminal(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        depth: u16,
        amounts: AmountState,
        outcome: TerminalOutcome,
        accounting: TerminalAccounting,
    ) -> Result<NodeId, CompilerError> {
        if accounting.reason != outcome.reason()
            || accounting.fee_reserve_remaining != amounts.fee_reserve_remaining
            || accounting.total()? != amounts.game_value()?
        {
            return Err(ChainError::ValueNotConserved.into());
        }
        let (alice_reserve, bob_reserve) = self.fee_policy.split_unused_reserve(
            accounting.fee_reserve_remaining,
            self.rules.split_remainder_recipient,
        );
        if alice_reserve
            .checked_add(bob_reserve)
            .ok_or(ChainError::ArithmeticOverflow)?
            != accounting.fee_reserve_remaining
        {
            return Err(ChainError::ValueNotConserved.into());
        }
        let alice_output_sat = accounting
            .alice_sat
            .checked_add(alice_reserve)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let bob_output_sat = accounting
            .bob_sat
            .checked_add(bob_reserve)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validate_terminal_output(alice_output_sat)?;
        self.validate_terminal_output(bob_output_sat)?;
        let terminal = PlannedTerminal {
            outcome,
            amounts,
            accounting,
            alice_output_sat,
            bob_output_sat,
        };
        if terminal.output_total()? != amounts.game_value()? {
            return Err(ChainError::ValueNotConserved.into());
        }
        let index = self.insert_child(
            parent_node_id,
            incoming_kind,
            PlannedState::Terminal(terminal),
            depth,
            None,
        )?;
        Ok(self.nodes[index].node_id)
    }

    fn validate_terminal_output(&self, value: u64) -> Result<(), CompilerError> {
        let dust_threshold = self.fee_policy.dust_threshold();
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

    fn insert_root(
        &mut self,
        state: PlannedState,
        timeout: TimeoutSpec,
    ) -> Result<usize, CompilerError> {
        if !self.nodes.is_empty() {
            return Err(profile("attempted to insert more than one graph root"));
        }
        let digest = planned_state_digest(&state)?;
        let node_id = self.root_node_id;
        self.insert_node_id(node_id)?;
        self.nodes.push(PlannedNode {
            node_id,
            parent_node_id: None,
            node_kind: NodeKind::Funded,
            state,
            logical_state_digest: digest,
            depth: 0,
            timeout: Some(timeout),
            edges: Vec::new(),
        });
        Ok(0)
    }

    fn insert_child(
        &mut self,
        parent_node_id: NodeId,
        incoming_kind: EdgeKind,
        state: PlannedState,
        depth: u16,
        timeout: Option<TimeoutSpec>,
    ) -> Result<usize, CompilerError> {
        if let Some(timeout) = timeout {
            timeout.validate()?;
        }
        let logical_state_digest = planned_state_digest(&state)?;
        let node_id = child_node_id(&parent_node_id, incoming_kind, &logical_state_digest);
        self.insert_node_id(node_id)?;
        let node_kind = state.node_kind();
        let index = self.nodes.len();
        self.record_lamport_expectation(node_id, &state);
        self.nodes.push(PlannedNode {
            node_id,
            parent_node_id: Some(parent_node_id),
            node_kind,
            state,
            logical_state_digest,
            depth,
            timeout,
            edges: Vec::new(),
        });
        Ok(index)
    }

    fn insert_node_id(&mut self, node_id: NodeId) -> Result<(), CompilerError> {
        if self.seen_node_ids.insert(node_id) {
            Ok(())
        } else {
            Err(profile("canonical node identifier collision"))
        }
    }

    fn record_lamport_expectation(&mut self, _node_id: NodeId, state: &PlannedState) {
        match state {
            PlannedState::AliceShowdown { .. } if self.expected_alice_lamport.is_empty() => {
                self.expected_alice_lamport.push(ExpectedLamportEntry::new(
                    self.root_node_id,
                    LamportPurpose::AliceScore24Bit,
                ));
            }
            PlannedState::BobTerminal { .. } if self.expected_bob_lamport.is_empty() => {
                self.expected_bob_lamport.push(ExpectedLamportEntry::new(
                    self.root_node_id,
                    LamportPurpose::BobScore24Bit,
                ));
            }
            _ => {}
        }
    }

    fn charge(
        &self,
        amounts: AmountState,
        fee_class: FeeClass,
    ) -> Result<AmountState, CompilerError> {
        let fee = self.fees.for_class(fee_class);
        Ok(amounts.charge_fee(fee)?)
    }

    fn edge(
        &self,
        kind: EdgeKind,
        authorization: AuthorizationPolicy,
        child_node_id: NodeId,
        fee_class: FeeClass,
        timeout: Option<TimeoutSpec>,
    ) -> PlannedEdge {
        PlannedEdge {
            kind,
            authorization,
            child_node_id,
            fee_class,
            fee_sat: self.fees.for_class(fee_class),
            timeout,
        }
    }

    fn finish_edges(
        &mut self,
        node_index: usize,
        mut edges: Vec<PlannedEdge>,
    ) -> Result<(), CompilerError> {
        edges.sort_unstable_by_key(|edge| edge.kind.path_code());
        if edges
            .windows(2)
            .any(|pair| pair[0].kind.path_code() >= pair[1].kind.path_code())
        {
            return Err(profile("node contains duplicate or unordered edge codes"));
        }
        if edges
            .iter()
            .position(|edge| edge.kind.is_timeout())
            .is_some_and(|index| index + 1 != edges.len())
        {
            return Err(profile("timeout edge is not last"));
        }
        self.nodes[node_index].edges = edges;
        Ok(())
    }
}

fn reveal_step_for_phase(
    rules: impl Into<PokerRules>,
    phase: Phase,
) -> Result<RevealStep, CompilerError> {
    let rules = &rules.into();
    match phase {
        Phase::DealAlice => Ok(hole_reveal_steps(rules)?[0]),
        Phase::DealBob => Ok(hole_reveal_steps(rules)?[1]),
        Phase::FlopRevealFirst => Ok(community_reveal_steps(rules, Street::Flop)?[0]),
        Phase::FlopRevealSecond => Ok(community_reveal_steps(rules, Street::Flop)?[1]),
        Phase::TurnRevealFirst => Ok(community_reveal_steps(rules, Street::Turn)?[0]),
        Phase::TurnRevealSecond => Ok(community_reveal_steps(rules, Street::Turn)?[1]),
        Phase::RiverRevealFirst => Ok(community_reveal_steps(rules, Street::River)?[0]),
        Phase::RiverRevealSecond => Ok(community_reveal_steps(rules, Street::River)?[1]),
        _ => Err(profile("non-reveal phase used as a reveal obligation")),
    }
}

fn state_after_completed_street(
    rules: impl Into<PokerRules>,
    street: Street,
    amounts: AmountState,
) -> Result<PlannedState, CompilerError> {
    let rules = &rules.into();
    if let Some(next_street) = street.next() {
        let step = community_reveal_steps(rules, next_street)?[0];
        Ok(PlannedState::Reveal {
            phase: step.phase,
            pattern: step.pattern,
            amounts,
        })
    } else {
        Ok(PlannedState::AliceShowdown { amounts })
    }
}

const fn is_all_in(amounts: AmountState) -> bool {
    amounts.alice_remaining == 0 || amounts.bob_remaining == 0
}

fn reveal_phase_street(phase: Phase) -> Result<Street, CompilerError> {
    match phase {
        Phase::FlopRevealFirst | Phase::FlopRevealSecond => Ok(Street::Flop),
        Phase::TurnRevealFirst | Phase::TurnRevealSecond => Ok(Street::Turn),
        Phase::RiverRevealFirst | Phase::RiverRevealSecond => Ok(Street::River),
        _ => Err(profile("phase does not identify a community street")),
    }
}

fn record_expected(
    node: &PlannedNode,
    root_node_id: NodeId,
    alice: &mut Vec<ExpectedLamportEntry>,
    bob: &mut Vec<ExpectedLamportEntry>,
) {
    match node.state {
        PlannedState::AliceShowdown { .. } if alice.is_empty() => alice.push(
            ExpectedLamportEntry::new(root_node_id, LamportPurpose::AliceScore24Bit),
        ),
        PlannedState::BobTerminal { .. } if bob.is_empty() => bob.push(ExpectedLamportEntry::new(
            root_node_id,
            LamportPurpose::BobScore24Bit,
        )),
        _ => {}
    }
}

fn reveal_edge_kind(pattern: RevealPattern) -> EdgeKind {
    match pattern {
        RevealPattern::DealAlice | RevealPattern::DealBob => EdgeKind::HoleCardReveal {
            revealer: pattern.revealer(),
        },
        RevealPattern::Flop(revealer) => EdgeKind::CommunityReveal {
            street: Street::Flop,
            revealer,
        },
        RevealPattern::Turn(revealer) => EdgeKind::CommunityReveal {
            street: Street::Turn,
            revealer,
        },
        RevealPattern::River(revealer) => EdgeKind::CommunityReveal {
            street: Street::River,
            revealer,
        },
    }
}

const fn valid_reveal_phase(phase: Phase, pattern: RevealPattern) -> bool {
    matches!(
        (phase, pattern),
        (Phase::DealAlice, RevealPattern::DealAlice)
            | (Phase::DealBob, RevealPattern::DealBob)
            | (
                Phase::FlopRevealFirst | Phase::FlopRevealSecond,
                RevealPattern::Flop(_)
            )
            | (
                Phase::TurnRevealFirst | Phase::TurnRevealSecond,
                RevealPattern::Turn(_)
            )
            | (
                Phase::RiverRevealFirst | Phase::RiverRevealSecond,
                RevealPattern::River(_)
            )
    )
}

fn with_fee_reserve(mut amounts: AmountState, fee_reserve_remaining: u64) -> AmountState {
    amounts.fee_reserve_remaining = fee_reserve_remaining;
    amounts
}

fn planned_state_digest(state: &PlannedState) -> Result<StateDigest, CompilerError> {
    logical_state_digest(state).map_err(|error| ChainError::from(error).into())
}

fn next_depth(depth: u16) -> Result<u16, CompilerError> {
    depth
        .checked_add(1)
        .ok_or_else(|| ChainError::ArithmeticOverflow.into())
}

const fn profile(reason: &'static str) -> CompilerError {
    CompilerError::ProfileMismatch { reason }
}

fn betting_phase(street: Street) -> Phase {
    match street {
        Street::Preflop => Phase::PreflopBetting,
        Street::Flop => Phase::FlopBetting,
        Street::Turn => Phase::TurnBetting,
        Street::River => Phase::RiverBetting,
    }
}

fn sort_lamport_entries(entries: &mut [ExpectedLamportEntry]) {
    entries.sort_unstable_by_key(|entry| (entry.node_id, entry.purpose));
}

#[cfg(test)]
mod tests;

mod verify;
use verify::{verify_plan, verify_reserve_split, verify_rules_plan};

mod fees;
use fees::exact_maximum_path_fee;
