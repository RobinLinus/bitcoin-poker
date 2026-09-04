//! Deterministic semantic planning for the complete literal transaction tree.
//!
//! This module deliberately stops before Taproot/script and Bitcoin transaction
//! materialization. [`LogicalGraphPlan`] retains every semantic fact required
//! by that later top-down pass without fabricating executable scripts or txids.

use std::collections::{BTreeMap, HashMap, HashSet};

use bp52_chain_bitcoin::{FeeClass, FeeError, FeePolicy, RevealPattern};
use bp52_chain_types::{
    AcceptedDeal, Action, AmountState, AuthorizationPolicy, BettingState, BettingTransition,
    ChainError, ChainGameDescriptor, EdgeKind, NodeId, NodeKind, Phase, Role, ShowdownOutcome,
    StateDigest, Street, TerminalAccounting, TerminalOutcome, TimeoutKind, TimeoutSpec,
    VerifiedChainDescriptor, chain_game_id, child_node_id, logical_state_digest, root_node_id,
    tagged_sha256, terminal_accounting,
};
use bp52_codec::{CodecError, Encode, Writer};
use bp52_lamport::{ExpectedLamportEntry, LamportPurpose};

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

const COMPILER_PROFILE_TAG: &str = "BP52/chain-compiler-profile/v11";
const COMPILER_PROFILE_DESCRIPTION: &[u8] = concat!(
    "chain_protocol_version=4\n",
    "compiler_profile=bp52-chain-reference-v11\n",
    "card_encoding=rank-major:card_id=rank*4+suit\n",
    "showdown_category_claim=positive-lower-bound;stronger-hands-accepted\n",
    "profile_erratum=funded-deal-alice-obligation-is-root\n",
    "descriptor_funding_outpoint=pre-existing-origin-escrow\n",
    "activation_template=version2-one-input-one-root-output-final-sequence\n",
    "gameplay_root_outpoint=activation-txid-vout0\n",
    "activation_counted_in_graph=false\n",
    "timeout_settlement_policy=pot-only;slash-reserved-rejected\n",
    "graph_shape=descriptor-derived;deep-reference-nodes=56132;deep-reference-transactions=56131\n",
    "maximum_path=descriptor-derived;deep-reference-maximum=33\n",
    "fee_reserve=descriptor-derived-maximum-executed-path\n",
    "max_bets_per_street=descriptor-bound-range-1-through-4\n",
    "phase_transitions=direct-no-intermediate-advance-nodes\n",
    "edge_order=path-code-ascending-timeout-last\n",
    "edge_codes=action:00000000-00000004;hole:00010000-00010001;",
    "community:0002<street><role>;alice:00030000;bob:00040000-00040002;",
    "advance:00001000-0000100d;timeout:00ff0000-00ff0002\n",
    "state_codec=bp52-chain-types-v2-little-endian\n",
    "state_output_commitment=hidden-unspendable-tapleaf:OP_RETURN-BP52SC1-logical_state_digest\n",
    "action_authorization=opponent-fixed-preauthorization;actor-live-signature\n",
    "timeout_authorization=opponent-fixed-preauthorization;beneficiary-live-signature\n",
    "network_identity=standard-genesis-or-tagged-custom-signet-genesis-plus-challenge\n",
    "action_lamport_keys=none\n",
    "showdown_lamport_keys=one-game-root-bound-score-key-per-role;mutually-exclusive-branches\n",
    "all_in=implicit-effective-stack-cap;responder-fold-or-call;called-all-in-forced-runout\n",
    "action_leaf=two-checksig-canonical-alice-bob-order\n",
    "bitcoin_signature_profile=taproot-sighash-default-64-byte-all-semantics\n",
)
.as_bytes();

/// Returns the identifier of the descriptor-derived reference compiler profile.
#[must_use]
pub fn reference_compiler_id() -> [u8; 32] {
    tagged_sha256(COMPILER_PROFILE_TAG, COMPILER_PROFILE_DESCRIPTION)
}

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
    /// Identifier of the signed descriptor.
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

/// Compiles the descriptor-derived graph without constructing scripts.
///
/// The activation output is the Deal-Alice obligation root. Every local
/// betting continuation is replaced directly by a fresh next-phase subtree;
/// there are no shared nodes and no witness-free `Advance` transactions.
///
/// # Errors
///
/// Rejects descriptor/deal/policy/profile mismatches, insufficient maximum-path
/// reserve, checked arithmetic failures, or any internal profile discrepancy.
pub fn compile_logical_graph(
    verified_descriptor: &VerifiedChainDescriptor,
    verified_deal: &bp52_protocol::VerifiedAcceptedDeal,
    fee_policy: &dyn FeePolicy,
) -> Result<LogicalGraphPlan, CompilerError> {
    let descriptor = verified_descriptor.as_descriptor();
    compile_logical_graph_descriptor(descriptor, verified_deal.as_deal(), fee_policy)
}

pub(crate) fn compile_logical_graph_descriptor(
    descriptor: &ChainGameDescriptor,
    deal: &AcceptedDeal,
    fee_policy: &dyn FeePolicy,
) -> Result<LogicalGraphPlan, CompilerError> {
    bp52_chain_types::validate_chain_descriptor(descriptor)?;
    if deal != &descriptor.deal {
        return Err(CompilerError::DealMismatch);
    }
    if fee_policy.policy_id() != descriptor.fee_policy_id {
        return Err(CompilerError::FeePolicyMismatch);
    }
    let expected_compiler_id = compiler_id_for_descriptor(descriptor);
    if descriptor.compiler_id != expected_compiler_id {
        return Err(CompilerError::CompilerIdMismatch);
    }

    let fees = FeeSchedule::new(fee_policy)?;
    // The effective-stack graph can be much shorter than the deep-stack
    // 33-transaction deep-stack tree. Graph construction debits every edge of
    // the actual descriptor-derived tree and therefore fails closed if any
    // branch exhausts the reserve; requiring the reference bound here would make
    // small all-in profiles needlessly unspendable.

    let chain_id = chain_game_id(descriptor)?;
    let root_id = root_node_id(&chain_id);
    let mut builder = GraphBuilder::new(descriptor, fee_policy, fees, root_id);
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
    let maximum_path_fee_sat = exact_maximum_path_fee(descriptor, &builder.nodes)?;
    if descriptor.fee_reserve_sat < maximum_path_fee_sat {
        return Err(CompilerError::InsufficientMaximumPathReserve {
            available: descriptor.fee_reserve_sat,
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
    verify_plan_against_descriptor(&plan, descriptor, fee_policy)?;
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

/// Immutable fee-policy facts retained by a materialized graph.
///
/// A [`FeePolicy`] is an arbitrary trait object, so a compiled graph cannot
/// clone it for later independent verification. This snapshot records every
/// policy result that can affect this finite plan: the class schedule, dust
/// threshold, and each terminal reserve disposition actually used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FeePolicySnapshot {
    policy_id: [u8; 32],
    schedule: FeeSchedule,
    dust_threshold: u64,
    reserve_splits: BTreeMap<(u64, Role), (u64, u64)>,
}

impl FeePolicySnapshot {
    pub(crate) fn capture(
        policy: &dyn FeePolicy,
        descriptor: &ChainGameDescriptor,
        plan: &LogicalGraphPlan,
    ) -> Result<Self, CompilerError> {
        let schedule = FeeSchedule::new(policy)?;
        let mut reserve_splits = BTreeMap::new();
        for terminal in plan.nodes.iter().filter_map(|node| match node.state {
            PlannedState::Terminal(terminal) => Some(terminal),
            _ => None,
        }) {
            let key = (
                terminal.accounting.fee_reserve_remaining,
                descriptor.split_remainder_recipient,
            );
            let split = policy.split_unused_reserve(key.0, key.1);
            let repeated = policy.split_unused_reserve(key.0, key.1);
            if split != repeated {
                return Err(profile(
                    "fee policy reserve disposition is nondeterministic",
                ));
            }
            verify_reserve_split(key.0, split)?;
            if reserve_splits
                .insert(key, split)
                .is_some_and(|old| old != split)
            {
                return Err(profile(
                    "fee policy reserve disposition changed during capture",
                ));
            }
        }
        Ok(Self {
            policy_id: policy.policy_id(),
            schedule,
            dust_threshold: policy.dust_threshold(),
            reserve_splits,
        })
    }

    pub(crate) const fn dust_threshold(&self) -> u64 {
        self.dust_threshold
    }
}

trait FeeSemantics {
    fn policy_id(&self) -> [u8; 32];
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
    fn policy_id(&self) -> [u8; 32] {
        self.0.policy_id()
    }

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

impl FeeSemantics for FeePolicySnapshot {
    fn policy_id(&self) -> [u8; 32] {
        self.policy_id
    }

    fn schedule(&self) -> Result<FeeSchedule, CompilerError> {
        Ok(self.schedule)
    }

    fn dust_threshold(&self) -> u64 {
        self.dust_threshold
    }

    fn reserve_split(
        &self,
        remaining: u64,
        remainder_recipient: Role,
    ) -> Result<(u64, u64), CompilerError> {
        self.reserve_splits
            .get(&(remaining, remainder_recipient))
            .copied()
            .ok_or_else(|| profile("fee-policy snapshot lacks terminal reserve disposition"))
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
    descriptor: &'a ChainGameDescriptor,
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
        descriptor: &'a ChainGameDescriptor,
        fee_policy: &'a dyn FeePolicy,
        fees: FeeSchedule,
        root_node_id: NodeId,
    ) -> Self {
        Self {
            descriptor,
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
        let [deal_alice, deal_bob] = hole_reveal_steps(self.descriptor)?;
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
            amounts: BettingState::initial_preflop(self.descriptor)?.amounts,
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
            AuthorizationPolicy::RevealPreimages {
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
        let mut preflop = BettingState::initial_preflop(self.descriptor)?;
        preflop.amounts.fee_reserve_remaining = after_fee.fee_reserve_remaining;
        preflop.validate(self.descriptor)?;
        let tree = expand_preflop(self.descriptor, preflop)?;
        let normal_child =
            self.build_betting_tree(node_id, normal_kind, &tree, preflop, next_depth(depth)?)?;
        let normal = self.edge(
            normal_kind,
            AuthorizationPolicy::RevealPreimages {
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
        actual_state.validate(self.descriptor)?;
        let timeout = TimeoutSpec::new(
            TimeoutKind::Action,
            self.descriptor.action_csv,
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
                    let accounting = fold_accounting(self.descriptor, after_fee, *folded)?;
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
        let [first, second] = community_reveal_steps(self.descriptor, street)?;
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
            AuthorizationPolicy::RevealPreimages {
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
            let betting_state =
                BettingState::start_postflop(street, self.descriptor, normal_amounts)?;
            let tree = expand_postflop(self.descriptor, betting_state)?;
            self.build_betting_tree(node_id, normal_kind, &tree, betting_state, child_depth)?
        };
        let normal = self.edge(
            normal_kind,
            AuthorizationPolicy::RevealPreimages {
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
        let timeout = alice_showdown_timeout(self.descriptor)?;
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
        let timeout = bob_showdown_timeout(self.descriptor)?;
        let state = PlannedState::BobTerminal { amounts };
        let node_index =
            self.insert_child(parent_node_id, incoming_kind, state, depth, Some(timeout))?;
        let node_id = self.nodes[node_index].node_id;
        let child_depth = next_depth(depth)?;
        let payout_amounts = self.charge(amounts, FeeClass::BobPayout)?;
        let branches = showdown_branches(self.descriptor, payout_amounts)?;
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
            timeout_accounting(self.descriptor, after_fee, timeout.kind, timeout.defaulting)?;
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
            self.descriptor.split_remainder_recipient,
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
                ))
            }
            PlannedState::BobTerminal { .. } if self.expected_bob_lamport.is_empty() => {
                self.expected_bob_lamport.push(ExpectedLamportEntry::new(
                    self.root_node_id,
                    LamportPurpose::BobScore24Bit,
                ))
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

/// Reverify all descriptor- and live-fee-policy-dependent plan semantics.
pub(crate) fn verify_plan_against_descriptor(
    plan: &LogicalGraphPlan,
    descriptor: &ChainGameDescriptor,
    fee_policy: &dyn FeePolicy,
) -> Result<(), CompilerError> {
    verify_plan_against_fee_semantics(plan, descriptor, &LiveFeeSemantics(fee_policy))
}

/// Reverify a materialized plan against the immutable fee facts it retained.
pub(crate) fn verify_plan_against_snapshot(
    plan: &LogicalGraphPlan,
    descriptor: &ChainGameDescriptor,
    fee_policy: &FeePolicySnapshot,
) -> Result<(), CompilerError> {
    verify_plan_against_fee_semantics(plan, descriptor, fee_policy)
}

fn verify_plan_against_fee_semantics(
    plan: &LogicalGraphPlan,
    descriptor: &ChainGameDescriptor,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    bp52_chain_types::validate_chain_descriptor(descriptor)?;
    if descriptor.compiler_id != compiler_id_for_descriptor(descriptor) {
        return Err(CompilerError::CompilerIdMismatch);
    }
    if descriptor.fee_policy_id != fee_policy.policy_id() {
        return Err(CompilerError::FeePolicyMismatch);
    }
    if fee_policy.dust_threshold() == 0 {
        return Err(FeeError::ZeroDustThreshold.into());
    }
    plan.verify()?;
    let expected_chain_id = chain_game_id(descriptor)?;
    if plan.chain_game_id != expected_chain_id
        || plan.root_node_id != root_node_id(&expected_chain_id)
    {
        return Err(profile("logical plan is not bound to the descriptor"));
    }
    let schedule = fee_policy.schedule()?;
    let reference_maximum_path_fee_sat = schedule.maximum_path_fee()?;
    if plan.maximum_path_fee_sat > reference_maximum_path_fee_sat {
        return Err(profile(
            "descriptor-derived maximum path fee exceeds the profile maximum",
        ));
    }
    if descriptor.fee_reserve_sat < plan.maximum_path_fee_sat {
        return Err(CompilerError::InsufficientMaximumPathReserve {
            available: descriptor.fee_reserve_sat,
            required: plan.maximum_path_fee_sat,
        });
    }
    let root = plan
        .nodes
        .first()
        .ok_or_else(|| profile("logical graph is empty"))?;
    if root.state.amounts() != BettingState::initial_preflop(descriptor)?.amounts {
        return Err(profile("funded root amounts disagree with the descriptor"));
    }
    let by_id: HashMap<_, _> = plan.nodes.iter().map(|node| (node.node_id, node)).collect();
    for node in &plan.nodes {
        verify_node_against_descriptor(node, descriptor)?;
        verify_betting_action_set(node, descriptor)?;
        for edge in &node.edges {
            if edge.fee_sat != schedule.for_class(edge.fee_class) {
                return Err(profile("edge fee disagrees with the fee policy"));
            }
            let child = by_id
                .get(&edge.child_node_id)
                .copied()
                .ok_or(CompilerError::DanglingNode)?;
            verify_transition_against_descriptor(node, edge, child, descriptor, fee_policy)?;
        }
    }
    Ok(())
}

fn compiler_id_for_descriptor(descriptor: &ChainGameDescriptor) -> [u8; 32] {
    let _ = descriptor;
    reference_compiler_id()
}

fn verify_betting_action_set(
    node: &PlannedNode,
    descriptor: &ChainGameDescriptor,
) -> Result<(), CompilerError> {
    let PlannedState::Betting { state, .. } = node.state else {
        return Ok(());
    };
    let expected_actions = state.legal_actions(descriptor)?;
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

fn verify_node_against_descriptor(
    node: &PlannedNode,
    descriptor: &ChainGameDescriptor,
) -> Result<(), CompilerError> {
    verify_exact_outgoing_kinds(node)?;
    let expected_timeout = match node.state {
        PlannedState::Reveal { phase, pattern, .. } => {
            let step = reveal_step_for_phase(descriptor, phase)?;
            if pattern != step.pattern {
                return Err(profile("reveal obligation disagrees with descriptor order"));
            }
            Some(step.timeout)
        }
        PlannedState::Betting { phase, state } => {
            if phase != betting_phase(state.street) {
                return Err(profile("betting phase disagrees with its street"));
            }
            state.validate(descriptor)?;
            Some(TimeoutSpec::new(
                TimeoutKind::Action,
                descriptor.action_csv,
                state.actor,
                state.actor.other(),
            )?)
        }
        PlannedState::AliceShowdown { .. } => Some(alice_showdown_timeout(descriptor)?),
        PlannedState::BobTerminal { .. } => Some(bob_showdown_timeout(descriptor)?),
        PlannedState::Terminal(_) => None,
    };
    if node.timeout != expected_timeout {
        return Err(profile("node timeout disagrees with the descriptor"));
    }
    Ok(())
}

fn reveal_step_for_phase(
    descriptor: &ChainGameDescriptor,
    phase: Phase,
) -> Result<RevealStep, CompilerError> {
    match phase {
        Phase::DealAlice => Ok(hole_reveal_steps(descriptor)?[0]),
        Phase::DealBob => Ok(hole_reveal_steps(descriptor)?[1]),
        Phase::FlopRevealFirst => Ok(community_reveal_steps(descriptor, Street::Flop)?[0]),
        Phase::FlopRevealSecond => Ok(community_reveal_steps(descriptor, Street::Flop)?[1]),
        Phase::TurnRevealFirst => Ok(community_reveal_steps(descriptor, Street::Turn)?[0]),
        Phase::TurnRevealSecond => Ok(community_reveal_steps(descriptor, Street::Turn)?[1]),
        Phase::RiverRevealFirst => Ok(community_reveal_steps(descriptor, Street::River)?[0]),
        Phase::RiverRevealSecond => Ok(community_reveal_steps(descriptor, Street::River)?[1]),
        _ => Err(profile("non-reveal phase used as a reveal obligation")),
    }
}

fn verify_transition_against_descriptor(
    parent: &PlannedNode,
    edge: &PlannedEdge,
    child: &PlannedNode,
    descriptor: &ChainGameDescriptor,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
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
        return verify_terminal_child(child, amounts, outcome, descriptor, fee_policy);
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
            verify_reveal_transition(*phase, *amounts, edge, child, descriptor)
        }
        (PlannedState::Betting { state, .. }, EdgeKind::Action(action)) => {
            verify_betting_transition(*state, action, edge, child, descriptor, fee_policy)
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
                descriptor,
                fee_policy,
            )
        }
        _ => Err(profile("edge is not a legal descriptor-bound transition")),
    }
}

fn verify_reveal_transition(
    phase: Phase,
    amounts: AmountState,
    edge: &PlannedEdge,
    child: &PlannedNode,
    descriptor: &ChainGameDescriptor,
) -> Result<(), CompilerError> {
    let after_fee = amounts.charge_fee(edge.fee_sat)?;
    let expected = match phase {
        Phase::DealAlice => {
            let step = hole_reveal_steps(descriptor)?[1];
            PlannedState::Reveal {
                phase: step.phase,
                pattern: step.pattern,
                amounts: after_fee,
            }
        }
        Phase::DealBob => {
            let mut state = BettingState::initial_preflop(descriptor)?;
            state.amounts.fee_reserve_remaining = after_fee.fee_reserve_remaining;
            PlannedState::Betting {
                phase: Phase::PreflopBetting,
                state,
            }
        }
        Phase::FlopRevealFirst | Phase::TurnRevealFirst | Phase::RiverRevealFirst => {
            let street = reveal_phase_street(phase)?;
            let step = community_reveal_steps(descriptor, street)?[1];
            PlannedState::Reveal {
                phase: step.phase,
                pattern: step.pattern,
                amounts: after_fee,
            }
        }
        Phase::FlopRevealSecond | Phase::TurnRevealSecond | Phase::RiverRevealSecond => {
            let street = reveal_phase_street(phase)?;
            if is_all_in(after_fee) {
                state_after_completed_street(descriptor, street, after_fee)?
            } else {
                PlannedState::Betting {
                    phase: betting_phase(street),
                    state: BettingState::start_postflop(street, descriptor, after_fee)?,
                }
            }
        }
        _ => return Err(profile("non-reveal phase used as reveal parent")),
    };
    require_state(child, &expected)
}

fn verify_betting_transition(
    state: BettingState,
    action: Action,
    edge: &PlannedEdge,
    child: &PlannedNode,
    descriptor: &ChainGameDescriptor,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    match state
        .apply_action(descriptor, action)?
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
            let expected = state_after_completed_street(descriptor, street, amounts)?;
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
                descriptor,
                fee_policy,
            )
        }
    }
}

fn state_after_completed_street(
    descriptor: &ChainGameDescriptor,
    street: Street,
    amounts: AmountState,
) -> Result<PlannedState, CompilerError> {
    if let Some(next_street) = street.next() {
        let step = community_reveal_steps(descriptor, next_street)?[0];
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

fn verify_terminal_child(
    child: &PlannedNode,
    amounts: AmountState,
    outcome: TerminalOutcome,
    descriptor: &ChainGameDescriptor,
    fee_policy: &impl FeeSemantics,
) -> Result<(), CompilerError> {
    let accounting = terminal_accounting(
        amounts,
        outcome,
        descriptor.timeout_policy,
        descriptor.split_remainder_recipient,
    )?;
    let (alice_reserve, bob_reserve) = fee_policy.reserve_split(
        accounting.fee_reserve_remaining,
        descriptor.split_remainder_recipient,
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

fn require_state(child: &PlannedNode, expected: &PlannedState) -> Result<(), CompilerError> {
    if &child.state == expected {
        Ok(())
    } else {
        Err(profile("child state disagrees with recomputed transition"))
    }
}

fn reveal_phase_street(phase: Phase) -> Result<Street, CompilerError> {
    match phase {
        Phase::FlopRevealFirst | Phase::FlopRevealSecond => Ok(Street::Flop),
        Phase::TurnRevealFirst | Phase::TurnRevealSecond => Ok(Street::Turn),
        Phase::RiverRevealFirst | Phase::RiverRevealSecond => Ok(Street::River),
        _ => Err(profile("phase does not identify a community street")),
    }
}

fn verify_reserve_split(remaining: u64, split: (u64, u64)) -> Result<(), CompilerError> {
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

fn verify_non_dust(value: u64, dust_threshold: u64) -> Result<(), CompilerError> {
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

fn exact_maximum_path_fee(
    descriptor: &ChainGameDescriptor,
    nodes: &[PlannedNode],
) -> Result<u64, CompilerError> {
    nodes
        .iter()
        .filter_map(|node| match node.state {
            PlannedState::Terminal(terminal) => Some(terminal.amounts.fee_reserve_remaining),
            _ => None,
        })
        .try_fold(0_u64, |maximum, remaining| {
            let consumed = descriptor
                .fee_reserve_sat
                .checked_sub(remaining)
                .ok_or(ChainError::ValueNotConserved)?;
            Ok(maximum.max(consumed))
        })
}

#[allow(clippy::too_many_lines)]
fn verify_plan(plan: &LogicalGraphPlan) -> Result<(), CompilerError> {
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
                    != child_node_id(&node.node_id, edge.kind, &child.logical_state_digest)
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

fn verify_plan_header(plan: &LogicalGraphPlan) -> Result<(), CompilerError> {
    if plan.nodes.is_empty()
        || plan.nodes.len() > REFERENCE_TOTAL_NODE_COUNT
        || plan.transaction_count() > REFERENCE_TRANSACTION_COUNT
        || plan.maximum_path_length > REFERENCE_MAX_PATH_LENGTH
    {
        return Err(profile(
            "logical graph has an invalid descriptor-derived shape",
        ));
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
fn verify_plan_totals(
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

fn verify_node_obligation(node: &PlannedNode) -> Result<(), CompilerError> {
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

fn verify_exact_outgoing_kinds(node: &PlannedNode) -> Result<(), CompilerError> {
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

fn edge_kinds_equal<const N: usize>(edges: &[PlannedEdge], expected: [EdgeKind; N]) -> bool {
    edges.len() == N
        && edges
            .iter()
            .zip(expected)
            .all(|(edge, kind)| edge.kind == kind)
}

fn verify_child_semantics(
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
                    EdgeKind::Action(bp52_chain_types::Action::Fold),
                    PlannedState::Terminal(terminal),
                ) => {
                    terminal.outcome
                        == TerminalOutcome::Fold {
                            folded: state.actor,
                        }
                }
                (EdgeKind::Action(action), child_state) => {
                    action != bp52_chain_types::Action::Fold
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

fn valid_reveal_successor(
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

fn valid_community_reveal_successor(
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

fn verify_terminal_intrinsic(terminal: PlannedTerminal) -> Result<(), CompilerError> {
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

fn verify_edge_semantics(parent: &PlannedNode, edge: &PlannedEdge) -> Result<(), CompilerError> {
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
            AuthorizationPolicy::RevealPreimages {
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

fn strictly_sorted_lamport(entries: &[ExpectedLamportEntry]) -> bool {
    entries
        .windows(2)
        .all(|pair| (pair[0].node_id, pair[0].purpose) < (pair[1].node_id, pair[1].purpose))
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
mod tests {
    use std::collections::HashSet;

    use bp52_chain_bitcoin::{FeeClass, FeeError, FeePolicy, FixedFeePolicy, RevealPattern};
    use bp52_chain_types::{
        Action, AuthorizationPolicy, BettingState, EdgeKind, NodeKind, Phase, Role,
        ShowdownOutcome, Street, TerminalOutcome, TimeoutKind, terminal_accounting,
    };
    use bp52_lamport::LamportPurpose;

    use super::{
        LiveFeeSemantics, LogicalGraphPlan, PlannedNode, PlannedState, PlannedTerminal,
        REFERENCE_ALICE_LAMPORT_ENTRIES, REFERENCE_BOB_LAMPORT_ENTRIES,
        compile_logical_graph_descriptor, reference_compiler_id, verify_betting_action_set,
        verify_child_semantics, verify_exact_outgoing_kinds, verify_terminal_intrinsic,
        verify_transition_against_descriptor,
    };
    use crate::{
        CompilerError, REFERENCE_ALICE_PREAUTHORIZATIONS, REFERENCE_ALICE_RUNTIME_SIGNATURES,
        REFERENCE_BOB_PREAUTHORIZATIONS, REFERENCE_BOB_RUNTIME_SIGNATURES,
        REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT, REFERENCE_TRANSACTION_COUNT,
        test_support::descriptor_fixture,
    };

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
        let mut descriptor = descriptor_fixture()?;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();
        Ok(compile_logical_graph_descriptor(
            &descriptor,
            &descriptor.deal,
            &policy,
        )?)
    }

    fn stack_graph_fixture(
        alice_units: u64,
        bob_units: u64,
    ) -> Result<(bp52_chain_types::ChainGameDescriptor, LogicalGraphPlan), Box<dyn std::error::Error>>
    {
        let policy = FixedFeePolicy::new(200, 330)?;
        let mut descriptor = descriptor_fixture()?;
        descriptor.alice_starting_stack_sat = descriptor.unit_sat * alice_units;
        descriptor.bob_starting_stack_sat = descriptor.unit_sat * bob_units;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();
        let plan = compile_logical_graph_descriptor(&descriptor, &descriptor.deal, &policy)?;
        Ok((descriptor, plan))
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

    fn assert_reveal_timeout(
        plan: &LogicalGraphPlan,
        node: &PlannedNode,
    ) -> Result<(), &'static str> {
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
    fn preflop_all_in_call_forces_every_remaining_reveal_pair()
    -> Result<(), Box<dyn std::error::Error>> {
        let (descriptor, plan) = stack_graph_fixture(2, 2)?;
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
                    state.legal_actions(&descriptor)?,
                    vec![Action::Fold, Action::Call]
                );
            }
        }
        Ok(())
    }

    #[test]
    fn called_all_in_on_each_postflop_street_forces_only_the_remaining_board()
    -> Result<(), Box<dyn std::error::Error>> {
        for (stack_units, all_in_street) in
            [(4, Street::Flop), (8, Street::Turn), (12, Street::River)]
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
        let (descriptor, plan) = stack_graph_fixture(3, 10)?;
        let initial = preflop_node(&plan)?;
        let big_blind_option = action_child(&plan, initial, Action::Call)?;
        let flop_first = action_child(&plan, big_blind_option, Action::Check)?;
        let flop_betting = reveal_pair(&plan, flop_first)?;
        let response = action_child(&plan, flop_betting, Action::Bet)?;
        let PlannedState::Betting { state, .. } = response.state else {
            return Err("all-in bet did not leave a response decision".into());
        };
        assert_eq!(state.current_wager, descriptor.unit_sat);
        assert_eq!(state.amounts.bob_remaining, descriptor.unit_sat * 7);
        assert_eq!(
            state.legal_actions(&descriptor)?,
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
        assert_eq!(fold.accounting.alice_sat, descriptor.unit_sat);
        assert_eq!(fold.accounting.bob_sat, descriptor.unit_sat * 12);

        let mut node = action_child(&plan, response, Action::Call)?;
        assert_eq!(node.state.amounts().alice_remaining, 0);
        assert_eq!(node.state.amounts().bob_remaining, descriptor.unit_sat * 7);
        assert_eq!(node.state.amounts().pot, descriptor.unit_sat * 6);
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
        assert_eq!(terminal.accounting.alice_sat, descriptor.unit_sat * 6);
        assert_eq!(terminal.accounting.bob_sat, descriptor.unit_sat * 7);
        assert_eq!(
            terminal.accounting.alice_sat + terminal.accounting.bob_sat,
            descriptor.alice_starting_stack_sat + descriptor.bob_starting_stack_sat
        );
        plan.verify()?;
        Ok(())
    }

    #[test]
    fn exact_outgoing_sets_reject_pruned_missing_and_extra_edges()
    -> Result<(), Box<dyn std::error::Error>> {
        let (descriptor, plan) = stack_graph_fixture(2, 2)?;

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
        assert!(verify_betting_action_set(&missing_action, &descriptor).is_err());

        let mut extra_non_action = betting.clone();
        let mut impossible = extra_non_action.edges[0];
        impossible.kind = EdgeKind::AliceShowdown;
        let timeout_index = extra_non_action.edges.len() - 1;
        extra_non_action.edges.insert(timeout_index, impossible);
        assert!(verify_exact_outgoing_kinds(&extra_non_action).is_err());
        assert!(verify_betting_action_set(&extra_non_action, &descriptor).is_err());

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
                    AuthorizationPolicy::RevealPreimages { revealer } => match revealer {
                        Role::Alice => bob_preauthorizations += 1,
                        Role::Bob => alice_preauthorizations += 1,
                    },
                    AuthorizationPolicy::AliceScore => bob_preauthorizations += 1,
                    AuthorizationPolicy::BettingAction { actor } => match actor {
                        Role::Alice => {
                            bob_preauthorizations += 1;
                        }
                        Role::Bob => {
                            alice_preauthorizations += 1;
                        }
                    },
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
                    EdgeKind::Timeout(bp52_chain_types::TimeoutKind::Action) => {
                        action_timeout += 1;
                    }
                    EdgeKind::Timeout(bp52_chain_types::TimeoutKind::Reveal) => reveal_timeout += 1,
                    EdgeKind::AliceShowdown => alice_showdown += 1,
                    EdgeKind::BobPayout(_) => bob_payout += 1,
                    EdgeKind::Timeout(bp52_chain_types::TimeoutKind::Showdown) => {
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
            alice_preauthorizations + bob_preauthorizations,
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
    fn funded_root_posts_blinds_before_hole_reveal_timeouts()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = FixedFeePolicy::new(200, 330)?;
        let mut descriptor = descriptor_fixture()?;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();
        let plan = compile_logical_graph_descriptor(&descriptor, &descriptor.deal, &policy)?;
        let initial = BettingState::initial_preflop(&descriptor)?;
        let root = &plan.nodes[0];

        assert_eq!(root.state.amounts(), initial.amounts);
        assert_eq!(initial.amounts.pot, descriptor.unit_sat * 3);
        assert_eq!(
            initial.amounts.alice_remaining,
            descriptor.alice_starting_stack_sat - descriptor.unit_sat
        );
        assert_eq!(
            initial.amounts.bob_remaining,
            descriptor.bob_starting_stack_sat - descriptor.unit_sat * 2
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
                descriptor.timeout_policy,
                descriptor.split_remainder_recipient,
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
        let mut descriptor = descriptor_fixture()?;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();
        let plan = compile_logical_graph_descriptor(&descriptor, &descriptor.deal, &policy)?;

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
            verify_transition_against_descriptor(
                betting,
                &relabeled,
                call_child,
                &descriptor,
                &fee_semantics,
            )
            .is_err()
        );

        let mut missing_action = betting.clone();
        missing_action
            .edges
            .retain(|edge| edge.kind != EdgeKind::Action(Action::Raise));
        assert!(verify_betting_action_set(&missing_action, &descriptor).is_err());

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
            verify_transition_against_descriptor(
                reveal_first,
                reveal_edge,
                &repeated_revealer,
                &descriptor,
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
            verify_transition_against_descriptor(
                &plan.nodes[0],
                terminal_edge,
                &shifted_terminal,
                &descriptor,
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
            verify_transition_against_descriptor(
                &plan.nodes[0],
                terminal_edge,
                &shifted_accounting,
                &descriptor,
                &fee_semantics,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn all_zero_fee_logical_graph_is_supported() -> Result<(), Box<dyn std::error::Error>> {
        let policy = ZeroFeePolicy;
        let mut descriptor = descriptor_fixture()?;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();
        let initial_reserve = descriptor.fee_reserve_sat;

        let plan = compile_logical_graph_descriptor(&descriptor, &descriptor.deal, &policy)?;
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

    #[test]
    fn compiler_binding_and_maximum_reserve_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = FixedFeePolicy::new(200, 330)?;
        let mut descriptor = descriptor_fixture()?;
        descriptor.fee_policy_id = policy.policy_id();
        descriptor.compiler_id = reference_compiler_id();

        let mut wrong_deal = descriptor.deal;
        wrong_deal.attempt = wrong_deal.attempt.wrapping_add(1);
        assert!(matches!(
            compile_logical_graph_descriptor(&descriptor, &wrong_deal, &policy),
            Err(CompilerError::DealMismatch)
        ));

        let mut wrong_compiler = descriptor;
        wrong_compiler.compiler_id[0] ^= 1;
        assert!(matches!(
            compile_logical_graph_descriptor(&wrong_compiler, &wrong_compiler.deal, &policy),
            Err(CompilerError::CompilerIdMismatch)
        ));

        let mut underfunded = descriptor;
        underfunded.fee_reserve_sat = 6_599;
        let underfunded_result =
            compile_logical_graph_descriptor(&underfunded, &underfunded.deal, &policy);
        assert!(underfunded_result.is_err());
        Ok(())
    }
}
