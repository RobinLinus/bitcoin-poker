//! Logical transaction-tree records.

use crate::{
    ChainError,
    descriptor::Role,
    outcome::ShowdownOutcome,
    state::{Action, Street, TimeoutKind, TimeoutSpec},
};

/// Path-dependent logical node identifier.
pub type NodeId = [u8; 32];
/// Digest of a node's canonical logical state.
pub type StateDigest = [u8; 32];
/// Identifier of the exact runtime witness predicate.
pub type PredicateId = [u8; 32];

/// Maximum script-pubkey bytes retained in one logical output.
pub const MAX_SCRIPT_PUBKEY_BYTES: usize = 10_000;
/// Maximum fixed non-witness transaction bytes retained in one record.
pub const MAX_NON_WITNESS_TRANSACTION_BYTES: usize = 1_000_000;
/// Maximum outputs on one fixed v1 transition.
pub const MAX_LOGICAL_OUTPUTS: usize = 4;
/// Maximum direct children of any fixed v1 node.
pub const MAX_NODE_CHILDREN: usize = 5;

/// Canonical phase entered by a witness-free progression edge.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Phase {
    /// Bob's delivery of Alice's hole-card shares.
    DealAlice = 0,
    /// Alice's delivery of Bob's hole-card shares.
    DealBob = 1,
    /// Preflop betting root.
    PreflopBetting = 2,
    /// First flop-share revealer.
    FlopRevealFirst = 3,
    /// Second flop-share revealer.
    FlopRevealSecond = 4,
    /// Flop betting root.
    FlopBetting = 5,
    /// First turn-share revealer.
    TurnRevealFirst = 6,
    /// Second turn-share revealer.
    TurnRevealSecond = 7,
    /// Turn betting root.
    TurnBetting = 8,
    /// First river-share revealer.
    RiverRevealFirst = 9,
    /// Second river-share revealer.
    RiverRevealSecond = 10,
    /// River betting root.
    RiverBetting = 11,
    /// Alice's score-certified showdown.
    AliceShowdown = 12,
    /// Bob's combined showdown/payout state.
    BobTerminal = 13,
}

impl Phase {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Semantic kind of one state or terminal node.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NodeKind {
    /// Confirmed funding state before hole-card delivery.
    Funded = 0,
    /// Bob must reveal Alice's two counterparty shares.
    DealAlice = 1,
    /// Alice must reveal Bob's two counterparty shares.
    DealBob = 2,
    /// One fixed-limit betting decision.
    Betting = 3,
    /// First revealer for a community street.
    CommunityRevealFirst = 4,
    /// Second revealer for a community street.
    CommunityRevealSecond = 5,
    /// Alice's hole-card reveal and score certificate.
    AliceShowdown = 6,
    /// Bob's combined hand verification and payout state.
    BobTerminal = 7,
    /// Fully settled leaf.
    Terminal = 8,
}

impl NodeKind {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns whether this node must have no children.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

/// Semantic branch label with a stable path-code assignment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EdgeKind {
    /// Witness-free transition into the next fixed protocol phase.
    Advance {
        /// Exact destination phase.
        phase: Phase,
    },
    /// One specialized betting action.
    Action(Action),
    /// One on-chain hole-card-share reveal.
    HoleCardReveal {
        /// Player publishing its committed shares.
        revealer: Role,
    },
    /// One community share-reveal round.
    CommunityReveal {
        /// Community street being revealed.
        street: Street,
        /// Player publishing its committed shares.
        revealer: Role,
    },
    /// Alice's score-certified showdown transition.
    AliceShowdown,
    /// Bob's combined showdown and branch-specific payout.
    BobPayout(ShowdownOutcome),
    /// Unilateral timelocked settlement.
    Timeout(TimeoutKind),
}

impl EdgeKind {
    /// Returns the unique four-byte big-endian v1 path code.
    ///
    /// The fixed-width code is included in child node identifiers. Associated
    /// roles, streets, outcomes, and actions therefore cannot alias.
    #[must_use]
    pub const fn path_code(self) -> [u8; 4] {
        let value = match self {
            Self::Advance { phase } => u32::from_be_bytes([0x00, 0x00, 0x10, phase.code()]),
            Self::Action(action) => u32::from_be_bytes([0x00, 0x00, 0x00, action.code()]),
            Self::HoleCardReveal { revealer } => {
                u32::from_be_bytes([0x00, 0x01, 0x00, revealer.code()])
            }
            Self::CommunityReveal { street, revealer } => {
                u32::from_be_bytes([0x00, 0x02, street.code(), revealer.code()])
            }
            Self::AliceShowdown => u32::from_be_bytes([0x00, 0x03, 0x00, 0x00]),
            Self::BobPayout(outcome) => u32::from_be_bytes([0x00, 0x04, 0x00, outcome.code()]),
            Self::Timeout(kind) => u32::from_be_bytes([0x00, 0xff, 0x00, kind.code()]),
        };
        value.to_be_bytes()
    }

    /// Returns whether this is a timelocked timeout edge.
    #[must_use]
    pub const fn is_timeout(self) -> bool {
        matches!(self, Self::Timeout(_))
    }
}

/// Explicit pre-exchange/runtime authorization class for one edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorizationPolicy {
    /// Both fixed transaction signatures are pre-exchanged; no runtime datum.
    BothPresigned,
    /// The opponent preauthorizes; the actor chooses and signs the action live.
    BettingAction {
        /// Active player retaining the live Bitcoin signing capability.
        actor: Role,
    },
    /// Both transaction signatures are pre-exchanged; revealer supplies shares.
    RevealOpenings {
        /// Player whose dlog openings authorize the edge.
        revealer: Role,
    },
    /// Both signatures are pre-exchanged; Alice supplies hole shares and score OTS.
    AliceScore,
    /// Alice preauthorizes; Bob supplies a live signature and valid hand witness.
    BobLivePayout,
    /// The defaulting player preauthorizes the fixed outputs; the beneficiary signs after CSV.
    Timeout {
        /// Player allowed to spend after maturity.
        beneficiary: Role,
    },
}

/// One fixed transaction output.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LogicalOutput {
    /// Output value in satoshis.
    pub value_sat: u64,
    /// Exact script pubkey bytes.
    pub script_pubkey: Vec<u8>,
}

impl LogicalOutput {
    /// Validates bounded, nonempty script bytes.
    ///
    /// Dust policy is deliberately enforced by the concrete fee/backend
    /// profile because it depends on the output script class.
    ///
    /// # Errors
    ///
    /// Returns a structural or length error.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.script_pubkey.is_empty() {
            return Err(invalid_record("logical output script is empty"));
        }
        check_bound(
            "script_pubkey",
            self.script_pubkey.len(),
            MAX_SCRIPT_PUBKEY_BYTES,
        )
    }
}

/// Witness-independent fixed Bitcoin transaction data for one edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalTransaction {
    /// Transaction version as an unsigned consensus bit pattern.
    pub version: u32,
    /// Absolute lock time; the reference profile uses zero.
    pub lock_time: u32,
    /// Exact parent state outpoint consensus bytes.
    pub input_outpoint: [u8; 36],
    /// Input sequence, including any node-specific CSV delay.
    pub sequence: u32,
    /// Fixed outputs in transaction order.
    pub outputs: Vec<LogicalOutput>,
    /// Exact fee charged to the descriptor's fee reserve.
    pub fee_sat: u64,
    /// Stable txid derived without witness data.
    pub txid: [u8; 32],
    /// Exact fixed non-witness consensus serialization.
    pub non_witness_serialization: Vec<u8>,
}

impl LogicalTransaction {
    /// Validates bounds and checked output/fee arithmetic.
    ///
    /// # Errors
    ///
    /// Returns a structural, bound, or arithmetic error.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.input_outpoint.iter().all(|byte| *byte == 0) {
            return Err(invalid_record("transaction input outpoint is all zero"));
        }
        if self.outputs.is_empty() {
            return Err(invalid_record("transaction has no outputs"));
        }
        check_bound(
            "transaction outputs",
            self.outputs.len(),
            MAX_LOGICAL_OUTPUTS,
        )?;
        for output in &self.outputs {
            output.validate()?;
        }
        if self.non_witness_serialization.is_empty() {
            return Err(invalid_record("non-witness transaction bytes are empty"));
        }
        check_bound(
            "non_witness_serialization",
            self.non_witness_serialization.len(),
            MAX_NON_WITNESS_TRANSACTION_BYTES,
        )?;
        if self.txid.iter().all(|byte| *byte == 0) {
            return Err(invalid_record("transaction id is all zero"));
        }
        self.output_value()?
            .checked_add(self.fee_sat)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Returns the sum of all fixed output values.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ArithmeticOverflow`] on overflow.
    pub fn output_value(&self) -> Result<u64, ChainError> {
        self.outputs.iter().try_fold(0_u64, |total, output| {
            total
                .checked_add(output.value_sat)
                .ok_or(ChainError::ArithmeticOverflow)
        })
    }
}

/// One canonical branch between logical nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalEdge {
    /// Parent state node consumed by the fixed transaction.
    pub parent_node_id: NodeId,
    /// Child state or terminal node created by the transaction.
    pub child_node_id: NodeId,
    /// Semantic branch label.
    pub kind: EdgeKind,
    /// Fixed witness-independent transaction.
    pub transaction: LogicalTransaction,
    /// Exact preauthorization/runtime authorization matrix entry.
    pub authorization: AuthorizationPolicy,
    /// Relative timeout metadata, present only on timeout edges.
    pub timeout: Option<TimeoutSpec>,
}

impl LogicalEdge {
    /// Validates identifiers, transaction shape, and timeout authorization.
    ///
    /// # Errors
    ///
    /// Returns a structural or nested transaction error.
    pub fn validate(&self) -> Result<(), ChainError> {
        reject_zero_id(&self.parent_node_id, "edge parent node id")?;
        reject_zero_id(&self.child_node_id, "edge child node id")?;
        if self.parent_node_id == self.child_node_id {
            return Err(invalid_record("edge parent and child ids are equal"));
        }
        self.transaction.validate()?;
        match (self.kind, self.timeout, self.authorization) {
            (
                EdgeKind::Timeout(kind),
                Some(timeout),
                AuthorizationPolicy::Timeout { beneficiary },
            ) if timeout.kind == kind && timeout.beneficiary == beneficiary => timeout.validate(),
            (kind, None, authorization)
                if !kind.is_timeout()
                    && !matches!(authorization, AuthorizationPolicy::Timeout { .. }) =>
            {
                validate_non_timeout_authorization(kind, authorization)
            }
            _ => Err(invalid_record(
                "edge kind, timeout record, and authorization disagree",
            )),
        }
    }
}

/// Canonical logical record committed into the graph manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalNodeRecord {
    /// Path-dependent node identifier.
    pub node_id: NodeId,
    /// Parent node, absent only for the funded root.
    pub parent_node_id: Option<NodeId>,
    /// Semantic node class.
    pub node_kind: NodeKind,
    /// SHA-256 digest of the canonical logical state.
    pub logical_state_digest: StateDigest,
    /// Fixed transaction creating this node, absent for the external funded root.
    pub transaction: Option<LogicalTransaction>,
    /// Exact runtime witness predicate identifier.
    pub required_predicate_id: PredicateId,
    /// Timeout attached to this obligation node, if any.
    pub timeout: Option<TimeoutSpec>,
    /// Child identifiers in canonical semantic edge order.
    pub child_node_ids: Vec<NodeId>,
}

impl LogicalNodeRecord {
    /// Validates one finalized canonical record.
    ///
    /// # Errors
    ///
    /// Returns a structural, bound, duplicate-child, or transaction error.
    pub fn validate(&self) -> Result<(), ChainError> {
        reject_zero_id(&self.node_id, "node id")?;
        reject_zero_id(&self.logical_state_digest, "logical state digest")?;
        reject_zero_id(&self.required_predicate_id, "predicate id")?;
        match (self.node_kind, self.parent_node_id, &self.transaction) {
            (NodeKind::Funded, None, None) => {}
            (NodeKind::Funded, _, _) => {
                return Err(invalid_record(
                    "funded root must omit parent and creating transaction",
                ));
            }
            (_, Some(parent), Some(transaction)) => {
                reject_zero_id(&parent, "parent node id")?;
                if parent == self.node_id {
                    return Err(invalid_record("node is its own parent"));
                }
                transaction.validate()?;
            }
            _ => {
                return Err(invalid_record(
                    "non-root node requires parent and creating transaction",
                ));
            }
        }
        check_bound(
            "node children",
            self.child_node_ids.len(),
            MAX_NODE_CHILDREN,
        )?;
        if self.node_kind.is_terminal() {
            if !self.child_node_ids.is_empty() || self.timeout.is_some() {
                return Err(invalid_record("terminal node has children or timeout"));
            }
        } else if self.child_node_ids.is_empty() {
            return Err(invalid_record("nonterminal node has no children"));
        }
        if let Some(timeout) = self.timeout {
            timeout.validate()?;
        }
        for (index, child) in self.child_node_ids.iter().enumerate() {
            reject_zero_id(child, "child node id")?;
            if child == &self.node_id {
                return Err(invalid_record("node lists itself as a child"));
            }
            if self.child_node_ids[..index].contains(child) {
                return Err(invalid_record("node contains a duplicate child"));
            }
        }
        Ok(())
    }
}

fn validate_non_timeout_authorization(
    kind: EdgeKind,
    authorization: AuthorizationPolicy,
) -> Result<(), ChainError> {
    match (kind, authorization) {
        (EdgeKind::Advance { .. }, AuthorizationPolicy::BothPresigned)
        | (EdgeKind::Action(_), AuthorizationPolicy::BettingAction { .. })
        | (EdgeKind::AliceShowdown, AuthorizationPolicy::AliceScore)
        | (EdgeKind::BobPayout(_), AuthorizationPolicy::BobLivePayout) => Ok(()),
        (
            EdgeKind::HoleCardReveal {
                revealer: edge_role,
            },
            AuthorizationPolicy::RevealOpenings {
                revealer: authorization_role,
            },
        ) if edge_role == authorization_role => Ok(()),
        (
            EdgeKind::CommunityReveal {
                revealer: edge_role,
                ..
            },
            AuthorizationPolicy::RevealOpenings {
                revealer: authorization_role,
            },
        ) if edge_role == authorization_role => Ok(()),
        _ => Err(invalid_record(
            "edge kind and non-timeout authorization disagree",
        )),
    }
}

fn reject_zero_id(identifier: &[u8; 32], reason: &'static str) -> Result<(), ChainError> {
    if identifier.iter().all(|byte| *byte == 0) {
        Err(invalid_record(reason))
    } else {
        Ok(())
    }
}

fn check_bound(field: &'static str, actual: usize, maximum: usize) -> Result<(), ChainError> {
    if actual > maximum {
        Err(ChainError::BoundExceeded {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

const fn invalid_record(reason: &'static str) -> ChainError {
    ChainError::InvalidLogicalRecord { reason }
}
