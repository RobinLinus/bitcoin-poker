//! Canonical encoding and deterministic identifier derivation.

use poker_codec::{CodecError, Decode, Encode, Reader, Writer};
use sha2::{Digest, Sha256};

use crate::{
    MAX_BETS_PER_STREET,
    node::{
        AuthorizationPolicy, EdgeKind, LogicalEdge, LogicalNodeRecord, LogicalOutput,
        LogicalTransaction, MAX_LOGICAL_OUTPUTS, MAX_NODE_CHILDREN,
        MAX_NON_WITNESS_TRANSACTION_BYTES, MAX_SCRIPT_PUBKEY_BYTES, NodeId, NodeKind, Phase,
        StateDigest,
    },
    outcome::{SettlementReason, ShowdownOutcome, TerminalAccounting, TerminalOutcome},
    roles::Role,
    rules::{RevealOrder, TimeoutSettlementPolicy},
    state::{
        Action, AmountState, BettingState, BettingTransition, Street, TimeoutKind, TimeoutSpec,
    },
};

/// BIP340 tag used to identify the external funded root.
pub const CHAIN_ROOT_TAG: &str = "BP52/chain-root/v1";
/// BIP340 tag used to derive a path-dependent child node identifier.
pub const CHAIN_NODE_TAG: &str = "BP52/chain-node/v1";
/// Computes the BIP340 tagged SHA-256 construction.
#[must_use]
pub fn tagged_sha256(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

/// Derives the path-independent identifier of the external funded root.
#[must_use]
pub fn root_node_id(chain_game_id: &[u8; 32]) -> NodeId {
    tagged_sha256(CHAIN_ROOT_TAG, chain_game_id)
}

/// Derives a path-dependent child identifier from its semantic edge kind.
#[must_use]
pub fn child_node_id(
    parent_node_id: &NodeId,
    edge_kind: EdgeKind,
    child_state_digest: &StateDigest,
) -> NodeId {
    child_node_id_from_code(parent_node_id, edge_kind.path_code(), child_state_digest)
}

/// Derives a path-dependent child identifier from an already validated edge code.
#[must_use]
pub fn child_node_id_from_code(
    parent_node_id: &NodeId,
    edge_code: [u8; 4],
    child_state_digest: &StateDigest,
) -> NodeId {
    let mut message = [0_u8; 68];
    message[..32].copy_from_slice(parent_node_id);
    message[32..36].copy_from_slice(&edge_code);
    message[36..].copy_from_slice(child_state_digest);
    tagged_sha256(CHAIN_NODE_TAG, &message)
}

/// Computes ordinary SHA-256 over one canonical logical-state encoding.
///
/// # Errors
///
/// Returns a canonical encoding error.
pub fn logical_state_digest<T: Encode>(state: &T) -> Result<StateDigest, CodecError> {
    Ok(Sha256::digest(state.encode_to_vec()?).into())
}

impl Encode for Role {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.code().encode(writer)
    }
}

impl Decode for Role {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::Alice),
            1 => Ok(Self::Bob),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for TimeoutSettlementPolicy {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.code().encode(writer)
    }
}

impl Decode for TimeoutSettlementPolicy {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::PotOnly),
            1 => Ok(Self::SlashRemainingStack),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for RevealOrder {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.flop_first.encode(writer)?;
        self.turn_first.encode(writer)?;
        self.river_first.encode(writer)
    }
}

impl Decode for RevealOrder {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            flop_first: Decode::decode(reader)?,
            turn_first: Decode::decode(reader)?,
            river_first: Decode::decode(reader)?,
        })
    }
}

macro_rules! impl_unit_enum_codec {
    ($type:ty, $code:expr, { $($wire:literal => $variant:path),+ $(,)? }) => {
        impl Encode for $type {
            fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
                ($code)(*self).encode(writer)
            }
        }

        impl Decode for $type {
            fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
                match u8::decode(reader)? {
                    $($wire => Ok($variant),)+
                    _ => Err(CodecError::NonCanonical),
                }
            }
        }
    };
}

impl_unit_enum_codec!(Street, Street::code, {
    0 => Street::Preflop,
    1 => Street::Flop,
    2 => Street::Turn,
    3 => Street::River,
});
impl_unit_enum_codec!(Action, Action::code, {
    0 => Action::Fold,
    1 => Action::Check,
    2 => Action::Call,
    3 => Action::Bet,
    4 => Action::Raise,
});
impl_unit_enum_codec!(TimeoutKind, TimeoutKind::code, {
    0 => TimeoutKind::Action,
    1 => TimeoutKind::Reveal,
    2 => TimeoutKind::Showdown,
});
impl_unit_enum_codec!(ShowdownOutcome, ShowdownOutcome::code, {
    0 => ShowdownOutcome::AliceWin,
    1 => ShowdownOutcome::BobWin,
    2 => ShowdownOutcome::Split,
});
impl_unit_enum_codec!(SettlementReason, SettlementReason::code, {
    0 => SettlementReason::Fold,
    1 => SettlementReason::ActionTimeout,
    2 => SettlementReason::RevealTimeout,
    3 => SettlementReason::ShowdownTimeout,
    4 => SettlementReason::Showdown,
});
impl_unit_enum_codec!(Phase, Phase::code, {
    0 => Phase::DealAlice,
    1 => Phase::DealBob,
    2 => Phase::PreflopBetting,
    3 => Phase::FlopRevealFirst,
    4 => Phase::FlopRevealSecond,
    5 => Phase::FlopBetting,
    6 => Phase::TurnRevealFirst,
    7 => Phase::TurnRevealSecond,
    8 => Phase::TurnBetting,
    9 => Phase::RiverRevealFirst,
    10 => Phase::RiverRevealSecond,
    11 => Phase::RiverBetting,
    12 => Phase::AliceShowdown,
    13 => Phase::BobTerminal,
});
impl_unit_enum_codec!(NodeKind, NodeKind::code, {
    0 => NodeKind::Funded,
    1 => NodeKind::DealAlice,
    2 => NodeKind::DealBob,
    3 => NodeKind::Betting,
    4 => NodeKind::CommunityRevealFirst,
    5 => NodeKind::CommunityRevealSecond,
    6 => NodeKind::AliceShowdown,
    7 => NodeKind::BobTerminal,
    8 => NodeKind::Terminal,
});

impl Encode for TimeoutSpec {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.validate().map_err(|_| CodecError::NonCanonical)?;
        self.kind.encode(writer)?;
        self.csv.encode(writer)?;
        self.defaulting.encode(writer)?;
        self.beneficiary.encode(writer)
    }
}

impl Decode for TimeoutSpec {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            kind: Decode::decode(reader)?,
            csv: Decode::decode(reader)?,
            defaulting: Decode::decode(reader)?,
            beneficiary: Decode::decode(reader)?,
        };
        value.validate().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

impl Encode for AmountState {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.game_value().map_err(|_| CodecError::NonCanonical)?;
        self.alice_remaining.encode(writer)?;
        self.bob_remaining.encode(writer)?;
        self.pot.encode(writer)?;
        self.fee_reserve_remaining.encode(writer)
    }
}

impl Decode for AmountState {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            alice_remaining: Decode::decode(reader)?,
            bob_remaining: Decode::decode(reader)?,
            pot: Decode::decode(reader)?,
            fee_reserve_remaining: Decode::decode(reader)?,
        };
        value.game_value().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

impl Encode for BettingState {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        validate_decoded_betting_state(self)?;
        self.street.encode(writer)?;
        self.actor.encode(writer)?;
        self.alice_committed_this_street.encode(writer)?;
        self.bob_committed_this_street.encode(writer)?;
        self.current_wager.encode(writer)?;
        self.bets_used.encode(writer)?;
        self.consecutive_checks.encode(writer)?;
        encode_bool(self.big_blind_option_pending, writer)?;
        self.amounts.encode(writer)
    }
}

impl Decode for BettingState {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            street: Decode::decode(reader)?,
            actor: Decode::decode(reader)?,
            alice_committed_this_street: Decode::decode(reader)?,
            bob_committed_this_street: Decode::decode(reader)?,
            current_wager: Decode::decode(reader)?,
            bets_used: Decode::decode(reader)?,
            consecutive_checks: Decode::decode(reader)?,
            big_blind_option_pending: decode_bool(reader)?,
            amounts: Decode::decode(reader)?,
        };
        validate_decoded_betting_state(&value)?;
        Ok(value)
    }
}

impl Encode for BettingTransition {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        match self {
            Self::Continue(state) => {
                0_u8.encode(writer)?;
                state.encode(writer)
            }
            Self::StreetComplete { street, amounts } => {
                1_u8.encode(writer)?;
                street.encode(writer)?;
                amounts.encode(writer)
            }
            Self::Fold {
                folded,
                winner,
                amounts,
            } => {
                if *winner != folded.other() {
                    return Err(CodecError::NonCanonical);
                }
                2_u8.encode(writer)?;
                folded.encode(writer)?;
                winner.encode(writer)?;
                amounts.encode(writer)
            }
        }
    }
}

impl Decode for BettingTransition {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::Continue(Decode::decode(reader)?)),
            1 => Ok(Self::StreetComplete {
                street: Decode::decode(reader)?,
                amounts: Decode::decode(reader)?,
            }),
            2 => {
                let folded = Role::decode(reader)?;
                let winner = Role::decode(reader)?;
                if winner != folded.other() {
                    return Err(CodecError::NonCanonical);
                }
                Ok(Self::Fold {
                    folded,
                    winner,
                    amounts: Decode::decode(reader)?,
                })
            }
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for TerminalOutcome {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        match self {
            Self::Fold { folded } => {
                0_u8.encode(writer)?;
                folded.encode(writer)
            }
            Self::Timeout { kind, defaulting } => {
                1_u8.encode(writer)?;
                kind.encode(writer)?;
                defaulting.encode(writer)
            }
            Self::Showdown(outcome) => {
                2_u8.encode(writer)?;
                outcome.encode(writer)
            }
        }
    }
}

impl Decode for TerminalOutcome {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::Fold {
                folded: Decode::decode(reader)?,
            }),
            1 => Ok(Self::Timeout {
                kind: Decode::decode(reader)?,
                defaulting: Decode::decode(reader)?,
            }),
            2 => Ok(Self::Showdown(Decode::decode(reader)?)),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for TerminalAccounting {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.total().map_err(|_| CodecError::NonCanonical)?;
        self.alice_sat.encode(writer)?;
        self.bob_sat.encode(writer)?;
        self.fee_reserve_remaining.encode(writer)?;
        self.reason.encode(writer)
    }
}

impl Decode for TerminalAccounting {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            alice_sat: Decode::decode(reader)?,
            bob_sat: Decode::decode(reader)?,
            fee_reserve_remaining: Decode::decode(reader)?,
            reason: Decode::decode(reader)?,
        };
        value.total().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

impl Encode for EdgeKind {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        match self {
            Self::Advance { phase } => {
                0_u8.encode(writer)?;
                phase.encode(writer)
            }
            Self::Action(action) => {
                1_u8.encode(writer)?;
                action.encode(writer)
            }
            Self::HoleCardReveal { revealer } => {
                2_u8.encode(writer)?;
                revealer.encode(writer)
            }
            Self::CommunityReveal { street, revealer } => {
                if *street == Street::Preflop {
                    return Err(CodecError::NonCanonical);
                }
                3_u8.encode(writer)?;
                street.encode(writer)?;
                revealer.encode(writer)
            }
            Self::AliceShowdown => 4_u8.encode(writer),
            Self::BobPayout(outcome) => {
                5_u8.encode(writer)?;
                outcome.encode(writer)
            }
            Self::Timeout(kind) => {
                6_u8.encode(writer)?;
                kind.encode(writer)
            }
        }
    }
}

impl Decode for EdgeKind {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::Advance {
                phase: Decode::decode(reader)?,
            }),
            1 => Ok(Self::Action(Decode::decode(reader)?)),
            2 => Ok(Self::HoleCardReveal {
                revealer: Decode::decode(reader)?,
            }),
            3 => {
                let street = Street::decode(reader)?;
                if street == Street::Preflop {
                    return Err(CodecError::NonCanonical);
                }
                Ok(Self::CommunityReveal {
                    street,
                    revealer: Decode::decode(reader)?,
                })
            }
            4 => Ok(Self::AliceShowdown),
            5 => Ok(Self::BobPayout(Decode::decode(reader)?)),
            6 => Ok(Self::Timeout(Decode::decode(reader)?)),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for AuthorizationPolicy {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        match self {
            Self::BothPresigned => 0_u8.encode(writer),
            Self::BettingAction { actor } => {
                1_u8.encode(writer)?;
                actor.encode(writer)
            }
            Self::RevealOpenings { revealer } => {
                2_u8.encode(writer)?;
                revealer.encode(writer)
            }
            Self::AliceScore => 3_u8.encode(writer),
            Self::BobLivePayout => 4_u8.encode(writer),
            Self::Timeout { beneficiary } => {
                5_u8.encode(writer)?;
                beneficiary.encode(writer)
            }
        }
    }
}

impl Decode for AuthorizationPolicy {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::BothPresigned),
            1 => Ok(Self::BettingAction {
                actor: Decode::decode(reader)?,
            }),
            2 => Ok(Self::RevealOpenings {
                revealer: Decode::decode(reader)?,
            }),
            3 => Ok(Self::AliceScore),
            4 => Ok(Self::BobLivePayout),
            5 => Ok(Self::Timeout {
                beneficiary: Decode::decode(reader)?,
            }),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

impl Encode for LogicalOutput {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.validate().map_err(|_| CodecError::NonCanonical)?;
        self.value_sat.encode(writer)?;
        writer.write_byte_vector(&self.script_pubkey)
    }
}

impl Decode for LogicalOutput {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            value_sat: Decode::decode(reader)?,
            script_pubkey: reader.read_byte_vector(MAX_SCRIPT_PUBKEY_BYTES)?,
        };
        value.validate().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

impl Encode for LogicalTransaction {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.validate().map_err(|_| CodecError::NonCanonical)?;
        self.version.encode(writer)?;
        self.lock_time.encode(writer)?;
        self.input_outpoint.encode(writer)?;
        self.sequence.encode(writer)?;
        encode_vec(&self.outputs, writer)?;
        self.fee_sat.encode(writer)?;
        self.txid.encode(writer)?;
        writer.write_byte_vector(&self.non_witness_serialization)
    }
}

impl Decode for LogicalTransaction {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            version: Decode::decode(reader)?,
            lock_time: Decode::decode(reader)?,
            input_outpoint: Decode::decode(reader)?,
            sequence: Decode::decode(reader)?,
            outputs: decode_vec(reader, MAX_LOGICAL_OUTPUTS)?,
            fee_sat: Decode::decode(reader)?,
            txid: Decode::decode(reader)?,
            non_witness_serialization: reader
                .read_byte_vector(MAX_NON_WITNESS_TRANSACTION_BYTES)?,
        };
        value.validate().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

impl Encode for LogicalEdge {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.validate().map_err(|_| CodecError::NonCanonical)?;
        self.parent_node_id.encode(writer)?;
        self.child_node_id.encode(writer)?;
        self.kind.encode(writer)?;
        self.transaction.encode(writer)?;
        self.authorization.encode(writer)?;
        encode_option(self.timeout.as_ref(), writer)
    }
}

impl Decode for LogicalEdge {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            parent_node_id: Decode::decode(reader)?,
            child_node_id: Decode::decode(reader)?,
            kind: Decode::decode(reader)?,
            transaction: Decode::decode(reader)?,
            authorization: Decode::decode(reader)?,
            timeout: decode_option(reader)?,
        };
        value.validate().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

impl Encode for LogicalNodeRecord {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.validate().map_err(|_| CodecError::NonCanonical)?;
        self.node_id.encode(writer)?;
        encode_option(self.parent_node_id.as_ref(), writer)?;
        self.node_kind.encode(writer)?;
        self.logical_state_digest.encode(writer)?;
        encode_option(self.transaction.as_ref(), writer)?;
        self.required_predicate_id.encode(writer)?;
        encode_option(self.timeout.as_ref(), writer)?;
        encode_vec(&self.child_node_ids, writer)
    }
}

impl Decode for LogicalNodeRecord {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            node_id: Decode::decode(reader)?,
            parent_node_id: decode_option(reader)?,
            node_kind: Decode::decode(reader)?,
            logical_state_digest: Decode::decode(reader)?,
            transaction: decode_option(reader)?,
            required_predicate_id: Decode::decode(reader)?,
            timeout: decode_option(reader)?,
            child_node_ids: decode_vec(reader, MAX_NODE_CHILDREN)?,
        };
        value.validate().map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

fn encode_bool(value: bool, writer: &mut Writer) -> Result<(), CodecError> {
    u8::from(value).encode(writer)
}

fn decode_bool(reader: &mut Reader<'_>) -> Result<bool, CodecError> {
    match u8::decode(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CodecError::NonCanonical),
    }
}

fn encode_option<T: Encode>(value: Option<&T>, writer: &mut Writer) -> Result<(), CodecError> {
    match value {
        None => 0_u8.encode(writer),
        Some(inner) => {
            1_u8.encode(writer)?;
            inner.encode(writer)
        }
    }
}

fn decode_option<T: Decode>(reader: &mut Reader<'_>) -> Result<Option<T>, CodecError> {
    match u8::decode(reader)? {
        0 => Ok(None),
        1 => Ok(Some(T::decode(reader)?)),
        _ => Err(CodecError::NonCanonical),
    }
}

fn encode_vec<T: Encode>(values: &[T], writer: &mut Writer) -> Result<(), CodecError> {
    let length = u32::try_from(values.len()).map_err(|_| CodecError::LengthOverflow)?;
    length.encode(writer)?;
    for value in values {
        value.encode(writer)?;
    }
    Ok(())
}

fn decode_vec<T: Decode>(reader: &mut Reader<'_>, maximum: usize) -> Result<Vec<T>, CodecError> {
    let length = usize::try_from(u32::decode(reader)?).map_err(|_| CodecError::LengthOverflow)?;
    if length > maximum {
        return Err(CodecError::LengthLimitExceeded);
    }
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(T::decode(reader)?);
    }
    Ok(values)
}

fn validate_decoded_betting_state(state: &BettingState) -> Result<(), CodecError> {
    if state.bets_used > MAX_BETS_PER_STREET
        || state.consecutive_checks > 1
        || state.alice_committed_this_street > state.current_wager
        || state.bob_committed_this_street > state.current_wager
        || (state.bets_used == 0
            && (state.current_wager != 0
                || state.alice_committed_this_street != 0
                || state.bob_committed_this_street != 0))
        || (state.big_blind_option_pending
            && (state.street != Street::Preflop
                || state.bets_used != 1
                || state.alice_committed_this_street != state.current_wager
                || state.bob_committed_this_street != state.current_wager))
    {
        return Err(CodecError::NonCanonical);
    }
    state
        .amounts
        .game_value()
        .map_err(|_| CodecError::NonCanonical)?;
    Ok(())
}
