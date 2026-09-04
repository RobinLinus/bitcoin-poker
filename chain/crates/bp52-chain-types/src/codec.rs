//! Canonical encoding and deterministic identifier derivation.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use sha2::{Digest, Sha256};

use crate::{
    CHAIN_PROTOCOL_VERSION, ChainError, MAX_BETS_PER_STREET,
    descriptor::{
        ChainGameDescriptor, RevealOrder, Role, SignedChainGameDescriptor, TimeoutSettlementPolicy,
        validate_chain_descriptor,
    },
    node::{
        AuthorizationPolicy, EdgeKind, LogicalEdge, LogicalNodeRecord, LogicalOutput,
        LogicalTransaction, MAX_LOGICAL_OUTPUTS, MAX_NODE_CHILDREN,
        MAX_NON_WITNESS_TRANSACTION_BYTES, MAX_SCRIPT_PUBKEY_BYTES, NodeId, NodeKind, Phase,
        StateDigest,
    },
    outcome::{SettlementReason, ShowdownOutcome, TerminalAccounting, TerminalOutcome},
    state::{
        Action, AmountState, BettingState, BettingTransition, Street, TimeoutKind, TimeoutSpec,
    },
};

/// BIP340 tag used to bind a chain descriptor to its game identifier.
pub const CHAIN_GAME_TAG: &str = "BP52/chain-game/v1";
/// BIP340 tag used to identify the external funded root.
pub const CHAIN_ROOT_TAG: &str = "BP52/chain-root/v1";
/// BIP340 tag used to derive a path-dependent child node identifier.
pub const CHAIN_NODE_TAG: &str = "BP52/chain-node/v1";
/// BIP340 tag used for long-term signatures over the chain descriptor.
pub const CHAIN_DESCRIPTOR_TAG: &str = "BP52/chain-descriptor/v1";

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

/// Validates and hashes a descriptor into its canonical chain-game identifier.
///
/// # Errors
///
/// Returns descriptor validation or canonical encoding errors.
pub fn chain_game_id(descriptor: &ChainGameDescriptor) -> Result<[u8; 32], ChainError> {
    validate_chain_descriptor(descriptor)?;
    Ok(tagged_sha256(CHAIN_GAME_TAG, &descriptor.encode_to_vec()?))
}

/// Computes the digest signed by both long-term keys for a chain descriptor.
///
/// The signature digest has a distinct domain from [`chain_game_id`] even
/// though both cover the same canonical descriptor bytes.
///
/// # Errors
///
/// Returns a canonical encoding error.
pub fn descriptor_signature_digest(
    descriptor: &ChainGameDescriptor,
) -> Result<[u8; 32], CodecError> {
    Ok(tagged_sha256(
        CHAIN_DESCRIPTOR_TAG,
        &descriptor.encode_to_vec()?,
    ))
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

/// Decodes one complete descriptor and performs all available semantic checks.
///
/// # Errors
///
/// Rejects malformed/trailing encoding or any invalid descriptor invariant.
pub fn decode_chain_descriptor(bytes: &[u8]) -> Result<ChainGameDescriptor, ChainError> {
    let descriptor = ChainGameDescriptor::decode_exact(bytes)?;
    validate_chain_descriptor(&descriptor)?;
    Ok(descriptor)
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

impl Encode for ChainGameDescriptor {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.chain_protocol_version.encode(writer)?;
        self.deal.encode(writer)?;
        self.network_id.encode(writer)?;
        self.funding_outpoint.encode(writer)?;
        self.deal_session_nonce.encode(writer)?;
        self.alice_xonly_pk.encode(writer)?;
        self.bob_xonly_pk.encode(writer)?;
        self.button.encode(writer)?;
        self.unit_sat.encode(writer)?;
        self.max_bets_per_street.encode(writer)?;
        self.alice_starting_stack_sat.encode(writer)?;
        self.bob_starting_stack_sat.encode(writer)?;
        self.fee_reserve_sat.encode(writer)?;
        self.action_csv.encode(writer)?;
        self.reveal_csv.encode(writer)?;
        self.showdown_csv.encode(writer)?;
        self.reveal_order.encode(writer)?;
        self.timeout_policy.encode(writer)?;
        self.split_remainder_recipient.encode(writer)?;
        self.fee_policy_id.encode(writer)?;
        self.compiler_id.encode(writer)
    }
}

impl Decode for ChainGameDescriptor {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let chain_protocol_version = u16::decode(reader)?;
        if chain_protocol_version != CHAIN_PROTOCOL_VERSION {
            return Err(CodecError::NonCanonical);
        }
        Ok(Self {
            chain_protocol_version,
            deal: Decode::decode(reader)?,
            network_id: Decode::decode(reader)?,
            funding_outpoint: Decode::decode(reader)?,
            deal_session_nonce: Decode::decode(reader)?,
            alice_xonly_pk: Decode::decode(reader)?,
            bob_xonly_pk: Decode::decode(reader)?,
            button: Decode::decode(reader)?,
            unit_sat: Decode::decode(reader)?,
            max_bets_per_street: Decode::decode(reader)?,
            alice_starting_stack_sat: Decode::decode(reader)?,
            bob_starting_stack_sat: Decode::decode(reader)?,
            fee_reserve_sat: Decode::decode(reader)?,
            action_csv: Decode::decode(reader)?,
            reveal_csv: Decode::decode(reader)?,
            showdown_csv: Decode::decode(reader)?,
            reveal_order: Decode::decode(reader)?,
            timeout_policy: Decode::decode(reader)?,
            split_remainder_recipient: Decode::decode(reader)?,
            fee_policy_id: Decode::decode(reader)?,
            compiler_id: Decode::decode(reader)?,
        })
    }
}

impl Encode for SignedChainGameDescriptor {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.descriptor.encode(writer)?;
        self.signature_a.encode(writer)?;
        self.signature_b.encode(writer)
    }
}

impl Decode for SignedChainGameDescriptor {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            descriptor: Decode::decode(reader)?,
            signature_a: Decode::decode(reader)?,
            signature_b: Decode::decode(reader)?,
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
            Self::RevealPreimages { revealer } => {
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
            2 => Ok(Self::RevealPreimages {
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, error::Error};

    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use bp52_codec::{CodecError, Decode, Encode, Writer};
    use bp52_protocol::{
        PROTOCOL_VERSION as DEAL_PROTOCOL_VERSION,
        auth::{CanonicalIdentities, accepted_deal_digest, derive_game_id},
    };

    use super::{
        chain_game_id, child_node_id, decode_chain_descriptor, descriptor_signature_digest,
        logical_state_digest, root_node_id,
    };
    use crate::{
        AcceptedDeal, Action, AmountState, AuthorizationPolicy, BettingState, BettingTransition,
        CHAIN_PROTOCOL_VERSION, ChainError, ChainGameDescriptor, EdgeKind, LogicalEdge,
        LogicalNodeRecord, LogicalOutput, LogicalTransaction, NodeKind, Phase, RevealOrder, Role,
        SettlementReason, ShowdownOutcome, SignedChainGameDescriptor, Street, TerminalOutcome,
        TimeoutKind, TimeoutSettlementPolicy, TimeoutSpec, terminal_accounting,
        validate_chain_descriptor, verify_signed_chain_descriptor,
    };

    type Fixture = (ChainGameDescriptor, Keypair, Keypair);

    fn keypair(secret_number: u8) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let mut secret = [0_u8; 32];
        secret[31] = secret_number;
        Keypair::from_seckey_slice(&secp, &secret)
    }

    fn fixture() -> Result<Fixture, Box<dyn Error>> {
        let first = keypair(1)?;
        let second = keypair(2)?;
        let first_public = first.x_only_public_key().0.serialize();
        let second_public = second.x_only_public_key().0.serialize();
        let (alice_key, bob_key) = if first_public < second_public {
            (first, second)
        } else {
            (second, first)
        };
        let alice_public = alice_key.x_only_public_key().0;
        let bob_public = bob_key.x_only_public_key().0;
        let identities = CanonicalIdentities::new(alice_public, bob_public)?;
        let network_id = [0x11; 32];
        let funding_outpoint = [0x22; 36];
        let deal_session_nonce = [0x33; 32];
        let mut deal = AcceptedDeal {
            protocol_version: DEAL_PROTOCOL_VERSION,
            game_id: derive_game_id(
                &network_id,
                &funding_outpoint,
                &identities,
                &deal_session_nonce,
            ),
            attempt: 7,
            hashes_a: core::array::from_fn(|index| [index.to_le_bytes()[0].wrapping_add(1); 32]),
            hashes_b: core::array::from_fn(|index| [index.to_le_bytes()[0].wrapping_add(10); 32]),
            verification_transcript_root: [0x44; 32],
            signature_a: [0_u8; 64],
            signature_b: [0_u8; 64],
        };
        sign_deal(&mut deal, &alice_key, &bob_key)?;
        Ok((
            ChainGameDescriptor {
                chain_protocol_version: CHAIN_PROTOCOL_VERSION,
                deal,
                network_id,
                funding_outpoint,
                deal_session_nonce,
                alice_xonly_pk: alice_public.serialize(),
                bob_xonly_pk: bob_public.serialize(),
                button: Role::Alice,
                unit_sat: 100,
                max_bets_per_street: crate::MAX_BETS_PER_STREET,
                alice_starting_stack_sat: 10_000,
                bob_starting_stack_sat: 12_000,
                fee_reserve_sat: 3_300,
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
                fee_policy_id: [0x55; 32],
                compiler_id: [0x66; 32],
            },
            alice_key,
            bob_key,
        ))
    }

    fn sign_deal(
        deal: &mut AcceptedDeal,
        alice_key: &Keypair,
        bob_key: &Keypair,
    ) -> Result<(), Box<dyn Error>> {
        let digest = accepted_deal_digest(&deal.body())?;
        let message = Message::from_digest(digest);
        let secp = Secp256k1::new();
        deal.signature_a = secp
            .sign_schnorr_no_aux_rand(&message, alice_key)
            .serialize();
        deal.signature_b = secp.sign_schnorr_no_aux_rand(&message, bob_key).serialize();
        Ok(())
    }

    fn sample_transaction() -> LogicalTransaction {
        LogicalTransaction {
            version: 2,
            lock_time: 0,
            input_outpoint: [0x71; 36],
            sequence: u32::MAX,
            outputs: vec![LogicalOutput {
                value_sat: 1_000,
                script_pubkey: vec![0x51],
            }],
            fee_sat: 100,
            txid: [0x72; 32],
            non_witness_serialization: vec![0x02, 0x00, 0x00, 0x00],
        }
    }

    #[test]
    fn descriptor_roundtrip_signatures_and_ids_are_bound() -> Result<(), Box<dyn Error>> {
        let (descriptor, alice_key, bob_key) = fixture()?;
        validate_chain_descriptor(&descriptor)?;

        let bytes = descriptor.encode_to_vec()?;
        assert_eq!(ChainGameDescriptor::decode_exact(&bytes)?, descriptor);
        assert_eq!(decode_chain_descriptor(&bytes)?, descriptor);
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ChainGameDescriptor::decode_exact(&trailing),
            Err(CodecError::TrailingBytes)
        );

        let game_id = chain_game_id(&descriptor)?;
        let root = root_node_id(&game_id);
        let state = logical_state_digest(&AmountState::funded(&descriptor))?;
        let call_child = child_node_id(&root, EdgeKind::Action(Action::Call), &state);
        let fold_child = child_node_id(&root, EdgeKind::Action(Action::Fold), &state);
        assert_ne!(root, game_id);
        assert_ne!(call_child, fold_child);
        assert_ne!(descriptor_signature_digest(&descriptor)?, game_id);

        let digest = descriptor_signature_digest(&descriptor)?;
        let message = Message::from_digest(digest);
        let secp = Secp256k1::new();
        let signed = SignedChainGameDescriptor {
            descriptor,
            signature_a: secp
                .sign_schnorr_no_aux_rand(&message, &alice_key)
                .serialize(),
            signature_b: secp
                .sign_schnorr_no_aux_rand(&message, &bob_key)
                .serialize(),
        };
        let verified = verify_signed_chain_descriptor(&signed)?;
        assert_eq!(verified.as_descriptor(), &descriptor);
        assert_eq!(
            SignedChainGameDescriptor::decode_exact(&signed.encode_to_vec()?)?,
            signed
        );

        let mut changed_terms = signed;
        changed_terms.descriptor.button = changed_terms.descriptor.button.other();
        assert!(matches!(
            verify_signed_chain_descriptor(&changed_terms),
            Err(ChainError::InvalidSignature {
                role: Role::Alice,
                object: "chain-descriptor"
            })
        ));
        Ok(())
    }

    #[test]
    fn descriptor_validation_fails_closed() -> Result<(), Box<dyn Error>> {
        let (descriptor, alice_key, bob_key) = fixture()?;

        let mut minimum_stacks = descriptor;
        minimum_stacks.alice_starting_stack_sat = 2 * minimum_stacks.unit_sat;
        minimum_stacks.bob_starting_stack_sat = 2 * minimum_stacks.unit_sat;
        validate_chain_descriptor(&minimum_stacks)?;

        let mut below_big_blind = minimum_stacks;
        below_big_blind.alice_starting_stack_sat -= 1;
        assert!(matches!(
            validate_chain_descriptor(&below_big_blind),
            Err(ChainError::StackTooSmall {
                role: Role::Alice,
                required: 200,
                actual: 199
            })
        ));

        for invalid_cap in [0, crate::MAX_BETS_PER_STREET + 1] {
            let mut invalid = descriptor;
            invalid.max_bets_per_street = invalid_cap;
            assert!(matches!(
                validate_chain_descriptor(&invalid),
                Err(ChainError::UnsupportedBetsPerStreet { actual, .. }) if actual == invalid_cap
            ));
        }

        let mut rebound = descriptor;
        rebound.deal_session_nonce[0] ^= 1;
        assert!(matches!(
            validate_chain_descriptor(&rebound),
            Err(ChainError::DealGameIdMismatch)
        ));

        let mut duplicate = descriptor;
        duplicate.deal.hashes_b[0] = duplicate.deal.hashes_a[0];
        sign_deal(&mut duplicate.deal, &alice_key, &bob_key)?;
        assert!(matches!(
            validate_chain_descriptor(&duplicate),
            Err(ChainError::DuplicateDealHash { .. })
        ));

        let mut bad_signature = descriptor;
        bad_signature.deal.signature_a[0] ^= 1;
        assert!(matches!(
            validate_chain_descriptor(&bad_signature),
            Err(ChainError::InvalidSignature {
                role: Role::Alice,
                object: "accepted-deal"
            })
        ));

        let mut no_fees = descriptor;
        no_fees.fee_reserve_sat = 0;
        assert!(matches!(
            validate_chain_descriptor(&no_fees),
            Err(ChainError::ZeroFeeReserve)
        ));

        let mut slashing = descriptor;
        slashing.timeout_policy = TimeoutSettlementPolicy::SlashRemainingStack;
        assert!(matches!(
            validate_chain_descriptor(&slashing),
            Err(ChainError::UnsupportedTimeoutSettlementPolicy {
                actual: TimeoutSettlementPolicy::SlashRemainingStack
            })
        ));
        let message = Message::from_digest(descriptor_signature_digest(&slashing)?);
        let secp = Secp256k1::new();
        let signed_slashing = SignedChainGameDescriptor {
            descriptor: slashing,
            signature_a: secp
                .sign_schnorr_no_aux_rand(&message, &alice_key)
                .serialize(),
            signature_b: secp
                .sign_schnorr_no_aux_rand(&message, &bob_key)
                .serialize(),
        };
        assert!(matches!(
            verify_signed_chain_descriptor(&signed_slashing),
            Err(ChainError::UnsupportedTimeoutSettlementPolicy {
                actual: TimeoutSettlementPolicy::SlashRemainingStack
            })
        ));

        let mut wrong_order = descriptor;
        core::mem::swap(
            &mut wrong_order.alice_xonly_pk,
            &mut wrong_order.bob_xonly_pk,
        );
        assert!(matches!(
            validate_chain_descriptor(&wrong_order),
            Err(ChainError::NonCanonicalIdentityOrder)
        ));
        Ok(())
    }

    #[test]
    fn betting_engine_covers_blind_option_cap_and_checks() -> Result<(), Box<dyn Error>> {
        let (descriptor, _, _) = fixture()?;
        let preflop = BettingState::initial_preflop(&descriptor)?;
        assert_eq!(preflop.amounts.pot, 300);
        assert_eq!(preflop.amounts.alice_remaining, 9_900);
        assert_eq!(preflop.amounts.bob_remaining, 11_800);
        assert_eq!(
            preflop.legal_actions(&descriptor)?,
            vec![Action::Fold, Action::Call, Action::Raise]
        );
        assert!(matches!(
            preflop.apply_action(&descriptor, Action::Bet),
            Err(ChainError::IllegalAction {
                action: Action::Bet
            })
        ));

        let BettingTransition::Continue(big_blind_option) =
            preflop.apply_action(&descriptor, Action::Call)?
        else {
            return Err("small-blind call did not preserve the big-blind option".into());
        };
        assert!(big_blind_option.big_blind_option_pending);
        assert_eq!(
            big_blind_option.legal_actions(&descriptor)?,
            vec![Action::Check, Action::Raise]
        );
        assert!(matches!(
            big_blind_option.apply_action(&descriptor, Action::Check)?,
            BettingTransition::StreetComplete {
                street: Street::Preflop,
                ..
            }
        ));

        let BettingTransition::Continue(second_bet) =
            big_blind_option.apply_action(&descriptor, Action::Raise)?
        else {
            return Err("raise did not continue betting".into());
        };
        let BettingTransition::Continue(third_bet) =
            second_bet.apply_action(&descriptor, Action::Raise)?
        else {
            return Err("second raise did not continue betting".into());
        };
        let BettingTransition::Continue(capped) =
            third_bet.apply_action(&descriptor, Action::Raise)?
        else {
            return Err("third raise did not continue betting".into());
        };
        assert_eq!(capped.bets_used, 4);
        assert_eq!(
            capped.legal_actions(&descriptor)?,
            vec![Action::Fold, Action::Call]
        );
        let BettingTransition::StreetComplete {
            amounts: preflop_complete,
            ..
        } = capped.apply_action(&descriptor, Action::Call)?
        else {
            return Err("final preflop call did not complete the street".into());
        };

        let postflop = BettingState::start_postflop(Street::Flop, &descriptor, preflop_complete)?;
        let BettingTransition::Continue(after_check) =
            postflop.apply_action(&descriptor, Action::Check)?
        else {
            return Err("first postflop check ended the street".into());
        };
        assert!(matches!(
            after_check.apply_action(&descriptor, Action::Check)?,
            BettingTransition::StreetComplete {
                street: Street::Flop,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn accounting_is_checked_and_conservative() -> Result<(), Box<dyn Error>> {
        let amounts = AmountState {
            alice_remaining: 900,
            bob_remaining: 800,
            pot: 301,
            fee_reserve_remaining: 100,
        };
        let alice_win = terminal_accounting(
            amounts,
            TerminalOutcome::Showdown(ShowdownOutcome::AliceWin),
            TimeoutSettlementPolicy::PotOnly,
            Role::Alice,
        )?;
        assert_eq!((alice_win.alice_sat, alice_win.bob_sat), (1_201, 800));
        assert_eq!(alice_win.reason, SettlementReason::Showdown);
        assert_eq!(alice_win.total()?, amounts.game_value()?);

        let split = terminal_accounting(
            amounts,
            TerminalOutcome::Showdown(ShowdownOutcome::Split),
            TimeoutSettlementPolicy::PotOnly,
            Role::Alice,
        )?;
        assert_eq!((split.alice_sat, split.bob_sat), (1_051, 950));

        assert!(matches!(
            terminal_accounting(
                amounts,
                TerminalOutcome::Timeout {
                    kind: TimeoutKind::Reveal,
                    defaulting: Role::Alice,
                },
                TimeoutSettlementPolicy::SlashRemainingStack,
                Role::Alice,
            ),
            Err(ChainError::UnsupportedTimeoutSettlementPolicy {
                actual: TimeoutSettlementPolicy::SlashRemainingStack
            })
        ));

        let charged = amounts.charge_fee(25)?;
        amounts.verify_transition(charged, 25)?;
        assert!(matches!(
            amounts.charge_fee(101),
            Err(ChainError::ArithmeticUnderflow)
        ));
        assert!(matches!(
            AmountState {
                alice_remaining: u64::MAX,
                bob_remaining: 1,
                pot: 0,
                fee_reserve_remaining: 0,
            }
            .game_value(),
            Err(ChainError::ArithmeticOverflow)
        ));
        Ok(())
    }

    #[test]
    fn node_records_roundtrip_and_authorization_is_exact() -> Result<(), Box<dyn Error>> {
        let transaction = sample_transaction();
        let edge = LogicalEdge {
            parent_node_id: [0x81; 32],
            child_node_id: [0x82; 32],
            kind: EdgeKind::Action(Action::Check),
            transaction: transaction.clone(),
            authorization: AuthorizationPolicy::BettingAction { actor: Role::Alice },
            timeout: None,
        };
        edge.validate()?;
        assert_eq!(LogicalEdge::decode_exact(&edge.encode_to_vec()?)?, edge);

        let mut wrong_authorization = edge;
        wrong_authorization.authorization = AuthorizationPolicy::BobLivePayout;
        assert!(matches!(
            wrong_authorization.validate(),
            Err(ChainError::InvalidLogicalRecord { .. })
        ));

        let timeout = TimeoutSpec::new(TimeoutKind::Action, 12, Role::Alice, Role::Bob)?;
        let timeout_edge = LogicalEdge {
            parent_node_id: [0x83; 32],
            child_node_id: [0x84; 32],
            kind: EdgeKind::Timeout(TimeoutKind::Action),
            transaction: transaction.clone(),
            authorization: AuthorizationPolicy::Timeout {
                beneficiary: Role::Bob,
            },
            timeout: Some(timeout),
        };
        timeout_edge.validate()?;

        let node = LogicalNodeRecord {
            node_id: [0x91; 32],
            parent_node_id: Some([0x92; 32]),
            node_kind: NodeKind::Betting,
            logical_state_digest: [0x93; 32],
            transaction: Some(transaction),
            required_predicate_id: [0x94; 32],
            timeout: Some(timeout),
            child_node_ids: vec![[0x95; 32], [0x96; 32]],
        };
        node.validate()?;
        assert_eq!(
            LogicalNodeRecord::decode_exact(&node.encode_to_vec()?)?,
            node
        );
        Ok(())
    }

    #[test]
    fn codec_rejects_unknown_noncanonical_and_oversized_values() -> Result<(), Box<dyn Error>> {
        assert_eq!(Action::decode_exact(&[5]), Err(CodecError::NonCanonical));
        assert_eq!(Role::decode_exact(&[2]), Err(CodecError::NonCanonical));
        assert_eq!(
            TimeoutSpec::decode_exact(&[TimeoutKind::Action.code(), 0, 0, 0, 0, 1]),
            Err(CodecError::NonCanonical)
        );

        let (descriptor, _, _) = fixture()?;
        let state = BettingState::initial_preflop(&descriptor)?;
        let mut state_bytes = state.encode_to_vec()?;
        state_bytes[28] = 2;
        assert_eq!(
            BettingState::decode_exact(&state_bytes),
            Err(CodecError::NonCanonical)
        );

        let mut oversized = Writer::new();
        1_u64.encode(&mut oversized)?;
        u32::try_from(crate::node::MAX_SCRIPT_PUBKEY_BYTES + 1)?.encode(&mut oversized)?;
        assert_eq!(
            LogicalOutput::decode_exact(&oversized.into_bytes()),
            Err(CodecError::LengthLimitExceeded)
        );
        assert_eq!(
            EdgeKind::CommunityReveal {
                street: Street::Preflop,
                revealer: Role::Alice,
            }
            .encode_to_vec(),
            Err(CodecError::NonCanonical)
        );
        Ok(())
    }

    #[test]
    fn every_v1_edge_path_code_is_unique() {
        let mut edges = Vec::new();
        edges.extend(
            [
                Phase::DealAlice,
                Phase::DealBob,
                Phase::PreflopBetting,
                Phase::FlopRevealFirst,
                Phase::FlopRevealSecond,
                Phase::FlopBetting,
                Phase::TurnRevealFirst,
                Phase::TurnRevealSecond,
                Phase::TurnBetting,
                Phase::RiverRevealFirst,
                Phase::RiverRevealSecond,
                Phase::RiverBetting,
                Phase::AliceShowdown,
                Phase::BobTerminal,
            ]
            .map(|phase| EdgeKind::Advance { phase }),
        );
        edges.extend(
            [
                Action::Fold,
                Action::Check,
                Action::Call,
                Action::Bet,
                Action::Raise,
            ]
            .map(EdgeKind::Action),
        );
        edges
            .extend([Role::Alice, Role::Bob].map(|revealer| EdgeKind::HoleCardReveal { revealer }));
        for street in [Street::Flop, Street::Turn, Street::River] {
            edges.extend(
                [Role::Alice, Role::Bob]
                    .map(|revealer| EdgeKind::CommunityReveal { street, revealer }),
            );
        }
        edges.push(EdgeKind::AliceShowdown);
        edges.extend(
            [
                ShowdownOutcome::AliceWin,
                ShowdownOutcome::BobWin,
                ShowdownOutcome::Split,
            ]
            .map(EdgeKind::BobPayout),
        );
        edges.extend(
            [
                TimeoutKind::Action,
                TimeoutKind::Reveal,
                TimeoutKind::Showdown,
            ]
            .map(EdgeKind::Timeout),
        );

        let codes: BTreeSet<_> = edges.iter().map(|edge| edge.path_code()).collect();
        assert_eq!(codes.len(), edges.len());
    }
}
