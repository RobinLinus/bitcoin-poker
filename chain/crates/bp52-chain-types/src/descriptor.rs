//! Chain-game descriptors and funding-context validation.

use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use bp52_protocol::{
    PROTOCOL_VERSION as DEAL_PROTOCOL_VERSION,
    auth::{CanonicalIdentities, derive_game_id, verify_accepted_deal_signature},
};

pub use bp52_protocol::messages::AcceptedDeal;

use crate::{
    CHAIN_PROTOCOL_VERSION, ChainError, MAX_BETS_PER_STREET, MIN_STARTING_STACK_UNITS,
    codec::descriptor_signature_digest,
    state::{Street, TimeoutKind},
};

/// Canonical player role for the chain protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Role {
    /// Lexicographically smaller long-term x-only identity key.
    Alice = 0,
    /// Lexicographically larger long-term x-only identity key.
    Bob = 1,
}

impl Role {
    /// Returns the other fixed participant.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }

    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Economic treatment of the defaulting player on a timeout path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TimeoutSettlementPolicy {
    /// Return both uncommitted stacks and award only the pot to the beneficiary.
    PotOnly = 0,
    /// Reserved wire value rejected by the BP52-CHAIN-v1 profile.
    SlashRemainingStack = 1,
}

impl TimeoutSettlementPolicy {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// First revealer selected independently for every community street.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RevealOrder {
    /// First revealer for the three-card flop.
    pub flop_first: Role,
    /// First revealer for the turn.
    pub turn_first: Role,
    /// First revealer for the river.
    pub river_first: Role,
}

impl RevealOrder {
    /// Returns the first revealer for a community street.
    ///
    /// Preflop has no community reveal and returns `None`.
    #[must_use]
    pub const fn first_for(self, street: Street) -> Option<Role> {
        match street {
            Street::Preflop => None,
            Street::Flop => Some(self.flop_first),
            Street::Turn => Some(self.turn_first),
            Street::River => Some(self.river_first),
        }
    }
}

/// Canonical signed input to the BP52-CHAIN-v1 compiler.
///
/// `deal_session_nonce` is required to rederive the embedded BP52-DEAL-v1
/// `game_id`; `fee_reserve_sat` binds the fee value tracked by every
/// [`crate::AmountState`]. Both fields are included in canonical encoding and
/// therefore in descriptor signatures and [`crate::chain_game_id`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainGameDescriptor {
    /// Chain protocol version; exactly one.
    pub chain_protocol_version: u16,
    /// Mutually signed and previously archive-verified deal certificate.
    pub deal: AcceptedDeal,
    /// Exact consensus-network identifier used by the deal context.
    ///
    /// Standard networks use their consensus-order genesis hash. Custom
    /// signets use a domain-separated commitment to signet's shared genesis
    /// plus the complete challenge script, preventing cross-signet replay.
    pub network_id: [u8; 32],
    /// Pre-existing origin-escrow outpoint consensus bytes (`txid || vout`).
    ///
    /// The accepted deal binds this already-known outpoint. A later,
    /// witness-independent activation transaction spends it into the compiled
    /// game root; it is not itself the root-state outpoint.
    pub funding_outpoint: [u8; 36],
    /// Session nonce used when deriving the embedded deal's `game_id`.
    pub deal_session_nonce: [u8; 32],
    /// Canonical Alice x-only identity key.
    pub alice_xonly_pk: [u8; 32],
    /// Canonical Bob x-only identity key.
    pub bob_xonly_pk: [u8; 32],
    /// Dealer/button role; this player posts the small blind.
    pub button: Role,
    /// Small-blind unit in satoshis.
    pub unit_sat: u64,
    /// Maximum total wagers on one street, including its opening bet.
    pub max_bets_per_street: u8,
    /// Alice's poker stack, excluding fee reserve.
    pub alice_starting_stack_sat: u64,
    /// Bob's poker stack, excluding fee reserve.
    pub bob_starting_stack_sat: u64,
    /// Explicit fee reserve locked alongside both poker stacks.
    pub fee_reserve_sat: u64,
    /// Relative delay for action timeout paths.
    pub action_csv: u16,
    /// Relative delay for card-share reveal timeout paths.
    pub reveal_csv: u16,
    /// Relative delay for showdown timeout paths.
    pub showdown_csv: u16,
    /// First revealer for every community street.
    pub reveal_order: RevealOrder,
    /// Descriptor-visible timeout settlement policy; v1 requires `PotOnly`.
    pub timeout_policy: TimeoutSettlementPolicy,
    /// Recipient of an odd satoshi when the pot is split.
    pub split_remainder_recipient: Role,
    /// Identifier of the exact fee schedule and reserve disposition.
    pub fee_policy_id: [u8; 32],
    /// Identifier of the deterministic compiler implementation/profile.
    pub compiler_id: [u8; 32],
}

impl ChainGameDescriptor {
    /// Returns the canonical identity key bytes for one role.
    #[must_use]
    pub const fn identity_key(&self, role: Role) -> &[u8; 32] {
        match role {
            Role::Alice => &self.alice_xonly_pk,
            Role::Bob => &self.bob_xonly_pk,
        }
    }

    /// Returns the nonbutton player.
    #[must_use]
    pub const fn nonbutton(&self) -> Role {
        self.button.other()
    }

    /// Returns the full value that the funding state must account for.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ArithmeticOverflow`] if the three descriptor
    /// amounts cannot be represented by `u64`.
    pub fn total_locked_value(&self) -> Result<u64, ChainError> {
        self.alice_starting_stack_sat
            .checked_add(self.bob_starting_stack_sat)
            .and_then(|value| value.checked_add(self.fee_reserve_sat))
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

/// Descriptor plus both long-term BIP340 signatures over its tagged digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedChainGameDescriptor {
    /// Exact descriptor covered by both signatures.
    pub descriptor: ChainGameDescriptor,
    /// Alice's BIP340 signature.
    pub signature_a: [u8; 64],
    /// Bob's BIP340 signature.
    pub signature_b: [u8; 64],
}

/// Opaque evidence that both participants authenticated the exact chain
/// descriptor after all descriptor-level invariants were checked.
///
/// The inner descriptor is deliberately private. Protocol entry points that
/// construct or authenticate the concrete graph accept this type rather than
/// a caller-constructed [`ChainGameDescriptor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedChainDescriptor {
    descriptor: ChainGameDescriptor,
}

impl VerifiedChainDescriptor {
    /// Borrow the exact descriptor covered by both identity signatures.
    #[must_use]
    pub const fn as_descriptor(&self) -> &ChainGameDescriptor {
        &self.descriptor
    }
}

/// Validates every descriptor property available without the archived deal
/// transcript or a concrete fee-policy implementation.
///
/// This verifies both signatures on the embedded accepted deal, the exact
/// funding/session `game_id` binding, canonical identities, all 18 hash locks,
/// stack bounds, pot-only timeout settlement, fee reserve, timeouts, and fixed
/// identifiers. Callers must additionally require a
/// [`bp52_protocol::VerifiedAcceptedDeal`] produced by full archive replay
/// before graph construction; that evidence cannot be reconstructed from the
/// certificate alone.
///
/// # Errors
///
/// Returns [`ChainError`] on the first failed invariant.
pub fn validate_chain_descriptor(descriptor: &ChainGameDescriptor) -> Result<(), ChainError> {
    if descriptor.chain_protocol_version != CHAIN_PROTOCOL_VERSION {
        return Err(ChainError::WrongChainProtocolVersion {
            actual: descriptor.chain_protocol_version,
        });
    }
    if descriptor.deal.protocol_version != DEAL_PROTOCOL_VERSION {
        return Err(ChainError::WrongDealProtocolVersion {
            actual: descriptor.deal.protocol_version,
        });
    }
    validate_timeout_policy(descriptor.timeout_policy)?;

    let alice = parse_identity(Role::Alice, descriptor.alice_xonly_pk)?;
    let bob = parse_identity(Role::Bob, descriptor.bob_xonly_pk)?;
    if descriptor.alice_xonly_pk >= descriptor.bob_xonly_pk {
        return Err(ChainError::NonCanonicalIdentityOrder);
    }
    let identities =
        CanonicalIdentities::new(alice, bob).map_err(|_| ChainError::NonCanonicalIdentityOrder)?;
    if identities.alice() != &alice || identities.bob() != &bob {
        return Err(ChainError::NonCanonicalIdentityOrder);
    }

    let secp = Secp256k1::verification_only();
    let body = descriptor.deal.body();
    verify_accepted_deal_signature(
        &secp,
        &body,
        bp52_protocol::Role::Alice,
        &descriptor.deal.signature_a,
        &identities,
    )
    .map_err(|_| ChainError::InvalidSignature {
        role: Role::Alice,
        object: "accepted-deal",
    })?;
    verify_accepted_deal_signature(
        &secp,
        &body,
        bp52_protocol::Role::Bob,
        &descriptor.deal.signature_b,
        &identities,
    )
    .map_err(|_| ChainError::InvalidSignature {
        role: Role::Bob,
        object: "accepted-deal",
    })?;

    let expected_game_id = derive_game_id(
        &descriptor.network_id,
        &descriptor.funding_outpoint,
        &identities,
        &descriptor.deal_session_nonce,
    );
    if descriptor.deal.game_id != expected_game_id {
        return Err(ChainError::DealGameIdMismatch);
    }
    validate_distinct_hashes(&descriptor.deal)?;

    if descriptor.unit_sat == 0 {
        return Err(ChainError::ZeroUnit);
    }
    if descriptor.max_bets_per_street == 0 || descriptor.max_bets_per_street > MAX_BETS_PER_STREET {
        return Err(ChainError::UnsupportedBetsPerStreet {
            actual: descriptor.max_bets_per_street,
            maximum: MAX_BETS_PER_STREET,
        });
    }
    if descriptor.fee_reserve_sat == 0 {
        return Err(ChainError::ZeroFeeReserve);
    }
    let minimum_stack = descriptor
        .unit_sat
        .checked_mul(MIN_STARTING_STACK_UNITS)
        .ok_or(ChainError::ArithmeticOverflow)?;
    for (role, actual) in [
        (Role::Alice, descriptor.alice_starting_stack_sat),
        (Role::Bob, descriptor.bob_starting_stack_sat),
    ] {
        if actual < minimum_stack {
            return Err(ChainError::StackTooSmall {
                role,
                required: minimum_stack,
                actual,
            });
        }
    }
    descriptor.total_locked_value()?;

    for (kind, value) in [
        (TimeoutKind::Action, descriptor.action_csv),
        (TimeoutKind::Reveal, descriptor.reveal_csv),
        (TimeoutKind::Showdown, descriptor.showdown_csv),
    ] {
        if value == 0 {
            return Err(ChainError::ZeroTimeout { kind });
        }
    }
    for (field, identifier) in [
        ("funding_outpoint", descriptor.funding_outpoint.as_slice()),
        ("fee_policy_id", descriptor.fee_policy_id.as_slice()),
        ("compiler_id", descriptor.compiler_id.as_slice()),
    ] {
        if identifier.iter().all(|byte| *byte == 0) {
            return Err(ChainError::ZeroIdentifier { field });
        }
    }
    Ok(())
}

/// Validates the descriptor and both signatures over its canonical tagged
/// digest.
///
/// # Errors
///
/// Returns the descriptor validation error or the exact signer role whose
/// BIP340 signature failed.
pub fn verify_signed_chain_descriptor(
    signed: &SignedChainGameDescriptor,
) -> Result<VerifiedChainDescriptor, ChainError> {
    validate_chain_descriptor(&signed.descriptor)?;
    let alice = parse_identity(Role::Alice, signed.descriptor.alice_xonly_pk)?;
    let bob = parse_identity(Role::Bob, signed.descriptor.bob_xonly_pk)?;
    let message = Message::from_digest(descriptor_signature_digest(&signed.descriptor)?);
    let secp = Secp256k1::verification_only();
    for (role, key, bytes) in [
        (Role::Alice, alice, signed.signature_a),
        (Role::Bob, bob, signed.signature_b),
    ] {
        let signature =
            Signature::from_slice(&bytes).map_err(|_| ChainError::InvalidSignature {
                role,
                object: "chain-descriptor",
            })?;
        secp.verify_schnorr(&signature, &message, &key)
            .map_err(|_| ChainError::InvalidSignature {
                role,
                object: "chain-descriptor",
            })?;
    }
    Ok(VerifiedChainDescriptor {
        descriptor: signed.descriptor,
    })
}

fn parse_identity(role: Role, bytes: [u8; 32]) -> Result<XOnlyPublicKey, ChainError> {
    XOnlyPublicKey::from_slice(&bytes).map_err(|_| ChainError::InvalidIdentityKey { role })
}

fn validate_timeout_policy(policy: TimeoutSettlementPolicy) -> Result<(), ChainError> {
    if policy == TimeoutSettlementPolicy::PotOnly {
        Ok(())
    } else {
        Err(ChainError::UnsupportedTimeoutSettlementPolicy { actual: policy })
    }
}

fn validate_distinct_hashes(deal: &AcceptedDeal) -> Result<(), ChainError> {
    for first in 0..18 {
        for second in (first + 1)..18 {
            if hash_at(deal, first) == hash_at(deal, second) {
                return Err(ChainError::DuplicateDealHash { first, second });
            }
        }
    }
    Ok(())
}

const fn hash_at(deal: &AcceptedDeal, index: usize) -> &[u8; 32] {
    if index < 9 {
        &deal.hashes_a[index]
    } else {
        &deal.hashes_b[index - 9]
    }
}
