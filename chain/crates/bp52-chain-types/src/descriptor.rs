//! Shared poker roles and reveal order.
use crate::state::Street;

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
