//! Shared card slots and reveal obligations.
use bp52_chain_types::Role;
/// Alice's seven-card order: slots `0,2,4,5,6,7,8`.
pub const ALICE_SEVEN_SLOTS: [u8; 7] = [0, 2, 4, 5, 6, 7, 8];
/// Bob's seven-card order: slots `1,3,4,5,6,7,8`.
pub const BOB_SEVEN_SLOTS: [u8; 7] = [1, 3, 4, 5, 6, 7, 8];

const DEAL_ALICE_SLOTS: [u8; 2] = [0, 2];
const DEAL_BOB_SLOTS: [u8; 2] = [1, 3];
const FLOP_SLOTS: [u8; 3] = [4, 5, 6];
const TURN_SLOTS: [u8; 1] = [7];
const RIVER_SLOTS: [u8; 1] = [8];

/// One exact protocol reveal obligation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RevealPattern {
    /// Bob delivers his shares for Alice's private slots 0 and 2.
    DealAlice,
    /// Alice delivers her shares for Bob's private slots 1 and 3.
    DealBob,
    /// One designated player reveals their three flop shares.
    Flop(Role),
    /// One designated player reveals their turn share.
    Turn(Role),
    /// One designated player reveals their river share.
    River(Role),
}

impl RevealPattern {
    /// Return the party obligated to reveal.
    #[must_use]
    pub const fn revealer(self) -> Role {
        match self {
            Self::DealAlice => Role::Bob,
            Self::DealBob => Role::Alice,
            Self::Flop(role) | Self::Turn(role) | Self::River(role) => role,
        }
    }

    /// Return the fixed ordered slots covered by this reveal.
    #[must_use]
    pub const fn slots(self) -> &'static [u8] {
        match self {
            Self::DealAlice => &DEAL_ALICE_SLOTS,
            Self::DealBob => &DEAL_BOB_SLOTS,
            Self::Flop(_) => &FLOP_SLOTS,
            Self::Turn(_) => &TURN_SLOTS,
            Self::River(_) => &RIVER_SLOTS,
        }
    }

    /// Return the stable program discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::DealAlice => 0,
            Self::DealBob => 1,
            Self::Flop(Role::Alice) => 2,
            Self::Flop(Role::Bob) => 3,
            Self::Turn(Role::Alice) => 4,
            Self::Turn(Role::Bob) => 5,
            Self::River(Role::Alice) => 6,
            Self::River(Role::Bob) => 7,
        }
    }
}
