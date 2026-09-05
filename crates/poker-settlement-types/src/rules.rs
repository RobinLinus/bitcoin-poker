//! Poker economics independent of accepted-deal cryptography.
use crate::Street;
use crate::{ChainError, MAX_BETS_PER_STREET, MIN_STARTING_STACK_UNITS, Role, TimeoutKind};

/// Complete finite-poker rules, independent of dealing cryptography.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PokerRules {
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
}
impl PokerRules {
    /// Validate amounts, betting limits, and relative deadlines.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied data fails validation or cannot be encoded.
    pub fn validate(&self) -> Result<(), ChainError> {
        let rules = self;
        if self.timeout_policy != TimeoutSettlementPolicy::PotOnly {
            return Err(ChainError::InvalidLogicalRecord {
                reason: "unsupported timeout policy",
            });
        }
        if rules.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        if rules.max_bets_per_street == 0 || rules.max_bets_per_street > MAX_BETS_PER_STREET {
            return Err(ChainError::UnsupportedBetsPerStreet {
                actual: rules.max_bets_per_street,
                maximum: MAX_BETS_PER_STREET,
            });
        }
        if rules.fee_reserve_sat == 0 {
            return Err(ChainError::ZeroFeeReserve);
        }
        let minimum_stack = rules
            .unit_sat
            .checked_mul(MIN_STARTING_STACK_UNITS)
            .ok_or(ChainError::ArithmeticOverflow)?;
        for (role, actual) in [
            (Role::Alice, rules.alice_starting_stack_sat),
            (Role::Bob, rules.bob_starting_stack_sat),
        ] {
            if actual < minimum_stack {
                return Err(ChainError::StackTooSmall {
                    role,
                    required: minimum_stack,
                    actual,
                });
            }
        }
        rules.total_locked_value()?;

        for (kind, value) in [
            (TimeoutKind::Action, rules.action_csv),
            (TimeoutKind::Reveal, rules.reveal_csv),
            (TimeoutKind::Showdown, rules.showdown_csv),
        ] {
            if value == 0 {
                return Err(ChainError::ZeroTimeout { kind });
            }
        }
        Ok(())
    }
    /// Player who posts the big blind.
    #[must_use]
    pub const fn nonbutton(&self) -> Role {
        self.button.other()
    }
    /// Total stack and reserve value.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied data fails validation or cannot be encoded.
    pub fn total_locked_value(&self) -> Result<u64, ChainError> {
        self.alice_starting_stack_sat
            .checked_add(self.bob_starting_stack_sat)
            .and_then(|s| s.checked_add(self.fee_reserve_sat))
            .ok_or(ChainError::ArithmeticOverflow)
    }
}

impl From<&PokerRules> for PokerRules {
    fn from(rules: &PokerRules) -> Self {
        *rules
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
