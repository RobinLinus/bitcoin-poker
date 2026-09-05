//! Poker economics independent of the accepted-deal cryptography.
use crate::{
    ChainError, ChainGameDescriptor, MAX_BETS_PER_STREET, MIN_STARTING_STACK_UNITS, RevealOrder,
    Role, TimeoutKind, TimeoutSettlementPolicy,
};

/// Complete finite-poker rules, independent of either dealing implementation.
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
    pub fn validate(&self) -> Result<(), ChainError> {
        let descriptor = self;
        if self.timeout_policy != TimeoutSettlementPolicy::PotOnly {
            return Err(ChainError::InvalidLogicalRecord {
                reason: "unsupported timeout policy",
            });
        }
        if descriptor.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        if descriptor.max_bets_per_street == 0
            || descriptor.max_bets_per_street > MAX_BETS_PER_STREET
        {
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
        Ok(())
    }
    /// Player who posts the big blind.
    pub const fn nonbutton(&self) -> Role {
        self.button.other()
    }
    /// Total stack and reserve value.
    pub fn total_locked_value(&self) -> Result<u64, ChainError> {
        self.alice_starting_stack_sat
            .checked_add(self.bob_starting_stack_sat)
            .and_then(|s| s.checked_add(self.fee_reserve_sat))
            .ok_or(ChainError::ArithmeticOverflow)
    }
}
impl From<&ChainGameDescriptor> for PokerRules {
    fn from(d: &ChainGameDescriptor) -> Self {
        Self {
            button: d.button,
            unit_sat: d.unit_sat,
            max_bets_per_street: d.max_bets_per_street,
            alice_starting_stack_sat: d.alice_starting_stack_sat,
            bob_starting_stack_sat: d.bob_starting_stack_sat,
            fee_reserve_sat: d.fee_reserve_sat,
            action_csv: d.action_csv,
            reveal_csv: d.reveal_csv,
            showdown_csv: d.showdown_csv,
            reveal_order: d.reveal_order,
            timeout_policy: d.timeout_policy,
            split_remainder_recipient: d.split_remainder_recipient,
        }
    }
}
impl From<&PokerRules> for PokerRules {
    fn from(rules: &PokerRules) -> Self {
        *rules
    }
}
