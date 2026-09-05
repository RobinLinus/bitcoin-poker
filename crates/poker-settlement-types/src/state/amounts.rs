//! Amounts and validation.
use super::{ChainError, PokerRules, Role};

/// Complete value accounting carried by every logical state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AmountState {
    /// Alice's uncommitted poker stack.
    pub alice_remaining: u64,
    /// Bob's uncommitted poker stack.
    pub bob_remaining: u64,
    /// Chips committed by either player and awarded at settlement.
    pub pot: u64,
    /// Fee reserve not yet consumed by fixed transaction fees.
    pub fee_reserve_remaining: u64,
}

impl AmountState {
    /// Creates the pre-blind funding amount state.
    #[must_use]
    pub fn funded(rules: impl Into<PokerRules>) -> Self {
        let rules = &rules.into();
        Self {
            alice_remaining: rules.alice_starting_stack_sat,
            bob_remaining: rules.bob_starting_stack_sat,
            pot: 0,
            fee_reserve_remaining: rules.fee_reserve_sat,
        }
    }

    /// Returns one player's remaining stack.
    #[must_use]
    pub const fn remaining(self, role: Role) -> u64 {
        match role {
            Role::Alice => self.alice_remaining,
            Role::Bob => self.bob_remaining,
        }
    }

    /// Computes the exact tracked game value.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ArithmeticOverflow`] if the state is not
    /// representable as one `u64` total.
    pub fn game_value(self) -> Result<u64, ChainError> {
        self.alice_remaining
            .checked_add(self.bob_remaining)
            .and_then(|value| value.checked_add(self.pot))
            .and_then(|value| value.checked_add(self.fee_reserve_remaining))
            .ok_or(ChainError::ArithmeticOverflow)
    }

    /// Moves an exact amount from one stack into the pot.
    ///
    /// # Errors
    ///
    /// Rejects stack underflow or pot overflow. The returned state conserves
    /// [`Self::game_value`].
    pub fn commit_to_pot(mut self, role: Role, amount: u64) -> Result<Self, ChainError> {
        let available = self.remaining(role);
        if available < amount {
            return Err(ChainError::InsufficientStack {
                role,
                available,
                required: amount,
            });
        }
        match role {
            Role::Alice => {
                self.alice_remaining = self
                    .alice_remaining
                    .checked_sub(amount)
                    .ok_or(ChainError::ArithmeticUnderflow)?;
            }
            Role::Bob => {
                self.bob_remaining = self
                    .bob_remaining
                    .checked_sub(amount)
                    .ok_or(ChainError::ArithmeticUnderflow)?;
            }
        }
        self.pot = self
            .pot
            .checked_add(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(self)
    }

    /// Deducts one fixed transaction fee from the dedicated reserve.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ArithmeticUnderflow`] if the reserve cannot cover
    /// the fee.
    pub fn charge_fee(mut self, fee_sat: u64) -> Result<Self, ChainError> {
        self.fee_reserve_remaining = self
            .fee_reserve_remaining
            .checked_sub(fee_sat)
            .ok_or(ChainError::ArithmeticUnderflow)?;
        Ok(self)
    }

    /// Confirms that `next` conserves value except for `fee_sat`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ValueNotConserved`] on disagreement or an
    /// arithmetic error for an unrepresentable state.
    pub fn verify_transition(self, next: Self, fee_sat: u64) -> Result<(), ChainError> {
        let expected = self
            .game_value()?
            .checked_sub(fee_sat)
            .ok_or(ChainError::ArithmeticUnderflow)?;
        if next.game_value()? == expected {
            Ok(())
        } else {
            Err(ChainError::ValueNotConserved)
        }
    }
}
