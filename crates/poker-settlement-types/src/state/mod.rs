//! Fixed-limit amount and betting states.

use crate::{ChainError, PokerRules, roles::Role};

/// Fixed-limit betting street.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Street {
    /// Forced blinds and first betting round.
    Preflop = 0,
    /// Three-card community street.
    Flop = 1,
    /// Fourth community card.
    Turn = 2,
    /// Fifth community card.
    River = 3,
}

impl Street {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the following street, or `None` after the river.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Preflop => Some(Self::Flop),
            Self::Flop => Some(Self::Turn),
            Self::Turn => Some(Self::River),
            Self::River => None,
        }
    }

    /// Returns the fixed number of small-blind units in one bet increment.
    #[must_use]
    pub const fn increment_units(self) -> u64 {
        match self {
            Self::Preflop | Self::Flop => 2,
            Self::Turn | Self::River => 4,
        }
    }

    /// Computes the exact bet increment for this street.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::ArithmeticOverflow`] if multiplication overflows.
    pub fn increment(self, unit_sat: u64) -> Result<u64, ChainError> {
        unit_sat
            .checked_mul(self.increment_units())
            .ok_or(ChainError::ArithmeticOverflow)
    }

    /// Returns the fixed deal slots revealed on this community street.
    #[must_use]
    pub const fn community_slots(self) -> &'static [u8] {
        match self {
            Self::Preflop => &[],
            Self::Flop => &[4, 5, 6],
            Self::Turn => &[7],
            Self::River => &[8],
        }
    }
}

/// Fixed three-bit betting action code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Action {
    /// Surrender the current pot.
    Fold = 0b000,
    /// Pass when no wager is outstanding.
    Check = 0b001,
    /// Match the exact outstanding wager.
    Call = 0b010,
    /// Open an unbet postflop street, capped by the effective stack.
    Bet = 0b011,
    /// Increase the wager by one street increment or a final short all-in.
    Raise = 0b100,
}

impl Action {
    /// Returns the exact three-bit action code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Complete fixed-limit decision state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BettingState {
    /// Current betting street.
    pub street: Street,
    /// Player responsible for the next action.
    pub actor: Role,
    /// Alice's contribution during this street.
    pub alice_committed_this_street: u64,
    /// Bob's contribution during this street.
    pub bob_committed_this_street: u64,
    /// Largest effective street contribution either player must match.
    pub current_wager: u64,
    /// Nominal opening-bet/raise level reached, in `0..=4`.
    ///
    /// A final effective-stack-capped wager may be smaller than
    /// `street.increment(unit) * bets_used`.
    pub bets_used: u8,
    /// Number of immediately preceding postflop checks, in `0..=1`.
    pub consecutive_checks: u8,
    /// Whether the big blind may check or raise after the small blind calls.
    pub big_blind_option_pending: bool,
    /// Complete stack, pot, and fee-reserve accounting.
    pub amounts: AmountState,
}

impl BettingState {
    /// Posts forced blinds and constructs the first preflop decision.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic or insufficient-stack error on malformed
    /// rules amounts.
    pub fn initial_preflop(rules: impl Into<PokerRules>) -> Result<Self, ChainError> {
        let rules = &rules.into();
        if rules.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        let small_blind = rules.unit_sat;
        let big_blind = rules
            .unit_sat
            .checked_mul(2)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let amounts = AmountState::funded(rules)
            .commit_to_pot(rules.button, small_blind)?
            .commit_to_pot(rules.nonbutton(), big_blind)?;
        let (alice_committed_this_street, bob_committed_this_street) = match rules.button {
            Role::Alice => (small_blind, big_blind),
            Role::Bob => (big_blind, small_blind),
        };
        let state = Self {
            street: Street::Preflop,
            actor: rules.button,
            alice_committed_this_street,
            bob_committed_this_street,
            current_wager: big_blind,
            bets_used: 1,
            consecutive_checks: 0,
            big_blind_option_pending: false,
            amounts,
        };
        state.validate(rules)?;
        Ok(state)
    }

    /// Starts one postflop street with the nonbutton acting first.
    ///
    /// # Errors
    ///
    /// Rejects `Preflop`, which must be created by [`Self::initial_preflop`].
    pub fn start_postflop(
        street: Street,
        rules: impl Into<PokerRules>,
        amounts: AmountState,
    ) -> Result<Self, ChainError> {
        let rules = &rules.into();
        if rules.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        if street == Street::Preflop {
            return Err(ChainError::InvalidBettingState {
                reason: "postflop initializer cannot create preflop",
            });
        }
        if amounts.alice_remaining == 0 || amounts.bob_remaining == 0 {
            return Err(ChainError::InvalidBettingState {
                reason: "postflop betting cannot start after an all-in",
            });
        }
        let state = Self {
            street,
            actor: rules.nonbutton(),
            alice_committed_this_street: 0,
            bob_committed_this_street: 0,
            current_wager: 0,
            bets_used: 0,
            consecutive_checks: 0,
            big_blind_option_pending: false,
            amounts,
        };
        state.validate(rules)?;
        Ok(state)
    }

    /// Returns one player's current-street contribution.
    #[must_use]
    pub const fn committed(self, role: Role) -> u64 {
        match role {
            Role::Alice => self.alice_committed_this_street,
            Role::Bob => self.bob_committed_this_street,
        }
    }

    /// Computes the exact amount the active player must call.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::InvalidBettingState`] if the actor contribution
    /// exceeds the current wager.
    pub fn to_call(self) -> Result<u64, ChainError> {
        self.current_wager
            .checked_sub(self.committed(self.actor))
            .ok_or(ChainError::InvalidBettingState {
                reason: "actor commitment exceeds current wager",
            })
    }

    /// Validates the fixed-limit shape against its rules.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::InvalidBettingState`] or an arithmetic error.
    pub fn validate(self, rules: impl Into<PokerRules>) -> Result<(), ChainError> {
        let rules = &rules.into();
        if rules.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        if self.bets_used > rules.max_bets_per_street {
            return Err(invalid_state("bets_used exceeds rules cap"));
        }
        if self.consecutive_checks > 1 {
            return Err(invalid_state("consecutive_checks exceeds one"));
        }
        if self.alice_committed_this_street > self.current_wager
            || self.bob_committed_this_street > self.current_wager
        {
            return Err(invalid_state("street commitment exceeds current wager"));
        }
        let increment = self.street.increment(rules.unit_sat)?;
        let nominal_wager = increment
            .checked_mul(u64::from(self.bets_used))
            .ok_or(ChainError::ArithmeticOverflow)?;
        if self.bets_used == 0
            && (self.current_wager != 0
                || self.alice_committed_this_street != 0
                || self.bob_committed_this_street != 0)
        {
            return Err(invalid_state("unopened street has a nonzero wager"));
        }
        if self.bets_used == 0 && self.street == Street::Preflop {
            return Err(invalid_state("preflop cannot be an unopened street"));
        }
        if self.bets_used > 0 {
            let prior_wager = increment
                .checked_mul(u64::from(self.bets_used - 1))
                .ok_or(ChainError::ArithmeticOverflow)?;
            if self.current_wager <= prior_wager || self.current_wager > nominal_wager {
                return Err(invalid_state("current wager disagrees with bets_used"));
            }
        }

        let capacities = self.validate_amounts(rules)?;
        let to_call = self.to_call()?;
        self.validate_decision_shape(rules, increment, nominal_wager, capacities, to_call)?;
        self.amounts.game_value()?;
        Ok(())
    }

    /// Returns the exact legal-action set in canonical action-code order.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or completed state rather than inventing an edge.
    pub fn legal_actions(self, rules: impl Into<PokerRules>) -> Result<Vec<Action>, ChainError> {
        let rules = &rules.into();
        self.validate(rules)?;
        let to_call = self.to_call()?;
        if to_call > 0 {
            let mut actions = vec![Action::Fold, Action::Call];
            if self.bets_used < rules.max_bets_per_street
                && self.aggression_target(rules, true)? > self.current_wager
            {
                actions.push(Action::Raise);
            }
            return Ok(actions);
        }
        if self.big_blind_option_pending {
            let mut actions = vec![Action::Check];
            if self.bets_used < rules.max_bets_per_street
                && self.aggression_target(rules, true)? > self.current_wager
            {
                actions.push(Action::Raise);
            }
            return Ok(actions);
        }
        if self.street != Street::Preflop && self.bets_used == 0 {
            let mut actions = vec![Action::Check];
            if self.aggression_target(rules, false)? > 0 {
                actions.push(Action::Bet);
            }
            return Ok(actions);
        }
        Err(invalid_state(
            "state has no semantically valid zero-call action",
        ))
    }

    /// Applies one exact fixed-limit poker action, excluding the edge fee.
    ///
    /// The transaction compiler must deduct its fixed fee from the returned
    /// amount state with [`AmountState::charge_fee`].
    ///
    /// # Errors
    ///
    /// Rejects illegal labels, malformed states, and arithmetic failures.
    pub fn apply_action(
        self,
        rules: impl Into<PokerRules>,
        action: Action,
    ) -> Result<BettingTransition, ChainError> {
        let rules = &rules.into();
        if !self.legal_actions(rules)?.contains(&action) {
            return Err(ChainError::IllegalAction { action });
        }
        match action {
            Action::Fold => Ok(BettingTransition::Fold {
                folded: self.actor,
                winner: self.actor.other(),
                amounts: self.amounts,
            }),
            Action::Check => Ok(self.apply_check()),
            Action::Call => self.apply_call(rules),
            Action::Bet => self.apply_aggression(rules, false),
            Action::Raise => self.apply_aggression(rules, true),
        }
    }

    fn apply_check(self) -> BettingTransition {
        if self.big_blind_option_pending || self.consecutive_checks == 1 {
            return BettingTransition::StreetComplete {
                street: self.street,
                amounts: self.amounts,
            };
        }
        let mut next = self;
        next.actor = self.actor.other();
        next.consecutive_checks = 1;
        BettingTransition::Continue(next)
    }

    fn apply_call(self, rules: impl Into<PokerRules>) -> Result<BettingTransition, ChainError> {
        let rules = &rules.into();
        let to_call = self.to_call()?;
        let amounts = self.amounts.commit_to_pot(self.actor, to_call)?;
        let mut next = self;
        next.amounts = amounts;
        next.set_committed(self.actor, self.current_wager);

        let small_blind_call = self.street == Street::Preflop
            && self.actor == rules.button
            && self.bets_used == 1
            && !self.big_blind_option_pending
            && self.committed(self.actor) == rules.unit_sat;
        if small_blind_call {
            if amounts.alice_remaining == 0 || amounts.bob_remaining == 0 {
                Ok(BettingTransition::StreetComplete {
                    street: self.street,
                    amounts,
                })
            } else {
                next.actor = rules.nonbutton();
                next.big_blind_option_pending = true;
                next.consecutive_checks = 0;
                next.validate(rules)?;
                Ok(BettingTransition::Continue(next))
            }
        } else {
            Ok(BettingTransition::StreetComplete {
                street: self.street,
                amounts,
            })
        }
    }

    fn apply_aggression(
        self,
        rules: impl Into<PokerRules>,
        is_raise: bool,
    ) -> Result<BettingTransition, ChainError> {
        let rules = &rules.into();
        let new_wager = self.aggression_target(rules, is_raise)?;
        let transfer = new_wager
            .checked_sub(self.committed(self.actor))
            .ok_or(ChainError::ArithmeticUnderflow)?;
        let mut next = self;
        next.amounts = self.amounts.commit_to_pot(self.actor, transfer)?;
        next.set_committed(self.actor, new_wager);
        next.current_wager = new_wager;
        next.bets_used = self
            .bets_used
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        next.consecutive_checks = 0;
        next.big_blind_option_pending = false;
        next.actor = self.actor.other();
        next.validate(rules)?;
        Ok(BettingTransition::Continue(next))
    }

    fn street_capacity(self, role: Role) -> Result<u64, ChainError> {
        self.committed(role)
            .checked_add(self.amounts.remaining(role))
            .ok_or(ChainError::ArithmeticOverflow)
    }

    fn validate_amounts(self, rules: impl Into<PokerRules>) -> Result<[u64; 2], ChainError> {
        let rules = &rules.into();
        let capacities = [
            self.street_capacity(Role::Alice)?,
            self.street_capacity(Role::Bob)?,
        ];
        if capacities[0] > rules.alice_starting_stack_sat
            || capacities[1] > rules.bob_starting_stack_sat
        {
            return Err(invalid_state("street capacity exceeds starting stack"));
        }
        let alice_prior = rules
            .alice_starting_stack_sat
            .checked_sub(capacities[0])
            .ok_or(ChainError::ArithmeticUnderflow)?;
        let bob_prior = rules
            .bob_starting_stack_sat
            .checked_sub(capacities[1])
            .ok_or(ChainError::ArithmeticUnderflow)?;
        if alice_prior != bob_prior {
            return Err(invalid_state("prior-street contributions are unequal"));
        }
        let street_committed = self
            .alice_committed_this_street
            .checked_add(self.bob_committed_this_street)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if street_committed > self.amounts.pot {
            return Err(invalid_state("street commitments exceed pot"));
        }
        let expected_poker_value = rules
            .alice_starting_stack_sat
            .checked_add(rules.bob_starting_stack_sat)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let actual_poker_value = self
            .amounts
            .alice_remaining
            .checked_add(self.amounts.bob_remaining)
            .and_then(|value| value.checked_add(self.amounts.pot))
            .ok_or(ChainError::ArithmeticOverflow)?;
        if actual_poker_value != expected_poker_value {
            return Err(invalid_state("poker value disagrees with rules"));
        }
        if self.amounts.fee_reserve_remaining > rules.fee_reserve_sat {
            return Err(invalid_state("fee reserve exceeds rules"));
        }
        if self.current_wager > capacities[0] || self.current_wager > capacities[1] {
            return Err(invalid_state("current wager exceeds effective stack"));
        }
        Ok(capacities)
    }

    fn validate_decision_shape(
        self,
        rules: impl Into<PokerRules>,
        increment: u64,
        nominal_wager: u64,
        capacities: [u64; 2],
        to_call: u64,
    ) -> Result<(), ChainError> {
        let rules = &rules.into();
        if to_call > 0 {
            if self.committed(self.actor.other()) != self.current_wager {
                return Err(invalid_state("aggressor did not commit the current wager"));
            }
            if self.consecutive_checks != 0 || self.big_blind_option_pending {
                return Err(invalid_state("outstanding wager has incompatible flags"));
            }
        } else if !self.big_blind_option_pending && self.bets_used > 0 {
            return Err(invalid_state("completed wager is not a betting state"));
        }
        if self.current_wager < nominal_wager
            && (to_call == 0
                || self.current_wager != capacities[0] && self.current_wager != capacities[1])
        {
            return Err(invalid_state("short wager is not effective-stack capped"));
        }
        if to_call == 0 && (self.amounts.alice_remaining == 0 || self.amounts.bob_remaining == 0) {
            return Err(invalid_state("zero stack has no pending all-in response"));
        }
        if self.consecutive_checks > 0
            && (self.street == Street::Preflop
                || self.bets_used != 0
                || self.current_wager != 0
                || self.big_blind_option_pending)
        {
            return Err(invalid_state("malformed checked state"));
        }
        self.validate_initial_actor(rules, increment)
    }

    fn validate_initial_actor(
        self,
        rules: impl Into<PokerRules>,
        increment: u64,
    ) -> Result<(), ChainError> {
        let rules = &rules.into();
        if self.bets_used == 0 {
            let expected_actor = if self.consecutive_checks == 0 {
                rules.nonbutton()
            } else {
                rules.button
            };
            if self.actor != expected_actor {
                return Err(invalid_state("unopened street has the wrong actor"));
            }
        }
        if self.street == Street::Preflop && self.bets_used == 1 {
            if self.current_wager != increment {
                return Err(invalid_state("preflop blind wager must be complete"));
            }
            if !self.big_blind_option_pending
                && (self.actor != rules.button
                    || self.committed(rules.button) != rules.unit_sat
                    || self.committed(rules.nonbutton()) != increment)
            {
                return Err(invalid_state("malformed initial blind state"));
            }
        }
        if self.big_blind_option_pending
            && (self.street != Street::Preflop
                || self.actor != rules.nonbutton()
                || self.current_wager != increment
                || self.bets_used != 1
                || self.alice_committed_this_street != increment
                || self.bob_committed_this_street != increment)
        {
            return Err(invalid_state("malformed big-blind option"));
        }
        Ok(())
    }

    fn aggression_target(
        self,
        rules: impl Into<PokerRules>,
        is_raise: bool,
    ) -> Result<u64, ChainError> {
        let rules = &rules.into();
        let increment = self.street.increment(rules.unit_sat)?;
        let nominal_target = if is_raise {
            self.current_wager
                .checked_add(increment)
                .ok_or(ChainError::ArithmeticOverflow)?
        } else {
            increment
        };
        Ok(nominal_target
            .min(self.street_capacity(self.actor)?)
            .min(self.street_capacity(self.actor.other())?))
    }

    fn set_committed(&mut self, role: Role, value: u64) {
        match role {
            Role::Alice => self.alice_committed_this_street = value,
            Role::Bob => self.bob_committed_this_street = value,
        }
    }
}

/// Result of one legal betting action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BettingTransition {
    /// Another betting decision is required on this street.
    Continue(BettingState),
    /// Betting ended normally and the graph proceeds to reveal/showdown.
    StreetComplete {
        /// Street that just completed.
        street: Street,
        /// Value state after all poker transfers.
        amounts: AmountState,
    },
    /// The active player folded and the other player wins the pot.
    Fold {
        /// Player who folded.
        folded: Role,
        /// Player awarded the pot.
        winner: Role,
        /// Value state at the fold.
        amounts: AmountState,
    },
}

impl BettingTransition {
    /// Returns the amount state carried by this transition.
    #[must_use]
    pub const fn amounts(self) -> AmountState {
        match self {
            Self::Continue(state) => state.amounts,
            Self::StreetComplete { amounts, .. } | Self::Fold { amounts, .. } => amounts,
        }
    }

    /// Deducts the edge's fixed fee from its amount state.
    ///
    /// # Errors
    ///
    /// Returns reserve underflow when the fee cannot be paid.
    pub fn charge_fee(self, fee_sat: u64) -> Result<Self, ChainError> {
        Ok(match self {
            Self::Continue(mut state) => {
                state.amounts = state.amounts.charge_fee(fee_sat)?;
                Self::Continue(state)
            }
            Self::StreetComplete { street, amounts } => Self::StreetComplete {
                street,
                amounts: amounts.charge_fee(fee_sat)?,
            },
            Self::Fold {
                folded,
                winner,
                amounts,
            } => Self::Fold {
                folded,
                winner,
                amounts: amounts.charge_fee(fee_sat)?,
            },
        })
    }
}

const fn invalid_state(reason: &'static str) -> ChainError {
    ChainError::InvalidBettingState { reason }
}

#[cfg(test)]
mod tests;

mod amounts;
pub use amounts::AmountState;

mod timeouts;
pub use timeouts::{TimeoutKind, TimeoutSpec};
