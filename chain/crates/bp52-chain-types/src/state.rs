//! Fixed-limit amount and betting states.

use crate::{ChainError, PokerRules, descriptor::Role};

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

/// Relative-timeout class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum TimeoutKind {
    /// Active player failed to select a betting action.
    Action = 0,
    /// Designated revealer failed to publish committed preimages.
    Reveal = 1,
    /// Designated player failed to complete a showdown obligation.
    Showdown = 2,
}

impl TimeoutKind {
    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Node-specific relative timeout and its economic roles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimeoutSpec {
    /// Timeout class used to select the descriptor CSV.
    pub kind: TimeoutKind,
    /// Relative block delay encoded by the spending input.
    pub csv: u16,
    /// Player who failed to satisfy the obligation.
    pub defaulting: Role,
    /// Other player who may exercise the timeout.
    pub beneficiary: Role,
}

impl TimeoutSpec {
    /// Constructs and validates one timeout record.
    ///
    /// # Errors
    ///
    /// Rejects a zero delay or equal defaulting/beneficiary roles.
    pub fn new(
        kind: TimeoutKind,
        csv: u16,
        defaulting: Role,
        beneficiary: Role,
    ) -> Result<Self, ChainError> {
        let timeout = Self {
            kind,
            csv,
            defaulting,
            beneficiary,
        };
        timeout.validate()?;
        Ok(timeout)
    }

    /// Validates a timeout record constructed or decoded by another layer.
    ///
    /// # Errors
    ///
    /// Rejects a zero delay or equal defaulting/beneficiary roles.
    pub fn validate(self) -> Result<(), ChainError> {
        if self.csv == 0 {
            return Err(ChainError::ZeroTimeout { kind: self.kind });
        }
        if self.defaulting == self.beneficiary {
            return Err(ChainError::InvalidLogicalRecord {
                reason: "timeout beneficiary must be the nondefaulting role",
            });
        }
        Ok(())
    }

    /// Selects the descriptor delay for this timeout class.
    #[must_use]
    pub fn descriptor_csv(kind: TimeoutKind, descriptor: impl Into<PokerRules>) -> u16 {
        let descriptor = &descriptor.into();
        match kind {
            TimeoutKind::Action => descriptor.action_csv,
            TimeoutKind::Reveal => descriptor.reveal_csv,
            TimeoutKind::Showdown => descriptor.showdown_csv,
        }
    }
}

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
    pub fn funded(descriptor: impl Into<PokerRules>) -> Self {
        let descriptor = &descriptor.into();
        Self {
            alice_remaining: descriptor.alice_starting_stack_sat,
            bob_remaining: descriptor.bob_starting_stack_sat,
            pot: 0,
            fee_reserve_remaining: descriptor.fee_reserve_sat,
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
    /// descriptor amounts.
    pub fn initial_preflop(descriptor: impl Into<PokerRules>) -> Result<Self, ChainError> {
        let descriptor = &descriptor.into();
        if descriptor.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        let small_blind = descriptor.unit_sat;
        let big_blind = descriptor
            .unit_sat
            .checked_mul(2)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let amounts = AmountState::funded(descriptor)
            .commit_to_pot(descriptor.button, small_blind)?
            .commit_to_pot(descriptor.nonbutton(), big_blind)?;
        let (alice_committed_this_street, bob_committed_this_street) = match descriptor.button {
            Role::Alice => (small_blind, big_blind),
            Role::Bob => (big_blind, small_blind),
        };
        let state = Self {
            street: Street::Preflop,
            actor: descriptor.button,
            alice_committed_this_street,
            bob_committed_this_street,
            current_wager: big_blind,
            bets_used: 1,
            consecutive_checks: 0,
            big_blind_option_pending: false,
            amounts,
        };
        state.validate(descriptor)?;
        Ok(state)
    }

    /// Starts one postflop street with the nonbutton acting first.
    ///
    /// # Errors
    ///
    /// Rejects `Preflop`, which must be created by [`Self::initial_preflop`].
    pub fn start_postflop(
        street: Street,
        descriptor: impl Into<PokerRules>,
        amounts: AmountState,
    ) -> Result<Self, ChainError> {
        let descriptor = &descriptor.into();
        if descriptor.unit_sat == 0 {
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
            actor: descriptor.nonbutton(),
            alice_committed_this_street: 0,
            bob_committed_this_street: 0,
            current_wager: 0,
            bets_used: 0,
            consecutive_checks: 0,
            big_blind_option_pending: false,
            amounts,
        };
        state.validate(descriptor)?;
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

    /// Validates the fixed-limit shape against its descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::InvalidBettingState`] or an arithmetic error.
    pub fn validate(self, descriptor: impl Into<PokerRules>) -> Result<(), ChainError> {
        let descriptor = &descriptor.into();
        if descriptor.unit_sat == 0 {
            return Err(ChainError::ZeroUnit);
        }
        if self.bets_used > descriptor.max_bets_per_street {
            return Err(invalid_state("bets_used exceeds descriptor cap"));
        }
        if self.consecutive_checks > 1 {
            return Err(invalid_state("consecutive_checks exceeds one"));
        }
        if self.alice_committed_this_street > self.current_wager
            || self.bob_committed_this_street > self.current_wager
        {
            return Err(invalid_state("street commitment exceeds current wager"));
        }
        let increment = self.street.increment(descriptor.unit_sat)?;
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

        let capacities = self.validate_amounts(descriptor)?;
        let to_call = self.to_call()?;
        self.validate_decision_shape(descriptor, increment, nominal_wager, capacities, to_call)?;
        self.amounts.game_value()?;
        Ok(())
    }

    /// Returns the exact legal-action set in canonical action-code order.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or completed state rather than inventing an edge.
    pub fn legal_actions(
        self,
        descriptor: impl Into<PokerRules>,
    ) -> Result<Vec<Action>, ChainError> {
        let descriptor = &descriptor.into();
        self.validate(descriptor)?;
        let to_call = self.to_call()?;
        if to_call > 0 {
            let mut actions = vec![Action::Fold, Action::Call];
            if self.bets_used < descriptor.max_bets_per_street
                && self.aggression_target(descriptor, true)? > self.current_wager
            {
                actions.push(Action::Raise);
            }
            return Ok(actions);
        }
        if self.big_blind_option_pending {
            let mut actions = vec![Action::Check];
            if self.bets_used < descriptor.max_bets_per_street
                && self.aggression_target(descriptor, true)? > self.current_wager
            {
                actions.push(Action::Raise);
            }
            return Ok(actions);
        }
        if self.street != Street::Preflop && self.bets_used == 0 {
            let mut actions = vec![Action::Check];
            if self.aggression_target(descriptor, false)? > 0 {
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
        descriptor: impl Into<PokerRules>,
        action: Action,
    ) -> Result<BettingTransition, ChainError> {
        let descriptor = &descriptor.into();
        if !self.legal_actions(descriptor)?.contains(&action) {
            return Err(ChainError::IllegalAction { action });
        }
        match action {
            Action::Fold => Ok(BettingTransition::Fold {
                folded: self.actor,
                winner: self.actor.other(),
                amounts: self.amounts,
            }),
            Action::Check => Ok(self.apply_check()),
            Action::Call => self.apply_call(descriptor),
            Action::Bet => self.apply_aggression(descriptor, false),
            Action::Raise => self.apply_aggression(descriptor, true),
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

    fn apply_call(
        self,
        descriptor: impl Into<PokerRules>,
    ) -> Result<BettingTransition, ChainError> {
        let descriptor = &descriptor.into();
        let to_call = self.to_call()?;
        let amounts = self.amounts.commit_to_pot(self.actor, to_call)?;
        let mut next = self;
        next.amounts = amounts;
        next.set_committed(self.actor, self.current_wager);

        let small_blind_call = self.street == Street::Preflop
            && self.actor == descriptor.button
            && self.bets_used == 1
            && !self.big_blind_option_pending
            && self.committed(self.actor) == descriptor.unit_sat;
        if small_blind_call {
            if amounts.alice_remaining == 0 || amounts.bob_remaining == 0 {
                Ok(BettingTransition::StreetComplete {
                    street: self.street,
                    amounts,
                })
            } else {
                next.actor = descriptor.nonbutton();
                next.big_blind_option_pending = true;
                next.consecutive_checks = 0;
                next.validate(descriptor)?;
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
        descriptor: impl Into<PokerRules>,
        is_raise: bool,
    ) -> Result<BettingTransition, ChainError> {
        let descriptor = &descriptor.into();
        let new_wager = self.aggression_target(descriptor, is_raise)?;
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
        next.validate(descriptor)?;
        Ok(BettingTransition::Continue(next))
    }

    fn street_capacity(self, role: Role) -> Result<u64, ChainError> {
        self.committed(role)
            .checked_add(self.amounts.remaining(role))
            .ok_or(ChainError::ArithmeticOverflow)
    }

    fn validate_amounts(self, descriptor: impl Into<PokerRules>) -> Result<[u64; 2], ChainError> {
        let descriptor = &descriptor.into();
        let capacities = [
            self.street_capacity(Role::Alice)?,
            self.street_capacity(Role::Bob)?,
        ];
        if capacities[0] > descriptor.alice_starting_stack_sat
            || capacities[1] > descriptor.bob_starting_stack_sat
        {
            return Err(invalid_state("street capacity exceeds starting stack"));
        }
        let alice_prior = descriptor
            .alice_starting_stack_sat
            .checked_sub(capacities[0])
            .ok_or(ChainError::ArithmeticUnderflow)?;
        let bob_prior = descriptor
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
        let expected_poker_value = descriptor
            .alice_starting_stack_sat
            .checked_add(descriptor.bob_starting_stack_sat)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let actual_poker_value = self
            .amounts
            .alice_remaining
            .checked_add(self.amounts.bob_remaining)
            .and_then(|value| value.checked_add(self.amounts.pot))
            .ok_or(ChainError::ArithmeticOverflow)?;
        if actual_poker_value != expected_poker_value {
            return Err(invalid_state("poker value disagrees with descriptor"));
        }
        if self.amounts.fee_reserve_remaining > descriptor.fee_reserve_sat {
            return Err(invalid_state("fee reserve exceeds descriptor"));
        }
        if self.current_wager > capacities[0] || self.current_wager > capacities[1] {
            return Err(invalid_state("current wager exceeds effective stack"));
        }
        Ok(capacities)
    }

    fn validate_decision_shape(
        self,
        descriptor: impl Into<PokerRules>,
        increment: u64,
        nominal_wager: u64,
        capacities: [u64; 2],
        to_call: u64,
    ) -> Result<(), ChainError> {
        let descriptor = &descriptor.into();
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
        self.validate_initial_actor(descriptor, increment)
    }

    fn validate_initial_actor(
        self,
        descriptor: impl Into<PokerRules>,
        increment: u64,
    ) -> Result<(), ChainError> {
        let descriptor = &descriptor.into();
        if self.bets_used == 0 {
            let expected_actor = if self.consecutive_checks == 0 {
                descriptor.nonbutton()
            } else {
                descriptor.button
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
                && (self.actor != descriptor.button
                    || self.committed(descriptor.button) != descriptor.unit_sat
                    || self.committed(descriptor.nonbutton()) != increment)
            {
                return Err(invalid_state("malformed initial blind state"));
            }
        }
        if self.big_blind_option_pending
            && (self.street != Street::Preflop
                || self.actor != descriptor.nonbutton()
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
        descriptor: impl Into<PokerRules>,
        is_raise: bool,
    ) -> Result<u64, ChainError> {
        let descriptor = &descriptor.into();
        let increment = self.street.increment(descriptor.unit_sat)?;
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
mod tests {
    use std::error::Error;

    use super::{Action, AmountState, BettingState, BettingTransition, Street};
    use crate::{ChainError, PokerRules, RevealOrder, Role, TimeoutSettlementPolicy};

    fn descriptor(alice_stack: u64, bob_stack: u64, button: Role) -> PokerRules {
        PokerRules {
            button,
            unit_sat: 100,
            max_bets_per_street: crate::MAX_BETS_PER_STREET,
            alice_starting_stack_sat: alice_stack,
            bob_starting_stack_sat: bob_stack,
            fee_reserve_sat: 10_000,
            action_csv: 1,
            reveal_csv: 1,
            showdown_csv: 1,
            reveal_order: RevealOrder {
                flop_first: Role::Alice,
                turn_first: Role::Bob,
                river_first: Role::Alice,
            },
            timeout_policy: TimeoutSettlementPolicy::PotOnly,
            split_remainder_recipient: Role::Alice,
        }
    }

    fn assert_tree_conserves_value(
        descriptor: &PokerRules,
        state: BettingState,
        depth: usize,
    ) -> Result<(), ChainError> {
        assert!(depth <= 8, "fixed-limit decision tree did not terminate");
        state.validate(descriptor)?;
        let actions = state.legal_actions(descriptor)?;
        assert!(!actions.is_empty());
        for action in actions {
            let transition = state.apply_action(descriptor, action)?;
            state.amounts.verify_transition(transition.amounts(), 0)?;
            if let BettingTransition::Continue(next) = transition {
                assert_tree_conserves_value(descriptor, next, depth + 1)?;
            }
        }
        Ok(())
    }

    #[test]
    fn minimum_stacks_post_full_blinds_and_skip_big_blind_option() -> Result<(), Box<dyn Error>> {
        for (alice_stack, bob_stack) in [(200, 200), (500, 200), (200, 500)] {
            let descriptor = descriptor(alice_stack, bob_stack, Role::Alice);
            let initial = BettingState::initial_preflop(&descriptor)?;
            assert_eq!(initial.amounts.pot, 300);
            assert_eq!(
                initial.legal_actions(&descriptor)?,
                vec![Action::Fold, Action::Call]
            );

            let BettingTransition::StreetComplete { street, amounts } =
                initial.apply_action(&descriptor, Action::Call)?
            else {
                return Err("an all-in blind call exposed the big-blind option".into());
            };
            assert_eq!(street, Street::Preflop);
            assert_eq!(amounts.pot, 400);
            assert!(amounts.alice_remaining == 0 || amounts.bob_remaining == 0);
            initial.amounts.verify_transition(amounts, 0)?;
        }
        Ok(())
    }

    #[test]
    fn bet_is_capped_by_opponents_effective_stack_without_unmatched_chips()
    -> Result<(), Box<dyn Error>> {
        let descriptor = descriptor(250, 1_000, Role::Alice);
        let before = AmountState {
            alice_remaining: 150,
            bob_remaining: 900,
            pot: 200,
            fee_reserve_remaining: descriptor.fee_reserve_sat,
        };
        let state = BettingState::start_postflop(Street::Flop, &descriptor, before)?;
        let BettingTransition::Continue(response) = state.apply_action(&descriptor, Action::Bet)?
        else {
            return Err("bet did not expose an all-in response".into());
        };
        assert_eq!(response.current_wager, 150);
        assert_eq!(response.bob_committed_this_street, 150);
        assert_eq!(response.amounts.bob_remaining, 750);
        assert_eq!(
            response.legal_actions(&descriptor)?,
            vec![Action::Fold, Action::Call]
        );
        before.verify_transition(response.amounts, 0)?;

        let BettingTransition::StreetComplete { amounts, .. } =
            response.apply_action(&descriptor, Action::Call)?
        else {
            return Err("effective-stack call did not complete the street".into());
        };
        assert_eq!(amounts.alice_remaining, 0);
        assert_eq!(amounts.bob_remaining, 750);
        assert_eq!(amounts.pot, 500);
        assert_eq!(response.committed(Role::Bob), 150);
        response.amounts.verify_transition(amounts, 0)?;
        Ok(())
    }

    #[test]
    fn bettor_can_commit_own_short_stack_without_exposing_a_raise() -> Result<(), Box<dyn Error>> {
        let descriptor = descriptor(1_000, 500, Role::Alice);
        let before = AmountState {
            alice_remaining: 575,
            bob_remaining: 75,
            pot: 850,
            fee_reserve_remaining: descriptor.fee_reserve_sat,
        };
        let state = BettingState::start_postflop(Street::Turn, &descriptor, before)?;
        let BettingTransition::Continue(response) = state.apply_action(&descriptor, Action::Bet)?
        else {
            return Err("short-stack bet did not expose a response".into());
        };
        assert_eq!(response.current_wager, 75);
        assert_eq!(response.amounts.bob_remaining, 0);
        assert_eq!(
            response.legal_actions(&descriptor)?,
            vec![Action::Fold, Action::Call]
        );

        let BettingTransition::StreetComplete { amounts, .. } =
            response.apply_action(&descriptor, Action::Call)?
        else {
            return Err("call of short-stack bet did not complete the street".into());
        };
        assert_eq!(amounts.alice_remaining, 500);
        assert_eq!(amounts.bob_remaining, 0);
        assert_eq!(amounts.pot, 1_000);
        before.verify_transition(amounts, 0)?;
        Ok(())
    }

    #[test]
    fn short_and_exact_all_in_raises_allow_only_fold_or_call() -> Result<(), Box<dyn Error>> {
        for (alice_stack, expected_wager) in [(250, 250), (400, 400)] {
            let descriptor = descriptor(alice_stack, 1_000, Role::Alice);
            let flop = BettingState::start_postflop(
                Street::Flop,
                &descriptor,
                AmountState::funded(&descriptor),
            )?;
            let BettingTransition::Continue(after_bet) =
                flop.apply_action(&descriptor, Action::Bet)?
            else {
                return Err("opening bet completed unexpectedly".into());
            };
            let BettingTransition::Continue(after_raise) =
                after_bet.apply_action(&descriptor, Action::Raise)?
            else {
                return Err("all-in raise completed unexpectedly".into());
            };

            assert_eq!(after_raise.current_wager, expected_wager);
            assert_eq!(after_raise.alice_committed_this_street, expected_wager);
            assert_eq!(after_raise.amounts.alice_remaining, 0);
            assert_eq!(
                after_raise.legal_actions(&descriptor)?,
                vec![Action::Fold, Action::Call]
            );
            assert!(matches!(
                after_raise.apply_action(&descriptor, Action::Raise),
                Err(ChainError::IllegalAction {
                    action: Action::Raise
                })
            ));

            let to_call = expected_wager - 200;
            let before_call = after_raise.amounts;
            let BettingTransition::StreetComplete { amounts, .. } =
                after_raise.apply_action(&descriptor, Action::Call)?
            else {
                return Err("all-in raise call did not complete the street".into());
            };
            assert_eq!(amounts.bob_remaining, 800 - to_call);
            assert_eq!(amounts.pot, expected_wager * 2);
            before_call.verify_transition(amounts, 0)?;
        }
        Ok(())
    }

    #[test]
    fn malformed_short_or_uncallable_wagers_are_rejected() -> Result<(), Box<dyn Error>> {
        let descriptor = descriptor(250, 1_000, Role::Alice);
        let before = AmountState {
            alice_remaining: 150,
            bob_remaining: 900,
            pot: 200,
            fee_reserve_remaining: descriptor.fee_reserve_sat,
        };
        let flop = BettingState::start_postflop(Street::Flop, &descriptor, before)?;
        let BettingTransition::Continue(valid_short) =
            flop.apply_action(&descriptor, Action::Bet)?
        else {
            return Err("capped bet did not continue".into());
        };

        let mut not_capped = valid_short;
        not_capped.amounts.alice_remaining += 1;
        not_capped.amounts.bob_remaining += 1;
        not_capped.amounts.pot -= 2;
        assert!(matches!(
            not_capped.validate(&descriptor),
            Err(ChainError::InvalidBettingState {
                reason: "short wager is not effective-stack capped"
            })
        ));

        let mut uncallable = valid_short;
        uncallable.amounts.alice_remaining -= 1;
        uncallable.amounts.bob_remaining -= 1;
        uncallable.amounts.pot += 2;
        assert!(matches!(
            uncallable.validate(&descriptor),
            Err(ChainError::InvalidBettingState {
                reason: "current wager exceeds effective stack"
            })
        ));

        let unequal_prior = AmountState {
            alice_remaining: 149,
            bob_remaining: 900,
            pot: 201,
            fee_reserve_remaining: descriptor.fee_reserve_sat,
        };
        assert!(matches!(
            BettingState::start_postflop(Street::Flop, &descriptor, unequal_prior),
            Err(ChainError::InvalidBettingState {
                reason: "prior-street contributions are unequal"
            })
        ));

        let all_in_amounts = AmountState {
            alice_remaining: 0,
            bob_remaining: 850,
            pot: 400,
            fee_reserve_remaining: descriptor.fee_reserve_sat,
        };
        assert!(matches!(
            BettingState::start_postflop(Street::Turn, &descriptor, all_in_amounts),
            Err(ChainError::InvalidBettingState {
                reason: "postflop betting cannot start after an all-in"
            })
        ));
        Ok(())
    }

    #[test]
    fn small_stack_decision_trees_are_finite_valid_and_conservative() -> Result<(), Box<dyn Error>>
    {
        let stack_sizes = [200, 201, 250, 399, 400, 401, 800];
        for button in [Role::Alice, Role::Bob] {
            for alice_stack in stack_sizes {
                for bob_stack in stack_sizes {
                    let descriptor = descriptor(alice_stack, bob_stack, button);
                    assert_tree_conserves_value(
                        &descriptor,
                        BettingState::initial_preflop(&descriptor)?,
                        0,
                    )?;
                    for street in [Street::Flop, Street::Turn, Street::River] {
                        assert_tree_conserves_value(
                            &descriptor,
                            BettingState::start_postflop(
                                street,
                                &descriptor,
                                AmountState::funded(&descriptor),
                            )?,
                            0,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn descriptor_cap_one_retains_real_betting_without_raises() -> Result<(), Box<dyn Error>> {
        let mut descriptor = descriptor(4_566, 4_566, Role::Alice);
        descriptor.max_bets_per_street = 1;

        let small_blind = BettingState::initial_preflop(&descriptor)?;
        assert_eq!(
            small_blind.legal_actions(&descriptor)?,
            vec![Action::Fold, Action::Call]
        );
        let BettingTransition::Continue(big_blind) =
            small_blind.apply_action(&descriptor, Action::Call)?
        else {
            return Err("deep-stack small-blind call completed preflop".into());
        };
        assert_eq!(big_blind.legal_actions(&descriptor)?, vec![Action::Check]);
        assert!(matches!(
            big_blind.apply_action(&descriptor, Action::Check)?,
            BettingTransition::StreetComplete {
                street: Street::Preflop,
                ..
            }
        ));

        let flop = BettingState::start_postflop(
            Street::Flop,
            &descriptor,
            AmountState::funded(&descriptor),
        )?;
        assert_eq!(
            flop.legal_actions(&descriptor)?,
            vec![Action::Check, Action::Bet]
        );
        let BettingTransition::Continue(response) = flop.apply_action(&descriptor, Action::Bet)?
        else {
            return Err("opening flop bet completed the street".into());
        };
        assert_eq!(
            response.legal_actions(&descriptor)?,
            vec![Action::Fold, Action::Call]
        );
        assert!(matches!(
            response.apply_action(&descriptor, Action::Raise),
            Err(ChainError::IllegalAction {
                action: Action::Raise
            })
        ));
        Ok(())
    }
}
