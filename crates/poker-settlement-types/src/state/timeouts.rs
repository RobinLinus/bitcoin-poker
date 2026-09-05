//! Timeouts and validation.
use super::{ChainError, PokerRules, Role};

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
    /// Timeout class used to select the rules CSV.
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

    /// Selects the rules delay for this timeout class.
    #[must_use]
    pub fn delay_for(kind: TimeoutKind, rules: impl Into<PokerRules>) -> u16 {
        let rules = &rules.into();
        match kind {
            TimeoutKind::Action => rules.action_csv,
            TimeoutKind::Reveal => rules.reveal_csv,
            TimeoutKind::Showdown => rules.showdown_csv,
        }
    }
}
