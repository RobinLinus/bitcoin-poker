//! Canonical hole-card and community reveal obligations.

use bp52_chain_bitcoin::RevealPattern;
use bp52_chain_types::{
    ChainError, ChainGameDescriptor, Phase, Role, Street, TimeoutKind, TimeoutSpec,
};

/// One reveal obligation in the exact protocol order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevealStep {
    /// Phase represented by the state output being spent.
    pub phase: Phase,
    /// Slots and revealer bound by the consensus predicate.
    pub pattern: RevealPattern,
    /// Unilateral settlement if the revealer misses the deadline.
    pub timeout: TimeoutSpec,
}

impl RevealStep {
    /// Construct and validate one reveal step from a descriptor.
    ///
    /// # Errors
    ///
    /// Rejects a zero reveal timeout through [`TimeoutSpec::new`].
    pub fn new(
        descriptor: &ChainGameDescriptor,
        phase: Phase,
        pattern: RevealPattern,
    ) -> Result<Self, ChainError> {
        let revealer = pattern.revealer();
        Ok(Self {
            phase,
            pattern,
            timeout: TimeoutSpec::new(
                TimeoutKind::Reveal,
                descriptor.reveal_csv,
                revealer,
                revealer.other(),
            )?,
        })
    }
}

/// Return the two fixed hole-card reveal obligations.
///
/// Bob first reveals his shares for Alice's slots `0,2`; Alice then reveals
/// her shares for Bob's slots `1,3`.
///
/// # Errors
///
/// Rejects an invalid descriptor reveal timeout.
pub fn hole_reveal_steps(descriptor: &ChainGameDescriptor) -> Result<[RevealStep; 2], ChainError> {
    Ok([
        RevealStep::new(descriptor, Phase::DealAlice, RevealPattern::DealAlice)?,
        RevealStep::new(descriptor, Phase::DealBob, RevealPattern::DealBob)?,
    ])
}

/// Return the two ordered reveal obligations for one community street.
///
/// # Errors
///
/// Rejects preflop (which has no community cards), a missing reveal order, or
/// an invalid descriptor reveal timeout.
pub fn community_reveal_steps(
    descriptor: &ChainGameDescriptor,
    street: Street,
) -> Result<[RevealStep; 2], ChainError> {
    let first =
        descriptor
            .reveal_order
            .first_for(street)
            .ok_or(ChainError::InvalidLogicalRecord {
                reason: "preflop has no community reveal phase",
            })?;
    let (first_phase, second_phase) = match street {
        Street::Preflop => {
            return Err(ChainError::InvalidLogicalRecord {
                reason: "preflop has no community reveal phase",
            });
        }
        Street::Flop => (Phase::FlopRevealFirst, Phase::FlopRevealSecond),
        Street::Turn => (Phase::TurnRevealFirst, Phase::TurnRevealSecond),
        Street::River => (Phase::RiverRevealFirst, Phase::RiverRevealSecond),
    };
    let pattern = |role: Role| match street {
        Street::Preflop | Street::Flop => RevealPattern::Flop(role),
        Street::Turn => RevealPattern::Turn(role),
        Street::River => RevealPattern::River(role),
    };
    Ok([
        RevealStep::new(descriptor, first_phase, pattern(first))?,
        RevealStep::new(descriptor, second_phase, pattern(first.other()))?,
    ])
}

#[cfg(test)]
mod tests {
    use bp52_chain_bitcoin::RevealPattern;
    use bp52_chain_types::{Phase, Role, Street};

    use super::community_reveal_steps;
    use crate::test_support::descriptor_fixture;

    #[test]
    fn community_order_is_descriptor_bound_and_nonrepeating()
    -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = descriptor_fixture()?;
        let flop = community_reveal_steps(&descriptor, Street::Flop)?;
        assert_eq!(flop[0].phase, Phase::FlopRevealFirst);
        assert_eq!(flop[1].phase, Phase::FlopRevealSecond);
        assert_eq!(flop[0].pattern, RevealPattern::Flop(Role::Bob));
        assert_eq!(flop[1].pattern, RevealPattern::Flop(Role::Alice));
        assert_eq!(flop[0].timeout.defaulting, Role::Bob);
        assert_eq!(flop[1].timeout.defaulting, Role::Alice);
        assert!(community_reveal_steps(&descriptor, Street::Preflop).is_err());
        Ok(())
    }
}
