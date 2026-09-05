//! Deterministic local fixed-limit betting-tree expansion.

use bp52_chain_types::{
    Action, BettingState, BettingTransition, ChainError, PokerRules, Role, Street,
};

/// Exact local-node counts for one descriptor-dependent betting subtree.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalBettingCounts {
    /// States at which one player must choose an action.
    pub decisions: usize,
    /// Fold terminal leaves.
    pub folds: usize,
    /// Normal street-completion leaves.
    pub continuations: usize,
    /// One timeout leaf per decision.
    pub timeouts: usize,
}

/// A fully expanded local betting tree whose continuations are placeholders
/// for the next reveal or showdown phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BettingTree {
    /// One action decision with canonical-code-ordered children.
    Decision {
        /// Exact state being authorized.
        state: BettingState,
        /// Timeout beneficiary if the actor fails to act.
        timeout_beneficiary: Role,
        /// One edge for every and only legal action.
        actions: Vec<BettingActionEdge>,
    },
    /// Actor folded and the named player wins.
    Fold {
        /// Player who folded.
        folded: Role,
        /// Player who receives the pot.
        winner: Role,
        /// State after poker transfers and before the edge fee.
        amounts: bp52_chain_types::AmountState,
    },
    /// Betting completed and compilation continues with the next phase.
    Continuation {
        /// Street that completed.
        street: Street,
        /// State after poker transfers and before the edge fee.
        amounts: bp52_chain_types::AmountState,
    },
}

/// One canonical action edge in a [`BettingTree`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BettingActionEdge {
    /// Three-bit protocol action.
    pub action: Action,
    /// Resulting local subtree or terminal/continuation leaf.
    pub child: Box<BettingTree>,
}

impl BettingTree {
    /// Counts all local nodes by semantic class.
    #[must_use]
    pub fn counts(&self) -> LocalBettingCounts {
        let mut counts = LocalBettingCounts::default();
        self.accumulate_counts(&mut counts);
        counts
    }

    fn accumulate_counts(&self, counts: &mut LocalBettingCounts) {
        match self {
            Self::Decision { actions, .. } => {
                counts.decisions += 1;
                counts.timeouts += 1;
                for edge in actions {
                    edge.child.accumulate_counts(counts);
                }
            }
            Self::Fold { .. } => counts.folds += 1,
            Self::Continuation { .. } => counts.continuations += 1,
        }
    }
}

/// Expands the exact preflop tree rooted at `state`.
///
/// # Errors
///
/// Rejects a non-preflop or malformed state and propagates checked transition
/// failures.
pub fn expand_preflop(
    descriptor: impl Into<PokerRules>,
    state: BettingState,
) -> Result<BettingTree, ChainError> {
    let descriptor = &descriptor.into();
    if state.street != Street::Preflop {
        return Err(ChainError::InvalidBettingState {
            reason: "preflop expansion requires a preflop state",
        });
    }
    expand(descriptor, state)
}

/// Expands one exact postflop betting tree rooted at `state`.
///
/// # Errors
///
/// Rejects preflop or malformed state and propagates checked transition
/// failures.
pub fn expand_postflop(
    descriptor: impl Into<PokerRules>,
    state: BettingState,
) -> Result<BettingTree, ChainError> {
    let descriptor = &descriptor.into();
    if state.street == Street::Preflop {
        return Err(ChainError::InvalidBettingState {
            reason: "postflop expansion cannot use a preflop state",
        });
    }
    expand(descriptor, state)
}

fn expand(
    descriptor: impl Into<PokerRules>,
    state: BettingState,
) -> Result<BettingTree, ChainError> {
    let descriptor = &descriptor.into();
    let legal = state.legal_actions(descriptor)?;
    let mut actions = Vec::with_capacity(legal.len());
    for action in legal {
        let transition = state.apply_action(descriptor, action)?;
        let child = match transition {
            BettingTransition::Continue(next) => expand(descriptor, next)?,
            BettingTransition::StreetComplete { street, amounts } => {
                BettingTree::Continuation { street, amounts }
            }
            BettingTransition::Fold {
                folded,
                winner,
                amounts,
            } => BettingTree::Fold {
                folded,
                winner,
                amounts,
            },
        };
        actions.push(BettingActionEdge {
            action,
            child: Box::new(child),
        });
    }
    actions.sort_unstable_by_key(|edge| edge.action.code());
    if actions
        .windows(2)
        .any(|pair| pair[0].action == pair[1].action)
    {
        return Err(ChainError::InvalidLogicalRecord {
            reason: "duplicate betting action edge",
        });
    }
    Ok(BettingTree::Decision {
        state,
        timeout_beneficiary: state.actor.other(),
        actions,
    })
}

#[cfg(test)]
mod tests {
    use bp52_chain_types::{AmountState, BettingState, Street};

    use super::{LocalBettingCounts, expand_postflop, expand_preflop};
    use crate::test_support::descriptor_fixture;

    #[test]
    fn exact_local_betting_counts_match_the_v1_recurrence() -> Result<(), Box<dyn std::error::Error>>
    {
        let descriptor = descriptor_fixture()?;
        let preflop = expand_preflop(&descriptor, BettingState::initial_preflop(&descriptor)?)?;
        assert_eq!(
            preflop.counts(),
            LocalBettingCounts {
                decisions: 8,
                folds: 7,
                continuations: 7,
                timeouts: 8,
            }
        );

        for street in [Street::Flop, Street::Turn, Street::River] {
            let state = BettingState::start_postflop(
                street,
                &descriptor,
                AmountState::funded(&descriptor),
            )?;
            assert_eq!(
                expand_postflop(&descriptor, state)?.counts(),
                LocalBettingCounts {
                    decisions: 10,
                    folds: 8,
                    continuations: 9,
                    timeouts: 10,
                }
            );
        }
        Ok(())
    }
}
