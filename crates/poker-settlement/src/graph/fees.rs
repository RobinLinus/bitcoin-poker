//! Fees.

use super::{ChainError, CompilerError, PlannedNode, PlannedState, PokerRules};

pub(super) fn exact_maximum_path_fee(
    rules: impl Into<PokerRules>,
    nodes: &[PlannedNode],
) -> Result<u64, CompilerError> {
    let rules = &rules.into();
    nodes
        .iter()
        .filter_map(|node| match node.state {
            PlannedState::Terminal(terminal) => Some(terminal.amounts.fee_reserve_remaining),
            _ => None,
        })
        .try_fold(0_u64, |maximum, remaining| {
            let consumed = rules
                .fee_reserve_sat
                .checked_sub(remaining)
                .ok_or(ChainError::ValueNotConserved)?;
            Ok(maximum.max(consumed))
        })
}
