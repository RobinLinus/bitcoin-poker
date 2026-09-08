#![forbid(unsafe_code)]
//! Dlog on-chain poker graph compiler and preparation.
/// Fixed-tree channel materialization and revocation protection.
pub mod channel;
pub mod betting;
mod error;
pub mod graph;
pub mod manifest;
pub mod preparation;
mod payout_projection;
pub mod reveals;
pub mod settlement;
pub mod showdown;
#[cfg(test)]
mod test_support;
pub use betting::{
    BettingActionEdge, BettingTree, LocalBettingCounts, expand_postflop, expand_preflop,
};
pub use error::CompilerError;
pub use graph::{
    LogicalGraphPlan, PlannedEdge, PlannedNode, PlannedState, PlannedTerminal,
    REFERENCE_ALICE_LAMPORT_ENTRIES, REFERENCE_BOB_LAMPORT_ENTRIES,
};
pub use manifest::{
    REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT, REFERENCE_TRANSACTION_COUNT,
};

/// Authenticated settlement parameters.
pub mod config;
