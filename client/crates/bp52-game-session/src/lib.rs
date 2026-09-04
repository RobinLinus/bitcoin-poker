//! Backend-neutral, event-sourced BP52 game-session coordination.
//!
//! The coordinator performs no network, wallet, clock, or storage I/O. It
//! accepts authenticated protocol artifacts and chain facts, validates them
//! through the DEAL and CHAIN implementations, and returns explicit intents
//! for an application adapter to satisfy.

#![forbid(unsafe_code)]

mod codec;
mod event;
mod policy;
mod state;

pub use event::{
    ChainSpend, ConfirmedOrigin, EventRecord, MAX_EVENT_ARTIFACT_BYTES, SessionEvent, TipFact,
};
pub use policy::{EventSource, SessionPhase};
pub use state::{
    ApplyResult, BroadcastPurpose, DescriptorTerms, EdgeIntent, GameSession,
    ORIGIN_WITNESS_SCRIPT_BYTES, SessionConfig, SessionError, SessionIntent, SessionStatus,
    TableBalances,
};
