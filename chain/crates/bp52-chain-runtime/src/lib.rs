//! Runtime witness construction and chain monitoring for `BP52-CHAIN-v1`.
//!
//! The compiler's [`bp52_chain_compiler::CompiledGraph`] implements the narrow
//! [`ChainBackend`] view used here. Everything above that boundary rechecks the
//! exact node, edge, transaction, and predicate association before consuming a
//! secret or requesting a live signature.

#![forbid(unsafe_code)]

mod backend;
mod broadcast;
mod builders;
mod compiled_graph;
mod error;
mod monitor;
mod preimages;
mod witness;

pub use backend::{
    BitcoinSigner, ChainBackend, PreparedTransaction, SignerError, ValidatedEdge,
    apply_offchain_witness, attach_offchain_witness, attach_timeout_witness, attach_witness,
    validate_exact_edge,
};
pub use broadcast::{BroadcastError, Broadcaster, broadcast_non_mainnet};
pub use builders::{
    build_action_witness, build_advance_witness, build_alice_showdown_witness,
    build_bob_payout_witness, build_reveal_witness, build_selected_action_witness,
    build_selected_alice_showdown_witness, build_selected_bob_payout_witness,
    build_selected_reveal_witness, build_timeout_witness, sign_selected_action,
};
pub use compiled_graph::{AuthorizedGraph, PreauthorizationSource};
pub use error::RuntimeError;
pub use monitor::{
    ChainMonitor, ConfirmedActiveNode, MatureTimeout, MonitorState, SecretEraser, TimeoutMaturity,
    erase_lamport_key,
};
pub use preimages::{
    InsertStatus, MAX_PUBLIC_PREIMAGES, PublicPreimageStore, SecretPreimageSource,
};
pub use witness::{MAX_ENCODED_WITNESS_BYTES, Witness};
