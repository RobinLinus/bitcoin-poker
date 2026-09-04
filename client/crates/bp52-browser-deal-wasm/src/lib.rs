//! Web Worker-owned BP52-DEAL-v1 participant runtime.
//!
//! The raw ABI accepts one strict Serde initialization control object plus
//! separately staged secret key and entropy regions. Subsequent protocol
//! artifacts remain opaque canonical bytes. JavaScript only performs bounded
//! memory copies and never owns the initialization layout or lifecycle tags.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", allow(unsafe_code))]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod dto;
mod engine;
mod rng;
mod state;
#[cfg(test)]
mod tests;
#[cfg(target_arch = "wasm32")]
mod wasm_exports;

pub(crate) const ABI_VERSION: u32 = 5;
pub(crate) const MAX_INPUT_LEN: usize = bp52_protocol::messages::MAX_ENVELOPE_SIZE;
pub(crate) const MAX_OUTPUT_LEN: usize = bp52_protocol::messages::MAX_ENVELOPE_SIZE;
pub(crate) const MAX_ERROR_LEN: usize = 1_024;
pub(crate) const SECRET_LEN: usize = 32;
pub(crate) const RNG_TAG: &[u8] = b"BP52/browser-deal-worker-rng/v1";
pub(crate) const RNG_REKEY_TAG: &[u8] = b"BP52/browser-deal-worker-rng/rekey/v1";

#[cfg(all(
    target_arch = "wasm32",
    feature = "raw-worker-entropy",
    feature = "wasm-bindgen-entropy"
))]
compile_error!("select only one browser entropy integration");
#[cfg(all(
    target_arch = "wasm32",
    not(any(feature = "raw-worker-entropy", feature = "wasm-bindgen-entropy"))
))]
compile_error!("select a browser entropy integration");
