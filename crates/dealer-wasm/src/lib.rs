// `no_mangle` is an unsafe attribute in Rust 2024. This boundary uses it only
// to expose one C-ABI symbol; the crate contains no unsafe block or operation.
//! Dealer WebAssembly bindings with separate live-participant and benchmark modules.

#[cfg(target_arch = "wasm32")]
fn reject_ambient_randomness(_: &mut [u8]) -> Result<(), getrandom::Error> {
    // The participant ABI requires caller-supplied CSPRNG entropy and never
    // falls back to ambient randomness inside Wasm.
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(reject_ambient_randomness);

mod benchmark;
#[cfg(target_arch = "wasm32")]
mod participant;
pub use benchmark::dealer_benchmark;
