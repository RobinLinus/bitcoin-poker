//! Serde-owned WebAssembly boundary for the two-party BP52 origin.
//!
//! JavaScript copies one bounded JSON DTO into linear memory and selects an
//! operation. Rust performs all schema validation, canonical hex decoding,
//! package reconstruction, artifact binding, and signature verification. The
//! resulting JSON is presentation metadata only: Bitcoin transactions and
//! signature digests are always constructed by [`poker_funding`].
//!
//! This module is deliberately stateless across operations. Every signing or
//! assembly request independently reconstructs the origin and revalidates all
//! durable artifacts supplied by the browser coordinator. Private keys never
//! enter this module; the separate wallet Wasm boundary signs only a digest
//! authorized here.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", allow(unsafe_code))]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod dto;
mod engine;

use std::sync::Mutex;

use dto::OriginCommandInput;
#[cfg(target_arch = "wasm32")]
use dto::{NonceCommitmentControlDto, SessionNonceControlDto};
use engine::Operation;
use serde::de::DeserializeOwned;

const ABI_VERSION: u32 = 2;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ERROR_BYTES: usize = 2 * 1024;

static MODULE: Mutex<ModuleState> = Mutex::new(ModuleState::new());

struct ModuleState {
    input: Vec<u8>,
    output: Vec<u8>,
    error: Vec<u8>,
}

impl ModuleState {
    const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            error: Vec::new(),
        }
    }

    fn fail(&mut self, code: i32, message: impl AsRef<str>) -> i32 {
        self.output.clear();
        self.error.clear();
        self.error.extend_from_slice(message.as_ref().as_bytes());
        self.error.truncate(MAX_ERROR_BYTES);
        code
    }

    fn succeed(&mut self, output: Vec<u8>) -> i32 {
        if output.is_empty() || output.len() > MAX_OUTPUT_BYTES {
            return self.fail(5, "origin result exceeds its fixed Wasm boundary");
        }
        self.output = output;
        self.error.clear();
        0
    }

    fn clear(&mut self) {
        self.input.fill(0);
        self.input.clear();
        self.output.clear();
        self.error.clear();
    }
}

fn with_module(operation: impl FnOnce(&mut ModuleState) -> i32) -> i32 {
    match MODULE.lock() {
        Ok(mut state) => operation(&mut state),
        Err(_) => -127,
    }
}

fn execute_serde<T: DeserializeOwned>(
    label: &str,
    operation: impl FnOnce(&T) -> Result<Vec<u8>, String>,
) -> i32 {
    with_module(|state| {
        state.error.clear();
        state.output.clear();
        let mut input = std::mem::take(&mut state.input);
        let request = serde_json::from_slice(&input);
        input.fill(0);
        let request: T = match request {
            Ok(request) => request,
            Err(error) => return state.fail(3, format!("invalid {label}: {error}")),
        };
        match operation(&request) {
            Ok(output) => state.succeed(output),
            Err(error) => state.fail(4, error),
        }
    })
}

fn execute_origin(operation: Operation) -> i32 {
    execute_serde::<OriginCommandInput>("origin request", |request| {
        engine::execute(operation, request)
    })
}

#[cfg(target_arch = "wasm32")]
mod wasm_exports {
    use super::*;

    /// Return the origin JSON ABI version.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_abi_version() -> u32 {
        ABI_VERSION
    }

    /// Return the largest accepted request region.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_max_input_len() -> u32 {
        u32::try_from(MAX_INPUT_BYTES).unwrap_or(0)
    }

    /// Return the largest result region.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_max_output_len() -> u32 {
        u32::try_from(MAX_OUTPUT_BYTES).unwrap_or(0)
    }

    /// Return the largest diagnostic region.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_max_error_len() -> u32 {
        u32::try_from(MAX_ERROR_BYTES).unwrap_or(0)
    }

    /// Allocate the bounded request region and clear previous results.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_begin_input(length: u32) -> i32 {
        with_module(|state| {
            state.clear();
            let Ok(length) = usize::try_from(length) else {
                return state.fail(2, "origin request length overflow");
            };
            if length == 0 || length > MAX_INPUT_BYTES {
                return state.fail(2, "origin request is empty or exceeds 65,536 bytes");
            }
            state.input.resize(length, 0);
            0
        })
    }

    /// Return the staged request pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_input_ptr() -> u32 {
        match MODULE.lock() {
            Ok(mut state) => u32::try_from(state.input.as_mut_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Validate wallet/chain observations and emit one opaque staging frame.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_build_staging_frame() -> i32 {
        execute_origin(Operation::BuildStagingFrame)
    }

    /// Construct and project the canonical origin package.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_build() -> i32 {
        execute_origin(Operation::BuildPackage)
    }

    /// Authorize the exact local refund digest for wallet signing.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_authorize_refund_signature() -> i32 {
        execute_origin(Operation::AuthorizeRefundSignature)
    }

    /// Validate and seal the wallet's local refund signature as an opaque frame.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_seal_refund_signature() -> i32 {
        execute_origin(Operation::SealRefundSignature)
    }

    /// Verify both shares and assemble the canonical refund transaction.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_assemble_refund() -> i32 {
        execute_origin(Operation::AssembleRefund)
    }

    /// Construct and project the root-bound activation transaction.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_build_activation() -> i32 {
        execute_origin(Operation::BuildActivation)
    }

    /// Authorize the exact local activation digest for wallet signing.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_authorize_activation_signature() -> i32 {
        execute_origin(Operation::AuthorizeActivationSignature)
    }

    /// Validate and seal the wallet's activation signature as an opaque frame.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_seal_activation_signature() -> i32 {
        execute_origin(Operation::SealActivationSignature)
    }

    /// Verify both shares and assemble the canonical activation transaction.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_assemble_activation() -> i32 {
        execute_origin(Operation::AssembleActivation)
    }

    /// Revalidate all protected artifacts before authorizing funding signing.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_authorize_funding_signature() -> i32 {
        execute_origin(Operation::AuthorizeFundingSignature)
    }

    /// Validate and seal the wallet's funding signature as an opaque frame.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_seal_funding_signature() -> i32 {
        execute_origin(Operation::SealFundingSignature)
    }

    /// Revalidate protected artifacts and assemble canonical funding.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_assemble_funding() -> i32 {
        execute_origin(Operation::AssembleFunding)
    }

    /// Commit to one context-bound session-nonce share.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_commit_session_nonce_share() -> i32 {
        execute_serde::<NonceCommitmentControlDto>("nonce commitment request", |request| {
            engine::nonce_commitment(request)
        })
    }

    /// Derive the common session nonce from canonically ordered shares.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_derive_session_nonce() -> i32 {
        execute_serde::<SessionNonceControlDto>("session nonce request", |request| {
            engine::session_nonce(request)
        })
    }

    /// Return the current result pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_output_ptr() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.output.as_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Return the current result length.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_output_len() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.output.len()).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }

    /// Return the latest bounded diagnostic pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_last_error_ptr() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.error.as_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Return the latest bounded diagnostic length.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_last_error_len() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.error.len()).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }

    /// Clear every transient request, result, and diagnostic byte.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_origin_clear() {
        if let Ok(mut state) = MODULE.lock() {
            state.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_operation_consumes_its_input() {
        assert_ne!(execute_origin(Operation::BuildPackage), 0);
        let state = MODULE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.input.is_empty());
        assert!(state.output.is_empty());
        assert!(!state.error.is_empty());
    }
}
