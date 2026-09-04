use bp52_circuit::hash_length::SLOT_HASH_LENGTH_PROOF_SIZE;
use bp52_protocol::{N_SLOTS, Role};
use zeroize::Zeroize;

#[cfg(feature = "raw-worker-entropy")]
use crate::rng::{FALLBACK_RNG, seed_fallback_rng};
use crate::{
    ABI_VERSION, MAX_ERROR_LEN, MAX_INPUT_LEN, MAX_OUTPUT_LEN, SECRET_LEN,
    dto::{DealInit, snapshot_json},
    engine::DealEngine,
    state::{MODULE, with_engine, with_module},
};

/// Returns the raw ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_abi_version() -> u32 {
    ABI_VERSION
}

/// Returns the largest accepted JSON or opaque artifact input.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_max_input_len() -> u32 {
    u32::try_from(MAX_INPUT_LEN).unwrap_or(0)
}

/// Returns the largest opaque or JSON output.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_max_output_len() -> u32 {
    u32::try_from(MAX_OUTPUT_LEN).unwrap_or(0)
}

/// Returns the largest diagnostic output.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_max_error_len() -> u32 {
    u32::try_from(MAX_ERROR_LEN).unwrap_or(0)
}

/// Returns the Rust-owned length of each separately staged secret.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_secret_len() -> u32 {
    u32::try_from(SECRET_LEN).unwrap_or(0)
}

/// Returns the staged local identity-secret pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_local_secret_ptr() -> u32 {
    match MODULE.lock() {
        Ok(mut state) if !state.permanently_cleared => {
            u32::try_from(state.local_secret.as_mut_ptr() as usize).unwrap_or(0)
        }
        Err(_) => 0,
        Ok(_) => 0,
    }
}

/// Returns the staged WebCrypto entropy pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_entropy_ptr() -> u32 {
    match MODULE.lock() {
        Ok(mut state) if !state.permanently_cleared => {
            u32::try_from(state.supplied_entropy.as_mut_ptr() as usize).unwrap_or(0)
        }
        Err(_) => 0,
        Ok(_) => 0,
    }
}

/// Initializes the one DEAL participant owned by this Worker.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_init() -> i32 {
    with_module(|state| {
        state.clear_error();
        if state.permanently_cleared {
            state.clear_staging();
            return state.fail(3, "cleared DEAL workers cannot be reinitialized");
        }
        if state.engine.is_some() {
            state.clear_staging();
            return state.fail(3, "DEAL worker is already initialized");
        }
        let mut control_json = std::mem::take(&mut state.input);
        let local_secret = std::mem::take(&mut state.local_secret);
        let supplied_entropy = std::mem::take(&mut state.supplied_entropy);
        let request = DealInit::decode(&control_json, local_secret, supplied_entropy);
        control_json.zeroize();
        let request = match request {
            Ok(request) => request,
            Err(error) => return state.fail(2, error),
        };
        #[cfg(feature = "raw-worker-entropy")]
        if let Err(error) = seed_fallback_rng(&request) {
            return state.fail(4, error);
        }
        let result = DealEngine::new(request);
        match result {
            Ok(engine) => {
                state.engine = Some(engine);
                0
            }
            Err(error) => state.fail(4, error),
        }
    })
}

/// Reallocates the bounded untrusted input staging buffer.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_begin_input(length: u32) -> i32 {
    with_module(|state| {
        state.clear_error();
        if state.permanently_cleared {
            return state.fail(3, "cleared DEAL workers cannot accept input");
        }
        let Ok(length) = usize::try_from(length) else {
            return state.fail(2, "input length overflow");
        };
        if length > MAX_INPUT_LEN {
            return state.fail(2, "input exceeds the bounded DEAL worker ABI");
        }
        state.input.zeroize();
        state.input = vec![0; length];
        0
    })
}

/// Returns the current bounded input pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_input_ptr() -> u32 {
    match MODULE.lock() {
        Ok(mut state) if !state.permanently_cleared => {
            u32::try_from(state.input.as_mut_ptr() as usize).unwrap_or(0)
        }
        Err(_) => 0,
        Ok(_) => 0,
    }
}

/// Generates, signs, locally verifies, and advances the next local envelope.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_generate_next() -> i32 {
    with_module(|state| with_engine(state, DealEngine::generate_next))
}

/// Precomputes the local private bundle proof once authenticated T6 exists.
///
/// Both participants may call this concurrently before Alice publishes
/// sequence 6. No protocol envelope is emitted or consumed.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_prepare_bundle() -> i32 {
    with_module(|state| with_engine(state, DealEngine::prepare_bundle))
}

/// Produces the ascending slot proofs selected by one nonzero nine-bit mask.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_prepare_bundle_slots(mask: u32) -> i32 {
    with_module(|state| {
        if mask == 0 || mask >= (1_u32 << N_SLOTS) {
            return state.fail(2, "bundle slot mask is invalid");
        }
        let selected = (0..N_SLOTS)
            .filter(|slot| mask & (1_u32 << slot) != 0)
            .collect::<Vec<_>>();
        with_engine(state, |engine| engine.prepare_bundle_slots(&selected))
    })
}

/// Installs exactly nine slot proofs and finishes the local player bundle.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_install_parallel_bundle() -> i32 {
    with_module(|state| {
        state.clear_error();
        if state.input.len() != SLOT_HASH_LENGTH_PROOF_SIZE * N_SLOTS {
            state.input.zeroize();
            state.input.clear();
            return state.fail(2, "parallel bundle has the wrong proof length");
        }
        let proofs = state
            .input
            .chunks_exact(SLOT_HASH_LENGTH_PROOF_SIZE)
            .map(<[u8]>::to_vec)
            .collect();
        state.input.zeroize();
        state.input.clear();
        let result = match state.engine.as_mut() {
            Some(engine) => engine.install_parallel_bundle(proofs),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        match result {
            Ok(()) => 0,
            Err(error) => state.fail(4, error),
        }
    })
}

/// Authenticates and semantically consumes one peer envelope.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_accept_envelope() -> i32 {
    with_module(|state| {
        state.clear_error();
        let input = state.input.clone();
        let result = match state.engine.as_mut() {
            Some(engine) => engine.accept_envelope(&input),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        state.input.zeroize();
        state.input.clear();
        match result {
            Ok(()) => 0,
            Err(error) => state.fail(4, error),
        }
    })
}

/// Replays one durable envelope, regenerating local private state when needed.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_replay_envelope() -> i32 {
    with_module(|state| {
        state.clear_error();
        let input = state.input.clone();
        let result = match state.engine.as_mut() {
            Some(engine) => engine.replay_envelope(&input),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        state.input.zeroize();
        state.input.clear();
        match result {
            Ok(()) => 0,
            Err(error) => state.fail(4, error),
        }
    })
}

/// Starts the exact verifier-authorized retry after coordinator approval.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_start_retry(approved_attempt: u32) -> i32 {
    with_module(|state| {
        state.clear_error();
        let result = match state.engine.as_mut() {
            Some(engine) => engine.start_retry(approved_attempt),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        match result {
            Ok(()) => 0,
            Err(error) => state.fail(4, error),
        }
    })
}

/// Signs the verifier-derived accepted body for the local canonical role.
///
/// Input must be the coordinator's canonical accepted body. The Worker
/// refuses to sign unless it exactly equals its independently derived body.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_make_acceptance_signature() -> i32 {
    with_module(|state| {
        state.clear_error();
        let body = state.input.clone();
        state.input.zeroize();
        state.input.clear();
        let result = match state.engine.as_mut() {
            Some(engine) => engine
                .make_acceptance_signature(&body)
                .map(|signature| signature.to_vec()),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        match result {
            Ok(output) => match state.replace_output(output) {
                Ok(()) => 0,
                Err(error) => state.fail(5, error),
            },
            Err(error) => state.fail(4, error),
        }
    })
}

/// Signs the exact reducer-derived retry digest for the local role.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_make_retry_signature(next_attempt: u32) -> i32 {
    with_module(|state| {
        state.clear_error();
        let digest: [u8; 32] = match state.input.as_slice().try_into() {
            Ok(value) => value,
            Err(_) => return state.fail(2, "retry digest must contain exactly 32 bytes"),
        };
        state.input.zeroize();
        state.input.clear();
        let result = match state.engine.as_mut() {
            Some(engine) => engine
                .make_retry_signature(next_attempt, digest)
                .map(|signature| signature.to_vec()),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        match result {
            Ok(output) => match state.replace_output(output) {
                Ok(()) => 0,
                Err(error) => state.fail(5, error),
            },
            Err(error) => state.fail(4, error),
        }
    })
}

/// Verifies and records the peer's 64-byte accepted-body signature.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_accept_acceptance_signature(role: u32) -> i32 {
    with_module(|state| {
        state.clear_error();
        let Some(role) = u8::try_from(role)
            .ok()
            .and_then(|value| Role::try_from(value).ok())
        else {
            return state.fail(2, "acceptance signature role is invalid");
        };
        let signature: [u8; 64] = match state.input.as_slice().try_into() {
            Ok(signature) => signature,
            Err(_) => {
                return state.fail(2, "acceptance signature must contain exactly 64 bytes");
            }
        };
        state.input.zeroize();
        state.input.clear();
        let result = match state.engine.as_mut() {
            Some(engine) => engine.accept_acceptance_signature(role, signature),
            None => return state.fail(1, "DEAL worker is not initialized"),
        };
        match result {
            Ok(()) => 0,
            Err(error) => state.fail(4, error),
        }
    })
}

/// Selects the verifier-derived accepted body.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_export_accepted_body() -> i32 {
    with_module(|state| with_engine(state, |engine| engine.accepted_body_bytes()))
}

/// Selects the fully signed accepted DEAL certificate.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_export_accepted_deal() -> i32 {
    with_module(|state| with_engine(state, |engine| engine.accepted_deal_bytes()))
}

/// Selects the last local accepted-body signature.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_export_local_acceptance_signature() -> i32 {
    with_module(|state| {
        with_engine(state, |engine| {
            engine
                .local_acceptance_signature
                .map(|signature| signature.to_vec())
                .ok_or_else(|| "local acceptance signature is not available".to_owned())
        })
    })
}

/// Selects the compact identity-signed verification attestation.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_export_verification_attestation() -> i32 {
    with_module(|state| with_engine(state, DealEngine::verification_attestation_bytes))
}

/// Selects the strict Serde lifecycle snapshot.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_snapshot() -> i32 {
    with_module(|state| with_engine(state, |engine| snapshot_json(engine)))
}

/// Explicitly exposes one accepted local share preimage for a CHAIN reveal.
///
/// The Worker keeps all other preimages private. Callers must never route this
/// output through the DEAL/session coordinator.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_reveal_local_preimage(slot: u32) -> i32 {
    with_module(|state| {
        let Ok(slot) = usize::try_from(slot) else {
            return state.fail(2, "preimage slot overflow");
        };
        with_engine(state, |engine| engine.reveal_local_preimage(slot))
    })
}

/// Encrypts the retained local preimages under a caller-owned 32-byte key.
///
/// The selected output is the protocol's canonical XChaCha20-Poly1305
/// sealed-preimage envelope. The raw storage key is erased from staging.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_seal_retained_preimages() -> i32 {
    with_module(|state| {
        state.clear_error();
        let mut key: [u8; 32] = match state.input.as_slice().try_into() {
            Ok(key) => key,
            Err(_) => return state.fail(2, "preimage storage key must contain 32 bytes"),
        };
        state.input.zeroize();
        state.input.clear();
        let Some(engine) = state.engine.as_mut() else {
            key.zeroize();
            return state.fail(1, "DEAL worker is not initialized");
        };
        let result = engine.seal_retained_preimages(&mut key);
        key.zeroize();
        match result {
            Ok(output) => match state.replace_output(output) {
                Ok(()) => 0,
                Err(error) => state.fail(5, error),
            },
            Err(error) => state.fail(4, error),
        }
    })
}

/// Returns the currently selected output length.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_output_len() -> u32 {
    match MODULE.lock() {
        Ok(state) => u32::try_from(state.output.len()).unwrap_or(u32::MAX),
        Err(_) => 0,
    }
}

/// Returns the currently selected output pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_output_ptr() -> u32 {
    match MODULE.lock() {
        Ok(state) => u32::try_from(state.output.as_ptr() as usize).unwrap_or(0),
        Err(_) => 0,
    }
}

/// Erases the currently selected output after its caller has copied it.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_clear_output() {
    if let Ok(mut state) = MODULE.lock() {
        state.output.zeroize();
        state.output.clear();
    }
}

/// Returns the latest bounded diagnostic string length.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_last_error_len() -> u32 {
    match MODULE.lock() {
        Ok(state) => u32::try_from(state.last_error.len()).unwrap_or(u32::MAX),
        Err(_) => 0,
    }
}

/// Returns the latest bounded diagnostic pointer.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_last_error_ptr() -> u32 {
    match MODULE.lock() {
        Ok(state) => u32::try_from(state.last_error.as_ptr() as usize).unwrap_or(0),
        Err(_) => 0,
    }
}

/// Drops and zeroizes all live secret owners. A cleared Worker is one-shot.
#[unsafe(no_mangle)]
pub extern "C" fn bp52_deal_clear() {
    if let Ok(mut state) = MODULE.lock() {
        state.engine.take();
        state.clear_staging();
        state.output.zeroize();
        state.output.clear();
        state.last_error.clear();
        state.permanently_cleared = true;
    }
    #[cfg(feature = "raw-worker-entropy")]
    if let Ok(mut fallback) = FALLBACK_RNG.lock() {
        fallback.take();
    }
}
