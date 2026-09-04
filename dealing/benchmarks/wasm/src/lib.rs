//! Raw-Wasm performance spike for the production BP52 hash-length circuit.
//!
//! The default deterministic entropy source is benchmark instrumentation and
//! is cryptographically unsafe. Browser applications must build with
//! `--no-default-features --features browser-entropy` instead.

use std::sync::{Mutex, OnceLock};

use bp52_circuit::hash_length::{
    AGGREGATED_SLOTS, HashLengthParameters, MESSAGE_BUFFER_BYTES, prove_hash_lengths,
    verify_hash_lengths, witness_buffer,
};
use bp52_group::{ProtocolGenerators, commit};
use bp52_proof_backend::{Scalar, Transcript};
#[cfg(feature = "benchmark-custom-rng")]
use getrandom::{Error as RandomError, register_custom_getrandom};
use sha2::{Digest, Sha256};

#[cfg(all(feature = "benchmark-custom-rng", feature = "browser-entropy"))]
compile_error!("benchmark-custom-rng and browser-entropy are mutually exclusive");
#[cfg(not(any(feature = "benchmark-custom-rng", feature = "browser-entropy")))]
compile_error!("select exactly one entropy feature");

static PARAMETERS: OnceLock<HashLengthParameters> = OnceLock::new();
static PROOF: Mutex<Option<Vec<u8>>> = Mutex::new(None);

#[cfg(feature = "benchmark-custom-rng")]
fn deterministic_random(destination: &mut [u8]) -> Result<(), RandomError> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for byte in destination {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state.to_le_bytes()[0];
    }
    Ok(())
}

#[cfg(feature = "benchmark-custom-rng")]
register_custom_getrandom!(deterministic_random);

struct Fixture {
    hashes: [[u8; 32]; AGGREGATED_SLOTS],
    commitments: [[u8; 32]; AGGREGATED_SLOTS],
    values: [u8; AGGREGATED_SLOTS],
    blindings: [Scalar; AGGREGATED_SLOTS],
    buffers: [[u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS],
}

fn fixture() -> Result<Fixture, ()> {
    let generators = ProtocolGenerators::derive().map_err(|_| ())?;
    let values = [0_u8, 7, 15, 23, 31, 39, 40, 47, 51];
    let blindings = std::array::from_fn(|index| Scalar::from(index as u64 + 101));
    let mut hashes = [[0_u8; 32]; AGGREGATED_SLOTS];
    let mut commitments = [[0_u8; 32]; AGGREGATED_SLOTS];
    let mut buffers = [[0_u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS];
    for index in 0..AGGREGATED_SLOTS {
        let length = 16 + usize::from(values[index]);
        let preimage = vec![u8::try_from(index).map_err(|_| ())?; length];
        hashes[index] = Sha256::digest(&preimage).into();
        let buffer = witness_buffer(&preimage).map_err(|_| ())?;
        buffers[index].copy_from_slice(buffer.as_array());
        commitments[index] = commit(
            Scalar::from(u64::from(values[index])),
            blindings[index],
            &generators,
        )
        .compress()
        .to_bytes();
    }
    Ok(Fixture {
        hashes,
        commitments,
        values,
        blindings,
        buffers,
    })
}

fn transcript(circuit_id: [u8; 32]) -> Transcript {
    let mut transcript = Transcript::new(b"BP52/bench/hash-length/v1");
    transcript.append_message(b"circuit-id", &circuit_id);
    transcript
}

/// Initializes the 65,536-point-per-vector Bulletproof parameters.
///
/// Returns zero on success and a stable nonzero diagnostic code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn setup_parameters() -> i32 {
    if PARAMETERS.get().is_some() {
        return 0;
    }
    let Ok(parameters) = HashLengthParameters::new() else {
        return 1;
    };
    if PARAMETERS.set(parameters).is_err() {
        return 1;
    }
    0
}

/// Generates one proof for the same fixture as the native hash-length bench.
///
/// Returns zero on success and a stable nonzero diagnostic code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn prove_once() -> i32 {
    let Some(parameters) = PARAMETERS.get() else {
        return 2;
    };
    let Ok(fixture) = fixture() else {
        return 3;
    };
    let Ok(proof) = prove_hash_lengths(
        parameters,
        transcript(parameters.circuit_id()),
        &fixture.hashes,
        &fixture.commitments,
        &fixture.values,
        &fixture.blindings,
        &fixture.buffers,
    ) else {
        return 4;
    };
    let Ok(mut slot) = PROOF.lock() else {
        return 5;
    };
    *slot = Some(proof);
    0
}

/// Verifies the proof retained by [`prove_once`].
///
/// Returns zero on success and a stable nonzero diagnostic code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn verify_once() -> i32 {
    let Some(parameters) = PARAMETERS.get() else {
        return 2;
    };
    let Ok(fixture) = fixture() else {
        return 3;
    };
    let Ok(slot) = PROOF.lock() else {
        return 5;
    };
    let Some(proof) = slot.as_ref() else {
        return 6;
    };
    if verify_hash_lengths(
        parameters,
        transcript(parameters.circuit_id()),
        &fixture.hashes,
        &fixture.commitments,
        proof,
    )
    .is_err()
    {
        return 7;
    }
    0
}
