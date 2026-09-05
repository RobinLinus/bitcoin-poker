//! Deterministic TEST ONLY live participants. Not served to browsers.
#![allow(dead_code)]
use bitcoin::hashes::Hash;
use dealer_protocol::{GameConfig, LiveParticipant, Role};
use k256::schnorr::SigningKey;
use std::error::Error;

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub fn try_array<T, const N: usize>(f: impl FnMut(usize) -> TestResult<T>) -> TestResult<[T; N]> {
    (0..N)
        .map(f)
        .collect::<TestResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| "wrong fixture array length".into())
}

pub fn participants() -> TestResult<([LiveParticipant; 2], [[u8; 32]; 2])> {
    participants_with_context([2; 32], [4; 32])
}

#[allow(
    clippy::large_stack_arrays,
    reason = "Fixture arrays and indices are bounded by the fixed nine-card protocol."
)]
pub fn participants_with_context(
    anchor: [u8; 32],
    rules_hash: [u8; 32],
) -> TestResult<([LiveParticipant; 2], [[u8; 32]; 2])> {
    let mut identities = [[3; 32], [5; 32]];
    identities.sort_by_key(|key| {
        SigningKey::from_bytes(key)
            .map(|s| s.verifying_key().to_bytes())
            .ok()
    });
    let config = GameConfig {
        network_genesis: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .block_hash()
            .to_byte_array(),
        session_anchor: anchor,
        identity_a: SigningKey::from_bytes(&identities[0])?
            .verifying_key()
            .to_bytes()
            .into(),
        identity_b: SigningKey::from_bytes(&identities[1])?
            .verifying_key()
            .to_bytes()
            .into(),
        session_nonce: [3; 32],
        rules_hash,
    };
    let mut a = LiveParticipant::new(config.clone(), Role::A, identities[0], [0x51; 32])?;
    let mut b = LiveParticipant::new(config, Role::B, identities[1], [0x62; 32])?;
    for _ in 0..500 {
        if a.snapshot().accepted && b.snapshot().accepted {
            break;
        }
        if a.snapshot().retry_required && b.snapshot().retry_required {
            let next = a.snapshot().attempt + 1;
            a.start_retry(next)?;
            b.start_retry(next)?;
        }
        let outgoing_a = a.prepare_outgoing()?;
        let outgoing_b = b.prepare_outgoing()?;
        if let Some(bytes) = &outgoing_a {
            a.confirm_persisted_outgoing(bytes)?;
        }
        if let Some(bytes) = &outgoing_b {
            b.confirm_persisted_outgoing(bytes)?;
        }
        if let Some(bytes) = &outgoing_a {
            b.accept_peer(bytes)?;
        }
        if let Some(bytes) = &outgoing_b {
            a.accept_peer(bytes)?;
        }
    }
    assert!(a.snapshot().accepted && b.snapshot().accepted);
    assert_eq!(a.certificate()?, b.certificate()?);
    dealer_protocol::verify_setup_certificate(a.certificate()?)?;
    Ok(([a, b], identities))
}
