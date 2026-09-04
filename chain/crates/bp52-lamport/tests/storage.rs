//! Encrypted-at-rest tests for Lamport secret owners.

#![forbid(unsafe_code)]

use bp52_lamport::{
    KeyContext, LamportPurpose, LamportStorageKey, Score24, SealedLamportSecretKey,
    SecretStorageError, generate_key, sign_alice_score, verify_alice_score,
};
use rand_core::{CryptoRng, Error as RngError, RngCore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct TestRng(u64);

impl TestRng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let bytes = self.next_u64().to_le_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

struct ConstantRng(u8);

impl RngCore for ConstantRng {
    fn next_u32(&mut self) -> u32 {
        u32::from(self.0).wrapping_mul(0x0101_0101)
    }

    fn next_u64(&mut self) -> u64 {
        u64::from(self.0).wrapping_mul(0x0101_0101_0101_0101)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(self.0);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for ConstantRng {}

struct FailingRng;

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(0);
    }

    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::from(std::num::NonZeroU32::MIN))
    }
}

impl CryptoRng for FailingRng {}

fn context(game: u8, node: u8) -> KeyContext {
    KeyContext::new([game; 32], [node; 32], LamportPurpose::AliceScore24Bit)
}

#[test]
fn seal_erases_only_after_success_and_open_reconstructs_exact_key() -> TestResult {
    let key_context = context(1, 2);
    let mut key_rng = TestRng::new(11);
    let (mut secret, public) = generate_key(&mut key_rng, key_context)?;
    let mut storage_key = LamportStorageKey::from_bytes([0x35; 32]);
    let mut nonce_rng = TestRng::new(12);

    let sealed = secret.seal_at_rest(&public, &mut storage_key, &mut nonce_rng)?;
    assert!(secret.is_erased());
    assert!(!format!("{sealed:?}").contains("35"));
    assert_eq!(
        format!("{storage_key:?}"),
        "LamportStorageKey { key_material: \"<redacted>\", .. }"
    );
    sealed.verify(&public, &storage_key)?;

    let persisted = sealed.into_bytes();
    let decoded = SealedLamportSecretKey::from_bytes(&persisted)?;
    let mut opened = decoded.open(&public, &storage_key)?;
    let score = Score24::new(0x12_3456)?;
    let signature = sign_alice_score(&mut opened, score)?;
    verify_alice_score(
        &public,
        key_context.chain_game_id,
        key_context.node_id,
        score,
        &signature,
    )?;
    Ok(())
}

#[test]
fn validation_and_rng_failures_leave_live_secret_usable() -> TestResult {
    let key_context = context(3, 4);
    let mut key_rng = TestRng::new(21);
    let (mut secret, public) = generate_key(&mut key_rng, key_context)?;
    let (_, wrong_public) = generate_key(&mut TestRng::new(22), key_context)?;
    let mut storage_key = LamportStorageKey::from_bytes([0x44; 32]);

    assert!(matches!(
        secret.seal_at_rest(&wrong_public, &mut storage_key, &mut TestRng::new(23)),
        Err(SecretStorageError::PublicKeyMismatch)
    ));
    assert!(secret.matches_public_key(&public));
    assert!(matches!(
        secret.seal_at_rest(&public, &mut storage_key, &mut FailingRng),
        Err(SecretStorageError::RandomnessUnavailable)
    ));
    assert!(secret.matches_public_key(&public));
    let score = Score24::new(0x23_4567)?;
    let signature = sign_alice_score(&mut secret, score)?;
    verify_alice_score(
        &public,
        key_context.chain_game_id,
        key_context.node_id,
        score,
        &signature,
    )?;
    Ok(())
}

#[test]
fn tampering_wrong_keys_and_wrong_contexts_are_rejected() -> TestResult {
    let key_context = context(5, 6);
    let mut key_rng = TestRng::new(31);
    let (mut secret, public) = generate_key(&mut key_rng, key_context)?;
    let mut storage_key = LamportStorageKey::from_bytes([0x55; 32]);
    let bytes = secret
        .seal_at_rest(&public, &mut storage_key, &mut TestRng::new(32))?
        .into_bytes();

    let wrong_key = LamportStorageKey::from_bytes([0x56; 32]);
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&bytes)?.open(&public, &wrong_key),
        Err(SecretStorageError::AuthenticationFailed)
    ));

    let (_, wrong_context_public) = generate_key(&mut TestRng::new(33), context(5, 7))?;
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&bytes)?.open(&wrong_context_public, &storage_key),
        Err(SecretStorageError::ContextMismatch)
    ));

    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&tampered)?.open(&public, &storage_key),
        Err(SecretStorageError::AuthenticationFailed)
    ));

    let mut nonce_tampered = bytes;
    nonce_tampered[76] ^= 1;
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&nonce_tampered)?.open(&public, &storage_key),
        Err(SecretStorageError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn canonical_envelope_rejects_versions_lengths_and_trailing_data() -> TestResult {
    let key_context = context(7, 8);
    let (mut secret, public) = generate_key(&mut TestRng::new(41), key_context)?;
    let mut storage_key = LamportStorageKey::from_bytes([0x65; 32]);
    let bytes = secret
        .seal_at_rest(&public, &mut storage_key, &mut TestRng::new(42))?
        .into_bytes();

    let mut bad_version = bytes.clone();
    bad_version[8] = 2;
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&bad_version),
        Err(SecretStorageError::UnsupportedVersion(2))
    ));

    let mut bad_length = bytes.clone();
    bad_length[100] ^= 1;
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&bad_length),
        Err(SecretStorageError::InvalidCiphertextLength { .. })
    ));
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&bytes[..bytes.len() - 1]),
        Err(SecretStorageError::TruncatedEnvelope)
    ));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        SealedLamportSecretKey::from_bytes(&trailing),
        Err(SecretStorageError::TrailingData)
    ));
    Ok(())
}

#[test]
fn repeated_nonce_is_refused_and_second_secret_remains_live() -> TestResult {
    let (mut first_secret, first_public) = generate_key(&mut TestRng::new(51), context(9, 10))?;
    let (mut second_secret, second_public) = generate_key(&mut TestRng::new(52), context(9, 11))?;
    let mut storage_key = LamportStorageKey::from_bytes([0x75; 32]);
    let mut repeated_nonce = ConstantRng(0x88);

    first_secret.seal_at_rest(&first_public, &mut storage_key, &mut repeated_nonce)?;
    assert!(matches!(
        second_secret.seal_at_rest(&second_public, &mut storage_key, &mut repeated_nonce),
        Err(SecretStorageError::NonceReuse)
    ));
    assert!(second_secret.matches_public_key(&second_public));
    Ok(())
}
