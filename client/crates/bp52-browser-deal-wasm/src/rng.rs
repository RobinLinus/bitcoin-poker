use rand_core::{CryptoRng, Error as RandomError, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
use getrandom::register_custom_getrandom;
#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
use std::sync::Mutex;

#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
use crate::dto::DealInit;
use crate::{RNG_REKEY_TAG, RNG_TAG};

#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
pub(crate) static FALLBACK_RNG: Mutex<Option<WorkerRng>> = Mutex::new(None);

#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
fn fallback_getrandom(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    let mut slot = FALLBACK_RNG
        .lock()
        .map_err(|_| getrandom::Error::UNSUPPORTED)?;
    let rng = slot.as_mut().ok_or(getrandom::Error::UNSUPPORTED)?;
    rng.fill_bytes(destination);
    Ok(())
}

#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
register_custom_getrandom!(fallback_getrandom);

/// SHA-256 rekeying CSPRNG seeded once by browser `WebCrypto`.
pub(crate) struct WorkerRng {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
    block: Zeroizing<[u8; 32]>,
    cursor: usize,
}

impl WorkerRng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(seed),
            counter: 0,
            block: Zeroizing::new([0; 32]),
            cursor: 32,
        }
    }

    fn refill(&mut self) {
        let mut output_hash = Sha256::new();
        output_hash.update(RNG_TAG);
        output_hash.update(&self.key[..]);
        output_hash.update(self.counter.to_le_bytes());
        self.block.copy_from_slice(&output_hash.finalize());

        let mut rekey_hash = Sha256::new();
        rekey_hash.update(RNG_REKEY_TAG);
        rekey_hash.update(&self.key[..]);
        rekey_hash.update(&self.block[..]);
        self.key.copy_from_slice(&rekey_hash.finalize());
        self.counter = self.counter.wrapping_add(1);
        self.cursor = 0;
    }
}

impl RngCore for WorkerRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        let mut written = 0;
        while written < destination.len() {
            if self.cursor == self.block.len() {
                self.refill();
            }
            let available = self.block.len() - self.cursor;
            let needed = destination.len() - written;
            let take = available.min(needed);
            destination[written..written + take]
                .copy_from_slice(&self.block[self.cursor..self.cursor + take]);
            self.cursor += take;
            written += take;
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for WorkerRng {}

impl Drop for WorkerRng {
    fn drop(&mut self) {
        self.key.zeroize();
        self.block.zeroize();
        self.counter.zeroize();
        self.cursor.zeroize();
    }
}

#[cfg(all(target_arch = "wasm32", feature = "raw-worker-entropy"))]
pub(crate) fn seed_fallback_rng(request: &DealInit) -> Result<(), String> {
    let mut hash = Sha256::new();
    hash.update(b"BP52/browser-deal-worker-getrandom/v1");
    hash.update(request.shared_config_hash);
    hash.update(request.session_nonce);
    hash.update(request.game_id);
    hash.update(request.local_secret.as_ref());
    hash.update(request.identity_keys[0]);
    hash.update(request.identity_keys[1]);
    hash.update(request.supplied_entropy.as_ref());
    let seed: [u8; 32] = hash.finalize().into();
    let mut slot = FALLBACK_RNG
        .lock()
        .map_err(|_| "fallback entropy lock was poisoned".to_owned())?;
    *slot = Some(WorkerRng::new(seed));
    Ok(())
}
