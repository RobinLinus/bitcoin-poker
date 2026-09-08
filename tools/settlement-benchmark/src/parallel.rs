//! Bounded local-worker ABI for the deterministic benchmark. No network capabilities.
use super::*;
use poker_settlement::preparation::batches::BatchVerifier;
thread_local! {
    static INPUT: RefCell<Vec<u8>> = const {RefCell::new(Vec::new())};
    static OUTPUT: RefCell<Vec<u8>> = const {RefCell::new(Vec::new())};
    static OWNER: RefCell<Option<SettlementPreparation>> = const {RefCell::new(None)};
    static VERIFIER: RefCell<Option<BatchVerifier>> = const {RefCell::new(None)};
    static KEY: RefCell<[u8;32]> = const {RefCell::new([0;32])};
    static ROLE: RefCell<u8> = const {RefCell::new(255)};
}
pub(super) fn store(preparation: SettlementPreparation) {
    OWNER.with(|owner| *owner.borrow_mut() = Some(preparation));
}
fn input() -> Vec<u8> {
    INPUT.with(|data| data.borrow().clone())
}
fn call(f: impl FnOnce() -> Result<Vec<u8>>) -> u32 {
    match f() {
        Ok(bytes) => {
            OUTPUT.with(|out| *out.borrow_mut() = bytes);
            1
        }
        Err(error) => {
            LAST_ERROR.with(|e| *e.borrow_mut() = error.to_string().into_bytes());
            0
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_input(len: usize) -> *mut u8 {
    if len > 32 * 1024 * 1024 {
        return std::ptr::null_mut();
    }
    INPUT.with(|data| {
        let mut data = data.borrow_mut();
        data.resize(len, 0);
        data.as_mut_ptr()
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_output_ptr() -> *const u8 {
    OUTPUT.with(|out| out.borrow().as_ptr())
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_output_len() -> usize {
    OUTPUT.with(|out| out.borrow().len())
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_prepare(full: u32) -> u32 {
    call(|| {
        run(full != 0, true)?;
        Ok(Vec::new())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_key() -> u32 {
    call(|| {
        let key: [u8; 32] = input().try_into().map_err(|_| "wrong key length")?;
        KEY.with(|slot| *slot.borrow_mut() = key);
        Ok(Vec::new())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_inventory() -> u32 {
    call(|| {
        OWNER.with(|owner| {
            Ok(owner
                .borrow()
                .as_ref()
                .ok_or("missing preparation")?
                .encode_inventory()?)
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_manifest() -> u32 {
    call(|| {
        OWNER.with(|owner| {
            let owner = owner.borrow();
            let preparation = owner.as_ref().ok_or("missing preparation")?;
            Ok(preparation
                .requests()
                .iter()
                .flat_map(|request| match request {
                    AuthorizationRequest::Signature { signer, .. } => [signer.code(), 0],
                    AuthorizationRequest::Reveal(c) => [1 - c.revealer, 1],
                })
                .collect())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_pool_init(role: u32) -> u32 {
    call(|| {
        if role > 1 {
            return Err("invalid signer role".into());
        }
        let data = input();
        if data.len() < 32 {
            return Err("missing delegation key".into());
        }
        let key = data[..32].try_into()?;
        let preparation = SettlementPreparation::from_inventory(&data[32..], Network::Regtest)?;
        let verifier = BatchVerifier::new(preparation, key)?;
        VERIFIER.with(|slot| *slot.borrow_mut() = Some(verifier));
        ROLE.with(|slot| *slot.borrow_mut() = role as u8);
        Ok(Vec::new())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_sign() -> u32 {
    call(|| {
        VERIFIER.with(|slot| {
            let slot = slot.borrow();
            let verifier = slot.as_ref().ok_or("missing inventory")?;
            let assigned = ROLE.with(|r| *r.borrow());
            let data = input();
            if data.is_empty() || data.len() % 4 != 0 || data.len() > 8192 {
                return Err("invalid index batch".into());
            }
            let secp = Secp256k1::new();
            let mut identities = [[3; 32], [5; 32]];
            identities.sort_by_key(|key| {
                SecretKey::from_slice(key)
                    .map(|key| {
                        Keypair::from_secret_key(&secp, &key)
                            .x_only_public_key()
                            .0
                            .serialize()
                    })
                    .ok()
            });
            // Only the assigned identity is instantiated as a signing key in this worker.
            let signer = Keypair::from_secret_key(
                &secp,
                &SecretKey::from_slice(&identities[usize::from(assigned)])?,
            );
            let mut out = Vec::new();
            let mut previous = None;
            for chunk in data.chunks_exact(4) {
                let index = u32::from_le_bytes(chunk.try_into()?) as usize;
                if previous.is_some_and(|p| index <= p) {
                    return Err("unordered indices".into());
                }
                previous = Some(index);
                let request = verifier
                    .requests()
                    .get(index)
                    .ok_or("invalid request index")?;
                let bytes = match request {
                    AuthorizationRequest::Signature {
                        signer: role,
                        sighash,
                        ..
                    } => {
                        if role.code() != assigned {
                            return Err("signer role mismatch".into());
                        }
                        sign_sighash_default(&secp, &signer, *sighash)
                            .to_bytes()
                            .to_vec()
                    }
                    AuthorizationRequest::Reveal(c) => {
                        if 1 - c.revealer != assigned {
                            return Err("reveal authorizer role mismatch".into());
                        }
                        let secret = [40 + c.revealer * 9 + c.slot; 32];
                        VerifiedRevealPackage::create(c.as_ref().clone(), &secret, &[80; 32])?
                            .to_bytes()
                    }
                };
                out.extend(chunk);
                out.extend(u32::try_from(bytes.len())?.to_le_bytes());
                out.extend(bytes);
                if out.len() > 256 * 1024 {
                    return Err("batch too large".into());
                }
            }
            Ok(out)
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_verify() -> u32 {
    call(|| {
        VERIFIER.with(|slot| {
            Ok(slot
                .borrow()
                .as_ref()
                .ok_or("missing verifier")?
                .verify_batch(&input())?)
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_accept() -> u32 {
    call(|| {
        OWNER.with(|owner| {
            owner
                .borrow_mut()
                .as_mut()
                .ok_or("missing preparation")?
                .accept_verified_batch(&KEY.with(|key| *key.borrow()), &input())?;
            Ok(Vec::new())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_snapshot() -> u32 {
    call(|| {
        OWNER.with(|owner| {
            let owner = owner.borrow();
            let preparation = owner.as_ref().ok_or("missing preparation")?;
            if preparation.missing_count() != 0 {
                return Err("incomplete preparation".into());
            }
            Ok(preparation.encode_snapshot()?)
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_checkpoint() -> u32 {
    call(|| {
        OWNER.with(|owner| {
            Ok(owner
                .borrow()
                .as_ref()
                .ok_or("missing preparation")?
                .seal_checkpoint(&KEY.with(|key| *key.borrow()))?)
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_resume() -> u32 {
    call(|| {
        let data = input();
        if data.len() < 32 {
            return Err("missing checkpoint key".into());
        }
        let key = data[..32].try_into()?;
        let owner = SettlementPreparation::open_checkpoint(&key, &data[32..], Network::Regtest)?;
        let binding = owner.inventory_binding()?.to_vec();
        store(owner);
        KEY.with(|slot| *slot.borrow_mut() = key);
        Ok(binding)
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn tree_parallel_binding() -> u32 {
    call(|| {
        OWNER.with(|owner| {
            Ok(owner
                .borrow()
                .as_ref()
                .ok_or("missing preparation")?
                .inventory_binding()?
                .to_vec())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipts_checkpoints_and_corrupt_batches() -> Result {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| test_batches().map_err(|e| e.to_string()))?
            .join()
            .map_err(|_| "batch test panicked")?
            .map_err(Into::into)
    }
    fn test_batches() -> Result {
        run(false, true)?;
        let inventory = OWNER.with(|owner| {
            owner
                .borrow()
                .as_ref()
                .ok_or("missing inventory")?
                .encode_inventory()
                .map_err(Into::<Box<dyn Error>>::into)
        })?;
        let key = [97; 32];
        let mut owner = SettlementPreparation::from_inventory(&inventory, Network::Regtest)?;
        assert!(owner.seal_checkpoint(&key).is_err());
        let verifier = BatchVerifier::new(
            SettlementPreparation::from_inventory(&inventory, Network::Regtest)?,
            key,
        )?;
        for role in 0..2 {
            INPUT.with(|input| {
                *input.borrow_mut() = [key.as_slice(), inventory.as_slice()].concat()
            });
            assert_eq!(tree_parallel_pool_init(role), 1);
            let indices: Vec<u8> = verifier
                .requests()
                .iter()
                .enumerate()
                .filter(|(_, request)| match request {
                    AuthorizationRequest::Signature { signer, .. } => {
                        u32::from(signer.code()) == role
                    }
                    AuthorizationRequest::Reveal(c) => u32::from(1 - c.revealer) == role,
                })
                .flat_map(|(index, _)| (index as u32).to_le_bytes())
                .collect();
            INPUT.with(|input| *input.borrow_mut() = indices);
            assert_eq!(tree_parallel_sign(), 1);
            let bytes = OUTPUT.with(|out| out.borrow().clone());
            let mut corrupt = bytes.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            assert!(verifier.verify_batch(&corrupt).is_err());
            let receipt = verifier.verify_batch(&bytes)?;
            let missing = owner.missing_count();
            assert!(owner.accept_verified_batch(&[98; 32], &receipt).is_err());
            let mut tampered = receipt.clone();
            tampered[8] ^= 1;
            assert!(owner.accept_verified_batch(&key, &tampered).is_err());
            assert_eq!(owner.missing_count(), missing);
            owner.accept_verified_batch(&key, &receipt)?;
            let missing = owner.missing_count();
            owner.accept_verified_batch(&key, &receipt)?;
            assert_eq!(owner.missing_count(), missing);
            let mut other = inventory.clone();
            let last = other.len() - 1;
            other[last] ^= 1;
            if let Ok(mut foreign) = SettlementPreparation::from_inventory(&other, Network::Regtest)
            {
                assert!(foreign.accept_verified_batch(&key, &receipt).is_err());
            } else {
                return Err("foreign-inventory fixture must decode".into());
            }
        }
        assert_eq!(owner.missing_count(), 0);
        let checkpoint = owner.seal_checkpoint(&key)?;
        assert!(
            SettlementPreparation::open_checkpoint(&[98; 32], &checkpoint, Network::Regtest)
                .is_err()
        );
        let mut corrupt = checkpoint.clone();
        corrupt[20] ^= 1;
        assert!(SettlementPreparation::open_checkpoint(&key, &corrupt, Network::Regtest).is_err());
        assert!(
            SettlementPreparation::open_checkpoint(&key, &checkpoint, Network::Bitcoin).is_err()
        );
        let restored = SettlementPreparation::open_checkpoint(&key, &checkpoint, Network::Regtest)?;
        assert_eq!(restored.encode_snapshot()?, owner.encode_snapshot()?);
        let requests = restored.requests().to_vec();
        let ready = restored.into_prepared_authorizations()?;
        for request in requests {
            if let AuthorizationRequest::Reveal(context) = request {
                ready.reveal(context.node_id, context.slot)?;
            }
        }
        Ok(())
    }
}
