//! Tiny, wallet-only WebAssembly boundary for browser prototypes.
//!
//! JavaScript supplies 32 bytes from `crypto.getRandomValues`; this module
//! validates the scalar and derives its compressed secp256k1 public key. The
//! same key can sign an externally computed, exactly 32-byte SegWit-v0
//! signature hash with deterministic, low-S ECDSA. It is deliberately separate
//! from the large BP52 proof module.
//! The module can also validate an arbitrary compressed public key and derive
//! its public P2WSH staging descriptor without installing it as the local
//! signing key.
//!
//! This module does not compute transaction signature hashes. The caller must
//! compute the BIP143 digest from the complete transaction, input amount, and
//! witness script, then append the matching sighash-type byte to the returned
//! DER signature when constructing the witness stack.
//! Verification likewise only proves a signature against the public key and
//! prehash supplied by the caller. The coordinator must independently bind
//! that key to the expected peer and construct the prehash from the exact
//! transaction, input value, witness script, and intended sighash type.
//!
//! WebAssembly is not a secret-key enclave. Same-origin JavaScript can supply
//! or use the key, and clearing linear memory is only a best-effort reduction
//! of its lifetime. The browser application remains responsible for durable,
//! private recovery material.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", allow(unsafe_code))]

#[cfg(any(target_arch = "wasm32", test))]
use k256::{
    SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::hazmat::{PrehashSigner, PrehashVerifier},
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
#[cfg(any(target_arch = "wasm32", test))]
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;

#[cfg(any(target_arch = "wasm32", test))]
const MAX_DER_SIGNATURE_LEN: usize = 72;
#[cfg(any(target_arch = "wasm32", test))]
const COMPACT_SIGNATURE_LEN: usize = 64;
#[cfg(any(target_arch = "wasm32", test))]
const WITNESS_SCRIPT_LEN: usize = 35;
#[cfg(any(target_arch = "wasm32", test))]
const SCRIPT_PUBKEY_LEN: usize = 34;
#[cfg(any(target_arch = "wasm32", test))]
const MAX_ADDRESS_LEN: usize = 90;
#[cfg(any(target_arch = "wasm32", test))]
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[cfg(any(target_arch = "wasm32", test))]
struct SignedSighash {
    der: [u8; MAX_DER_SIGNATURE_LEN],
    der_len: u8,
    compact: [u8; COMPACT_SIGNATURE_LEN],
}

#[cfg(any(target_arch = "wasm32", test))]
fn derive_compressed_public_key(secret: &[u8; 32]) -> Option<[u8; 33]> {
    let secret = SecretKey::from_slice(secret).ok()?;
    let encoded = secret.public_key().to_encoded_point(true);
    let mut public = [0_u8; 33];
    public.copy_from_slice(encoded.as_bytes());
    Some(public)
}

#[cfg(any(target_arch = "wasm32", test))]
struct StagingDescriptor {
    witness_script: [u8; WITNESS_SCRIPT_LEN],
    script_pubkey: [u8; SCRIPT_PUBKEY_LEN],
    address: [u8; MAX_ADDRESS_LEN],
    address_len: u8,
}

#[cfg(any(target_arch = "wasm32", test))]
fn derive_staging_descriptor(public: [u8; 33], network: u32) -> Option<StagingDescriptor> {
    if !matches!(public[0], 0x02 | 0x03) || VerifyingKey::from_sec1_bytes(&public).is_err() {
        return None;
    }
    let hrp = match network {
        0 => b"bc".as_slice(),
        1 => b"tb".as_slice(),
        2 => b"bcrt".as_slice(),
        _ => return None,
    };
    let mut witness_script = [0_u8; WITNESS_SCRIPT_LEN];
    witness_script[0] = 0x21;
    witness_script[1..34].copy_from_slice(&public);
    witness_script[34] = 0xac;
    let witness_program: [u8; 32] = Sha256::digest(witness_script).into();
    let mut script_pubkey = [0_u8; SCRIPT_PUBKEY_LEN];
    script_pubkey[0] = 0x00;
    script_pubkey[1] = 0x20;
    script_pubkey[2..].copy_from_slice(&witness_program);
    let encoded = encode_segwit_v0_address(hrp, witness_program)?;
    let address_len = u8::try_from(encoded.len()).ok()?;
    let mut address = [0_u8; MAX_ADDRESS_LEN];
    address.get_mut(..encoded.len())?.copy_from_slice(&encoded);
    Some(StagingDescriptor {
        witness_script,
        script_pubkey,
        address,
        address_len,
    })
}

#[cfg(any(target_arch = "wasm32", test))]
fn encode_segwit_v0_address(hrp: &[u8], program: [u8; 32]) -> Option<Vec<u8>> {
    let mut data = vec![0_u8];
    let mut accumulator = 0_u16;
    let mut bit_count = 0_u8;
    for byte in program {
        accumulator = (accumulator << 8) | u16::from(byte);
        bit_count = bit_count.checked_add(8)?;
        while bit_count >= 5 {
            bit_count -= 5;
            data.push(u8::try_from((accumulator >> bit_count) & 31).ok()?);
        }
    }
    if bit_count > 0 {
        data.push(u8::try_from((accumulator << (5 - bit_count)) & 31).ok()?);
    }

    let mut checksum_input = Vec::with_capacity(hrp.len() * 2 + data.len() + 7);
    checksum_input.extend(hrp.iter().map(|byte| byte >> 5));
    checksum_input.push(0);
    checksum_input.extend(hrp.iter().map(|byte| byte & 31));
    checksum_input.extend_from_slice(&data);
    checksum_input.extend_from_slice(&[0; 6]);
    let checksum = bech32_polymod(&checksum_input) ^ 1;

    let mut output = Vec::with_capacity(hrp.len() + 1 + data.len() + 6);
    output.extend_from_slice(hrp);
    output.push(b'1');
    for value in data {
        output.push(*BECH32_CHARSET.get(usize::from(value))?);
    }
    for index in 0..6 {
        let shift = 5 * (5 - index);
        let value = u8::try_from((checksum >> shift) & 31).ok()?;
        output.push(*BECH32_CHARSET.get(usize::from(value))?);
    }
    Some(output)
}

#[cfg(any(target_arch = "wasm32", test))]
fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if ((top >> index) & 1) != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

#[cfg(any(target_arch = "wasm32", test))]
fn sign_sighash(secret: &[u8; 32], sighash: &[u8; 32]) -> Option<SignedSighash> {
    let signing_key = SigningKey::from_slice(secret).ok()?;
    let signature: Signature = signing_key.sign_prehash(sighash).ok()?;
    // k256's secp256k1 signing primitive already normalizes S, but retain this
    // explicit normalization so the boundary's low-S contract stays local.
    let signature = signature.normalize_s().unwrap_or(signature);
    let encoded = signature.to_der();
    let encoded_bytes = encoded.as_bytes();
    let encoded_len = u8::try_from(encoded_bytes.len()).ok()?;
    let mut der = [0_u8; MAX_DER_SIGNATURE_LEN];
    der.get_mut(..encoded_bytes.len())?
        .copy_from_slice(encoded_bytes);
    let mut compact = [0_u8; COMPACT_SIGNATURE_LEN];
    compact.copy_from_slice(&signature.to_bytes());
    Some(SignedSighash {
        der,
        der_len: encoded_len,
        compact,
    })
}

#[cfg(any(target_arch = "wasm32", test))]
fn verify_sighash_compact(
    public_key: &[u8; 33],
    sighash: &[u8; 32],
    compact_signature: &[u8; COMPACT_SIGNATURE_LEN],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(compact_signature) else {
        return false;
    };
    if signature.normalize_s().is_some() {
        return false;
    }
    verifying_key.verify_prehash(sighash, &signature).is_ok()
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static STATE: RefCell<WalletState> = const { RefCell::new(WalletState::new()) };
}

#[cfg(target_arch = "wasm32")]
struct WalletState {
    secret: [u8; 32],
    secret_written: u32,
    public: [u8; 33],
    staging_public_key: [u8; 33],
    staging_public_key_written: u64,
    witness_script: [u8; WITNESS_SCRIPT_LEN],
    script_pubkey: [u8; SCRIPT_PUBKEY_LEN],
    address: [u8; MAX_ADDRESS_LEN],
    address_len: u8,
    sighash: [u8; 32],
    sighash_written: u32,
    signature: [u8; MAX_DER_SIGNATURE_LEN],
    signature_len: u8,
    compact_signature: [u8; COMPACT_SIGNATURE_LEN],
    verify_public_key: [u8; 33],
    verify_public_key_written: u64,
    verify_sighash: [u8; 32],
    verify_sighash_written: u32,
    verify_signature: [u8; COMPACT_SIGNATURE_LEN],
    verify_signature_written: u64,
}

#[cfg(target_arch = "wasm32")]
impl WalletState {
    const fn new() -> Self {
        Self {
            secret: [0; 32],
            secret_written: 0,
            public: [0; 33],
            staging_public_key: [0; 33],
            staging_public_key_written: 0,
            witness_script: [0; WITNESS_SCRIPT_LEN],
            script_pubkey: [0; SCRIPT_PUBKEY_LEN],
            address: [0; MAX_ADDRESS_LEN],
            address_len: 0,
            sighash: [0; 32],
            sighash_written: 0,
            signature: [0; MAX_DER_SIGNATURE_LEN],
            signature_len: 0,
            compact_signature: [0; COMPACT_SIGNATURE_LEN],
            verify_public_key: [0; 33],
            verify_public_key_written: 0,
            verify_sighash: [0; 32],
            verify_sighash_written: 0,
            verify_signature: [0; COMPACT_SIGNATURE_LEN],
            verify_signature_written: 0,
        }
    }

    fn clear_signature(&mut self) {
        self.signature.fill(0);
        self.signature_len = 0;
        self.compact_signature.fill(0);
    }

    fn clear_descriptor(&mut self) {
        self.witness_script.fill(0);
        self.script_pubkey.fill(0);
        self.address.fill(0);
        self.address_len = 0;
    }

    fn clear_staging_public_key(&mut self) {
        self.staging_public_key.fill(0);
        self.staging_public_key_written = 0;
    }

    fn set_descriptor(&mut self, descriptor: StagingDescriptor) {
        self.witness_script = descriptor.witness_script;
        self.script_pubkey = descriptor.script_pubkey;
        self.address = descriptor.address;
        self.address_len = descriptor.address_len;
    }

    fn clear_sighash(&mut self) {
        self.sighash.fill(0);
        self.sighash_written = 0;
    }

    fn clear_verification(&mut self) {
        self.verify_public_key.fill(0);
        self.verify_public_key_written = 0;
        self.verify_sighash.fill(0);
        self.verify_sighash_written = 0;
        self.verify_signature.fill(0);
        self.verify_signature_written = 0;
    }
}

/// Sets one byte in the temporary scalar input buffer.
///
/// All 32 positions must be written after clearing before derivation or
/// signing. Returns one on success and zero for an invalid index or byte value.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_set_secret_byte(index: u32, value: u32) -> u32 {
    let Ok(value) = u8::try_from(value) else {
        return 0;
    };
    if index >= 32 {
        return 0;
    }
    STATE.with_borrow_mut(|state| {
        state.secret[index as usize] = value;
        state.secret_written |= 1_u32 << index;
        state.public.fill(0);
        state.clear_descriptor();
        state.clear_signature();
    });
    1
}

/// Validates the buffered scalar and derives its compressed public key.
///
/// Returns one on success and zero when the scalar is incomplete or invalid.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_derive_public_key() -> u32 {
    STATE.with_borrow_mut(|state| {
        if state.secret_written != u32::MAX {
            state.public.fill(0);
            return 0;
        }
        let Some(public) = derive_compressed_public_key(&state.secret) else {
            state.public.fill(0);
            return 0;
        };
        state.public = public;
        1
    })
}

/// Reads one byte from the last successfully derived compressed public key.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_public_key_byte(index: u32) -> u32 {
    if index >= 33 {
        return 0;
    }
    STATE.with_borrow(|state| u32::from(state.public[index as usize]))
}

/// Derive the P2WSH staging script, scriptPubKey, and Bech32 address in Rust.
///
/// Network zero is mainnet (`bc`), one is testnet/Signet (`tb`), and two is
/// regtest (`bcrt`). Returns one on success and zero for an invalid network or
/// when a public key has not been derived.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_derive_staging_descriptor(network: u32) -> u32 {
    STATE.with_borrow_mut(|state| {
        state.clear_descriptor();
        if state.public == [0; 33] {
            return 0;
        }
        let Some(descriptor) = derive_staging_descriptor(state.public, network) else {
            return 0;
        };
        state.set_descriptor(descriptor);
        1
    })
}

/// Sets one byte of an arbitrary compressed SEC1 public key for descriptor
/// derivation without changing the wallet's locally derived signing key.
///
/// All 33 positions must be written before calling
/// [`bp52_wallet_derive_staging_descriptor_from_public_key`]. Writing a valid
/// byte clears the previous descriptor output. Returns one on success and zero
/// for an invalid index or byte value.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_set_staging_public_key_byte(index: u32, value: u32) -> u32 {
    let Ok(value) = u8::try_from(value) else {
        return 0;
    };
    if index >= 33 {
        return 0;
    }
    STATE.with_borrow_mut(|state| {
        state.staging_public_key[index as usize] = value;
        state.staging_public_key_written |= 1_u64 << index;
        state.clear_descriptor();
    });
    1
}

/// Derives a P2WSH staging descriptor from a staged compressed SEC1 public key.
///
/// Network zero is mainnet (`bc`), one is testnet/Signet (`tb`), and two is
/// regtest (`bcrt`). The public-key input is consumed on every attempt. Returns
/// one only when all 33 bytes were written and encode a valid compressed
/// secp256k1 point on a supported network.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_derive_staging_descriptor_from_public_key(network: u32) -> u32 {
    const FULL_PUBLIC_KEY_MASK: u64 = (1_u64 << 33) - 1;

    STATE.with_borrow_mut(|state| {
        state.clear_descriptor();
        if state.staging_public_key_written != FULL_PUBLIC_KEY_MASK {
            state.clear_staging_public_key();
            return 0;
        }
        let public = state.staging_public_key;
        state.clear_staging_public_key();
        let Some(descriptor) = derive_staging_descriptor(public, network) else {
            return 0;
        };
        state.set_descriptor(descriptor);
        1
    })
}

/// Return the derived staging witness-script byte at `index`.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_witness_script_byte(index: u32) -> u32 {
    STATE.with_borrow(|state| {
        usize::try_from(index)
            .ok()
            .and_then(|index| state.witness_script.get(index))
            .map_or(0, |byte| u32::from(*byte))
    })
}

/// Return the derived staging scriptPubKey byte at `index`.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_script_pubkey_byte(index: u32) -> u32 {
    STATE.with_borrow(|state| {
        usize::try_from(index)
            .ok()
            .and_then(|index| state.script_pubkey.get(index))
            .map_or(0, |byte| u32::from(*byte))
    })
}

/// Return the byte length of the derived ASCII staging address.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_address_len() -> u32 {
    STATE.with_borrow(|state| u32::from(state.address_len))
}

/// Return the derived staging-address byte at `index`.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_address_byte(index: u32) -> u32 {
    STATE.with_borrow(|state| {
        if index >= u32::from(state.address_len) {
            return 0;
        }
        u32::from(state.address[index as usize])
    })
}

/// Sets one byte in the externally computed 32-byte SegWit-v0 signature hash.
///
/// All 32 byte positions must be written after the previous signing attempt or
/// clear operation. Returns one on success and zero for an invalid index or
/// byte value. Writing any byte invalidates the previous signature.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_set_sighash_byte(index: u32, value: u32) -> u32 {
    let Ok(value) = u8::try_from(value) else {
        return 0;
    };
    if index >= 32 {
        return 0;
    }
    STATE.with_borrow_mut(|state| {
        state.sighash[index as usize] = value;
        state.sighash_written |= 1_u32 << index;
        state.clear_signature();
    });
    1
}

/// Signs the buffered 32-byte SegWit-v0 signature hash as strict low-S DER.
///
/// Returns the DER byte length (at most 72) on success and zero when the key or
/// signature hash is incomplete or invalid. Every attempt consumes and clears
/// the signature-hash buffer. The returned bytes do not include a Bitcoin
/// sighash-type byte. The same operation also makes the 64-byte compact form
/// available through [`bp52_wallet_compact_signature_byte`].
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_sign_sighash_der() -> u32 {
    STATE.with_borrow_mut(|state| {
        state.clear_signature();
        if state.secret_written != u32::MAX || state.sighash_written != u32::MAX {
            state.clear_sighash();
            return 0;
        }

        let signed = sign_sighash(&state.secret, &state.sighash);
        state.clear_sighash();
        let Some(signed) = signed else {
            return 0;
        };
        state.signature = signed.der;
        state.signature_len = signed.der_len;
        state.compact_signature = signed.compact;
        u32::from(signed.der_len)
    })
}

/// Returns the byte length of a compact ECDSA signature emitted by this ABI.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_compact_signature_len() -> u32 {
    let Ok(length) = u32::try_from(COMPACT_SIGNATURE_LEN) else {
        return 0;
    };
    length
}

/// Reads one byte from the last successfully generated DER signature.
///
/// Returns zero for an index outside the signature length. Callers use the
/// length returned by [`bp52_wallet_sign_sighash_der`] to distinguish an
/// encoded zero byte from an invalid index.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_signature_byte(index: u32) -> u32 {
    STATE.with_borrow(|state| {
        if index >= u32::from(state.signature_len) {
            return 0;
        }
        u32::from(state.signature[index as usize])
    })
}

/// Reads one byte from the last generated 64-byte compact signature.
///
/// Returns zero if no signature is available or the index is outside 0..64.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_compact_signature_byte(index: u32) -> u32 {
    STATE.with_borrow(|state| {
        let Ok(index) = usize::try_from(index) else {
            return 0;
        };
        if state.signature_len == 0 || index >= COMPACT_SIGNATURE_LEN {
            return 0;
        }
        u32::from(state.compact_signature[index])
    })
}

/// Sets one byte of the compressed SEC1 public key used for verification.
///
/// All 33 positions must be written before verification. Returns one on
/// success and zero for an invalid index or byte value.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_set_verify_public_key_byte(index: u32, value: u32) -> u32 {
    let Ok(value) = u8::try_from(value) else {
        return 0;
    };
    if index >= 33 {
        return 0;
    }
    STATE.with_borrow_mut(|state| {
        state.verify_public_key[index as usize] = value;
        state.verify_public_key_written |= 1_u64 << index;
    });
    1
}

/// Sets one byte of the externally computed 32-byte prehash to verify.
///
/// All 32 positions must be written before verification. Returns one on
/// success and zero for an invalid index or byte value.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_set_verify_sighash_byte(index: u32, value: u32) -> u32 {
    let Ok(value) = u8::try_from(value) else {
        return 0;
    };
    if index >= 32 {
        return 0;
    }
    STATE.with_borrow_mut(|state| {
        state.verify_sighash[index as usize] = value;
        state.verify_sighash_written |= 1_u32 << index;
    });
    1
}

/// Sets one byte of the 64-byte compact ECDSA signature to verify.
///
/// All 64 positions must be written before verification. Returns one on
/// success and zero for an invalid index or byte value.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_set_verify_signature_byte(index: u32, value: u32) -> u32 {
    let Ok(value) = u8::try_from(value) else {
        return 0;
    };
    let Ok(array_index) = usize::try_from(index) else {
        return 0;
    };
    if array_index >= COMPACT_SIGNATURE_LEN {
        return 0;
    }
    STATE.with_borrow_mut(|state| {
        state.verify_signature[array_index] = value;
        state.verify_signature_written |= 1_u64 << index;
    });
    1
}

/// Verifies a strict low-S compact ECDSA signature over an exact prehash.
///
/// Returns one only when the 33-byte compressed SEC1 public key, 32-byte
/// signature hash, and 64-byte compact signature were all staged and valid.
/// Returns zero otherwise. Every attempt consumes and clears all verification
/// inputs, including incomplete inputs.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_verify_sighash_compact() -> u32 {
    const FULL_PUBLIC_KEY_MASK: u64 = (1_u64 << 33) - 1;

    STATE.with_borrow_mut(|state| {
        if state.verify_public_key_written != FULL_PUBLIC_KEY_MASK
            || state.verify_sighash_written != u32::MAX
            || state.verify_signature_written != u64::MAX
        {
            state.clear_verification();
            return 0;
        }
        let verified = verify_sighash_compact(
            &state.verify_public_key,
            &state.verify_sighash,
            &state.verify_signature,
        );
        state.clear_verification();
        u32::from(verified)
    })
}

/// Clears all temporary key, prehash, signature, and verification buffers.
///
/// Clearing is best-effort and does not make WebAssembly a key-security
/// boundary from same-origin JavaScript.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bp52_wallet_clear() {
    STATE.with_borrow_mut(|state| {
        state.secret.fill(0);
        state.secret_written = 0;
        state.public.fill(0);
        state.clear_staging_public_key();
        state.clear_descriptor();
        state.clear_sighash();
        state.clear_signature();
        state.clear_verification();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::DerSignature;

    #[test]
    fn derives_known_compressed_public_key() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let public = derive_compressed_public_key(&secret);
        assert_eq!(
            public,
            Some([
                0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98,
            ])
        );
    }

    #[test]
    fn rejects_zero_scalar() {
        assert_eq!(derive_compressed_public_key(&[0; 32]), None);
    }

    #[test]
    fn derives_standard_signet_staging_descriptor() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let Some(public) = derive_compressed_public_key(&secret) else {
            unreachable!("test scalar must derive a public key");
        };
        let Some(descriptor) = derive_staging_descriptor(public, 1) else {
            unreachable!("test network and public key must derive a descriptor");
        };
        let address =
            core::str::from_utf8(&descriptor.address[..usize::from(descriptor.address_len)]);
        assert_eq!(
            address,
            Ok("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
        );
        assert_eq!(descriptor.witness_script[0], 0x21);
        assert_eq!(descriptor.witness_script[34], 0xac);
        assert_eq!(&descriptor.script_pubkey[..2], &[0x00, 0x20]);
    }

    #[test]
    fn staging_descriptor_rejects_non_compressed_or_invalid_public_keys() {
        let mut uncompressed_prefix = [0_u8; 33];
        uncompressed_prefix[0] = 0x04;
        assert!(derive_staging_descriptor(uncompressed_prefix, 1).is_none());

        let mut invalid_point = [0xff_u8; 33];
        invalid_point[0] = 0x02;
        assert!(derive_staging_descriptor(invalid_point, 1).is_none());
    }

    #[test]
    fn signs_sighash_as_deterministic_strict_low_s_der() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let sighash = [0x42; 32];

        let first = sign_sighash(&secret, &sighash);
        let second = sign_sighash(&secret, &sighash);
        assert!(first.is_some());
        assert!(second.is_some());

        let Some(first) = first else {
            unreachable!("a valid scalar and 32-byte digest must sign");
        };
        let Some(second) = second else {
            unreachable!("a valid scalar and 32-byte digest must sign");
        };
        assert_eq!(first.der, second.der);
        assert_eq!(first.der_len, second.der_len);
        assert_eq!(first.compact, second.compact);

        let encoded = &first.der[..usize::from(first.der_len)];
        let der = DerSignature::from_bytes(encoded);
        assert!(der.is_ok());
        let Ok(der) = der else {
            unreachable!("the signer must emit strict DER");
        };
        let signature = Signature::from_der(der.as_bytes());
        assert!(signature.is_ok());
        let Ok(signature) = signature else {
            unreachable!("the DER signature must decode to a compact signature");
        };
        assert_eq!(signature.to_bytes().as_slice(), first.compact);
        assert!(signature.normalize_s().is_none());

        let signing_key = SigningKey::from_slice(&secret);
        assert!(signing_key.is_ok());
        let Ok(signing_key) = signing_key else {
            unreachable!("test scalar must be valid");
        };
        let verifying_key = VerifyingKey::from(&signing_key);
        assert!(verifying_key.verify_prehash(&sighash, &signature).is_ok());
    }

    #[test]
    fn signer_rejects_invalid_scalar() {
        assert!(sign_sighash(&[0; 32], &[0x42; 32]).is_none());
    }

    #[test]
    fn verifies_only_matching_low_s_compact_signature() {
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let sighash = [0x42; 32];
        let Some(signed) = sign_sighash(&secret, &sighash) else {
            unreachable!("test scalar must sign");
        };
        let Some(public_key) = derive_compressed_public_key(&secret) else {
            unreachable!("test scalar must derive a public key");
        };

        assert!(verify_sighash_compact(
            &public_key,
            &sighash,
            &signed.compact
        ));

        let mut wrong_sighash = sighash;
        wrong_sighash[0] ^= 1;
        assert!(!verify_sighash_compact(
            &public_key,
            &wrong_sighash,
            &signed.compact
        ));

        let mut malformed_public_key = public_key;
        malformed_public_key[0] = 0x04;
        assert!(!verify_sighash_compact(
            &malformed_public_key,
            &sighash,
            &signed.compact
        ));
    }

    #[test]
    fn verifier_rejects_high_s_signature() {
        const CURVE_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];

        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let sighash = [0x42; 32];
        let Some(signed) = sign_sighash(&secret, &sighash) else {
            unreachable!("test scalar must sign");
        };
        let Some(public_key) = derive_compressed_public_key(&secret) else {
            unreachable!("test scalar must derive a public key");
        };
        let mut high_s = signed.compact;
        let mut borrow = 0_u16;
        for index in (0..32).rev() {
            let minuend = u16::from(CURVE_ORDER[index]);
            let subtrahend = u16::from(high_s[index + 32]) + borrow;
            let difference = if minuend >= subtrahend {
                borrow = 0;
                minuend - subtrahend
            } else {
                borrow = 1;
                256 + minuend - subtrahend
            };
            let Ok(difference) = u8::try_from(difference) else {
                unreachable!("a single-byte subtraction must fit in a byte");
            };
            high_s[index + 32] = difference;
        }
        assert_eq!(borrow, 0);
        let high_signature = Signature::from_slice(&high_s);
        assert!(high_signature.is_ok());
        let Ok(high_signature) = high_signature else {
            unreachable!("n minus a valid nonzero scalar must remain valid");
        };
        assert!(high_signature.normalize_s().is_some());
        assert!(!verify_sighash_compact(&public_key, &sighash, &high_s));
    }
}
