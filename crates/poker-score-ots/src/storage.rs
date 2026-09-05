//! Authenticated encrypted persistence for unused Lamport secret keys.

use std::{collections::BTreeSet, fmt};

use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{HASH_SIZE, KeyContext, LamportPurpose};

const ENVELOPE_MAGIC: [u8; 8] = *b"BP52LSK1";
const ENVELOPE_VERSION: u16 = 1;
const ALGORITHM_XCHACHA20_POLY1305: u8 = 1;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const HEADER_SIZE: usize = 8 + 2 + 1 + HASH_SIZE + HASH_SIZE + 1 + NONCE_SIZE + 2;
const NONCE_DOMAIN: &[u8] = b"BP52/lamport-storage-nonce/v1";

/// Failures while sealing or opening an unused Lamport secret key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SecretStorageError {
    /// The random source failed while generating a key or nonce.
    #[error("secure storage randomness is unavailable")]
    RandomnessUnavailable,
    /// The random source repeated a nonce already emitted by this key owner.
    #[error("refusing to reuse an XChaCha20-Poly1305 nonce")]
    NonceReuse,
    /// Only a fresh, wholly unused Lamport key can be persisted.
    #[error("only a fresh Lamport secret key can be sealed")]
    SecretNotFresh,
    /// The secret key is not the private half of the expected public key.
    #[error("Lamport secret key does not match the expected public key")]
    PublicKeyMismatch,
    /// The encrypted envelope has the wrong magic prefix.
    #[error("invalid encrypted Lamport-key envelope prefix")]
    InvalidPrefix,
    /// The encrypted envelope uses an unsupported format version.
    #[error("unsupported encrypted Lamport-key envelope version {0}")]
    UnsupportedVersion(u16),
    /// The encrypted envelope selects an unsupported AEAD algorithm.
    #[error("unsupported encrypted Lamport-key algorithm {0}")]
    UnsupportedAlgorithm(u8),
    /// The encrypted envelope contains an unknown Lamport purpose.
    #[error("invalid encrypted Lamport-key purpose {0}")]
    InvalidPurpose(u8),
    /// The encrypted envelope ends before all canonical fields are present.
    #[error("truncated encrypted Lamport-key envelope")]
    TruncatedEnvelope,
    /// The encrypted envelope contains bytes after its canonical end.
    #[error("trailing data in encrypted Lamport-key envelope")]
    TrailingData,
    /// The ciphertext length is not the unique length for the bound purpose.
    #[error("invalid encrypted Lamport-key ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength {
        /// Unique ciphertext length required by the purpose.
        expected: usize,
        /// Length encoded in or supplied with the envelope.
        actual: usize,
    },
    /// The envelope belongs to a different game, node, or Lamport purpose.
    #[error("encrypted Lamport-key context does not match the expected public key")]
    ContextMismatch,
    /// AEAD authentication failed; wrong keys and tampering are indistinguishable.
    #[error("encrypted Lamport-key authentication failed")]
    AuthenticationFailed,
    /// Authenticated plaintext did not reconstruct the expected private key.
    #[error("authenticated Lamport-key plaintext is invalid")]
    InvalidPlaintext,
}

/// Caller-owned key used to encrypt unused Lamport secrets at rest.
///
/// This owner is intentionally non-`Clone`, redacts `Debug`, and zeroizes its
/// key bytes on drop. Construct it from 32 bytes obtained from an OS keyring,
/// HSM, or comparably protected source. Durable key custody, backup, and
/// coordination of a single sealing writer remain the caller's responsibility.
pub struct LamportStorageKey {
    bytes: Zeroizing<[u8; 32]>,
    emitted_nonces: BTreeSet<[u8; NONCE_SIZE]>,
}

impl LamportStorageKey {
    /// Takes ownership of 32 caller-supplied storage-key bytes.
    ///
    /// The caller remains responsible for erasing any other copies made while
    /// loading these bytes from its OS keyring or HSM.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            emitted_nonces: BTreeSet::new(),
        }
    }

    /// Generates a fresh storage key with a cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStorageError::RandomnessUnavailable`] if the source
    /// cannot fill the complete 32-byte key.
    pub fn generate<R>(rng: &mut R) -> Result<Self, SecretStorageError>
    where
        R: CryptoRng + RngCore,
    {
        let mut bytes = [0_u8; 32];
        if rng.try_fill_bytes(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(SecretStorageError::RandomnessUnavailable);
        }
        Ok(Self::from_bytes(bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn fresh_nonce<R>(&mut self, rng: &mut R) -> Result<[u8; NONCE_SIZE], SecretStorageError>
    where
        R: CryptoRng + RngCore,
    {
        let mut nonce = [0_u8; NONCE_SIZE];
        if rng.try_fill_bytes(&mut nonce).is_err() {
            nonce.zeroize();
            return Err(SecretStorageError::RandomnessUnavailable);
        }

        // XORing a fixed domain mask preserves all 192 random bits while
        // ensuring another BP52 secret-owner domain cannot use the same AEAD
        // nonce if an application provisions identical raw key bytes.
        let domain_mask = Sha256::digest(NONCE_DOMAIN);
        for (byte, mask) in nonce.iter_mut().zip(domain_mask.iter()) {
            *byte ^= mask;
        }
        if !self.emitted_nonces.insert(nonce) {
            nonce.zeroize();
            return Err(SecretStorageError::NonceReuse);
        }
        Ok(nonce)
    }
}

impl fmt::Debug for LamportStorageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LamportStorageKey")
            .field("key_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for LamportStorageKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.emitted_nonces.clear();
    }
}

/// Canonical authenticated ciphertext containing one unused Lamport key.
///
/// The ciphertext owner is intentionally non-`Clone`. Its byte APIs expose
/// only the encrypted envelope suitable for ordinary file or database storage.
pub struct SealedLamportSecretKey {
    bytes: Vec<u8>,
}

impl SealedLamportSecretKey {
    /// Strictly parses one bounded canonical encrypted envelope.
    ///
    /// This validates public framing and lengths. Authentication and private
    /// key reconstruction happen only in [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns a format error for an unknown version or algorithm, malformed
    /// context, incorrect length, truncation, or trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretStorageError> {
        parse_envelope(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Borrows the canonical ciphertext envelope for persistence.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the ciphertext owner and returns its canonical encrypted bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn seal<R>(
        context: KeyContext,
        plaintext: &[u8],
        storage_key: &mut LamportStorageKey,
        rng: &mut R,
    ) -> Result<Self, SecretStorageError>
    where
        R: CryptoRng + RngCore,
    {
        let expected_plaintext = plaintext_len(context.purpose);
        if plaintext.len() != expected_plaintext {
            return Err(SecretStorageError::InvalidPlaintext);
        }
        let nonce = storage_key.fresh_nonce(rng)?;
        let ciphertext_len = expected_plaintext + TAG_SIZE;
        let ciphertext_len_u16 =
            u16::try_from(ciphertext_len).map_err(|_| SecretStorageError::InvalidPlaintext)?;
        let mut bytes = Vec::with_capacity(HEADER_SIZE + ciphertext_len);
        bytes.extend_from_slice(&ENVELOPE_MAGIC);
        bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        bytes.push(ALGORITHM_XCHACHA20_POLY1305);
        bytes.extend_from_slice(&context.chain_game_id);
        bytes.extend_from_slice(&context.node_id);
        bytes.push(context.purpose as u8);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext_len_u16.to_le_bytes());
        debug_assert_eq!(bytes.len(), HEADER_SIZE);

        let key: &Key = storage_key.bytes().into();
        let xnonce: &XNonce = (&nonce).into();
        let cipher = XChaCha20Poly1305::new(key);
        let ciphertext = cipher
            .encrypt(
                xnonce,
                Payload {
                    msg: plaintext,
                    aad: &bytes,
                },
            )
            .map_err(|_| SecretStorageError::AuthenticationFailed)?;
        debug_assert_eq!(ciphertext.len(), ciphertext_len);
        bytes.extend_from_slice(&ciphertext);
        Ok(Self { bytes })
    }

    pub(crate) fn open_plaintext(
        &self,
        expected_context: KeyContext,
        storage_key: &LamportStorageKey,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStorageError> {
        let parsed = parse_envelope(&self.bytes)?;
        if parsed.context != expected_context {
            return Err(SecretStorageError::ContextMismatch);
        }
        let key: &Key = storage_key.bytes().into();
        let xnonce: &XNonce = (&parsed.nonce).into();
        let cipher = XChaCha20Poly1305::new(key);
        cipher
            .decrypt(
                xnonce,
                Payload {
                    msg: parsed.ciphertext,
                    aad: parsed.aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| SecretStorageError::AuthenticationFailed)
    }
}

impl fmt::Debug for SealedLamportSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedLamportSecretKey")
            .field("ciphertext", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct ParsedEnvelope<'a> {
    context: KeyContext,
    nonce: [u8; NONCE_SIZE],
    aad: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, SecretStorageError> {
    if bytes.len() < HEADER_SIZE {
        return Err(SecretStorageError::TruncatedEnvelope);
    }
    if bytes[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
        return Err(SecretStorageError::InvalidPrefix);
    }

    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != ENVELOPE_VERSION {
        return Err(SecretStorageError::UnsupportedVersion(version));
    }
    let algorithm = bytes[10];
    if algorithm != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(SecretStorageError::UnsupportedAlgorithm(algorithm));
    }

    let mut chain_game_id = [0_u8; HASH_SIZE];
    chain_game_id.copy_from_slice(&bytes[11..43]);
    let mut node_id = [0_u8; HASH_SIZE];
    node_id.copy_from_slice(&bytes[43..75]);
    let purpose_byte = bytes[75];
    let purpose = match purpose_byte {
        1 => LamportPurpose::AliceScore24Bit,
        2 => LamportPurpose::BobScore24Bit,
        other => return Err(SecretStorageError::InvalidPurpose(other)),
    };
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[76..100]);
    let encoded_ciphertext_len = usize::from(u16::from_le_bytes([bytes[100], bytes[101]]));
    let expected_ciphertext_len = plaintext_len(purpose) + TAG_SIZE;
    if encoded_ciphertext_len != expected_ciphertext_len {
        return Err(SecretStorageError::InvalidCiphertextLength {
            expected: expected_ciphertext_len,
            actual: encoded_ciphertext_len,
        });
    }
    let expected_total = HEADER_SIZE + expected_ciphertext_len;
    if bytes.len() < expected_total {
        return Err(SecretStorageError::TruncatedEnvelope);
    }
    if bytes.len() > expected_total {
        return Err(SecretStorageError::TrailingData);
    }

    Ok(ParsedEnvelope {
        context: KeyContext::new(chain_game_id, node_id, purpose),
        nonce,
        aad: &bytes[..HEADER_SIZE],
        ciphertext: &bytes[HEADER_SIZE..],
    })
}

pub(crate) const fn plaintext_len(purpose: LamportPurpose) -> usize {
    purpose.bit_width() as usize * 2 * HASH_SIZE
}
