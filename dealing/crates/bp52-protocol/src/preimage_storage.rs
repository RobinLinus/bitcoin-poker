//! Authenticated encrypted persistence for accepted-deal share preimages.

use std::{collections::BTreeSet, fmt};

use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    N_SLOTS, PREIMAGE_BASE_LEN, PREIMAGE_MAX_LEN, Role, auth::accepted_deal_digest,
    messages::AcceptedDeal,
};

const ENVELOPE_MAGIC: [u8; 8] = *b"BP52PRE1";
const ENVELOPE_VERSION: u16 = 1;
const ALGORITHM_XCHACHA20_POLY1305: u8 = 1;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const HEADER_SIZE: usize = 8 + 2 + 1 + 32 + 4 + 1 + 32 + NONCE_SIZE + 2;
const MIN_PLAINTEXT_SIZE: usize = N_SLOTS * (1 + PREIMAGE_BASE_LEN);
const MAX_PLAINTEXT_SIZE: usize = N_SLOTS * (1 + PREIMAGE_MAX_LEN);
const NONCE_DOMAIN: &[u8] = b"BP52/preimage-storage-nonce/v1";

/// Failures while sealing or opening accepted-deal share preimages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PreimageStorageError {
    /// The random source failed while generating a key or nonce.
    #[error("secure preimage-storage randomness is unavailable")]
    RandomnessUnavailable,
    /// The random source repeated a nonce already emitted by this key owner.
    #[error("refusing to reuse an XChaCha20-Poly1305 nonce")]
    NonceReuse,
    /// The accepted-deal body is not canonically encodable as protocol v1.
    #[error("accepted deal is not a canonical v1 storage context")]
    InvalidAcceptedDeal,
    /// A retained preimage has a length outside the protocol bounds.
    #[error("retained preimage {slot} has invalid length {length}")]
    InvalidPreimageLength {
        /// Zero-based local share slot.
        slot: usize,
        /// Supplied preimage length.
        length: usize,
    },
    /// A retained preimage does not hash to its role's accepted hash lock.
    #[error("retained preimage {slot} does not match the accepted deal")]
    PreimageMismatch {
        /// Zero-based local share slot.
        slot: usize,
    },
    /// The encrypted envelope has the wrong magic prefix.
    #[error("invalid encrypted preimage envelope prefix")]
    InvalidPrefix,
    /// The encrypted envelope uses an unsupported format version.
    #[error("unsupported encrypted preimage envelope version {0}")]
    UnsupportedVersion(u16),
    /// The encrypted envelope selects an unsupported AEAD algorithm.
    #[error("unsupported encrypted preimage algorithm {0}")]
    UnsupportedAlgorithm(u8),
    /// The encrypted envelope contains an unknown protocol role.
    #[error("invalid encrypted preimage role {0}")]
    InvalidRole(u8),
    /// The encrypted envelope ends before all canonical fields are present.
    #[error("truncated encrypted preimage envelope")]
    TruncatedEnvelope,
    /// The encrypted envelope contains bytes after its canonical end.
    #[error("trailing data in encrypted preimage envelope")]
    TrailingData,
    /// The ciphertext length is outside the fixed protocol bounds.
    #[error("invalid encrypted preimage ciphertext length {actual}")]
    InvalidCiphertextLength {
        /// Length encoded in the envelope.
        actual: usize,
    },
    /// The envelope belongs to a different accepted deal or local role.
    #[error("encrypted preimage context does not match the expected accepted deal")]
    ContextMismatch,
    /// AEAD authentication failed; wrong keys and tampering are indistinguishable.
    #[error("encrypted preimage authentication failed")]
    AuthenticationFailed,
    /// Authenticated plaintext is not the unique nine-preimage encoding.
    #[error("authenticated retained-preimage plaintext is invalid")]
    InvalidPlaintext,
}

/// Caller-owned key used to encrypt accepted-deal preimages at rest.
///
/// This owner is intentionally non-`Clone`, redacts `Debug`, and zeroizes its
/// key bytes on drop. Construct it from 32 bytes obtained from an OS keyring,
/// HSM, or comparably protected source. Durable key custody, backup, and
/// coordination of a single sealing writer remain the caller's responsibility.
pub struct PreimageStorageKey {
    bytes: Zeroizing<[u8; 32]>,
    emitted_nonces: BTreeSet<[u8; NONCE_SIZE]>,
}

impl PreimageStorageKey {
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
    /// Returns [`PreimageStorageError::RandomnessUnavailable`] if the source
    /// cannot fill the complete 32-byte key.
    pub fn generate<R>(rng: &mut R) -> Result<Self, PreimageStorageError>
    where
        R: CryptoRng + RngCore,
    {
        let mut bytes = [0_u8; 32];
        if rng.try_fill_bytes(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(PreimageStorageError::RandomnessUnavailable);
        }
        Ok(Self::from_bytes(bytes))
    }

    fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn fresh_nonce<R>(&mut self, rng: &mut R) -> Result<[u8; NONCE_SIZE], PreimageStorageError>
    where
        R: CryptoRng + RngCore,
    {
        let mut nonce = [0_u8; NONCE_SIZE];
        if rng.try_fill_bytes(&mut nonce).is_err() {
            nonce.zeroize();
            return Err(PreimageStorageError::RandomnessUnavailable);
        }
        let domain_mask = Sha256::digest(NONCE_DOMAIN);
        for (byte, mask) in nonce.iter_mut().zip(domain_mask.iter()) {
            *byte ^= mask;
        }
        if !self.emitted_nonces.insert(nonce) {
            nonce.zeroize();
            return Err(PreimageStorageError::NonceReuse);
        }
        Ok(nonce)
    }
}

impl fmt::Debug for PreimageStorageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreimageStorageKey")
            .field("key_material", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for PreimageStorageKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.emitted_nonces.clear();
    }
}

/// Canonical authenticated ciphertext containing nine retained preimages.
///
/// The ciphertext owner is intentionally non-`Clone`. Its byte APIs expose
/// only the encrypted envelope suitable for ordinary file or database storage.
pub struct SealedRetainedPreimages {
    bytes: Vec<u8>,
}

impl SealedRetainedPreimages {
    /// Strictly parses one bounded canonical encrypted envelope.
    ///
    /// This validates public framing and lengths. Authentication, exact
    /// private parsing, and hash-lock checks happen only in [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns a format error for an unknown version, algorithm, or role,
    /// incorrect length, truncation, or trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PreimageStorageError> {
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
        context: StorageContext,
        plaintext: &[u8],
        storage_key: &mut PreimageStorageKey,
        rng: &mut R,
    ) -> Result<Self, PreimageStorageError>
    where
        R: CryptoRng + RngCore,
    {
        if !(MIN_PLAINTEXT_SIZE..=MAX_PLAINTEXT_SIZE).contains(&plaintext.len()) {
            return Err(PreimageStorageError::InvalidPlaintext);
        }
        let nonce = storage_key.fresh_nonce(rng)?;
        let ciphertext_len = plaintext.len() + TAG_SIZE;
        let ciphertext_len_u16 =
            u16::try_from(ciphertext_len).map_err(|_| PreimageStorageError::InvalidPlaintext)?;
        let mut bytes = Vec::with_capacity(HEADER_SIZE + ciphertext_len);
        bytes.extend_from_slice(&ENVELOPE_MAGIC);
        bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        bytes.push(ALGORITHM_XCHACHA20_POLY1305);
        bytes.extend_from_slice(&context.game_id);
        bytes.extend_from_slice(&context.attempt.to_le_bytes());
        bytes.push(context.role as u8);
        bytes.extend_from_slice(&context.accepted_deal_digest);
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
            .map_err(|_| PreimageStorageError::AuthenticationFailed)?;
        debug_assert_eq!(ciphertext.len(), ciphertext_len);
        bytes.extend_from_slice(&ciphertext);
        Ok(Self { bytes })
    }

    pub(crate) fn open_plaintext(
        &self,
        expected_context: StorageContext,
        storage_key: &PreimageStorageKey,
    ) -> Result<Zeroizing<Vec<u8>>, PreimageStorageError> {
        let parsed = parse_envelope(&self.bytes)?;
        if parsed.context != expected_context {
            return Err(PreimageStorageError::ContextMismatch);
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
            .map_err(|_| PreimageStorageError::AuthenticationFailed)
    }
}

impl fmt::Debug for SealedRetainedPreimages {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedRetainedPreimages")
            .field("ciphertext", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageContext {
    game_id: [u8; 32],
    attempt: u32,
    role: Role,
    accepted_deal_digest: [u8; 32],
}

impl StorageContext {
    pub(crate) fn from_deal(deal: &AcceptedDeal, role: Role) -> Result<Self, PreimageStorageError> {
        let digest = accepted_deal_digest(&deal.body())
            .map_err(|_| PreimageStorageError::InvalidAcceptedDeal)?;
        Ok(Self {
            game_id: deal.game_id,
            attempt: deal.attempt,
            role,
            accepted_deal_digest: digest,
        })
    }
}

struct ParsedEnvelope<'a> {
    context: StorageContext,
    nonce: [u8; NONCE_SIZE],
    aad: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope<'_>, PreimageStorageError> {
    if bytes.len() < HEADER_SIZE {
        return Err(PreimageStorageError::TruncatedEnvelope);
    }
    if bytes[..ENVELOPE_MAGIC.len()] != ENVELOPE_MAGIC {
        return Err(PreimageStorageError::InvalidPrefix);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != ENVELOPE_VERSION {
        return Err(PreimageStorageError::UnsupportedVersion(version));
    }
    let algorithm = bytes[10];
    if algorithm != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(PreimageStorageError::UnsupportedAlgorithm(algorithm));
    }

    let mut game_id = [0_u8; 32];
    game_id.copy_from_slice(&bytes[11..43]);
    let attempt = u32::from_le_bytes([bytes[43], bytes[44], bytes[45], bytes[46]]);
    let role = match bytes[47] {
        0 => Role::Alice,
        1 => Role::Bob,
        other => return Err(PreimageStorageError::InvalidRole(other)),
    };
    let mut accepted_deal_digest = [0_u8; 32];
    accepted_deal_digest.copy_from_slice(&bytes[48..80]);
    let mut nonce = [0_u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[80..104]);
    let ciphertext_len = usize::from(u16::from_le_bytes([bytes[104], bytes[105]]));
    if !(MIN_PLAINTEXT_SIZE + TAG_SIZE..=MAX_PLAINTEXT_SIZE + TAG_SIZE).contains(&ciphertext_len) {
        return Err(PreimageStorageError::InvalidCiphertextLength {
            actual: ciphertext_len,
        });
    }
    let expected_total = HEADER_SIZE + ciphertext_len;
    if bytes.len() < expected_total {
        return Err(PreimageStorageError::TruncatedEnvelope);
    }
    if bytes.len() > expected_total {
        return Err(PreimageStorageError::TrailingData);
    }

    Ok(ParsedEnvelope {
        context: StorageContext {
            game_id,
            attempt,
            role,
            accepted_deal_digest,
        },
        nonce,
        aad: &bytes[..HEADER_SIZE],
        ciphertext: &bytes[HEADER_SIZE..],
    })
}
