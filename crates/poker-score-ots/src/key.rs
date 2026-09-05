//! Lamport message, key-context, and key-material types.

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    LamportError, LamportStorageKey, SealedLamportSecretKey, SecretStorageError,
    storage::plaintext_len,
};

/// Size in bytes of a Lamport secret or public hash.
pub const HASH_SIZE: usize = 32;
/// Width of either player's showdown-score message.
pub const SCORE_BIT_WIDTH: u8 = 24;

/// Purpose domain for a one-time key.
///
/// Wire discriminant zero was the retired betting-action purpose and is
/// deliberately rejected so old action keys cannot be reinterpreted.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LamportPurpose {
    /// Alice's packed 24-bit showdown score.
    AliceScore24Bit = 1,
    /// Bob's packed 24-bit showdown score.
    BobScore24Bit = 2,
}

impl LamportPurpose {
    /// Returns the only valid bit width for this purpose.
    #[must_use]
    pub const fn bit_width(self) -> u8 {
        match self {
            Self::AliceScore24Bit | Self::BobScore24Bit => SCORE_BIT_WIDTH,
        }
    }
}

impl TryFrom<u8> for LamportPurpose {
    type Error = LamportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AliceScore24Bit),
            2 => Ok(Self::BobScore24Bit),
            other => Err(LamportError::InvalidPurpose(other)),
        }
    }
}

/// A positive unsigned value that fits exactly in the 24-bit score field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Score24(u32);

impl Score24 {
    /// Largest value representable by the score certificate.
    pub const MAX: u32 = 0x00ff_ffff;

    /// Validates and constructs a fixed-width score message.
    ///
    /// # Errors
    ///
    /// Returns [`LamportError::InvalidScore`] for zero or a value wider than
    /// 24 bits. Poker-score canonicality is enforced by the poker layer.
    pub fn new(value: u32) -> Result<Self, LamportError> {
        if value == 0 || value > Self::MAX {
            return Err(LamportError::InvalidScore(value));
        }
        Ok(Self(value))
    }

    /// Returns the packed score integer.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the exact three-byte big-endian representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 3] {
        let bytes = self.0.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }
}

impl TryFrom<u32> for Score24 {
    type Error = LamportError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Score24> for u32 {
    fn from(value: Score24) -> Self {
        value.get()
    }
}

/// One of the two score messages authenticated by the Lamport layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LamportMessage {
    /// Alice's 24-bit showdown score.
    AliceScore(Score24),
    /// Bob's 24-bit showdown score.
    BobScore(Score24),
}

impl LamportMessage {
    /// Returns the key purpose required for this message.
    #[must_use]
    pub const fn purpose(self) -> LamportPurpose {
        match self {
            Self::AliceScore(_) => LamportPurpose::AliceScore24Bit,
            Self::BobScore(_) => LamportPurpose::BobScore24Bit,
        }
    }

    /// Returns message bits in fixed-width, most-significant-first order.
    #[must_use]
    pub fn bits_msb_first(self) -> Vec<u8> {
        match self {
            Self::AliceScore(score) | Self::BobScore(score) => {
                bits_from_u32(score.get(), SCORE_BIT_WIDTH)
            }
        }
    }
}

/// Immutable game, node, and purpose binding carried by a key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyContext {
    /// Identifier of the exact compiled chain game.
    pub chain_game_id: [u8; 32],
    /// Path-dependent identifier of the exact graph node.
    pub node_id: [u8; 32],
    /// Exact use authorized by the one-time key.
    pub purpose: LamportPurpose,
}

impl KeyContext {
    /// Constructs an exact one-time key context.
    #[must_use]
    pub const fn new(chain_game_id: [u8; 32], node_id: [u8; 32], purpose: LamportPurpose) -> Self {
        Self {
            chain_game_id,
            node_id,
            purpose,
        }
    }
}

/// Public half of a context-bound Lamport one-time key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LamportPublicKey {
    context: KeyContext,
    public_hash_pairs: Vec<[[u8; HASH_SIZE]; 2]>,
}

impl LamportPublicKey {
    /// Constructs and validates public key material received from a peer.
    ///
    /// # Errors
    ///
    /// Returns [`LamportError::InvalidBitWidth`] unless the pair count is
    /// exactly the fixed width assigned to `context.purpose`.
    pub fn from_parts(
        context: KeyContext,
        public_hash_pairs: Vec<[[u8; HASH_SIZE]; 2]>,
    ) -> Result<Self, LamportError> {
        validate_width(context.purpose, public_hash_pairs.len())?;
        validate_unique_public_hashes(&public_hash_pairs)?;
        Ok(Self {
            context,
            public_hash_pairs,
        })
    }

    /// Returns the exact game/node/purpose context.
    #[must_use]
    pub const fn context(&self) -> KeyContext {
        self.context
    }

    /// Returns the public hash pairs in most-significant-first bit order.
    #[must_use]
    pub fn public_hash_pairs(&self) -> &[[[u8; HASH_SIZE]; 2]] {
        &self.public_hash_pairs
    }

    /// Returns the exact number of message bits accepted by the key.
    #[must_use]
    pub fn bit_width(&self) -> usize {
        self.public_hash_pairs.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretState {
    Fresh,
    SignatureIssued,
    Destroyed,
}

/// Secret half of a context-bound Lamport one-time key.
///
/// This type intentionally does not implement `Clone`, exposes no secret-key
/// codec, redacts its `Debug` output, and erases its allocation on drop.
pub struct LamportSecretKey {
    context: KeyContext,
    secret_pairs: Vec<[[u8; HASH_SIZE]; 2]>,
    state: SecretState,
}

impl LamportSecretKey {
    /// Returns the immutable context without exposing secret material.
    #[must_use]
    pub const fn context(&self) -> KeyContext {
        self.context
    }

    /// Returns whether this key has already issued a signature.
    #[must_use]
    pub const fn signature_was_issued(&self) -> bool {
        matches!(self.state, SecretState::SignatureIssued)
    }

    /// Returns whether all in-memory secret pairs have been erased.
    #[must_use]
    pub fn is_erased(&self) -> bool {
        self.state == SecretState::Destroyed
            && self
                .secret_pairs
                .iter()
                .flatten()
                .all(|secret| secret.iter().all(|byte| *byte == 0))
    }

    /// Check whether this fresh secret key is the private half of an exact
    /// public key without revealing or consuming any secret material.
    ///
    /// This returns `false` after a signature has been issued or the key has
    /// been destroyed because selected secrets are no longer available for a
    /// complete comparison.
    #[must_use]
    pub fn matches_public_key(&self, public_key: &LamportPublicKey) -> bool {
        if self.state != SecretState::Fresh
            || self.context != public_key.context
            || self.secret_pairs.len() != public_key.public_hash_pairs.len()
        {
            return false;
        }
        let mut difference = 0_u8;
        for (secret_pair, public_pair) in
            self.secret_pairs.iter().zip(&public_key.public_hash_pairs)
        {
            for choice in 0..2 {
                let derived = sha256(&secret_pair[choice]);
                for (actual, expected) in derived.iter().zip(&public_pair[choice]) {
                    difference |= actual ^ expected;
                }
            }
        }
        difference == 0
    }

    /// Authenticates and encrypts this unused key for persistence, then erases
    /// its live plaintext allocation.
    ///
    /// The expected public key is checked before encryption, preventing a
    /// correctly encrypted but unusable private key from entering storage.
    /// The operation is atomic with respect to this owner: validation, RNG,
    /// or AEAD failure leaves the live secret untouched and usable, while a
    /// successful return leaves `self` destroyed.
    ///
    /// # Errors
    ///
    /// Returns [`SecretStorageError::SecretNotFresh`] after signing or erasure,
    /// [`SecretStorageError::PublicKeyMismatch`] for the wrong public key, or
    /// an RNG/AEAD storage error.
    pub fn seal_at_rest<R>(
        &mut self,
        expected_public_key: &LamportPublicKey,
        storage_key: &mut LamportStorageKey,
        rng: &mut R,
    ) -> Result<SealedLamportSecretKey, SecretStorageError>
    where
        R: CryptoRng + RngCore,
    {
        if self.state != SecretState::Fresh {
            return Err(SecretStorageError::SecretNotFresh);
        }
        if !self.matches_public_key(expected_public_key) {
            return Err(SecretStorageError::PublicKeyMismatch);
        }

        let mut plaintext = Zeroizing::new(Vec::with_capacity(plaintext_len(self.context.purpose)));
        for pair in &self.secret_pairs {
            plaintext.extend_from_slice(&pair[0]);
            plaintext.extend_from_slice(&pair[1]);
        }
        let sealed = SealedLamportSecretKey::seal(self.context, &plaintext, storage_key, rng)?;
        self.zeroize();
        Ok(sealed)
    }

    /// Erases all remaining secrets after any branch of this node confirms.
    ///
    /// This is idempotent and may be called for a timeout branch even if the
    /// local actor never issued a signature.
    pub fn erase_after_branch_confirmation(&mut self) {
        self.zeroize();
    }

    pub(crate) fn reveal_once(
        &mut self,
        message: LamportMessage,
    ) -> Result<Vec<[u8; HASH_SIZE]>, LamportError> {
        if self.context.purpose != message.purpose() {
            return Err(LamportError::WrongPurpose);
        }
        match self.state {
            SecretState::Fresh => {}
            SecretState::SignatureIssued => return Err(LamportError::KeyAlreadyUsed),
            SecretState::Destroyed => return Err(LamportError::KeyDestroyed),
        }

        let bits = message.bits_msb_first();
        validate_width(self.context.purpose, bits.len())?;
        let mut revealed = Vec::with_capacity(bits.len());
        for (pair, bit) in self.secret_pairs.iter_mut().zip(bits) {
            let selected = usize::from(bit);
            revealed.push(pair[selected]);
            pair[selected].zeroize();
        }
        self.state = SecretState::SignatureIssued;
        Ok(revealed)
    }
}

impl SealedLamportSecretKey {
    /// Authenticates this stored key and verifies its complete private/public
    /// correspondence without releasing a live signing key.
    ///
    /// This is intended for pre-funding inventory checks. The ciphertext owner
    /// remains sealed and can later be consumed by [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns a context, authentication, length, or private-key mismatch.
    pub fn verify(
        &self,
        expected_public_key: &LamportPublicKey,
        storage_key: &LamportStorageKey,
    ) -> Result<(), SecretStorageError> {
        let secret = self.reconstruct(expected_public_key, storage_key)?;
        drop(secret);
        Ok(())
    }

    /// Authenticates and consumes this encrypted owner, returning a fresh
    /// in-memory Lamport key only after complete private-key validation.
    ///
    /// The caller should load `expected_public_key` from the verified compiled
    /// graph. The encrypted envelope binds its exact game, node, and purpose,
    /// and the reconstructed secrets must hash to every expected public hash.
    ///
    /// # Errors
    ///
    /// Returns a context, authentication, length, or private-key mismatch
    /// without returning any partially reconstructed secret owner.
    pub fn open(
        self,
        expected_public_key: &LamportPublicKey,
        storage_key: &LamportStorageKey,
    ) -> Result<LamportSecretKey, SecretStorageError> {
        self.reconstruct(expected_public_key, storage_key)
    }

    fn reconstruct(
        &self,
        expected_public_key: &LamportPublicKey,
        storage_key: &LamportStorageKey,
    ) -> Result<LamportSecretKey, SecretStorageError> {
        let expected_context = expected_public_key.context();
        let plaintext = self.open_plaintext(expected_context, storage_key)?;
        if plaintext.len() != plaintext_len(expected_context.purpose) {
            return Err(SecretStorageError::InvalidPlaintext);
        }

        let mut secret_pairs =
            Vec::with_capacity(usize::from(expected_context.purpose.bit_width()));
        for pair_bytes in plaintext.chunks_exact(2 * HASH_SIZE) {
            let mut pair = [[0_u8; HASH_SIZE]; 2];
            pair[0].copy_from_slice(&pair_bytes[..HASH_SIZE]);
            pair[1].copy_from_slice(&pair_bytes[HASH_SIZE..]);
            secret_pairs.push(pair);
        }
        let secret = LamportSecretKey {
            context: expected_context,
            secret_pairs,
            state: SecretState::Fresh,
        };
        if !secret.matches_public_key(expected_public_key) {
            return Err(SecretStorageError::InvalidPlaintext);
        }
        Ok(secret)
    }
}

impl fmt::Debug for LamportSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LamportSecretKey")
            .field("context", &self.context)
            .field("secret_material", &"<redacted>")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Zeroize for LamportSecretKey {
    fn zeroize(&mut self) {
        self.secret_pairs.zeroize();
        self.state = SecretState::Destroyed;
    }
}

impl Drop for LamportSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generates fresh independent secret pairs for one exact key context.
///
/// The caller must provide a cryptographically secure random generator. The
/// function rejects duplicate 32-byte secrets even though they should be
/// computationally negligible with a correct generator.
///
/// # Errors
///
/// Returns [`LamportError::DuplicateGeneratedSecret`] if the supplied random
/// generator repeats any secret inside this key.
pub fn generate_key<R>(
    rng: &mut R,
    context: KeyContext,
) -> Result<(LamportSecretKey, LamportPublicKey), LamportError>
where
    R: CryptoRng + RngCore,
{
    let width = usize::from(context.purpose.bit_width());
    let mut secret_pairs = Vec::with_capacity(width);
    let mut public_hash_pairs = Vec::with_capacity(width);

    for pair_index in 0..width {
        secret_pairs.push([[0_u8; HASH_SIZE]; 2]);
        for choice in 0..2 {
            rng.fill_bytes(&mut secret_pairs[pair_index][choice]);
            let duplicates_previous_pair = secret_pairs[..pair_index]
                .iter()
                .flatten()
                .any(|prior| prior == &secret_pairs[pair_index][choice]);
            let duplicates_current_pair =
                choice == 1 && secret_pairs[pair_index][0] == secret_pairs[pair_index][1];
            if duplicates_previous_pair || duplicates_current_pair {
                secret_pairs.zeroize();
                return Err(LamportError::DuplicateGeneratedSecret);
            }
        }
        public_hash_pairs.push([
            sha256(&secret_pairs[pair_index][0]),
            sha256(&secret_pairs[pair_index][1]),
        ]);
    }

    let public = LamportPublicKey {
        context,
        public_hash_pairs,
    };
    let secret = LamportSecretKey {
        context,
        secret_pairs,
        state: SecretState::Fresh,
    };
    Ok((secret, public))
}

pub(crate) fn sha256(value: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    Sha256::digest(value).into()
}

pub(crate) fn tagged_sha256(tag: &[u8], bytes: &[u8]) -> [u8; HASH_SIZE] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn bits_from_u32(value: u32, width: u8) -> Vec<u8> {
    (0..width)
        .map(|index| {
            let shift = u32::from(width - 1 - index);
            u8::from(((value >> shift) & 1) != 0)
        })
        .collect()
}

pub(crate) fn validate_width(purpose: LamportPurpose, actual: usize) -> Result<(), LamportError> {
    let expected = purpose.bit_width();
    let actual_u8 = u8::try_from(actual).unwrap_or(u8::MAX);
    if actual_u8 != expected {
        return Err(LamportError::InvalidBitWidth {
            expected,
            actual: actual_u8,
        });
    }
    Ok(())
}

fn validate_unique_public_hashes(
    public_hash_pairs: &[[[u8; HASH_SIZE]; 2]],
) -> Result<(), LamportError> {
    for (index, hash) in public_hash_pairs.iter().flatten().enumerate() {
        if public_hash_pairs
            .iter()
            .flatten()
            .skip(index + 1)
            .any(|candidate| candidate == hash)
        {
            return Err(LamportError::DuplicatePublicHash);
        }
    }
    Ok(())
}
