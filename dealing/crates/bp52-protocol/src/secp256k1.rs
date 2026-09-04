//! Pure-Rust browser adapter for the narrow `rust-secp256k1` API used here.
//!
//! This is not a general secp256k1 compatibility layer. It only supplies
//! x-only keys and BIP340 signing/verification for authenticated DEAL wire
//! objects. The implementation delegates those operations to `k256`.

use core::{fmt, marker::PhantomData};

use k256::schnorr::{SigningKey, VerifyingKey};

/// Marker for a context capable of signing and verification.
#[derive(Clone, Copy, Debug)]
pub struct All;

/// Marker trait for signing-capable contexts.
pub trait Signing {}

/// Marker trait for verification-capable contexts.
pub trait Verification {}

impl Signing for All {}
impl Verification for All {}

/// Browser BIP340 operation context.
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1<C> {
    marker: PhantomData<C>,
}

impl Secp256k1<All> {
    /// Constructs a signing and verification context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl Default for Secp256k1<All> {
    fn default() -> Self {
        Self::new()
    }
}

/// BIP340 signing keypair.
#[derive(Clone)]
pub struct Keypair(SigningKey);

impl Keypair {
    /// Parses a 32-byte big-endian secp256k1 secret scalar.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for zero, out-of-range, or non-32-byte input.
    pub fn from_seckey_slice<C>(_: &Secp256k1<C>, bytes: &[u8]) -> Result<Self, Error> {
        SigningKey::from_bytes(bytes).map(Self).map_err(|_| Error)
    }

    /// Returns the BIP340 x-only public key and its normalized even parity.
    #[must_use]
    pub fn x_only_public_key(&self) -> (XOnlyPublicKey, Parity) {
        (
            XOnlyPublicKey(self.0.verifying_key().to_bytes().into()),
            Parity::Even,
        )
    }
}

/// Parity of the normalized BIP340 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parity {
    /// BIP340 normalizes signing keys to an even-y public point.
    Even,
}

/// Canonical 32-byte BIP340 x-only public key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct XOnlyPublicKey([u8; 32]);

impl XOnlyPublicKey {
    /// Parses and validates an x-only secp256k1 public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] unless the bytes encode a curve x-coordinate.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| Error)?;
        Ok(Self(key.to_bytes().into()))
    }

    /// Serializes the x-only key.
    #[must_use]
    pub const fn serialize(self) -> [u8; 32] {
        self.0
    }
}

/// Exact 32-byte already-hashed BIP340 message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message([u8; 32]);

impl Message {
    /// Wraps an exact digest without hashing it again.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

/// BIP340 signature support.
pub mod schnorr {
    use super::Error;

    /// Canonical 64-byte BIP340 signature.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Signature(pub(super) k256::schnorr::Signature);

    impl Signature {
        /// Parses a canonical BIP340 signature.
        ///
        /// # Errors
        ///
        /// Returns [`Error`] for malformed scalars or coordinates.
        pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
            k256::schnorr::Signature::try_from(bytes)
                .map(Self)
                .map_err(|_| Error)
        }

        /// Serializes this signature.
        #[must_use]
        pub fn serialize(self) -> [u8; 64] {
            self.0.to_bytes()
        }
    }
}

impl<C: Signing> Secp256k1<C> {
    /// Signs a digest using the BIP340 auxiliary-randomness construction.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for the cryptographically negligible invalid nonce
    /// or response-scalar cases defined by BIP340.
    pub fn sign_schnorr_with_aux_rand(
        &self,
        message: &Message,
        keypair: &Keypair,
        auxiliary_randomness: &[u8; 32],
    ) -> Result<schnorr::Signature, Error> {
        keypair
            .0
            .sign_prehash_with_aux_rand(&message.0, auxiliary_randomness)
            .map(schnorr::Signature)
            .map_err(|_| Error)
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Verifies an exact already-hashed BIP340 message.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when signature verification fails.
    pub fn verify_schnorr(
        &self,
        signature: &schnorr::Signature,
        message: &Message,
        public_key: &XOnlyPublicKey,
    ) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(&public_key.0).map_err(|_| Error)?;
        key.verify_raw(&message.0, &signature.0).map_err(|_| Error)
    }
}

/// Browser adapter error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid secp256k1 key or BIP340 signature")
    }
}

impl std::error::Error for Error {}
