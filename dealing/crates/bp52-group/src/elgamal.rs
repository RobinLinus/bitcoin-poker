//! Threshold exponential ElGamal operations.

use core::{fmt, ops};

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::generators::ProtocolGenerators;

/// Errors raised while validating or operating on group values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GroupError {
    /// The fixed message generator failed its required checks.
    #[error("invalid fixed protocol generator")]
    InvalidGenerator,
    /// A compressed Ristretto encoding did not decompress canonically.
    #[error("invalid compressed Ristretto point")]
    InvalidPoint,
    /// A scalar was not canonically encoded.
    #[error("noncanonical scalar")]
    NonCanonicalScalar,
    /// A point required to be nonidentity was the identity.
    #[error("unexpected identity point")]
    UnexpectedIdentity,
    /// A scalar required to be nonzero was zero.
    #[error("zero scalar")]
    ZeroScalar,
    /// The sum of the two public-key shares was the identity.
    #[error("joint public key is the identity")]
    JointKeyIdentity,
    /// Equal key shares would reveal the complete joint secret to both roles.
    #[error("threshold public-key shares are equal")]
    DuplicateKeyShare,
    /// A caller-supplied RNG repeatedly returned rejected values.
    #[error("random source failed rejection sampling")]
    RngFailure,
}

const MAX_REJECTION_ATTEMPTS: usize = 128;

/// A secret scalar statically known to be nonzero.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NonZeroScalar(Scalar);

impl NonZeroScalar {
    /// Samples uniformly from the nonzero field elements.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::RngFailure`] if the random source produces only
    /// zero scalars through the bounded sampling loop.
    pub fn random<R>(rng: &mut R) -> Result<Self, GroupError>
    where
        R: CryptoRng + RngCore,
    {
        for _ in 0..MAX_REJECTION_ATTEMPTS {
            let scalar = Scalar::random(&mut *rng);
            if scalar != Scalar::ZERO {
                return Ok(Self(scalar));
            }
        }
        Err(GroupError::RngFailure)
    }

    /// Validates an existing scalar as nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::ZeroScalar`] when `scalar` is zero.
    pub fn new(scalar: Scalar) -> Result<Self, GroupError> {
        if scalar == Scalar::ZERO {
            Err(GroupError::ZeroScalar)
        } else {
            Ok(Self(scalar))
        }
    }

    /// Borrows the inner scalar for group operations.
    #[must_use]
    pub const fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Returns the canonical scalar bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for NonZeroScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NonZeroScalar([REDACTED])")
    }
}

/// One threshold secret-key share.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyShare(NonZeroScalar);

impl SecretKeyShare {
    /// Samples a fresh nonzero key share.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::RngFailure`] if bounded nonzero sampling fails.
    pub fn random<R>(rng: &mut R) -> Result<Self, GroupError>
    where
        R: CryptoRng + RngCore,
    {
        Ok(Self(NonZeroScalar::random(rng)?))
    }

    /// Constructs a key share from a validated nonzero scalar.
    #[must_use]
    pub const fn from_nonzero(scalar: NonZeroScalar) -> Self {
        Self(scalar)
    }

    /// Returns the public-key share for these fixed generators.
    #[must_use]
    pub fn public_key(&self, generators: &ProtocolGenerators) -> PublicKeyShare {
        PublicKeyShare(self.0.as_scalar() * generators.blinding())
    }

    /// Computes a partial decryption point `sk * R`.
    #[must_use]
    pub fn partial_decrypt(&self, ciphertext: &ElGamalCiphertext) -> RistrettoPoint {
        self.0.as_scalar() * ciphertext.r
    }

    /// Borrows the nonzero scalar for proof generation.
    #[must_use]
    pub const fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        &self.0
    }
}

/// A validated public-key share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyShare(RistrettoPoint);

impl PublicKeyShare {
    /// Validates a public-key share as nonidentity.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::UnexpectedIdentity`] for the identity point.
    pub fn new(point: RistrettoPoint) -> Result<Self, GroupError> {
        if point.is_identity() {
            Err(GroupError::UnexpectedIdentity)
        } else {
            Ok(Self(point))
        }
    }

    /// Borrows the public point.
    #[must_use]
    pub const fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    /// Returns the canonical compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Decodes a canonical, nonidentity public-key share.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::InvalidPoint`] for an invalid encoding or
    /// [`GroupError::UnexpectedIdentity`] for the identity.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, GroupError> {
        Self::new(decode_point(bytes, false)?)
    }
}

/// A validated joint threshold public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JointPublicKey(RistrettoPoint);

impl JointPublicKey {
    /// Adds two public shares and rejects the identity result.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::DuplicateKeyShare`] for equal shares or
    /// [`GroupError::JointKeyIdentity`] when their sum is the identity.
    pub fn combine(a: &PublicKeyShare, b: &PublicKeyShare) -> Result<Self, GroupError> {
        if a == b {
            return Err(GroupError::DuplicateKeyShare);
        }
        let point = a.as_point() + b.as_point();
        if point.is_identity() {
            Err(GroupError::JointKeyIdentity)
        } else {
            Ok(Self(point))
        }
    }

    /// Validates a directly decoded joint key.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::JointKeyIdentity`] for the identity point.
    pub fn new(point: RistrettoPoint) -> Result<Self, GroupError> {
        if point.is_identity() {
            Err(GroupError::JointKeyIdentity)
        } else {
            Ok(Self(point))
        }
    }

    /// Borrows the joint public point.
    #[must_use]
    pub const fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    /// Returns the canonical compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

/// An in-memory exponential-ElGamal ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalCiphertext {
    /// Encryption-randomness component `r*G`.
    pub r: RistrettoPoint,
    /// Masked message component `v*M + r*Y`.
    pub s: RistrettoPoint,
}

impl ElGamalCiphertext {
    /// Encrypts a scalar with caller-provided nonzero randomness.
    #[must_use]
    pub fn encrypt(
        value: Scalar,
        randomness: &NonZeroScalar,
        joint_key: &JointPublicKey,
        generators: &ProtocolGenerators,
    ) -> Self {
        let r = randomness.as_scalar() * generators.blinding();
        let s = value * generators.message() + randomness.as_scalar() * joint_key.as_point();
        Self { r, s }
    }

    /// Encodes a public constant with zero encryption randomness.
    #[must_use]
    pub fn public_constant(value: i64, generators: &ProtocolGenerators) -> Self {
        Self {
            r: RistrettoPoint::identity(),
            s: scalar_from_i64(value) * generators.message(),
        }
    }

    /// Multiplies both components by the same scalar.
    #[must_use]
    pub fn scale(&self, scalar: &Scalar) -> Self {
        Self {
            r: scalar * self.r,
            s: scalar * self.s,
        }
    }

    /// Compresses both points into the canonical wire representation.
    #[must_use]
    pub fn to_bytes(&self) -> CiphertextBytes {
        CiphertextBytes {
            r: self.r.compress().to_bytes(),
            s: self.s.compress().to_bytes(),
        }
    }
}

impl ops::Add<&ElGamalCiphertext> for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn add(self, rhs: &ElGamalCiphertext) -> Self::Output {
        ElGamalCiphertext {
            r: self.r + rhs.r,
            s: self.s + rhs.s,
        }
    }
}

impl ops::Sub<&ElGamalCiphertext> for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;

    fn sub(self, rhs: &ElGamalCiphertext) -> Self::Output {
        ElGamalCiphertext {
            r: self.r - rhs.r,
            s: self.s - rhs.s,
        }
    }
}

/// Canonically compressed ciphertext used at the wire/API boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CiphertextBytes {
    /// Compressed `R` component.
    pub r: [u8; 32],
    /// Compressed `S` component.
    pub s: [u8; 32],
}

impl CiphertextBytes {
    /// Decompresses both components. Identity components are permitted because
    /// derived ciphertexts and public constants can contain them.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::InvalidPoint`] if either encoding is invalid.
    pub fn decompress(self) -> Result<ElGamalCiphertext, GroupError> {
        Ok(ElGamalCiphertext {
            r: decode_point(self.r, true)?,
            s: decode_point(self.s, true)?,
        })
    }

    /// Decompresses an original contribution and rejects identity `R`.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::InvalidPoint`] for an invalid component or
    /// [`GroupError::UnexpectedIdentity`] when `R` is the identity.
    pub fn decompress_contribution(self) -> Result<ElGamalCiphertext, GroupError> {
        let ciphertext = self.decompress()?;
        if ciphertext.r.is_identity() {
            Err(GroupError::UnexpectedIdentity)
        } else {
            Ok(ciphertext)
        }
    }
}

impl Encode for CiphertextBytes {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_bytes(&self.r);
        writer.write_bytes(&self.s);
        Ok(())
    }
}

impl Decode for CiphertextBytes {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            r: reader.read_array()?,
            s: reader.read_array()?,
        })
    }
}

/// Creates a Pedersen commitment `value*M + blinding*G`.
#[must_use]
pub fn commit(value: Scalar, blinding: Scalar, generators: &ProtocolGenerators) -> RistrettoPoint {
    value * generators.message() + blinding * generators.blinding()
}

/// Combines two threshold shares into the encoded plaintext group element.
#[must_use]
pub fn complete_decryption(
    ciphertext: &ElGamalCiphertext,
    share_a: &RistrettoPoint,
    share_b: &RistrettoPoint,
) -> RistrettoPoint {
    ciphertext.s - share_a - share_b
}

/// Decodes a canonical Ristretto point and optionally permits identity.
///
/// # Errors
///
/// Returns [`GroupError::InvalidPoint`] if `bytes` does not decompress and
/// [`GroupError::UnexpectedIdentity`] when identity is disallowed.
pub fn decode_point(bytes: [u8; 32], allow_identity: bool) -> Result<RistrettoPoint, GroupError> {
    let point = CompressedRistretto(bytes)
        .decompress()
        .ok_or(GroupError::InvalidPoint)?;
    if !allow_identity && point.is_identity() {
        return Err(GroupError::UnexpectedIdentity);
    }
    Ok(point)
}

/// Decodes a canonical scalar.
///
/// # Errors
///
/// Returns [`GroupError::NonCanonicalScalar`] for a noncanonical encoding.
pub fn decode_scalar(bytes: [u8; 32]) -> Result<Scalar, GroupError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(GroupError::NonCanonicalScalar)
}

/// Samples a contribution uniformly from `0..52` using byte rejection.
///
/// # Errors
///
/// Returns [`GroupError::RngFailure`] if bounded byte rejection fails.
pub fn sample_card_value<R>(rng: &mut R) -> Result<u8, GroupError>
where
    R: CryptoRng + RngCore,
{
    for _ in 0..MAX_REJECTION_ATTEMPTS {
        let mut byte = [0_u8; 1];
        rng.fill_bytes(&mut byte);
        if byte[0] < 208 {
            return Ok(byte[0] % 52);
        }
    }
    Err(GroupError::RngFailure)
}

fn scalar_from_i64(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value.unsigned_abs())
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use curve25519_dalek::{scalar::Scalar, traits::IsIdentity};
    use rand_core::OsRng;

    use super::{
        CiphertextBytes, ElGamalCiphertext, GroupError, JointPublicKey, NonZeroScalar,
        SecretKeyShare, commit, complete_decryption, decode_scalar, sample_card_value,
    };
    use crate::ProtocolGenerators;

    #[test]
    fn threshold_encryption_round_trip() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public_a = secret_a.public_key(&generators);
        let public_b = secret_b.public_key(&generators);
        let joint =
            JointPublicKey::combine(&public_a, &public_b).unwrap_or_else(|error| panic!("{error}"));
        let randomness =
            NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let ciphertext =
            ElGamalCiphertext::encrypt(Scalar::from(37_u64), &randomness, &joint, &generators);

        let plaintext = complete_decryption(
            &ciphertext,
            &secret_a.partial_decrypt(&ciphertext),
            &secret_b.partial_decrypt(&ciphertext),
        );
        assert_eq!(plaintext, Scalar::from(37_u64) * generators.message());
    }

    #[test]
    fn homomorphic_addition_and_subtraction() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let joint = JointPublicKey::combine(
            &secret_a.public_key(&generators),
            &secret_b.public_key(&generators),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let first = ElGamalCiphertext::encrypt(
            Scalar::from(51_u64),
            &NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}")),
            &joint,
            &generators,
        );
        let second = ElGamalCiphertext::encrypt(
            Scalar::from(12_u64),
            &NonZeroScalar::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}")),
            &joint,
            &generators,
        );
        let difference = &(&first + &second) - &ElGamalCiphertext::public_constant(52, &generators);
        let plaintext = complete_decryption(
            &difference,
            &secret_a.partial_decrypt(&difference),
            &secret_b.partial_decrypt(&difference),
        );
        assert_eq!(plaintext, Scalar::from(11_u64) * generators.message());
    }

    #[test]
    fn contribution_decoder_rejects_identity_r() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let bytes = CiphertextBytes {
            r: curve25519_dalek::RistrettoPoint::default()
                .compress()
                .to_bytes(),
            s: generators.message().compress().to_bytes(),
        };
        assert_eq!(
            bytes.decompress_contribution(),
            Err(GroupError::UnexpectedIdentity)
        );
    }

    #[test]
    fn scalar_parser_rejects_noncanonical_encoding() {
        assert_eq!(
            decode_scalar([0xff; 32]),
            Err(GroupError::NonCanonicalScalar)
        );
    }

    #[test]
    fn equal_threshold_key_shares_are_rejected() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public = secret.public_key(&generators);
        assert_eq!(
            JointPublicKey::combine(&public, &public),
            Err(GroupError::DuplicateKeyShare)
        );
    }

    #[test]
    fn commitment_formula_uses_independent_generators() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let commitment = commit(Scalar::from(4_u64), Scalar::from(9_u64), &generators);
        assert_eq!(
            commitment,
            Scalar::from(4_u64) * generators.message()
                + Scalar::from(9_u64) * generators.blinding()
        );
        assert!(!commitment.is_identity());
    }

    #[test]
    fn sampled_values_are_in_range() {
        for _ in 0..10_000 {
            assert!(sample_card_value(&mut OsRng).unwrap_or_else(|error| panic!("{error}")) < 52);
        }
    }

    #[derive(Default)]
    struct ZeroRng;

    impl rand_core::RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
            destination.fill(0);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for ZeroRng {}

    #[test]
    fn broken_rng_cannot_hang_nonzero_scalar_sampling() {
        assert!(matches!(
            NonZeroScalar::random(&mut ZeroRng),
            Err(GroupError::RngFailure)
        ));
    }
}
