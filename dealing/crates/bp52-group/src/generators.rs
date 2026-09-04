//! Fixed Ristretto generators.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    traits::{Identity, IsIdentity},
};
use sha2::Sha512;

use crate::elgamal::GroupError;

/// Exact domain string used to derive the independent message generator.
pub const MESSAGE_GENERATOR_DOMAIN: &[u8] = b"BP52-DEAL-v1/message-generator";

/// The fixed v1 Ristretto generators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolGenerators {
    blinding: RistrettoPoint,
    message: RistrettoPoint,
}

impl ProtocolGenerators {
    /// Derives and validates the fixed v1 generator pair.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::InvalidGenerator`] if the fixed hash-to-group
    /// output violates the required generator separation invariants.
    pub fn derive() -> Result<Self, GroupError> {
        let blinding = RISTRETTO_BASEPOINT_POINT;
        let message = RistrettoPoint::hash_from_bytes::<Sha512>(MESSAGE_GENERATOR_DOMAIN);

        if message.is_identity()
            || message == blinding
            || message == -blinding
            || blinding == RistrettoPoint::identity()
        {
            return Err(GroupError::InvalidGenerator);
        }

        Ok(Self { blinding, message })
    }

    /// Returns the fixed standard Ristretto base point used for keys and
    /// blindings.
    #[must_use]
    pub const fn blinding(&self) -> RistrettoPoint {
        self.blinding
    }

    /// Returns the fixed independently hash-derived plaintext generator.
    #[must_use]
    pub const fn message(&self) -> RistrettoPoint {
        self.message
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use curve25519_dalek::traits::IsIdentity;

    use super::ProtocolGenerators;

    #[test]
    fn generators_are_distinct_and_nonidentity() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| {
            panic!("fixed generator derivation failed: {error}");
        });
        assert!(!generators.blinding().is_identity());
        assert!(!generators.message().is_identity());
        assert_ne!(generators.blinding(), generators.message());
        assert_ne!(-generators.blinding(), generators.message());
    }

    #[test]
    fn message_generator_is_deterministic() {
        let first = ProtocolGenerators::derive().unwrap_or_else(|error| {
            panic!("fixed generator derivation failed: {error}");
        });
        let second = ProtocolGenerators::derive().unwrap_or_else(|error| {
            panic!("fixed generator derivation failed: {error}");
        });
        assert_eq!(first, second);
        assert_eq!(
            first.message().compress().to_bytes(),
            [
                0x5c, 0x08, 0x96, 0x9e, 0x21, 0x16, 0x50, 0x4c, 0xb9, 0xa1, 0x99, 0x9c, 0xe0, 0x34,
                0x7f, 0xa8, 0x22, 0xb0, 0x5a, 0xdd, 0x6a, 0x6f, 0xc7, 0x96, 0x49, 0x93, 0x02, 0x47,
                0x33, 0xda, 0x6e, 0x20,
            ]
        );
    }
}
