#![forbid(unsafe_code)]
//! Tagged hashes and exact rejection-sampled Fiat--Shamir challenges.

use dlog52_codec::{put_ascii, put_bytes, put_u32};
use k256::{FieldBytes, Scalar, elliptic_curve::PrimeField};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Challenge derivation failed after exhausting the counter space.
#[derive(Debug, Error)]
#[error("challenge counter exhausted")]
pub struct ChallengeExhausted;

/// BIP340-style tagged SHA-256 with no implicit data framing.
#[must_use]
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);
    h.finalize().into()
}

/// Derive the first canonical, nonzero secp256k1 scalar.
pub fn hash_scalar(label: &str, body: &[u8]) -> Result<Scalar, ChallengeExhausted> {
    for counter in 0..=u32::MAX {
        let mut framed = Vec::with_capacity(label.len() + body.len() + 12);
        put_ascii(&mut framed, label);
        put_bytes(&mut framed, body);
        put_u32(&mut framed, counter);
        let digest = tagged_hash("DLOG52/challenge/v1", &framed);
        let candidate = Scalar::from_repr(FieldBytes::from(digest));
        if let Some(scalar) = Option::<Scalar>::from(candidate) {
            if !bool::from(scalar.is_zero()) {
                return Ok(scalar);
            }
        }
    }
    Err(ChallengeExhausted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tagged_hash_is_stable() {
        assert_eq!(
            hex::encode(tagged_hash("tag", b"data")),
            "c4e484e58d2f73685d37e56369524916937d3f72bb0bb5e0cc962f5d65836500"
        );
        assert!(!bool::from(
            hash_scalar("example", b"body").unwrap().is_zero()
        ));
    }
}
