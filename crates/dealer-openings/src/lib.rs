#![forbid(unsafe_code)]
//! Verified selective openings and card-specific BIP340 signing capability.

use dealer_group::{N_SLOTS, encode_scalar, protocol_parameters};
use dealer_protocol::{Role, VerifiedAcceptedDeal, point_xonly};
use k256::{
    Scalar,
    schnorr::{Signature, SigningKey},
};
use thiserror::Error;
use zeroize::Zeroize;

/// Opening or key-derivation failure.
#[derive(Debug, Error)]
pub enum OpeningError {
    /// Slot is outside 0..8.
    #[error("invalid slot")]
    Slot,
    /// Value is outside 0..51 or the commitment equation fails.
    #[error("invalid share opening")]
    Opening,
    /// The two openings do not derive the accepted candidate key.
    #[error("candidate key mismatch")]
    Candidate,
    /// Derived scalar is zero.
    #[error("derived signing key is zero")]
    ZeroKey,
    /// BIP340 signing failed.
    #[error("BIP340 signing failed")]
    Signing,
}

/// Canonical contribution opening.
pub struct ShareOpening {
    /// Contribution in 0..51.
    pub value: u8,
    /// Pedersen commitment blinder.
    pub blinding: Scalar,
}

impl Drop for ShareOpening {
    fn drop(&mut self) {
        self.value.zeroize();
        self.blinding.zeroize();
    }
}

/// Share opening tied to one accepted commitment.
pub struct VerifiedShareOpening {
    role: Role,
    slot: u8,
    value: u8,
    blinding: Scalar,
}

impl VerifiedShareOpening {
    /// Verified contribution value.
    #[must_use]
    pub const fn value(&self) -> u8 {
        self.value
    }
    /// Accepted slot.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.slot
    }
    /// Owning role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
}

impl Drop for VerifiedShareOpening {
    fn drop(&mut self) {
        self.value.zeroize();
        self.blinding.zeroize();
    }
}

/// Verify a share against the accepted commitment at a fixed slot.
///
/// # Errors
///
/// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
#[allow(
    clippy::needless_pass_by_value,
    reason = "Consume and zeroize the unverified secret opening on return."
)]
pub fn verify_share_opening(
    deal: &VerifiedAcceptedDeal,
    role: Role,
    slot: u8,
    opening: ShareOpening,
) -> Result<VerifiedShareOpening, OpeningError> {
    let index = usize::from(slot);
    if index >= N_SLOTS {
        return Err(OpeningError::Slot);
    }
    if opening.value > 51 {
        return Err(OpeningError::Opening);
    }
    let commitments = match role {
        Role::A => &deal.as_deal().body.commitments_a,
        Role::B => &deal.as_deal().body.commitments_b,
    };
    let expected = protocol_parameters().m * Scalar::from(u64::from(opening.value))
        + protocol_parameters().g * opening.blinding;
    if expected != commitments[index] {
        return Err(OpeningError::Opening);
    }
    Ok(VerifiedShareOpening {
        role,
        slot,
        value: opening.value,
        blinding: opening.blinding,
    })
}

/// Non-exportable-by-default card-specific signing key.
pub struct CardSigningKey {
    scalar: Scalar,
    slot: u8,
    raw_sum: u8,
    card: u8,
    public_xonly: [u8; 32],
}

impl CardSigningKey {
    /// Accepted slot.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.slot
    }
    /// Ordinary integer raw sum in 0..102.
    #[must_use]
    pub const fn raw_sum(&self) -> u8 {
        self.raw_sum
    }
    /// Card identifier modulo 52.
    #[must_use]
    pub const fn card_id(&self) -> u8 {
        self.card
    }
    /// Expected BIP340 x-only public key.
    #[must_use]
    pub const fn public_xonly(&self) -> [u8; 32] {
        self.public_xonly
    }

    /// Sign an already-computed 32-byte tapscript sighash with fresh caller-supplied auxiliary randomness.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn sign_tapscript_sighash(
        &self,
        sighash: &[u8; 32],
        aux_rand: &[u8; 32],
    ) -> Result<Signature, OpeningError> {
        let mut bytes = Vec::with_capacity(32);
        encode_scalar(&self.scalar, &mut bytes);
        let signing = SigningKey::from_bytes(&bytes).map_err(|_| OpeningError::Signing)?;
        signing
            .sign_prehash_with_aux_rand(sighash, aux_rand)
            .map_err(|_| OpeningError::Signing)
    }
}

impl Drop for CardSigningKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

/// Combine opposite-role verified openings into the accepted candidate key.
///
/// # Errors
///
/// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
pub fn derive_card_signing_key(
    deal: &VerifiedAcceptedDeal,
    slot: u8,
    a: &VerifiedShareOpening,
    b: &VerifiedShareOpening,
) -> Result<CardSigningKey, OpeningError> {
    if a.role != Role::A || b.role != Role::B || a.slot != slot || b.slot != slot {
        return Err(OpeningError::Candidate);
    }
    let raw_sum = a
        .value
        .checked_add(b.value)
        .ok_or(OpeningError::Candidate)?;
    let scalar = a.blinding + b.blinding;
    if bool::from(scalar.is_zero()) {
        return Err(OpeningError::ZeroKey);
    }
    let point = protocol_parameters().g * scalar;
    if point != deal.catalogue().keys[usize::from(slot)][usize::from(raw_sum)] {
        return Err(OpeningError::Candidate);
    }
    let public_xonly = point_xonly(&point).map_err(|_| OpeningError::Candidate)?;
    Ok(CardSigningKey {
        scalar,
        slot,
        raw_sum,
        card: raw_sum % 52,
        public_xonly,
    })
}
