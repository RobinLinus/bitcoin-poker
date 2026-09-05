use dlog52_codec::{Reader, put_u16};
use dlog52_group::{decode_scalar, encode_scalar, protocol_parameters};
use dlog52_transcript::tagged_hash;
use k256::{
    Scalar,
    schnorr::{Signature, SigningKey, VerifyingKey},
};

use crate::{ProtocolError, Role, VerifiedAcceptedDeal, accepted_body_hash};

const BODY_BYTES: usize = 135;
const SIGNED_BYTES: usize = 199;

/// Canonical identity-signed selective share reveal.
pub struct SignedShareReveal {
    bytes: [u8; SIGNED_BYTES],
}

impl SignedShareReveal {
    /// Borrow the exact 199-byte wire representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNED_BYTES] {
        &self.bytes
    }
}

/// A reveal whose context, authorization shape, signature, and commitment were verified.
pub struct VerifiedShareReveal {
    sender: Role,
    recipient: u8,
    slot: u8,
    stage: u8,
    value: u8,
    blinding: Scalar,
}

impl VerifiedShareReveal {
    /// Sender that owns the revealed share.
    #[must_use]
    pub const fn sender(&self) -> Role {
        self.sender
    }
    /// Canonical recipient (`0`, `1`, or `255`).
    #[must_use]
    pub const fn recipient(&self) -> u8 {
        self.recipient
    }
    /// Deal slot.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.slot
    }
    /// Authorized reveal stage.
    #[must_use]
    pub const fn stage(&self) -> u8 {
        self.stage
    }
    /// Contribution value.
    #[must_use]
    pub const fn value(&self) -> u8 {
        self.value
    }
    /// Commitment blinder.
    #[must_use]
    pub const fn blinding(&self) -> &Scalar {
        &self.blinding
    }
}

fn authorized(sender: Role, recipient: u8, slot: u8, stage: u8) -> bool {
    match stage {
        0 => matches!(
            (sender, recipient, slot),
            (Role::B, 0, 0 | 2) | (Role::A, 1, 1 | 3)
        ),
        1 => recipient == 255 && (4..=6).contains(&slot),
        2 => recipient == 255 && slot == 7,
        3 => recipient == 255 && slot == 8,
        4 => recipient == 255 && slot < 4,
        _ => false,
    }
}

fn body_bytes(
    deal: &VerifiedAcceptedDeal,
    sender: Role,
    recipient: u8,
    slot: u8,
    stage: u8,
    value: u8,
    blinding: &Scalar,
) -> Result<Vec<u8>, ProtocolError> {
    if !authorized(sender, recipient, slot, stage) || value > 51 {
        return Err(ProtocolError::Reveal);
    }
    let commitments = match sender {
        Role::A => &deal.as_deal().body.commitments_a,
        Role::B => &deal.as_deal().body.commitments_b,
    };
    let commitment = commitments
        .get(usize::from(slot))
        .ok_or(ProtocolError::Reveal)?;
    let expected = protocol_parameters().m * Scalar::from(u64::from(value))
        + protocol_parameters().g * blinding;
    if expected != *commitment {
        return Err(ProtocolError::Reveal);
    }
    let mut body = Vec::with_capacity(BODY_BYTES);
    put_u16(&mut body, 1);
    body.extend_from_slice(&protocol_parameters().params_id);
    body.extend_from_slice(&deal.as_deal().body.game_id);
    body.extend_from_slice(&accepted_body_hash(&deal.as_deal().body));
    body.extend_from_slice(&[sender.as_u8(), recipient, slot, stage, value]);
    encode_scalar(blinding, &mut body);
    if body.len() != BODY_BYTES {
        return Err(ProtocolError::Reveal);
    }
    Ok(body)
}

/// Create the exact signed reveal after the host authorizes its stage and recipient.
pub fn create_share_reveal(
    deal: &VerifiedAcceptedDeal,
    sender: Role,
    recipient: u8,
    slot: u8,
    stage: u8,
    value: u8,
    blinding: &Scalar,
    signing_key: &SigningKey,
    auxiliary_randomness: &[u8; 32],
) -> Result<SignedShareReveal, ProtocolError> {
    let identity = match sender {
        Role::A => deal.game_config().identity_a,
        Role::B => deal.game_config().identity_b,
    };
    if signing_key.verifying_key().to_bytes().as_slice() != identity {
        return Err(ProtocolError::Reveal);
    }
    let body = body_bytes(deal, sender, recipient, slot, stage, value, blinding)?;
    let digest = tagged_hash("DLOG52/share-reveal/v1", &body);
    let signature = signing_key
        .sign_prehash_with_aux_rand(&digest, auxiliary_randomness)
        .map_err(|_| ProtocolError::Reveal)?;
    let mut bytes = [0_u8; SIGNED_BYTES];
    bytes[..BODY_BYTES].copy_from_slice(&body);
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(SignedShareReveal { bytes })
}

/// Verify an exact signed reveal against the accepted deal and commitment.
pub fn verify_share_reveal(
    deal: &VerifiedAcceptedDeal,
    encoded: &[u8],
) -> Result<VerifiedShareReveal, ProtocolError> {
    if encoded.len() != SIGNED_BYTES {
        return Err(ProtocolError::Reveal);
    }
    let (body, signature_bytes) = encoded.split_at(BODY_BYTES);
    let mut reader = Reader::new(body);
    if reader.u16().map_err(|_| ProtocolError::Reveal)? != 1
        || reader.array::<32>().map_err(|_| ProtocolError::Reveal)?
            != protocol_parameters().params_id
        || reader.array::<32>().map_err(|_| ProtocolError::Reveal)? != deal.as_deal().body.game_id
        || reader.array::<32>().map_err(|_| ProtocolError::Reveal)?
            != accepted_body_hash(&deal.as_deal().body)
    {
        return Err(ProtocolError::Reveal);
    }
    let sender = match reader.u8().map_err(|_| ProtocolError::Reveal)? {
        0 => Role::A,
        1 => Role::B,
        _ => return Err(ProtocolError::Reveal),
    };
    let recipient = reader.u8().map_err(|_| ProtocolError::Reveal)?;
    let slot = reader.u8().map_err(|_| ProtocolError::Reveal)?;
    let stage = reader.u8().map_err(|_| ProtocolError::Reveal)?;
    let value = reader.u8().map_err(|_| ProtocolError::Reveal)?;
    let blinding = decode_scalar(&mut reader).map_err(|_| ProtocolError::Reveal)?;
    reader.finish().map_err(|_| ProtocolError::Reveal)?;
    let canonical = body_bytes(deal, sender, recipient, slot, stage, value, &blinding)?;
    if canonical != body {
        return Err(ProtocolError::Reveal);
    }
    let identity = match sender {
        Role::A => deal.game_config().identity_a,
        Role::B => deal.game_config().identity_b,
    };
    let verifier = VerifyingKey::from_bytes(&identity).map_err(|_| ProtocolError::Reveal)?;
    let signature = Signature::try_from(signature_bytes).map_err(|_| ProtocolError::Reveal)?;
    verifier
        .verify_raw(&tagged_hash("DLOG52/share-reveal/v1", body), &signature)
        .map_err(|_| ProtocolError::Reveal)?;
    Ok(VerifiedShareReveal {
        sender,
        recipient,
        slot,
        stage,
        value,
        blinding,
    })
}
