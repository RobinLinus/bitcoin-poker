//! Complete reference verification semantics for BP52 Lamport witnesses.

use crate::key::sha256;
use crate::{
    KeyContext, LamportError, LamportMessage, LamportPublicKey, LamportPurpose, LamportSignature,
    Score24,
};

/// Verifies one structured message and signature under an exact key context.
///
/// # Errors
///
/// Returns an error for a context, purpose, width, or public-hash mismatch.
pub fn verify_message(
    public_key: &LamportPublicKey,
    expected_context: KeyContext,
    message: LamportMessage,
    signature: &LamportSignature,
) -> Result<(), LamportError> {
    validate_context(public_key.context(), expected_context)?;
    if public_key.context().purpose != message.purpose() || signature.purpose() != message.purpose()
    {
        return Err(LamportError::WrongPurpose);
    }

    let expected = usize::from(message.purpose().bit_width());
    if signature.preimages().len() != expected {
        return Err(LamportError::InvalidSignatureLength {
            expected,
            actual: signature.preimages().len(),
        });
    }
    if public_key.public_hash_pairs().len() != expected {
        return Err(LamportError::InvalidBitWidth {
            expected: message.purpose().bit_width(),
            actual: u8::try_from(public_key.public_hash_pairs().len()).unwrap_or(u8::MAX),
        });
    }

    let bits = message.bits_msb_first();
    for (bit_index, ((preimage, pair), bit)) in signature
        .preimages()
        .iter()
        .zip(public_key.public_hash_pairs())
        .zip(bits)
        .enumerate()
    {
        if sha256(preimage) != pair[usize::from(bit)] {
            return Err(LamportError::InvalidSignature { bit_index });
        }
    }
    Ok(())
}

/// Verifies Alice's 24-bit packed score under one exact game and node key.
///
/// # Errors
///
/// Returns an error for a context, purpose, width, or public-hash mismatch.
pub fn verify_alice_score(
    public_key: &LamportPublicKey,
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    score: Score24,
    signature: &LamportSignature,
) -> Result<(), LamportError> {
    let expected = KeyContext::new(chain_game_id, node_id, LamportPurpose::AliceScore24Bit);
    verify_message(
        public_key,
        expected,
        LamportMessage::AliceScore(score),
        signature,
    )
}

/// Verifies Bob's 24-bit packed score under one exact game and node key.
///
/// # Errors
///
/// Returns an error for a context, purpose, width, or public-hash mismatch.
pub fn verify_bob_score(
    public_key: &LamportPublicKey,
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    score: Score24,
    signature: &LamportSignature,
) -> Result<(), LamportError> {
    let expected = KeyContext::new(chain_game_id, node_id, LamportPurpose::BobScore24Bit);
    verify_message(
        public_key,
        expected,
        LamportMessage::BobScore(score),
        signature,
    )
}

fn validate_context(actual: KeyContext, expected: KeyContext) -> Result<(), LamportError> {
    if actual.chain_game_id != expected.chain_game_id {
        return Err(LamportError::WrongGame);
    }
    if actual.node_id != expected.node_id {
        return Err(LamportError::WrongNode);
    }
    if actual.purpose != expected.purpose {
        return Err(LamportError::WrongPurpose);
    }
    Ok(())
}
