//! Deterministic predicate description for the Bitcoin backend.
//!
//! This is intentionally not a Tapscript builder. It commits to every public
//! hash and implements the complete witness semantics that a concrete
//! `bp52-chain-bitcoin` leaf must reproduce.

use crate::key::tagged_sha256;
use crate::{
    HASH_SIZE, LamportError, LamportMessage, LamportPublicKey, LamportPurpose, LamportSignature,
    Score24, verify_alice_score, verify_bob_score, verify_message,
};

const PROGRAM_MAGIC: &[u8; 8] = b"BP52LSP1";
const PROGRAM_ID_TAG: &[u8] = b"BP52/lamport-script-predicate/v1";

/// Deterministic program description for one Lamport verification leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LamportScriptPredicate {
    public_key: LamportPublicKey,
}

impl LamportScriptPredicate {
    /// Constructs the predicate for one validated public key.
    #[must_use]
    pub fn new(public_key: LamportPublicKey) -> Self {
        Self { public_key }
    }

    /// Returns the public key and exact context committed by the predicate.
    #[must_use]
    pub const fn public_key(&self) -> &LamportPublicKey {
        &self.public_key
    }

    /// Returns the exact number of 32-byte stack elements in a valid witness.
    #[must_use]
    pub fn required_witness_elements(&self) -> usize {
        self.public_key.bit_width()
    }

    /// Serializes the predicate deterministically for backend commitments.
    #[must_use]
    pub fn encode_program(&self) -> Vec<u8> {
        let key = self.public_key.encode();
        let mut encoded = Vec::with_capacity(PROGRAM_MAGIC.len() + key.len());
        encoded.extend_from_slice(PROGRAM_MAGIC);
        encoded.extend_from_slice(&key);
        encoded
    }

    /// Decodes one canonical program description and rejects trailing data.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid program prefix or malformed key body.
    pub fn decode_program(encoded: &[u8]) -> Result<Self, LamportError> {
        let key_bytes =
            encoded
                .strip_prefix(PROGRAM_MAGIC)
                .ok_or(LamportError::InvalidEncodingPrefix {
                    kind: "Lamport script predicate",
                })?;
        Ok(Self::new(LamportPublicKey::decode(key_bytes)?))
    }

    /// Returns a stable tagged identifier for the complete predicate.
    #[must_use]
    pub fn program_id(&self) -> [u8; 32] {
        tagged_sha256(PROGRAM_ID_TAG, &self.encode_program())
    }

    /// Verifies structured witness elements with complete reference semantics.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong witness width, purpose, or public hash.
    pub fn verify_witness(
        &self,
        message: LamportMessage,
        witness_elements: &[[u8; HASH_SIZE]],
    ) -> Result<(), LamportError> {
        let signature = LamportSignature::from_parts(message.purpose(), witness_elements.to_vec())?;
        verify_message(
            &self.public_key,
            self.public_key.context(),
            message,
            &signature,
        )
    }

    /// Verifies an Alice-score witness and an externally expected game/node context.
    ///
    /// # Errors
    ///
    /// Returns an error for a context mismatch or invalid score witness.
    pub fn verify_alice_score_witness(
        &self,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score: Score24,
        witness_elements: &[[u8; HASH_SIZE]],
    ) -> Result<(), LamportError> {
        let signature = LamportSignature::from_parts(
            LamportPurpose::AliceScore24Bit,
            witness_elements.to_vec(),
        )?;
        verify_alice_score(&self.public_key, chain_game_id, node_id, score, &signature)
    }

    /// Verifies a Bob-score witness and an externally expected game/node context.
    ///
    /// # Errors
    ///
    /// Returns an error for a context mismatch or invalid score witness.
    pub fn verify_bob_score_witness(
        &self,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score: Score24,
        witness_elements: &[[u8; HASH_SIZE]],
    ) -> Result<(), LamportError> {
        let signature =
            LamportSignature::from_parts(LamportPurpose::BobScore24Bit, witness_elements.to_vec())?;
        verify_bob_score(&self.public_key, chain_game_id, node_id, score, &signature)
    }
}
