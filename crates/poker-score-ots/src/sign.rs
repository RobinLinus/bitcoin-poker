//! One-time signing operations.

use crate::{HASH_SIZE, LamportError, LamportMessage, LamportPurpose, LamportSecretKey, Score24};

/// Revealed Lamport preimages for one fixed-width message.
///
/// Signature preimages are public after use. Unlike [`LamportSecretKey`], this
/// type may therefore be cloned and logged by transaction tooling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LamportSignature {
    purpose: LamportPurpose,
    preimages: Vec<[u8; HASH_SIZE]>,
}

/// Alice's public score certificate repeated across the showdown boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliceScoreCertificate {
    score_a: Score24,
    lamport_signature: LamportSignature,
}

impl AliceScoreCertificate {
    /// Constructs a certificate from public witness components.
    ///
    /// # Errors
    ///
    /// Returns [`LamportError::WrongPurpose`] if the signature is not an
    /// Alice-score signature. Signature width is guaranteed by its type.
    pub fn from_parts(
        score_a: Score24,
        lamport_signature: LamportSignature,
    ) -> Result<Self, LamportError> {
        if lamport_signature.purpose() != LamportPurpose::AliceScore24Bit {
            return Err(LamportError::WrongPurpose);
        }
        Ok(Self {
            score_a,
            lamport_signature,
        })
    }

    /// Returns Alice's packed 24-bit score.
    #[must_use]
    pub const fn score_a(&self) -> Score24 {
        self.score_a
    }

    /// Returns the exact 24 revealed Lamport preimages.
    #[must_use]
    pub const fn lamport_signature(&self) -> &LamportSignature {
        &self.lamport_signature
    }

    /// Verifies the certificate under the score key committed by the node.
    ///
    /// # Errors
    ///
    /// Returns an error for a game, node, purpose, width, or hash mismatch.
    pub fn verify(
        &self,
        public_key: &crate::LamportPublicKey,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
    ) -> Result<(), LamportError> {
        crate::verify_alice_score(
            public_key,
            chain_game_id,
            node_id,
            self.score_a,
            &self.lamport_signature,
        )
    }
}

/// Bob's public score certificate consumed by his payout branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BobScoreCertificate {
    score_b: Score24,
    lamport_signature: LamportSignature,
}

impl BobScoreCertificate {
    /// Constructs a certificate from public witness components.
    ///
    /// # Errors
    ///
    /// Returns [`LamportError::WrongPurpose`] if the signature is not a
    /// Bob-score signature. Signature width is guaranteed by its type.
    pub fn from_parts(
        score_b: Score24,
        lamport_signature: LamportSignature,
    ) -> Result<Self, LamportError> {
        if lamport_signature.purpose() != LamportPurpose::BobScore24Bit {
            return Err(LamportError::WrongPurpose);
        }
        Ok(Self {
            score_b,
            lamport_signature,
        })
    }

    /// Returns Bob's packed 24-bit score.
    #[must_use]
    pub const fn score_b(&self) -> Score24 {
        self.score_b
    }

    /// Returns the exact 24 revealed Lamport preimages.
    #[must_use]
    pub const fn lamport_signature(&self) -> &LamportSignature {
        &self.lamport_signature
    }

    /// Verifies the certificate under the Bob-score key committed by the node.
    ///
    /// # Errors
    ///
    /// Returns an error for a game, node, purpose, width, or hash mismatch.
    pub fn verify(
        &self,
        public_key: &crate::LamportPublicKey,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
    ) -> Result<(), LamportError> {
        crate::verify_bob_score(
            public_key,
            chain_game_id,
            node_id,
            self.score_b,
            &self.lamport_signature,
        )
    }
}

impl LamportSignature {
    /// Constructs a signature from a decoded Bitcoin witness or wire frame.
    ///
    /// # Errors
    ///
    /// Returns [`LamportError::InvalidSignatureLength`] unless the number of
    /// preimages exactly matches the fixed purpose width.
    pub fn from_parts(
        purpose: LamportPurpose,
        preimages: Vec<[u8; HASH_SIZE]>,
    ) -> Result<Self, LamportError> {
        let expected = usize::from(purpose.bit_width());
        if preimages.len() != expected {
            return Err(LamportError::InvalidSignatureLength {
                expected,
                actual: preimages.len(),
            });
        }
        Ok(Self { purpose, preimages })
    }

    /// Returns the exact purpose encoded by the signature.
    #[must_use]
    pub const fn purpose(&self) -> LamportPurpose {
        self.purpose
    }

    /// Returns the revealed preimages in most-significant-first bit order.
    #[must_use]
    pub fn preimages(&self) -> &[[u8; HASH_SIZE]] {
        &self.preimages
    }

    /// Consumes the signature and returns Bitcoin witness stack elements.
    #[must_use]
    pub fn into_witness_elements(self) -> Vec<[u8; HASH_SIZE]> {
        self.preimages
    }
}

/// Signs Alice's packed showdown score and permanently marks the key as used.
///
/// # Errors
///
/// Returns an error for a wrong-purpose, already-used, or erased key.
pub fn sign_alice_score(
    key: &mut LamportSecretKey,
    score: Score24,
) -> Result<LamportSignature, LamportError> {
    sign_message(key, LamportMessage::AliceScore(score))
}

/// Issues Alice's one permitted certificate for a showdown score.
///
/// # Errors
///
/// Returns an error for a wrong-purpose, already-used, or erased key.
pub fn issue_alice_score_certificate(
    key: &mut LamportSecretKey,
    score: Score24,
) -> Result<AliceScoreCertificate, LamportError> {
    AliceScoreCertificate::from_parts(score, sign_alice_score(key, score)?)
}

/// Signs Bob's packed showdown score and permanently marks the key as used.
///
/// # Errors
///
/// Returns an error for a wrong-purpose, already-used, or erased key.
pub fn sign_bob_score(
    key: &mut LamportSecretKey,
    score: Score24,
) -> Result<LamportSignature, LamportError> {
    sign_message(key, LamportMessage::BobScore(score))
}

/// Issues Bob's one permitted certificate for a showdown score.
///
/// # Errors
///
/// Returns an error for a wrong-purpose, already-used, or erased key.
pub fn issue_bob_score_certificate(
    key: &mut LamportSecretKey,
    score: Score24,
) -> Result<BobScoreCertificate, LamportError> {
    BobScoreCertificate::from_parts(score, sign_bob_score(key, score)?)
}

pub(crate) fn sign_message(
    key: &mut LamportSecretKey,
    message: LamportMessage,
) -> Result<LamportSignature, LamportError> {
    let preimages = key.reveal_once(message)?;
    LamportSignature::from_parts(message.purpose(), preimages)
}
