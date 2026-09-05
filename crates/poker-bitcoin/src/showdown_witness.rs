//! Strict bridges from verified DLOG52 deals to card gates and showdown witnesses.

use dealer_protocol::VerifiedAcceptedDeal;

pub use dealer_bitcoin::{
    GateLeaf, SlotGateManifest, assemble_gate_witness, gate_tapscript_sighash,
};

/// Seven candidate signatures verified for one role and exact transaction digest.
/// This type cannot be constructed from unauthenticated card numbers.
pub struct ShowdownWitness {
    role: poker_settlement_types::Role,
    raw_sums: [u8; 7],
    signatures: [[u8; 64]; 7],
    subset: u8,
    score: u32,
    evaluation: crate::Eval5ScriptWitness,
}

impl ShowdownWitness {
    /// Authenticate all card candidates and the selected five-card score.
    #[allow(clippy::too_many_arguments)]
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn verify(
        deal: &VerifiedAcceptedDeal,
        role: poker_settlement_types::Role,
        sighash: [u8; 32],
        raw_sums: [u8; 7],
        signatures: [[u8; 64]; 7],
        subset: u8,
        score: u32,
    ) -> Result<Self, crate::BitcoinBackendError> {
        use crate::BitcoinBackendError as Error;
        use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
        let slots = match role {
            poker_settlement_types::Role::Alice => crate::ALICE_SEVEN_SLOTS,
            poker_settlement_types::Role::Bob => crate::BOB_SEVEN_SLOTS,
        };
        let secp = Secp256k1::verification_only();
        for i in 0..7 {
            let candidate = deal.catalogue().keys[usize::from(slots[i])]
                .get(usize::from(raw_sums[i]))
                .ok_or(Error::InvalidBitcoinSignature)?;
            let bytes = dealer_protocol::point_xonly(candidate)
                .map_err(|_| Error::InvalidBitcoinSignature)?;
            let key =
                XOnlyPublicKey::from_slice(&bytes).map_err(|_| Error::InvalidBitcoinSignature)?;
            let signature = Signature::from_slice(&signatures[i])
                .map_err(|_| Error::InvalidBitcoinSignature)?;
            secp.verify_schnorr(&signature, &Message::from_digest(sighash), &key)
                .map_err(|_| Error::InvalidBitcoinSignature)?;
        }
        let cards = raw_sums.map(|value| value % 52);
        poker_eval::verify_claimed_hand(cards, subset, score)?;
        let selected = poker_eval::selected_five(cards, subset)?;
        let evaluation = crate::Eval5ScriptWitness::from_claimed_score(
            selected,
            poker_eval::HandScore::try_from(score)?,
        )?;
        Ok(Self {
            role,
            raw_sums,
            signatures,
            subset,
            score,
            evaluation,
        })
    }

    fn append_hand(&self, elements: &mut Vec<Vec<u8>>) {
        elements.extend(self.evaluation.to_witness_elements());
        elements.push(crate::encode_script_num(i64::from(self.subset)));
        for (signature, sum) in self.signatures.iter().zip(self.raw_sums) {
            elements.push(signature.to_vec());
            elements.push(crate::encode_script_num(i64::from(sum)));
        }
    }

    /// Assemble Alice's score certificate, payment authorizations, and dlog hand.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn alice_elements(
        &self,
        authorizations: [[u8; 64]; 2],
        certificate: &poker_score_ots::AliceScoreCertificate,
    ) -> Result<Vec<Vec<u8>>, crate::BitcoinBackendError> {
        if self.role != poker_settlement_types::Role::Alice
            || self.score != certificate.score_a().get()
        {
            return Err(crate::BitcoinBackendError::AliceCertificateMismatch {
                certificate: certificate.score_a().get(),
                hand: self.score,
            });
        }
        let mut elements = crate::taproot::alice_score_certificate_elements(certificate);
        elements.extend(authorizations.map(|s| s.to_vec()));
        self.append_hand(&mut elements);
        Ok(elements)
    }

    /// Assemble Bob's hand plus both score certificates for the payout script.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn bob_elements(
        &self,
        authorizations: [[u8; 64]; 2],
        alice: &poker_score_ots::AliceScoreCertificate,
        bob: &poker_score_ots::BobScoreCertificate,
    ) -> Result<Vec<Vec<u8>>, crate::BitcoinBackendError> {
        if self.role != poker_settlement_types::Role::Bob || self.score != bob.score_b().get() {
            return Err(crate::BitcoinBackendError::BobCertificateMismatch {
                certificate: bob.score_b().get(),
                hand: self.score,
            });
        }
        let mut elements = crate::taproot::alice_score_certificate_elements(alice);
        elements.extend(crate::taproot::bob_score_certificate_elements(bob));
        elements.extend(authorizations.map(|s| s.to_vec()));
        self.append_hand(&mut elements);
        Ok(elements)
    }
}
