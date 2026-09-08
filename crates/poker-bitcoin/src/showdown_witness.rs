//! Strict bridges from verified DLOG52 deals to card gates and showdown witnesses.

use dealer_protocol::VerifiedAcceptedDeal;

mod observed_score;
pub use observed_score::ObservedAliceScoreCertificate;

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
    /// Verify a cooperative showdown without relying on a chain confirmation.
    /// Both funding authorizations, all score preimages, the authenticated cards,
    /// the exact evaluation proof and Bob's selected payout comparison are checked.
    /// Cooperative frames use the canonical witness produced by this protocol.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical proofs, invalid signatures or wrong outcomes.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_cooperative_elements(
        deal: &VerifiedAcceptedDeal, role: poker_settlement_types::Role, sighash: [u8; 32],
        identities: [[u8; 32]; 2], scores: &[poker_score_ots::LamportPublicKey; 2],
        outcome: Option<poker_settlement_types::ShowdownOutcome>, elements: &[&[u8]],
    ) -> Result<(), crate::BitcoinBackendError> {
        use crate::BitcoinBackendError as Error;
        use poker_settlement_types::{Role, ShowdownOutcome};
        let invalid = || Error::InvalidBitcoinSignature;
        let certificates = if role == Role::Alice { 1 } else { 2 };
        let authorizations = certificates * ObservedAliceScoreCertificate::WITNESS_ELEMENTS;
        if elements.len() < authorizations + 17 { return Err(invalid()); }
        let alice = ObservedAliceScoreCertificate::from_witness_elements(&elements[..49], &scores[0])?;
        let score = if role == Role::Bob {
            let bob = ObservedAliceScoreCertificate::authenticate(&elements[49..98], &scores[1])?;
            let actual = match alice.score_a().get().cmp(&bob.score_a().get()) {
                std::cmp::Ordering::Greater => ShowdownOutcome::AliceWin,
                std::cmp::Ordering::Less => ShowdownOutcome::BobWin,
                std::cmp::Ordering::Equal => ShowdownOutcome::Split,
            };
            if outcome != Some(actual) { return Err(invalid()); }
            bob.score_a().get()
        } else {
            if outcome.is_some() { return Err(invalid()); }
            alice.score_a().get()
        };
        for i in 0..2 {
            crate::verify_sighash_default(&bitcoin::secp256k1::Secp256k1::verification_only(),
                identities[i], sighash, crate::DefaultSighashSignature::from_slice(elements[authorizations + i])?)?;
        }
        let tail = elements.len() - 15;
        let subset = decode_canonical_byte(elements[tail])?;
        let mut raw_sums = [0; 7];
        let mut signatures = [[0; 64]; 7];
        for i in 0..7 {
            signatures[i] = elements[tail + 1 + i * 2].try_into().map_err(|_| invalid())?;
            raw_sums[i] = decode_canonical_byte(elements[tail + 2 + i * 2])?;
        }
        let hand = Self::verify(deal, role, sighash, raw_sums, signatures, subset, score)?;
        let mut expected = vec![];
        hand.append_hand(&mut expected);
        if expected.len() != elements.len() - authorizations - 2
            || expected.iter().zip(&elements[authorizations + 2..]).any(|(a,b)| a.as_slice() != *b) {
            return Err(invalid());
        }
        Ok(())
    }
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
        self.bob_elements_with_alice_stack(
            authorizations,
            crate::taproot::alice_score_certificate_elements(alice),
            bob,
        )
    }

    /// Assemble Bob's payout using Alice's authenticated on-chain certificate.
    ///
    /// This preserves preimages of every length accepted by Alice's script.
    ///
    /// # Errors
    ///
    /// Rejects a non-Bob hand or a Bob certificate with a mismatched score.
    pub fn bob_elements_with_observed_alice(
        &self,
        authorizations: [[u8; 64]; 2],
        alice: &ObservedAliceScoreCertificate,
        bob: &poker_score_ots::BobScoreCertificate,
    ) -> Result<Vec<Vec<u8>>, crate::BitcoinBackendError> {
        self.bob_elements_with_alice_stack(authorizations, alice.to_witness_elements(), bob)
    }

    fn bob_elements_with_alice_stack(
        &self,
        authorizations: [[u8; 64]; 2],
        mut elements: Vec<Vec<u8>>,
        bob: &poker_score_ots::BobScoreCertificate,
    ) -> Result<Vec<Vec<u8>>, crate::BitcoinBackendError> {
        if self.role != poker_settlement_types::Role::Bob || self.score != bob.score_b().get() {
            return Err(crate::BitcoinBackendError::BobCertificateMismatch {
                certificate: bob.score_b().get(),
                hand: self.score,
            });
        }
        elements.extend(crate::taproot::bob_score_certificate_elements(bob));
        elements.extend(authorizations.map(|s| s.to_vec()));
        self.append_hand(&mut elements);
        Ok(elements)
    }
}

fn decode_canonical_byte(bytes: &[u8]) -> Result<u8, crate::BitcoinBackendError> {
    let value = match bytes { [] => 0, [n] if (1..=127).contains(n) => *n,
        [n, 0] if *n >= 128 => *n, _ => return Err(crate::BitcoinBackendError::InvalidBitcoinSignature) };
    Ok(value)
}
