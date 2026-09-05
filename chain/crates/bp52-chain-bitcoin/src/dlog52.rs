//! Strict bridges from verified DLOG52 deals to card gates and showdown witnesses.

use bitcoin::Network;
use dlog52_bitcoin::{BitcoinError, RegtestGateManifest};
use dlog52_protocol::VerifiedAcceptedDeal;

/// Compile the nine independent single-slot card gates defined by the DLOG52
/// implementation specification.
///
/// The input cannot be assembled from unchecked wire data: it must first pass
/// the DLOG52 public-certificate replay verifier. The profile deliberately
/// rejects every network except regtest and is not a poker settlement graph.
pub fn compile_regtest_card_gates(
    network: Network,
    accepted: &VerifiedAcceptedDeal,
) -> Result<RegtestGateManifest, BitcoinError> {
    dlog52_bitcoin::require_regtest(network)?;
    dlog52_bitcoin::build_regtest_gate(accepted)
}

pub use dlog52_bitcoin::{
    GateLeaf, SlotGateManifest, assemble_gate_witness, gate_tapscript_sighash,
};

/// Seven candidate signatures verified for one role and exact transaction digest.
/// This type cannot be constructed from unauthenticated card numbers.
pub struct DlogShowdownWitness {
    role: bp52_chain_types::Role,
    raw_sums: [u8; 7],
    signatures: [[u8; 64]; 7],
    subset: u8,
    score: u32,
    evaluation: crate::Eval5ScriptWitness,
}

impl DlogShowdownWitness {
    /// Authenticate all card candidates and the selected five-card score.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        deal: &VerifiedAcceptedDeal,
        role: bp52_chain_types::Role,
        sighash: [u8; 32],
        raw_sums: [u8; 7],
        signatures: [[u8; 64]; 7],
        subset: u8,
        score: u32,
    ) -> Result<Self, crate::BitcoinBackendError> {
        use crate::BitcoinBackendError as Error;
        use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
        let slots = match role {
            bp52_chain_types::Role::Alice => crate::ALICE_SEVEN_SLOTS,
            bp52_chain_types::Role::Bob => crate::BOB_SEVEN_SLOTS,
        };
        let secp = Secp256k1::verification_only();
        for i in 0..7 {
            let candidate = deal.catalogue().keys[usize::from(slots[i])]
                .get(usize::from(raw_sums[i]))
                .ok_or(Error::InvalidBitcoinSignature)?;
            let bytes = dlog52_protocol::point_xonly(candidate)
                .map_err(|_| Error::InvalidBitcoinSignature)?;
            let key =
                XOnlyPublicKey::from_slice(&bytes).map_err(|_| Error::InvalidBitcoinSignature)?;
            let signature = Signature::from_slice(&signatures[i])
                .map_err(|_| Error::InvalidBitcoinSignature)?;
            secp.verify_schnorr(&signature, &Message::from_digest(sighash), &key)
                .map_err(|_| Error::InvalidBitcoinSignature)?;
        }
        let cards = raw_sums.map(|value| value % 52);
        bp52_poker::verify_claimed_hand(cards, subset, score)?;
        let selected = bp52_poker::selected_five(cards, subset)?;
        let evaluation = crate::Eval5ScriptWitness::from_claimed_score(
            selected,
            bp52_poker::HandScore::try_from(score)?,
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
    pub fn alice_elements(
        &self,
        authorizations: [[u8; 64]; 2],
        certificate: &bp52_lamport::AliceScoreCertificate,
    ) -> Result<Vec<Vec<u8>>, crate::BitcoinBackendError> {
        if self.role != bp52_chain_types::Role::Alice || self.score != certificate.score_a().get() {
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
    pub fn bob_elements(
        &self,
        authorizations: [[u8; 64]; 2],
        alice: &bp52_lamport::AliceScoreCertificate,
        bob: &bp52_lamport::BobScoreCertificate,
    ) -> Result<Vec<Vec<u8>>, crate::BitcoinBackendError> {
        if self.role != bp52_chain_types::Role::Bob || self.score != bob.score_b().get() {
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
