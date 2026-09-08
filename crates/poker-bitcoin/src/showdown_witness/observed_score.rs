//! Alice's authenticated on-chain score, including arbitrary-size hash preimages.

use poker_score_ots::{LamportError, LamportPublicKey, LamportPurpose, Score24};
use sha2::{Digest, Sha256};

use crate::{BitcoinBackendError, encode_script_num};

/// A verified Alice certificate recovered from a confirmed showdown witness.
///
/// Honest wire certificates retain their fixed 32-byte preimages. Script only
/// authenticates each preimage's hash, so a peer's on-chain certificate may use
/// other lengths and must remain usable in Bob's subsequent payout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedAliceScoreCertificate {
    score: Score24,
    preimages: Vec<Vec<u8>>,
}

impl ObservedAliceScoreCertificate {
    /// Number of witness elements occupied by Alice's score and certificate.
    pub const WITNESS_ELEMENTS: usize = 49;

    /// Authenticate the score-certificate prefix under the agreed Alice key.
    ///
    /// The caller supplies the independently authenticated public key and must
    /// verify the containing transaction before treating its score as confirmed.
    ///
    /// # Errors
    ///
    /// Rejects the wrong purpose or element count, noncanonical score bits,
    /// oversized preimages, hash mismatches, and a mismatched score field.
    pub fn from_witness_elements(
        elements: &[impl AsRef<[u8]>],
        public_key: &LamportPublicKey,
    ) -> Result<Self, BitcoinBackendError> {
        if public_key.context().purpose != LamportPurpose::AliceScore24Bit {
            return Err(LamportError::WrongPurpose.into());
        }
        Self::authenticate(elements, public_key)
    }

    pub(super) fn authenticate(
        elements: &[impl AsRef<[u8]>], public_key: &LamportPublicKey,
    ) -> Result<Self, BitcoinBackendError> {
        if !matches!(public_key.context().purpose, LamportPurpose::AliceScore24Bit | LamportPurpose::BobScore24Bit) {
            return Err(LamportError::WrongPurpose.into());
        }
        if elements.len() != Self::WITNESS_ELEMENTS {
            return Err(BitcoinBackendError::WrongWitnessElementCount {
                expected: Self::WITNESS_ELEMENTS,
                actual: elements.len(),
            });
        }
        let mut value = 0_u32;
        let mut preimages = Vec::with_capacity(24);
        for (bit_index, pair) in public_key.public_hash_pairs().iter().enumerate() {
            let preimage = elements[1 + 2 * bit_index].as_ref();
            let bit = match elements[2 + 2 * bit_index].as_ref() {
                [] => 0,
                [1] => 1,
                _ => return Err(LamportError::InvalidSignature { bit_index }.into()),
            };
            if preimage.len() > crate::taproot::MAX_WITNESS_ELEMENT_BYTES {
                return Err(BitcoinBackendError::OversizedWitnessElement {
                    actual: preimage.len(),
                    maximum: crate::taproot::MAX_WITNESS_ELEMENT_BYTES,
                });
            }
            let actual_hash: [u8; 32] = Sha256::digest(preimage).into();
            if actual_hash != pair[bit] {
                return Err(LamportError::InvalidSignature { bit_index }.into());
            }
            value = (value << 1) | u32::from(bit == 1);
            preimages.push(preimage.to_vec());
        }
        let score = Score24::new(value)?;
        poker_eval::HandScore::try_from(value)?;

        // OP_NUMEQUALVERIFY permits any four-byte, nonnegative Script-number
        // encoding of the authenticated score, including redundant zero bytes.
        let encoded_score = elements[0].as_ref();
        if encoded_score.len() > 4 || encoded_score.last().is_some_and(|byte| byte & 0x80 != 0) {
            return Err(LamportError::InvalidScore(0).into());
        }
        let mut bytes = [0_u8; 4];
        bytes[..encoded_score.len()].copy_from_slice(encoded_score);
        let supplied = u32::from_le_bytes(bytes);
        if supplied != value {
            return Err(LamportError::InvalidScore(supplied).into());
        }
        Ok(Self { score, preimages })
    }

    /// Return Alice's authenticated score.
    #[must_use]
    pub const fn score_a(&self) -> Score24 {
        self.score
    }

    /// Recreate the certificate stack while retaining the exact hash preimages.
    #[must_use]
    pub fn to_witness_elements(&self) -> Vec<Vec<u8>> {
        let mut elements = Vec::with_capacity(Self::WITNESS_ELEMENTS);
        elements.push(encode_script_num(i64::from(self.score.get())));
        let bits = poker_score_ots::LamportMessage::AliceScore(self.score).bits_msb_first();
        for (preimage, bit) in self.preimages.iter().zip(bits) {
            elements.push(preimage.clone());
            elements.push(encode_script_num(i64::from(bit)));
        }
        elements
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use poker_score_ots::{KeyContext, LamportMessage, generate_key, issue_bob_score_certificate};
    use rand_core::OsRng;

    use super::*;
    use crate::showdown_witness::ShowdownWitness;

    type TestResult = Result<(), Box<dyn Error>>;
    type CertificateFixture = (LamportPublicKey, Vec<Vec<u8>>, Score24);

    fn variable_certificate() -> Result<CertificateFixture, Box<dyn Error>> {
        let score = Score24::new(poker_eval::evaluate_five_cards([0, 9, 22, 35, 48])?)?;
        let bits = LamportMessage::AliceScore(score).bits_msb_first();
        let mut pairs = Vec::with_capacity(24);
        let mut elements = vec![encode_script_num(i64::from(score.get()))];
        for (index, bit) in bits.into_iter().enumerate() {
            let length = [0, 1, 31, 32, 33, 520].get(index).copied().unwrap_or(32);
            let preimages: [Vec<u8>; 2] = std::array::from_fn(|choice| {
                vec![
                    u8::try_from(2 * index + choice + 1).unwrap_or(0);
                    if choice == usize::from(bit) {
                        length
                    } else {
                        32
                    }
                ]
            });
            pairs.push(
                preimages
                    .each_ref()
                    .map(|preimage| Sha256::digest(preimage).into()),
            );
            elements.push(preimages[usize::from(bit)].clone());
            elements.push(encode_script_num(i64::from(bit)));
        }
        let key = LamportPublicKey::from_parts(
            KeyContext::new([1; 32], [2; 32], LamportPurpose::AliceScore24Bit),
            pairs,
        )?;
        Ok((key, elements, score))
    }

    #[test]
    fn observed_certificate_preserves_every_consensus_preimage_length() -> TestResult {
        let (key, elements, score) = variable_certificate()?;
        let observed = ObservedAliceScoreCertificate::from_witness_elements(&elements, &key)?;
        assert_eq!(observed.score_a(), score);
        assert_eq!(observed.to_witness_elements(), elements);
        for (index, length) in [0, 1, 31, 32, 33, 520].into_iter().enumerate() {
            assert_eq!(elements[1 + 2 * index].len(), length);
        }

        let mut nonminimal_score = elements.clone();
        nonminimal_score[0].push(0);
        assert_eq!(
            ObservedAliceScoreCertificate::from_witness_elements(&nonminimal_score, &key)?,
            observed,
        );
        Ok(())
    }

    #[test]
    fn observed_certificate_rejects_tampering_and_malformed_witnesses() -> TestResult {
        let (key, elements, score) = variable_certificate()?;
        for index in (1..elements.len()).step_by(2) {
            let mut changed = elements.clone();
            if let Some(first) = changed[index].first_mut() {
                *first ^= 1;
            } else {
                changed[index].push(1);
            }
            assert!(ObservedAliceScoreCertificate::from_witness_elements(&changed, &key).is_err());
        }
        for replacement in [vec![2], vec![0], vec![1, 0]] {
            let mut changed = elements.clone();
            changed[2] = replacement;
            assert!(ObservedAliceScoreCertificate::from_witness_elements(&changed, &key).is_err());
        }
        for replacement in [
            encode_script_num(i64::from(score.get()) + 1),
            vec![0xff],
            vec![0; 5],
        ] {
            let mut changed = elements.clone();
            changed[0] = replacement;
            assert!(ObservedAliceScoreCertificate::from_witness_elements(&changed, &key).is_err());
        }
        let mut oversized = elements.clone();
        oversized[1] = vec![0; 521];
        assert!(ObservedAliceScoreCertificate::from_witness_elements(&oversized, &key).is_err());
        assert!(
            ObservedAliceScoreCertificate::from_witness_elements(&elements[..48], &key).is_err()
        );
        let wrong_purpose = LamportPublicKey::from_parts(
            KeyContext::new([1; 32], [2; 32], LamportPurpose::BobScore24Bit),
            key.public_hash_pairs().to_vec(),
        )?;
        assert!(
            ObservedAliceScoreCertificate::from_witness_elements(&elements, &wrong_purpose)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn bob_payout_carries_alices_observed_preimages_unchanged() -> TestResult {
        let (key, elements, score) = variable_certificate()?;
        let observed = ObservedAliceScoreCertificate::from_witness_elements(&elements, &key)?;
        let (mut secret, _) = generate_key(
            &mut OsRng,
            KeyContext::new([1; 32], [2; 32], LamportPurpose::BobScore24Bit),
        )?;
        let bob = issue_bob_score_certificate(&mut secret, score)?;
        // Exercise the assembly boundary directly; candidate-signature
        // verification is covered separately by ShowdownWitness::verify tests.
        let hand = ShowdownWitness {
            role: poker_settlement_types::Role::Bob,
            raw_sums: [0, 9, 22, 35, 48, 1, 2],
            signatures: [[1; 64]; 7],
            subset: 0,
            score: score.get(),
            evaluation: crate::Eval5ScriptWitness::from_cards([0, 9, 22, 35, 48])?,
        };
        let payout = hand.bob_elements_with_observed_alice([[2; 64]; 2], &observed, &bob)?;
        assert_eq!(
            payout[..ObservedAliceScoreCertificate::WITNESS_ELEMENTS],
            elements
        );
        assert_eq!(
            payout[ObservedAliceScoreCertificate::WITNESS_ELEMENTS..98],
            crate::taproot::bob_score_certificate_elements(&bob),
        );
        Ok(())
    }
}
