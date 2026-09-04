//! Native reference semantics for reveal and showdown predicates.

use bp52_bitcoin::verify_share_opening;
use bp52_chain_types::{AcceptedDeal, Role, ShowdownOutcome};
use bp52_lamport::{
    AliceScoreCertificate, BobScoreCertificate, LamportPublicKey, LamportSignature, Score24,
};
use bp52_poker::{HandScore, selected_five, verify_claimed_hand};

use crate::{BitcoinBackendError, DefaultSighashSignature, verify_sighash_default};

/// Alice's seven-card order: slots `0,2,4,5,6,7,8`.
pub const ALICE_SEVEN_SLOTS: [u8; 7] = [0, 2, 4, 5, 6, 7, 8];
/// Bob's seven-card order: slots `1,3,4,5,6,7,8`.
pub const BOB_SEVEN_SLOTS: [u8; 7] = [1, 3, 4, 5, 6, 7, 8];

const DEAL_ALICE_SLOTS: [u8; 2] = [0, 2];
const DEAL_BOB_SLOTS: [u8; 2] = [1, 3];
const FLOP_SLOTS: [u8; 3] = [4, 5, 6];
const TURN_SLOTS: [u8; 1] = [7];
const RIVER_SLOTS: [u8; 1] = [8];

/// One exact protocol reveal obligation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RevealPattern {
    /// Bob delivers his shares for Alice's private slots 0 and 2.
    DealAlice,
    /// Alice delivers her shares for Bob's private slots 1 and 3.
    DealBob,
    /// One designated player reveals their three flop shares.
    Flop(Role),
    /// One designated player reveals their turn share.
    Turn(Role),
    /// One designated player reveals their river share.
    River(Role),
}

impl RevealPattern {
    /// Return the party obligated to reveal.
    #[must_use]
    pub const fn revealer(self) -> Role {
        match self {
            Self::DealAlice => Role::Bob,
            Self::DealBob => Role::Alice,
            Self::Flop(role) | Self::Turn(role) | Self::River(role) => role,
        }
    }

    /// Return the fixed ordered slots covered by this reveal.
    #[must_use]
    pub const fn slots(self) -> &'static [u8] {
        match self {
            Self::DealAlice => &DEAL_ALICE_SLOTS,
            Self::DealBob => &DEAL_BOB_SLOTS,
            Self::Flop(_) => &FLOP_SLOTS,
            Self::Turn(_) => &TURN_SLOTS,
            Self::River(_) => &RIVER_SLOTS,
        }
    }

    /// Return the stable program discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::DealAlice => 0,
            Self::DealBob => 1,
            Self::Flop(Role::Alice) => 2,
            Self::Flop(Role::Bob) => 3,
            Self::Turn(Role::Alice) => 4,
            Self::Turn(Role::Bob) => 5,
            Self::River(Role::Alice) => 6,
            Self::River(Role::Bob) => 7,
        }
    }
}

/// Public hashes committed by one fixed reveal leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareRevealPredicate {
    pattern: RevealPattern,
    expected_hashes: Vec<[u8; 32]>,
}

impl ShareRevealPredicate {
    /// Bind a reveal pattern to the corresponding accepted-deal hashes.
    #[must_use]
    pub fn new(deal: &AcceptedDeal, pattern: RevealPattern) -> Self {
        let role = pattern.revealer();
        let expected_hashes = pattern
            .slots()
            .iter()
            .map(|slot| hash_for_role(deal, role, usize::from(*slot)))
            .collect();
        Self {
            pattern,
            expected_hashes,
        }
    }

    /// Return the exact phase and revealer.
    #[must_use]
    pub const fn pattern(&self) -> RevealPattern {
        self.pattern
    }

    /// Return expected hashes in canonical slot order.
    #[must_use]
    pub fn expected_hashes(&self) -> &[[u8; 32]] {
        &self.expected_hashes
    }

    /// Verify all preimages for this reveal and reject missing or extra data.
    ///
    /// # Errors
    ///
    /// Returns a count error or the first slot-specific length/hash failure.
    pub fn verify(&self, preimages: &[&[u8]]) -> Result<(), BitcoinBackendError> {
        if preimages.len() != self.expected_hashes.len() {
            return Err(BitcoinBackendError::WrongRevealCount {
                expected: self.expected_hashes.len(),
                actual: preimages.len(),
            });
        }
        for ((slot, expected_hash), preimage) in self
            .pattern
            .slots()
            .iter()
            .zip(&self.expected_hashes)
            .zip(preimages)
        {
            verify_share_opening(expected_hash, preimage).map_err(|source| {
                BitcoinBackendError::InvalidOpening {
                    slot: *slot,
                    source,
                }
            })?;
        }
        Ok(())
    }
}

/// Alice-then-Bob preimages for one public card reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardOpeningWitness {
    slot: u8,
    preimage_a: Vec<u8>,
    preimage_b: Vec<u8>,
}

impl CardOpeningWitness {
    /// Construct one ordered card-opening witness.
    #[must_use]
    pub fn new(slot: u8, preimage_a: Vec<u8>, preimage_b: Vec<u8>) -> Self {
        Self {
            slot,
            preimage_a,
            preimage_b,
        }
    }

    /// Return the claimed canonical deal slot.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.slot
    }

    /// Return Alice's contribution preimage.
    #[must_use]
    pub fn preimage_a(&self) -> &[u8] {
        &self.preimage_a
    }

    /// Return Bob's contribution preimage.
    #[must_use]
    pub fn preimage_b(&self) -> &[u8] {
        &self.preimage_b
    }
}

/// One selected five-card claim backed by all seven ordered card openings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShowdownHandWitness {
    openings: [CardOpeningWitness; 7],
    subset_id: u8,
    claimed_score: u32,
}

impl ShowdownHandWitness {
    /// Construct a structured showdown hand witness.
    #[must_use]
    pub const fn new(openings: [CardOpeningWitness; 7], subset_id: u8, claimed_score: u32) -> Self {
        Self {
            openings,
            subset_id,
            claimed_score,
        }
    }

    /// Return the seven ordered openings.
    #[must_use]
    pub const fn openings(&self) -> &[CardOpeningWitness; 7] {
        &self.openings
    }

    /// Return the unsigned subset witness.
    #[must_use]
    pub const fn subset_id(&self) -> u8 {
        self.subset_id
    }

    /// Return the claimed packed score.
    #[must_use]
    pub const fn claimed_score(&self) -> u32 {
        self.claimed_score
    }
}

/// A hand accepted by the exact native opening and poker predicates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedShowdownHand {
    seven: [u8; 7],
    selected: [u8; 5],
    score: HandScore,
}

impl VerifiedShowdownHand {
    /// Return all reconstructed cards in the role-specific protocol order.
    #[must_use]
    pub const fn seven(&self) -> [u8; 7] {
        self.seven
    }

    /// Return the exact selected subset.
    #[must_use]
    pub const fn selected(&self) -> [u8; 5] {
        self.selected
    }

    /// Return the validated canonical score.
    #[must_use]
    pub const fn score(&self) -> HandScore {
        self.score
    }
}

/// Verify one role's exact ordered seven-card claim.
///
/// # Errors
///
/// Rejects wrong slots, invalid openings, duplicate cards, invalid subsets,
/// malformed scores, and score mismatches.
pub fn verify_showdown_hand(
    deal: &AcceptedDeal,
    role: Role,
    witness: &ShowdownHandWitness,
) -> Result<VerifiedShowdownHand, BitcoinBackendError> {
    let expected_slots = match role {
        Role::Alice => ALICE_SEVEN_SLOTS,
        Role::Bob => BOB_SEVEN_SLOTS,
    };
    let mut seven = [0_u8; 7];
    for (position, (opening, expected_slot)) in
        witness.openings.iter().zip(expected_slots).enumerate()
    {
        if opening.slot != expected_slot {
            return Err(BitcoinBackendError::WrongShowdownSlot {
                position,
                expected: expected_slot,
                actual: opening.slot,
            });
        }
        seven[position] = verify_card_witness(deal, opening)?;
    }

    verify_claimed_hand(seven, witness.subset_id, witness.claimed_score)?;
    let selected = selected_five(seven, witness.subset_id)?;
    let score = HandScore::try_from(witness.claimed_score)?;
    Ok(VerifiedShowdownHand {
        seven,
        selected,
        score,
    })
}

/// Verify both committed contributions for one deal slot and reconstruct its
/// canonical card identifier.
///
/// # Errors
///
/// Rejects slots outside `0..=8`, then returns the first exact length or hash
/// error from Alice's or Bob's opening.
pub fn verify_card_witness(
    deal: &AcceptedDeal,
    opening: &CardOpeningWitness,
) -> Result<u8, BitcoinBackendError> {
    let index = usize::from(opening.slot);
    let hash_a = deal
        .hashes_a
        .get(index)
        .ok_or(BitcoinBackendError::InvalidDealSlot { slot: opening.slot })?;
    let hash_b = deal
        .hashes_b
        .get(index)
        .ok_or(BitcoinBackendError::InvalidDealSlot { slot: opening.slot })?;
    let a = verify_share_opening(hash_a, &opening.preimage_a).map_err(|source| {
        BitcoinBackendError::InvalidOpening {
            slot: opening.slot,
            source,
        }
    })?;
    let b = verify_share_opening(hash_b, &opening.preimage_b).map_err(|source| {
        BitcoinBackendError::InvalidOpening {
            slot: opening.slot,
            source,
        }
    })?;
    let sum = u16::from(a) + u16::from(b);
    let reduced = if sum >= 52 { sum - 52 } else { sum };
    // Both share values are in 0..=51, hence one subtraction always yields
    // 0..=51. Keep the conversion checked so this function remains fail closed
    // if the upstream opening profile ever changes.
    u8::try_from(reduced).map_err(|_| BitcoinBackendError::InvalidTransactionTemplate {
        reason: "card reduction exceeded u8",
    })
}

/// Verify Alice's repeated score certificate under the exact game/node key.
///
/// # Errors
///
/// Rejects noncanonical poker scores and every Lamport width, purpose,
/// context, or hash mismatch.
pub fn verify_alice_score_certificate(
    chain_game_id: [u8; 32],
    alice_showdown_node_id: [u8; 32],
    public_key: &LamportPublicKey,
    certificate: &AliceScoreCertificate,
) -> Result<HandScore, BitcoinBackendError> {
    let score = HandScore::try_from(certificate.score_a().get())?;
    certificate.verify(public_key, chain_game_id, alice_showdown_node_id)?;
    Ok(score)
}

/// Verify Bob's score certificate under the exact terminal-node key.
///
/// # Errors
///
/// Rejects noncanonical poker scores and every Lamport width, purpose,
/// context, or hash mismatch.
pub fn verify_bob_score_certificate(
    chain_game_id: [u8; 32],
    bob_terminal_node_id: [u8; 32],
    public_key: &LamportPublicKey,
    certificate: &BobScoreCertificate,
) -> Result<HandScore, BitcoinBackendError> {
    let score = HandScore::try_from(certificate.score_b().get())?;
    certificate.verify(public_key, chain_game_id, bob_terminal_node_id)?;
    Ok(score)
}

/// Verify Alice's hand and its score certificate in her showdown spend.
///
/// # Errors
///
/// Returns the underlying hand/certificate error or a score mismatch.
pub fn verify_alice_showdown(
    deal: &AcceptedDeal,
    chain_game_id: [u8; 32],
    alice_showdown_node_id: [u8; 32],
    public_key: &LamportPublicKey,
    hand: &ShowdownHandWitness,
    signature: LamportSignature,
) -> Result<(VerifiedShowdownHand, AliceScoreCertificate), BitcoinBackendError> {
    let verified_hand = verify_showdown_hand(deal, Role::Alice, hand)?;
    let certificate =
        AliceScoreCertificate::from_parts(Score24::new(hand.claimed_score)?, signature)?;
    let certificate_score = verify_alice_score_certificate(
        chain_game_id,
        alice_showdown_node_id,
        public_key,
        &certificate,
    )?;
    if certificate_score != verified_hand.score {
        return Err(BitcoinBackendError::AliceCertificateMismatch {
            certificate: certificate_score.as_u32(),
            hand: verified_hand.score.as_u32(),
        });
    }
    Ok((verified_hand, certificate))
}

/// Verify Bob's selected hand, both score certificates, and the exact
/// comparison branch. This function deliberately does not verify Bob's live
/// transaction signature; call [`crate::verify_sighash_default`] on the
/// selected fixed terminal template as the final authorization check.
///
/// # Errors
///
/// Rejects either hand/certificate or a comparison inconsistent with
/// `outcome`.
#[allow(clippy::too_many_arguments)]
pub fn verify_bob_showdown_outcome(
    deal: &AcceptedDeal,
    chain_game_id: [u8; 32],
    alice_showdown_node_id: [u8; 32],
    bob_terminal_node_id: [u8; 32],
    alice_score_public_key: &LamportPublicKey,
    bob_score_public_key: &LamportPublicKey,
    alice_certificate: &AliceScoreCertificate,
    bob_certificate: &BobScoreCertificate,
    bob_hand: &ShowdownHandWitness,
    outcome: ShowdownOutcome,
) -> Result<VerifiedShowdownHand, BitcoinBackendError> {
    let score_a = verify_alice_score_certificate(
        chain_game_id,
        alice_showdown_node_id,
        alice_score_public_key,
        alice_certificate,
    )?;
    let certified_score_b = verify_bob_score_certificate(
        chain_game_id,
        bob_terminal_node_id,
        bob_score_public_key,
        bob_certificate,
    )?;
    let verified_bob = verify_showdown_hand(deal, Role::Bob, bob_hand)?;
    if certified_score_b != verified_bob.score {
        return Err(BitcoinBackendError::BobCertificateMismatch {
            certificate: certified_score_b.as_u32(),
            hand: verified_bob.score.as_u32(),
        });
    }
    let valid = match outcome {
        ShowdownOutcome::AliceWin => certified_score_b < score_a,
        ShowdownOutcome::BobWin => certified_score_b > score_a,
        ShowdownOutcome::Split => certified_score_b == score_a,
    };
    if !valid {
        return Err(BitcoinBackendError::WrongShowdownOutcome {
            score_a: score_a.as_u32(),
            score_b: certified_score_b.as_u32(),
            outcome: outcome_name(outcome),
        });
    }
    Ok(verified_bob)
}

/// Verify the complete native Bob terminal predicate, including Alice's fixed
/// preauthorization and Bob's live signature over the same terminal template.
///
/// # Errors
///
/// Rejects either `SIGHASH_DEFAULT` signature, either hand/certificate,
/// or an outcome branch inconsistent with the two scores.
#[allow(clippy::too_many_arguments)]
pub fn verify_bob_terminal(
    deal: &AcceptedDeal,
    chain_game_id: [u8; 32],
    alice_showdown_node_id: [u8; 32],
    bob_terminal_node_id: [u8; 32],
    alice_score_public_key: &LamportPublicKey,
    bob_score_public_key: &LamportPublicKey,
    alice_certificate: &AliceScoreCertificate,
    bob_certificate: &BobScoreCertificate,
    bob_hand: &ShowdownHandWitness,
    outcome: ShowdownOutcome,
    terminal_sighash: [u8; 32],
    alice_xonly_key: [u8; 32],
    alice_signature: DefaultSighashSignature,
    bob_xonly_key: [u8; 32],
    bob_live_signature: DefaultSighashSignature,
) -> Result<VerifiedShowdownHand, BitcoinBackendError> {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    verify_sighash_default(&secp, alice_xonly_key, terminal_sighash, alice_signature)?;
    verify_sighash_default(&secp, bob_xonly_key, terminal_sighash, bob_live_signature)?;
    verify_bob_showdown_outcome(
        deal,
        chain_game_id,
        alice_showdown_node_id,
        bob_terminal_node_id,
        alice_score_public_key,
        bob_score_public_key,
        alice_certificate,
        bob_certificate,
        bob_hand,
        outcome,
    )
}

fn hash_for_role(deal: &AcceptedDeal, role: Role, slot: usize) -> [u8; 32] {
    match role {
        Role::Alice => deal.hashes_a[slot],
        Role::Bob => deal.hashes_b[slot],
    }
}

const fn outcome_name(outcome: ShowdownOutcome) -> &'static str {
    match outcome {
        ShowdownOutcome::AliceWin => "AliceWin",
        ShowdownOutcome::BobWin => "BobWin",
        ShowdownOutcome::Split => "Split",
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bp52_chain_types::{AcceptedDeal, Role, ShowdownOutcome};
    use bp52_lamport::{
        AliceScoreCertificate, BobScoreCertificate, KeyContext, LamportMessage, LamportPublicKey,
        LamportPurpose, LamportSignature, Score24,
    };
    use bp52_poker::evaluate_five_cards;
    use sha2::{Digest, Sha256};

    use super::{
        ALICE_SEVEN_SLOTS, BOB_SEVEN_SLOTS, CardOpeningWitness, RevealPattern,
        ShareRevealPredicate, ShowdownHandWitness, verify_alice_score_certificate,
        verify_bob_score_certificate, verify_bob_showdown_outcome, verify_bob_terminal,
        verify_card_witness, verify_showdown_hand,
    };
    use crate::{BitcoinBackendError, sign_sighash_default};

    struct Fixture {
        deal: AcceptedDeal,
        preimages_a: [Vec<u8>; 9],
        preimages_b: [Vec<u8>; 9],
    }

    fn fixture() -> Fixture {
        let preimages_a =
            core::array::from_fn(|index| vec![0x20 + u8::try_from(index).unwrap_or_default(); 16]);
        let preimages_b = core::array::from_fn(|index| {
            vec![0x60 + u8::try_from(index).unwrap_or_default(); 16 + index]
        });
        let hashes_a = core::array::from_fn(|index| Sha256::digest(&preimages_a[index]).into());
        let hashes_b = core::array::from_fn(|index| Sha256::digest(&preimages_b[index]).into());
        Fixture {
            deal: AcceptedDeal {
                protocol_version: 1,
                game_id: [1_u8; 32],
                attempt: 0,
                hashes_a,
                hashes_b,
                verification_transcript_root: [2_u8; 32],
                signature_a: [3_u8; 64],
                signature_b: [4_u8; 64],
            },
            preimages_a,
            preimages_b,
        }
    }

    fn hand_witness(
        fixture: &Fixture,
        role: Role,
        subset_id: u8,
        claimed_score: u32,
    ) -> ShowdownHandWitness {
        let slots = match role {
            Role::Alice => ALICE_SEVEN_SLOTS,
            Role::Bob => BOB_SEVEN_SLOTS,
        };
        let openings = slots.map(|slot| {
            let index = usize::from(slot);
            CardOpeningWitness::new(
                slot,
                fixture.preimages_a[index].clone(),
                fixture.preimages_b[index].clone(),
            )
        });
        ShowdownHandWitness::new(openings, subset_id, claimed_score)
    }

    fn score_key_and_signature(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score: u32,
    ) -> Result<(LamportPublicKey, LamportSignature), bp52_lamport::LamportError> {
        let message = LamportMessage::AliceScore(Score24::new(score)?);
        let bits = message.bits_msb_first();
        let mut pairs = Vec::with_capacity(bits.len());
        let mut revealed = Vec::with_capacity(bits.len());
        for (index, bit) in bits.into_iter().enumerate() {
            let index_byte = u8::try_from(index).unwrap_or_default();
            let secrets = [[index_byte + 1; 32], [index_byte + 101; 32]];
            pairs.push([
                Sha256::digest(secrets[0]).into(),
                Sha256::digest(secrets[1]).into(),
            ]);
            revealed.push(secrets[usize::from(bit)]);
        }
        let key = LamportPublicKey::from_parts(
            KeyContext::new(chain_game_id, node_id, LamportPurpose::AliceScore24Bit),
            pairs,
        )?;
        let signature = LamportSignature::from_parts(LamportPurpose::AliceScore24Bit, revealed)?;
        Ok((key, signature))
    }

    fn bob_score_key_and_signature(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score: u32,
    ) -> Result<(LamportPublicKey, LamportSignature), bp52_lamport::LamportError> {
        let message = LamportMessage::BobScore(Score24::new(score)?);
        let bits = message.bits_msb_first();
        let mut pairs = Vec::with_capacity(bits.len());
        let mut revealed = Vec::with_capacity(bits.len());
        for (index, bit) in bits.into_iter().enumerate() {
            let index_byte = u8::try_from(index).unwrap_or_default();
            let secrets = [[index_byte + 1; 32], [index_byte + 101; 32]];
            pairs.push([
                Sha256::digest(secrets[0]).into(),
                Sha256::digest(secrets[1]).into(),
            ]);
            revealed.push(secrets[usize::from(bit)]);
        }
        let key = LamportPublicKey::from_parts(
            KeyContext::new(chain_game_id, node_id, LamportPurpose::BobScore24Bit),
            pairs,
        )?;
        let signature = LamportSignature::from_parts(LamportPurpose::BobScore24Bit, revealed)?;
        Ok((key, signature))
    }

    fn bitcoin_keypair(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        byte: u8,
    ) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secret = SecretKey::from_slice(&[byte; 32])?;
        Ok(Keypair::from_secret_key(secp, &secret))
    }

    #[test]
    fn exact_reveal_patterns_accept_only_complete_correct_preimages() {
        let fixture = fixture();
        let predicate = ShareRevealPredicate::new(&fixture.deal, RevealPattern::DealAlice);
        let valid = [
            fixture.preimages_b[0].as_slice(),
            fixture.preimages_b[2].as_slice(),
        ];
        assert_eq!(predicate.pattern().revealer(), Role::Bob);
        assert_eq!(predicate.pattern().slots(), [0, 2]);
        assert_eq!(predicate.verify(&valid), Ok(()));
        assert!(matches!(
            predicate.verify(&valid[..1]),
            Err(BitcoinBackendError::WrongRevealCount { .. })
        ));

        let wrong = [
            fixture.preimages_a[0].as_slice(),
            fixture.preimages_b[2].as_slice(),
        ];
        assert!(matches!(
            predicate.verify(&wrong),
            Err(BitcoinBackendError::InvalidOpening { slot: 0, .. })
        ));

        for pattern in [
            RevealPattern::DealAlice,
            RevealPattern::DealBob,
            RevealPattern::Flop(Role::Alice),
            RevealPattern::Flop(Role::Bob),
            RevealPattern::Turn(Role::Alice),
            RevealPattern::Turn(Role::Bob),
            RevealPattern::River(Role::Alice),
            RevealPattern::River(Role::Bob),
        ] {
            let predicate = ShareRevealPredicate::new(&fixture.deal, pattern);
            let openings = pattern
                .slots()
                .iter()
                .map(|slot| match pattern.revealer() {
                    Role::Alice => fixture.preimages_a[usize::from(*slot)].as_slice(),
                    Role::Bob => fixture.preimages_b[usize::from(*slot)].as_slice(),
                })
                .collect::<Vec<_>>();
            assert_eq!(predicate.verify(&openings), Ok(()));

            let mut too_short = openings;
            too_short[0] = &[0_u8; 15];
            assert!(matches!(
                predicate.verify(&too_short),
                Err(BitcoinBackendError::InvalidOpening {
                    source: bp52_bitcoin::OpeningError::InvalidPreimageLength { actual: 15 },
                    ..
                })
            ));
        }
    }

    #[test]
    fn card_witness_reconstructs_modulo_52_and_rejects_unknown_slots()
    -> Result<(), BitcoinBackendError> {
        let mut fixture = fixture();
        let long_a = vec![0xa5; 67];
        let long_b = vec![0x5a; 67];
        fixture.deal.hashes_a[0] = Sha256::digest(&long_a).into();
        fixture.deal.hashes_b[0] = Sha256::digest(&long_b).into();
        assert_eq!(
            verify_card_witness(&fixture.deal, &CardOpeningWitness::new(0, long_a, long_b),)?,
            50
        );
        assert_eq!(
            verify_card_witness(
                &fixture.deal,
                &CardOpeningWitness::new(9, vec![0; 16], vec![0; 16]),
            ),
            Err(BitcoinBackendError::InvalidDealSlot { slot: 9 })
        );
        Ok(())
    }

    #[test]
    fn showdown_reconstructs_exact_role_slots_and_accepts_board_tie()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture();
        let board_score = evaluate_five_cards([4, 5, 6, 7, 8])?;
        let alice = hand_witness(&fixture, Role::Alice, 20, board_score);
        let bob = hand_witness(&fixture, Role::Bob, 20, board_score);
        assert_eq!(
            verify_showdown_hand(&fixture.deal, Role::Alice, &alice)?.seven(),
            [0, 2, 4, 5, 6, 7, 8]
        );
        assert_eq!(
            verify_showdown_hand(&fixture.deal, Role::Bob, &bob)?.seven(),
            [1, 3, 4, 5, 6, 7, 8]
        );

        // A deliberately weaker but still valid subset is accepted. The
        // protocol intentionally contains no max-over-21 check.
        let weaker_score = evaluate_five_cards([0, 2, 4, 5, 6])?;
        assert!(weaker_score < board_score);
        let weaker = hand_witness(&fixture, Role::Alice, 0, weaker_score);
        assert_eq!(
            verify_showdown_hand(&fixture.deal, Role::Alice, &weaker)?
                .score()
                .as_u32(),
            weaker_score
        );

        let mut wrong_openings = alice.openings().clone();
        wrong_openings.swap(0, 1);
        let wrong = ShowdownHandWitness::new(wrong_openings, 20, board_score);
        assert!(matches!(
            verify_showdown_hand(&fixture.deal, Role::Alice, &wrong),
            Err(BitcoinBackendError::WrongShowdownSlot { position: 0, .. })
        ));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_terminal_comparison_is_strict_and_branch_specific()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture();
        let chain_game_id = [31_u8; 32];
        let alice_node_id = [32_u8; 32];
        let bob_node_id = [33_u8; 32];
        let weak_score = evaluate_five_cards([1, 3, 4, 5, 6])?;
        let strong_score = evaluate_five_cards([4, 5, 6, 7, 8])?;
        assert!(weak_score < strong_score);

        let weak_bob = hand_witness(&fixture, Role::Bob, 0, weak_score);
        let strong_bob = hand_witness(&fixture, Role::Bob, 20, strong_score);
        let (key, strong_signature) =
            score_key_and_signature(chain_game_id, alice_node_id, strong_score)?;
        let strong_certificate =
            AliceScoreCertificate::from_parts(Score24::new(strong_score)?, strong_signature)?;
        let (bob_key, weak_bob_signature) =
            bob_score_key_and_signature(chain_game_id, bob_node_id, weak_score)?;
        let weak_bob_certificate =
            BobScoreCertificate::from_parts(Score24::new(weak_score)?, weak_bob_signature)?;
        let (same_bob_key, strong_bob_signature) =
            bob_score_key_and_signature(chain_game_id, bob_node_id, strong_score)?;
        assert_eq!(same_bob_key, bob_key);
        let strong_bob_certificate =
            BobScoreCertificate::from_parts(Score24::new(strong_score)?, strong_bob_signature)?;
        assert!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &key,
                &bob_key,
                &strong_certificate,
                &weak_bob_certificate,
                &weak_bob,
                ShowdownOutcome::AliceWin,
            )
            .is_ok()
        );
        assert!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &key,
                &bob_key,
                &strong_certificate,
                &strong_bob_certificate,
                &strong_bob,
                ShowdownOutcome::Split,
            )
            .is_ok()
        );

        let (same_key, weak_signature) =
            score_key_and_signature(chain_game_id, alice_node_id, weak_score)?;
        assert_eq!(same_key, key);
        let weak_certificate =
            AliceScoreCertificate::from_parts(Score24::new(weak_score)?, weak_signature)?;
        assert!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &key,
                &bob_key,
                &weak_certificate,
                &strong_bob_certificate,
                &strong_bob,
                ShowdownOutcome::BobWin,
            )
            .is_ok()
        );
        assert!(matches!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &key,
                &bob_key,
                &weak_certificate,
                &strong_bob_certificate,
                &strong_bob,
                ShowdownOutcome::Split,
            ),
            Err(BitcoinBackendError::WrongShowdownOutcome { .. })
        ));
        assert!(matches!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &key,
                &bob_key,
                &strong_certificate,
                &strong_bob_certificate,
                &weak_bob,
                ShowdownOutcome::AliceWin,
            ),
            Err(BitcoinBackendError::BobCertificateMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn score_certificate_is_context_bound_and_reusable_by_bob()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture();
        let chain_game_id = [9_u8; 32];
        let alice_node_id = [10_u8; 32];
        let bob_node_id = [11_u8; 32];
        let score = evaluate_five_cards([4, 5, 6, 7, 8])?;
        let (public_key, signature) = score_key_and_signature(chain_game_id, alice_node_id, score)?;
        let certificate = AliceScoreCertificate::from_parts(Score24::new(score)?, signature)?;
        assert_eq!(
            verify_alice_score_certificate(
                chain_game_id,
                alice_node_id,
                &public_key,
                &certificate,
            )?,
            bp52_poker::HandScore::try_from(score)?
        );
        assert!(matches!(
            verify_alice_score_certificate([8_u8; 32], alice_node_id, &public_key, &certificate),
            Err(BitcoinBackendError::Lamport(
                bp52_lamport::LamportError::WrongGame
            ))
        ));

        let (bob_score_key, bob_signature) =
            bob_score_key_and_signature(chain_game_id, bob_node_id, score)?;
        let bob_certificate = BobScoreCertificate::from_parts(Score24::new(score)?, bob_signature)?;
        assert_eq!(
            verify_bob_score_certificate(
                chain_game_id,
                bob_node_id,
                &bob_score_key,
                &bob_certificate,
            )?,
            bp52_poker::HandScore::try_from(score)?
        );

        let bob = hand_witness(&fixture, Role::Bob, 20, score);
        assert!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &public_key,
                &bob_score_key,
                &certificate,
                &bob_certificate,
                &bob,
                ShowdownOutcome::Split,
            )
            .is_ok()
        );
        assert!(matches!(
            verify_bob_showdown_outcome(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &public_key,
                &bob_score_key,
                &certificate,
                &bob_certificate,
                &bob,
                ShowdownOutcome::BobWin,
            ),
            Err(BitcoinBackendError::WrongShowdownOutcome { .. })
        ));
        Ok(())
    }

    #[test]
    fn bob_terminal_requires_both_signatures_on_selected_branch()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture();
        let chain_game_id = [11_u8; 32];
        let alice_node_id = [12_u8; 32];
        let bob_node_id = [13_u8; 32];
        let score = evaluate_five_cards([4, 5, 6, 7, 8])?;
        let (score_key, score_signature) =
            score_key_and_signature(chain_game_id, alice_node_id, score)?;
        let certificate = AliceScoreCertificate::from_parts(Score24::new(score)?, score_signature)?;
        let (bob_score_key, bob_score_signature) =
            bob_score_key_and_signature(chain_game_id, bob_node_id, score)?;
        let bob_certificate =
            BobScoreCertificate::from_parts(Score24::new(score)?, bob_score_signature)?;
        let bob_hand = hand_witness(&fixture, Role::Bob, 20, score);

        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 21)?;
        let bob_keypair = bitcoin_keypair(&secp, 22)?;
        let (alice_public, _) = alice_keypair.x_only_public_key();
        let (bob_public, _) = bob_keypair.x_only_public_key();
        let digest = [13_u8; 32];
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, digest);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, digest);
        assert!(
            verify_bob_terminal(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &score_key,
                &bob_score_key,
                &certificate,
                &bob_certificate,
                &bob_hand,
                ShowdownOutcome::Split,
                digest,
                alice_public.serialize(),
                alice_signature,
                bob_public.serialize(),
                bob_signature,
            )
            .is_ok()
        );

        let wrong_bob_signature = sign_sighash_default(&secp, &alice_keypair, digest);
        assert_eq!(
            verify_bob_terminal(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &score_key,
                &bob_score_key,
                &certificate,
                &bob_certificate,
                &bob_hand,
                ShowdownOutcome::Split,
                digest,
                alice_public.serialize(),
                alice_signature,
                bob_public.serialize(),
                wrong_bob_signature,
            ),
            Err(BitcoinBackendError::InvalidBitcoinSignature)
        );
        assert_eq!(
            verify_bob_terminal(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                bob_node_id,
                &score_key,
                &bob_score_key,
                &certificate,
                &bob_certificate,
                &bob_hand,
                ShowdownOutcome::Split,
                [14_u8; 32],
                alice_public.serialize(),
                alice_signature,
                bob_public.serialize(),
                bob_signature,
            ),
            Err(BitcoinBackendError::InvalidBitcoinSignature)
        );
        Ok(())
    }
}
