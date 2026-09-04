//! Stage-aware selective-reveal helpers for an accepted deal.
//!
//! These functions validate reveals against a certificate whose complete
//! sixteen-envelope archive has already been replayed successfully.

use bp52_protocol::{Role, VerifiedAcceptedDeal, messages::AcceptedDeal};
use thiserror::Error;

use crate::opening::{DECK_SIZE, OpeningError, verify_card_opening, verify_share_opening};

/// Alice's two hole-card slots in canonical deal order.
pub const ALICE_HOLE_SLOTS: [u8; 2] = [0, 2];
/// Bob's two hole-card slots in canonical deal order.
pub const BOB_HOLE_SLOTS: [u8; 2] = [1, 3];
/// The three flop slots in canonical deal order.
pub const FLOP_SLOTS: [u8; 3] = [4, 5, 6];
/// The turn slot.
pub const TURN_SLOT: u8 = 7;
/// The river slot.
pub const RIVER_SLOT: u8 = 8;

/// A public community-card reveal stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityStage {
    /// The three-card flop in slots 4, 5, and 6.
    Flop,
    /// The turn in slot 7.
    Turn,
    /// The river in slot 8.
    River,
}

impl CommunityStage {
    /// Returns whether `slot` belongs to this reveal stage.
    #[must_use]
    pub const fn contains(self, slot: u8) -> bool {
        match self {
            Self::Flop => matches!(slot, 4..=6),
            Self::Turn => slot == TURN_SLOT,
            Self::River => slot == RIVER_SLOT,
        }
    }
}

/// A card whose hash openings and deal slot have been verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCard {
    slot: u8,
    card: u8,
}

impl VerifiedCard {
    /// Returns the canonical deal slot in `0..=8`.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        self.slot
    }

    /// Returns the card identifier in `0..=51`.
    #[must_use]
    pub const fn card(&self) -> u8 {
        self.card
    }
}

/// Failure to deliver or publicly reveal a card from an accepted deal.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevealError {
    /// The requested slot was not one of the nine accepted-deal slots.
    #[error("invalid deal slot {slot}; expected 0..=8")]
    InvalidSlot {
        /// Rejected slot identifier.
        slot: u8,
    },
    /// The requested hole-card slot belongs to the other player or is public.
    #[error("slot {slot} is not a hole-card slot owned by {player:?}")]
    WrongHoleCardOwner {
        /// Player for whom the reveal was requested.
        player: Role,
        /// Rejected slot identifier.
        slot: u8,
    },
    /// The requested public slot does not belong to the given stage.
    #[error("slot {slot} is not part of the {stage:?} reveal")]
    WrongCommunityStage {
        /// Requested community-card stage.
        stage: CommunityStage,
        /// Rejected slot identifier.
        slot: u8,
    },
    /// One of the hash, length, claimed-card, or raw-sum checks failed.
    #[error(transparent)]
    InvalidOpening(#[from] OpeningError),
}

/// Verifies delivery of the peer's share for one private hole card.
///
/// `own_preimage` is the recipient's contribution and `peer_preimage` is the
/// newly delivered contribution. The function checks both against the signed
/// accepted-deal hash arrays and returns the complete card without exposing
/// either preimage to the other player.
///
/// # Errors
///
/// Rejects an invalid or incorrectly owned slot and propagates either share's
/// length or SHA-256 mismatch.
pub fn verify_hole_card_delivery(
    deal: &VerifiedAcceptedDeal,
    player: Role,
    slot: u8,
    own_preimage: &[u8],
    peer_preimage: &[u8],
) -> Result<VerifiedCard, RevealError> {
    verify_hole_card_delivery_for_deal(deal.as_deal(), player, slot, own_preimage, peer_preimage)
}

fn verify_hole_card_delivery_for_deal(
    deal: &AcceptedDeal,
    player: Role,
    slot: u8,
    own_preimage: &[u8],
    peer_preimage: &[u8],
) -> Result<VerifiedCard, RevealError> {
    let index = slot_index(slot)?;
    if !is_hole_slot(player, slot) {
        return Err(RevealError::WrongHoleCardOwner { player, slot });
    }

    let (preimage_a, preimage_b) = match player {
        Role::Alice => (own_preimage, peer_preimage),
        Role::Bob => (peer_preimage, own_preimage),
    };
    let a = verify_share_opening(&deal.hashes_a[index], preimage_a)?;
    let b = verify_share_opening(&deal.hashes_b[index], preimage_b)?;
    let raw_sum = u16::from(a) + u16::from(b);
    let deck_size = u16::from(DECK_SIZE);
    let card = if raw_sum >= deck_size {
        u8::try_from(raw_sum - deck_size).map_err(|_| OpeningError::CardMismatch {
            claimed_card: 0,
            raw_sum,
        })?
    } else {
        u8::try_from(raw_sum).map_err(|_| OpeningError::CardMismatch {
            claimed_card: 0,
            raw_sum,
        })?
    };

    Ok(VerifiedCard { slot, card })
}

/// Verifies a player's public showdown reveal of one of its hole cards.
///
/// Both preimages are supplied in canonical Alice-then-Bob order. This is the
/// public verification step after the opponent's share was delivered privately.
///
/// # Errors
///
/// Rejects an invalid or incorrectly owned slot and propagates any opening
/// predicate failure.
pub fn verify_showdown_reveal(
    deal: &VerifiedAcceptedDeal,
    player: Role,
    slot: u8,
    preimage_a: &[u8],
    preimage_b: &[u8],
    claimed_card: u8,
) -> Result<VerifiedCard, RevealError> {
    verify_showdown_reveal_for_deal(
        deal.as_deal(),
        player,
        slot,
        preimage_a,
        preimage_b,
        claimed_card,
    )
}

fn verify_showdown_reveal_for_deal(
    deal: &AcceptedDeal,
    player: Role,
    slot: u8,
    preimage_a: &[u8],
    preimage_b: &[u8],
    claimed_card: u8,
) -> Result<VerifiedCard, RevealError> {
    let index = slot_index(slot)?;
    if !is_hole_slot(player, slot) {
        return Err(RevealError::WrongHoleCardOwner { player, slot });
    }
    verify_card_opening(
        &deal.hashes_a[index],
        preimage_a,
        &deal.hashes_b[index],
        preimage_b,
        claimed_card,
    )?;
    Ok(VerifiedCard {
        slot,
        card: claimed_card,
    })
}

/// Verifies one public community-card reveal at its protocol stage.
///
/// Both preimages are supplied in canonical Alice-then-Bob order.
///
/// # Errors
///
/// Rejects an invalid slot, a slot not assigned to `stage`, or any opening
/// predicate failure.
pub fn verify_community_reveal(
    deal: &VerifiedAcceptedDeal,
    stage: CommunityStage,
    slot: u8,
    preimage_a: &[u8],
    preimage_b: &[u8],
    claimed_card: u8,
) -> Result<VerifiedCard, RevealError> {
    verify_community_reveal_for_deal(
        deal.as_deal(),
        stage,
        slot,
        preimage_a,
        preimage_b,
        claimed_card,
    )
}

fn verify_community_reveal_for_deal(
    deal: &AcceptedDeal,
    stage: CommunityStage,
    slot: u8,
    preimage_a: &[u8],
    preimage_b: &[u8],
    claimed_card: u8,
) -> Result<VerifiedCard, RevealError> {
    let index = slot_index(slot)?;
    if !stage.contains(slot) {
        return Err(RevealError::WrongCommunityStage { stage, slot });
    }
    verify_card_opening(
        &deal.hashes_a[index],
        preimage_a,
        &deal.hashes_b[index],
        preimage_b,
        claimed_card,
    )?;
    Ok(VerifiedCard {
        slot,
        card: claimed_card,
    })
}

fn slot_index(slot: u8) -> Result<usize, RevealError> {
    if slot <= RIVER_SLOT {
        Ok(usize::from(slot))
    } else {
        Err(RevealError::InvalidSlot { slot })
    }
}

const fn is_hole_slot(player: Role, slot: u8) -> bool {
    match player {
        Role::Alice => matches!(slot, 0 | 2),
        Role::Bob => matches!(slot, 1 | 3),
    }
}

#[cfg(test)]
mod tests {
    use bp52_protocol::{PROTOCOL_VERSION, Role, messages::AcceptedDeal};
    use sha2::{Digest, Sha256};

    use super::{
        CommunityStage, RevealError, VerifiedCard,
        verify_community_reveal_for_deal as verify_community_reveal,
        verify_hole_card_delivery_for_deal as verify_hole_card_delivery,
        verify_showdown_reveal_for_deal as verify_showdown_reveal,
    };
    use crate::opening::{BASE_PREIMAGE_LENGTH, OpeningError};

    fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    struct RevealFixtures {
        deal: AcceptedDeal,
        preimages_a: [Vec<u8>; 9],
        preimages_b: [Vec<u8>; 9],
        cards: [u8; 9],
    }

    fn fixtures() -> RevealFixtures {
        let values_a = [0_u8, 1, 2, 3, 4, 5, 51, 51, 51];
        let values_b = [0_u8, 9, 18, 27, 36, 45, 7, 8, 9];
        let preimages_a = core::array::from_fn(|index| {
            vec![
                0xa0_u8 + u8::try_from(index).unwrap_or(0);
                BASE_PREIMAGE_LENGTH + usize::from(values_a[index])
            ]
        });
        let preimages_b = core::array::from_fn(|index| {
            vec![
                0xb0_u8 + u8::try_from(index).unwrap_or(0);
                BASE_PREIMAGE_LENGTH + usize::from(values_b[index])
            ]
        });
        let cards = core::array::from_fn(|index| {
            let sum = u16::from(values_a[index]) + u16::from(values_b[index]);
            u8::try_from(if sum >= 52 { sum - 52 } else { sum }).unwrap_or(0)
        });
        let deal = AcceptedDeal {
            protocol_version: PROTOCOL_VERSION,
            game_id: [1_u8; 32],
            attempt: 0,
            hashes_a: core::array::from_fn(|index| hash(&preimages_a[index])),
            hashes_b: core::array::from_fn(|index| hash(&preimages_b[index])),
            verification_transcript_root: [2_u8; 32],
            signature_a: [3_u8; 64],
            signature_b: [4_u8; 64],
        };
        RevealFixtures {
            deal,
            preimages_a,
            preimages_b,
            cards,
        }
    }

    #[test]
    fn private_hole_delivery_respects_owner_and_preimage_order() {
        let RevealFixtures {
            deal,
            preimages_a,
            preimages_b,
            cards,
        } = fixtures();
        for (player, slots) in [(Role::Alice, [0_u8, 2]), (Role::Bob, [1_u8, 3])] {
            for slot in slots {
                let index = usize::from(slot);
                let (own, peer) = match player {
                    Role::Alice => (&preimages_a[index], &preimages_b[index]),
                    Role::Bob => (&preimages_b[index], &preimages_a[index]),
                };
                assert_eq!(
                    verify_hole_card_delivery(&deal, player, slot, own, peer),
                    Ok(VerifiedCard {
                        slot,
                        card: cards[index]
                    })
                );
            }
        }

        assert_eq!(
            verify_hole_card_delivery(&deal, Role::Alice, 1, &preimages_a[1], &preimages_b[1]),
            Err(RevealError::WrongHoleCardOwner {
                player: Role::Alice,
                slot: 1,
            })
        );
    }

    #[test]
    fn showdown_accepts_only_the_players_hole_slots() {
        let RevealFixtures {
            deal,
            preimages_a,
            preimages_b,
            cards,
        } = fixtures();
        for (player, slots) in [(Role::Alice, [0_u8, 2]), (Role::Bob, [1_u8, 3])] {
            for slot in slots {
                let index = usize::from(slot);
                assert_eq!(
                    verify_showdown_reveal(
                        &deal,
                        player,
                        slot,
                        &preimages_a[index],
                        &preimages_b[index],
                        cards[index],
                    ),
                    Ok(VerifiedCard {
                        slot,
                        card: cards[index]
                    })
                );
            }
        }
        assert_eq!(
            verify_showdown_reveal(
                &deal,
                Role::Bob,
                2,
                &preimages_a[2],
                &preimages_b[2],
                cards[2],
            ),
            Err(RevealError::WrongHoleCardOwner {
                player: Role::Bob,
                slot: 2,
            })
        );
    }

    #[test]
    fn community_reveals_are_stage_bound() {
        let RevealFixtures {
            deal,
            preimages_a,
            preimages_b,
            cards,
        } = fixtures();
        for (stage, slots) in [
            (CommunityStage::Flop, &[4_u8, 5, 6][..]),
            (CommunityStage::Turn, &[7_u8][..]),
            (CommunityStage::River, &[8_u8][..]),
        ] {
            for slot in slots {
                let index = usize::from(*slot);
                assert_eq!(
                    verify_community_reveal(
                        &deal,
                        stage,
                        *slot,
                        &preimages_a[index],
                        &preimages_b[index],
                        cards[index],
                    ),
                    Ok(VerifiedCard {
                        slot: *slot,
                        card: cards[index]
                    })
                );
            }
        }

        assert_eq!(
            verify_community_reveal(
                &deal,
                CommunityStage::Flop,
                7,
                &preimages_a[7],
                &preimages_b[7],
                cards[7],
            ),
            Err(RevealError::WrongCommunityStage {
                stage: CommunityStage::Flop,
                slot: 7,
            })
        );
        assert_eq!(
            verify_community_reveal(&deal, CommunityStage::River, 9, &[], &[], 0,),
            Err(RevealError::InvalidSlot { slot: 9 })
        );
    }

    #[test]
    fn reveal_apis_reject_wrong_hashes_and_claims() {
        let RevealFixtures {
            deal,
            preimages_a,
            preimages_b,
            cards,
        } = fixtures();
        let mut wrong = preimages_a[0].clone();
        wrong[0] ^= 1;
        assert_eq!(
            verify_hole_card_delivery(&deal, Role::Alice, 0, &wrong, &preimages_b[0]),
            Err(RevealError::InvalidOpening(OpeningError::HashMismatch))
        );

        assert!(matches!(
            verify_community_reveal(
                &deal,
                CommunityStage::Flop,
                4,
                &preimages_a[4],
                &preimages_b[4],
                cards[4].wrapping_add(1),
            ),
            Err(RevealError::InvalidOpening(
                OpeningError::CardMismatch { .. }
            ))
        ));
    }
}
