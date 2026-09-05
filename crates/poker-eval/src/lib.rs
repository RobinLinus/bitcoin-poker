#![forbid(unsafe_code)]
//! Pure poker primitives for BP52-CHAIN-v1.
//!
//! The protocol deliberately verifies one claimed five-card subset of a
//! player's seven cards. It does not search for, or require, the best of all
//! 21 subsets.

pub mod card;
pub mod eval5;
pub mod score;
pub mod subsets;

use core::fmt;

pub use card::{Card, CardId, DECK_SIZE, RANK_COUNT, SUIT_COUNT, decode_card};
pub use eval5::eval5;
pub use score::{HandCategory, HandScore};
pub use subsets::{SUBSETS_5_OF_7, selected_five};

/// An invalid poker input or an untrue five-card score claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PokerError {
    /// A card identifier was outside the BP52 deck range `0..=51`.
    InvalidCard {
        /// The rejected identifier.
        card_id: u8,
    },
    /// A card identifier appeared more than once in one hand.
    DuplicateCard {
        /// The repeated identifier.
        card_id: u8,
    },
    /// A subset witness was outside the fixed range `0..=20`.
    InvalidSubsetId {
        /// The rejected subset identifier.
        subset_id: u8,
    },
    /// A packed score was not a canonical BP52 24-bit score.
    InvalidHandScore {
        /// The rejected packed score.
        score: u32,
    },
    /// The selected five cards did not support the claimed lower-bound score.
    ClaimedScoreMismatch {
        /// The score supplied by the claimant.
        claimed_score: u32,
        /// The canonical score of the selected five cards.
        actual_score: u32,
    },
}

impl fmt::Display for PokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidCard { card_id } => {
                write!(formatter, "card identifier {card_id} is outside 0..=51")
            }
            Self::DuplicateCard { card_id } => {
                write!(
                    formatter,
                    "card identifier {card_id} appears more than once"
                )
            }
            Self::InvalidSubsetId { subset_id } => {
                write!(formatter, "subset identifier {subset_id} is outside 0..=20")
            }
            Self::InvalidHandScore { score } => {
                write!(
                    formatter,
                    "0x{score:08x} is not a canonical 24-bit hand score"
                )
            }
            Self::ClaimedScoreMismatch {
                claimed_score,
                actual_score,
            } => write!(
                formatter,
                "claimed score 0x{claimed_score:06x} is not supported by selected-hand score 0x{actual_score:06x}"
            ),
        }
    }
}

impl std::error::Error for PokerError {}

/// Evaluate exactly five BP52 card identifiers and return their canonical
/// packed 24-bit score.
///
/// # Errors
///
/// Returns [`PokerError::InvalidCard`] for an identifier above 51 and
/// [`PokerError::DuplicateCard`] if a card occurs more than once.
pub fn evaluate_five_cards(cards: [u8; 5]) -> Result<u32, PokerError> {
    eval5(cards).map(HandScore::as_u32)
}

/// Verify that one explicitly selected five-card subset witnesses a score.
///
/// An exact score is required within one category. A strictly stronger
/// category also satisfies the claim, matching category-specialized Taproot
/// leaves. This function intentionally performs no max-over-21 check.
///
/// # Errors
///
/// Returns an error when the seven-card set, subset identifier, or packed
/// score is malformed, or when the selected cards do not witness the claim.
pub fn verify_claimed_hand(
    seven: [u8; 7],
    subset_id: u8,
    claimed_score: u32,
) -> Result<(), PokerError> {
    let selected = selected_five(seven, subset_id)?;
    let actual = eval5(selected)?;
    let claimed = HandScore::try_from(claimed_score)?;

    if actual == claimed || actual.category() > claimed.category() {
        Ok(())
    } else {
        Err(PokerError::ClaimedScoreMismatch {
            claimed_score,
            actual_score: actual.as_u32(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(rank: u8, suit: u8) -> u8 {
        rank * SUIT_COUNT + suit
    }

    #[test]
    fn public_api_uses_the_canonical_score() {
        let royal_flush = [
            card(12, 3),
            card(11, 3),
            card(10, 3),
            card(9, 3),
            card(8, 3),
        ];
        assert_eq!(evaluate_five_cards(royal_flush), Ok(0x8c_0000));
    }

    #[test]
    fn stronger_category_satisfies_a_lower_bound_claim() -> Result<(), PokerError> {
        let straight_flush = [
            card(12, 3),
            card(11, 3),
            card(10, 3),
            card(9, 3),
            card(8, 3),
        ];
        let seven = [
            straight_flush[0],
            straight_flush[1],
            straight_flush[2],
            straight_flush[3],
            straight_flush[4],
            card(0, 0),
            card(1, 1),
        ];
        let straight = HandScore::from_components(HandCategory::Straight, [12, 0, 0, 0, 0])?;
        assert_eq!(verify_claimed_hand(seven, 0, straight.as_u32()), Ok(()));
        Ok(())
    }

    #[test]
    fn claimed_hand_checks_only_the_requested_subset() -> Result<(), PokerError> {
        let seven = [
            card(12, 0),
            card(12, 1),
            card(11, 0),
            card(10, 1),
            card(9, 2),
            card(8, 3),
            card(0, 0),
        ];

        let weaker = selected_five(seven, 0)?;
        let weaker_score = evaluate_five_cards(weaker)?;
        assert_eq!(verify_claimed_hand(seven, 0, weaker_score), Ok(()));

        let stronger = selected_five(seven, 10)?;
        let stronger_score = evaluate_five_cards(stronger)?;
        assert!(stronger_score > weaker_score);
        assert_eq!(
            verify_claimed_hand(seven, 0, stronger_score),
            Err(PokerError::ClaimedScoreMismatch {
                claimed_score: stronger_score,
                actual_score: weaker_score,
            })
        );
        Ok(())
    }

    #[test]
    fn board_only_hands_tie_and_weaker_valid_claims_remain_valid() -> Result<(), PokerError> {
        let board = [
            card(8, 0),
            card(9, 1),
            card(10, 2),
            card(11, 3),
            card(12, 0),
        ];
        let alice_seven = [
            card(0, 0),
            card(1, 1),
            board[0],
            board[1],
            board[2],
            board[3],
            board[4],
        ];
        let bob_seven = [
            card(6, 2),
            card(7, 3),
            board[0],
            board[1],
            board[2],
            board[3],
            board[4],
        ];
        let board_score = evaluate_five_cards(board)?;

        assert_eq!(verify_claimed_hand(alice_seven, 20, board_score), Ok(()));
        assert_eq!(verify_claimed_hand(bob_seven, 20, board_score), Ok(()));

        // Alice could instead witness her weaker high-card subset. The API
        // must not silently replace it with the best of all 21 subsets.
        let weaker = selected_five(alice_seven, 0)?;
        let weaker_score = evaluate_five_cards(weaker)?;
        assert!(weaker_score < board_score);
        assert_eq!(verify_claimed_hand(alice_seven, 0, weaker_score), Ok(()));
        Ok(())
    }
}
