//! The canonical lexicographic mapping of subset witnesses to five cards.

use crate::{CardId, PokerError, card::validate_distinct_cards};

/// All `5-of-7` index subsets in lexicographic order.
pub const SUBSETS_5_OF_7: [[u8; 5]; 21] = [
    [0, 1, 2, 3, 4],
    [0, 1, 2, 3, 5],
    [0, 1, 2, 3, 6],
    [0, 1, 2, 4, 5],
    [0, 1, 2, 4, 6],
    [0, 1, 2, 5, 6],
    [0, 1, 3, 4, 5],
    [0, 1, 3, 4, 6],
    [0, 1, 3, 5, 6],
    [0, 1, 4, 5, 6],
    [0, 2, 3, 4, 5],
    [0, 2, 3, 4, 6],
    [0, 2, 3, 5, 6],
    [0, 2, 4, 5, 6],
    [0, 3, 4, 5, 6],
    [1, 2, 3, 4, 5],
    [1, 2, 3, 4, 6],
    [1, 2, 3, 5, 6],
    [1, 2, 4, 5, 6],
    [1, 3, 4, 5, 6],
    [2, 3, 4, 5, 6],
];

/// Select one canonical subset from seven ordered cards.
///
/// All seven cards are validated as a distinct BP52 card set before the
/// subset is returned. This keeps malformed reconstructed hands from being
/// hidden in an unselected position.
///
/// # Errors
///
/// Returns an error for a subset identifier above 20, an out-of-range card,
/// or a duplicate anywhere in `seven`.
pub fn selected_five(seven: [CardId; 7], subset_id: u8) -> Result<[CardId; 5], PokerError> {
    let indices = SUBSETS_5_OF_7
        .get(usize::from(subset_id))
        .ok_or(PokerError::InvalidSubsetId { subset_id })?;
    validate_distinct_cards(seven)?;

    Ok(indices.map(|index| seven[usize::from(index)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_the_complete_lexicographic_five_of_seven_set() {
        assert_eq!(SUBSETS_5_OF_7.len(), 21);

        let mut generated = Vec::new();
        for a in 0..3 {
            for b in (a + 1)..4 {
                for c in (b + 1)..5 {
                    for d in (c + 1)..6 {
                        for e in (d + 1)..7 {
                            generated.push([a, b, c, d, e]);
                        }
                    }
                }
            }
        }

        assert_eq!(generated.as_slice(), SUBSETS_5_OF_7.as_slice());
        for (position, subset) in SUBSETS_5_OF_7.iter().enumerate() {
            assert!(subset.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(subset.iter().all(|index| *index < 7));
            assert_eq!(
                SUBSETS_5_OF_7
                    .iter()
                    .filter(|other| *other == subset)
                    .count(),
                1,
                "duplicate subset at {position}"
            );
        }
    }

    #[test]
    fn selection_uses_the_fixed_table() {
        let seven = [10, 11, 12, 13, 14, 15, 16];
        assert_eq!(selected_five(seven, 0), Ok([10, 11, 12, 13, 14]));
        assert_eq!(selected_five(seven, 20), Ok([12, 13, 14, 15, 16]));
        assert_eq!(
            selected_five(seven, 21),
            Err(PokerError::InvalidSubsetId { subset_id: 21 })
        );
    }

    #[test]
    fn selection_rejects_malformed_seven_card_sets() {
        assert_eq!(
            selected_five([0, 1, 2, 3, 4, 5, 52], 0),
            Err(PokerError::InvalidCard { card_id: 52 })
        );
        assert_eq!(
            selected_five([0, 1, 2, 3, 4, 5, 0], 0),
            Err(PokerError::DuplicateCard { card_id: 0 })
        );
    }
}
