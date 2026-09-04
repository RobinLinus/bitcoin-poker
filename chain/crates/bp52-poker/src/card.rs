//! BP52 card identifiers and their fixed rank/suit mapping.

use crate::PokerError;

/// The protocol's card identifier type.
pub type CardId = u8;

/// Number of cards in the fixed BP52 deck.
pub const DECK_SIZE: u8 = 52;
/// Number of ranks, ordered from deuce (`0`) through ace (`12`).
pub const RANK_COUNT: u8 = 13;
/// Number of suits, ordered clubs, diamonds, hearts, spades.
pub const SUIT_COUNT: u8 = 4;

/// A decoded BP52 card.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Card {
    id: CardId,
    rank_index: u8,
    suit_index: u8,
}

impl Card {
    /// Return the original identifier in `0..=51`.
    #[must_use]
    pub const fn id(self) -> CardId {
        self.id
    }

    /// Return the rank index in `0..=12`.
    #[must_use]
    pub const fn rank_index(self) -> u8 {
        self.rank_index
    }

    /// Return the suit index in `0..=3`.
    #[must_use]
    pub const fn suit_index(self) -> u8 {
        self.suit_index
    }
}

impl TryFrom<CardId> for Card {
    type Error = PokerError;

    fn try_from(card_id: CardId) -> Result<Self, Self::Error> {
        decode_card(card_id)
    }
}

/// Decode a card according to `rank = floor(id / 4)`, `suit = id mod 4`.
///
/// # Errors
///
/// Returns [`PokerError::InvalidCard`] when `card_id` is above 51.
pub fn decode_card(card_id: CardId) -> Result<Card, PokerError> {
    if card_id >= DECK_SIZE {
        return Err(PokerError::InvalidCard { card_id });
    }

    Ok(Card {
        id: card_id,
        rank_index: card_id / SUIT_COUNT,
        suit_index: card_id % SUIT_COUNT,
    })
}

pub(crate) fn validate_distinct_cards<const N: usize>(
    cards: [CardId; N],
) -> Result<(), PokerError> {
    let mut seen = [false; DECK_SIZE as usize];
    for card_id in cards {
        decode_card(card_id)?;
        let seen_entry = &mut seen[usize::from(card_id)];
        if *seen_entry {
            return Err(PokerError::DuplicateCard { card_id });
        }
        *seen_entry = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_card_identifiers_decode_per_the_fixed_mapping() -> Result<(), PokerError> {
        for id in 0..DECK_SIZE {
            let decoded = decode_card(id)?;
            assert_eq!(decoded.id(), id);
            assert_eq!(decoded.rank_index(), id / 4);
            assert_eq!(decoded.suit_index(), id % 4);
        }
        Ok(())
    }

    #[test]
    fn out_of_range_cards_are_rejected() {
        for id in DECK_SIZE..=u8::MAX {
            assert_eq!(
                decode_card(id),
                Err(PokerError::InvalidCard { card_id: id })
            );
        }
    }
}
