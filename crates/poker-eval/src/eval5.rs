//! Exact evaluation of one five-card poker hand.

use crate::{
    CardId, HandCategory, HandScore, PokerError, RANK_COUNT,
    card::{decode_card, validate_distinct_cards},
};

/// Evaluate exactly five cards into the canonical BP52 score.
///
/// # Errors
///
/// Returns [`PokerError::InvalidCard`] for an identifier above 51 and
/// [`PokerError::DuplicateCard`] if a card occurs more than once.
pub fn eval5(cards: [CardId; 5]) -> Result<HandScore, PokerError> {
    validate_distinct_cards(cards)?;

    let mut rank_counts = [0_u8; RANK_COUNT as usize];
    let mut suits = [0_u8; 5];
    for (position, card_id) in cards.into_iter().enumerate() {
        let card = decode_card(card_id)?;
        rank_counts[usize::from(card.rank_index())] += 1;
        suits[position] = card.suit_index();
    }

    let is_flush = suits[1..].iter().all(|suit| *suit == suits[0]);

    let mut distinct_ranks_desc = [0_u8; 5];
    let mut distinct_count = 0_usize;
    for rank in (0..RANK_COUNT).rev() {
        if rank_counts[usize::from(rank)] != 0 {
            distinct_ranks_desc[distinct_count] = rank;
            distinct_count += 1;
        }
    }

    let straight_high = if distinct_count == 5 {
        if distinct_ranks_desc == [12, 3, 2, 1, 0] {
            Some(3)
        } else if distinct_ranks_desc
            .windows(2)
            .all(|pair| pair[0] == pair[1] + 1)
        {
            Some(distinct_ranks_desc[0])
        } else {
            None
        }
    } else {
        None
    };

    if let (true, Some(high)) = (is_flush, straight_high) {
        return Ok(score(HandCategory::StraightFlush, [high, 0, 0, 0, 0]));
    }

    let mut quads = None;
    let mut trips = None;
    let mut pairs = [0_u8; 2];
    let mut pair_count = 0_usize;
    let mut singletons = [0_u8; 5];
    let mut singleton_count = 0_usize;

    for rank in (0..RANK_COUNT).rev() {
        match rank_counts[usize::from(rank)] {
            4 => quads = Some(rank),
            3 => trips = Some(rank),
            2 => {
                pairs[pair_count] = rank;
                pair_count += 1;
            }
            1 => {
                singletons[singleton_count] = rank;
                singleton_count += 1;
            }
            _ => {}
        }
    }

    if let Some(quads_rank) = quads {
        return Ok(score(
            HandCategory::FourOfAKind,
            [quads_rank, singletons[0], 0, 0, 0],
        ));
    }

    if let (Some(trips_rank), 1) = (trips, pair_count) {
        return Ok(score(
            HandCategory::FullHouse,
            [trips_rank, pairs[0], 0, 0, 0],
        ));
    }

    if is_flush {
        return Ok(score(HandCategory::Flush, distinct_ranks_desc));
    }

    if let Some(high) = straight_high {
        return Ok(score(HandCategory::Straight, [high, 0, 0, 0, 0]));
    }

    if let Some(trips_rank) = trips {
        return Ok(score(
            HandCategory::ThreeOfAKind,
            [trips_rank, singletons[0], singletons[1], 0, 0],
        ));
    }

    if pair_count == 2 {
        return Ok(score(
            HandCategory::TwoPair,
            [pairs[0], pairs[1], singletons[0], 0, 0],
        ));
    }

    if pair_count == 1 {
        return Ok(score(
            HandCategory::OnePair,
            [pairs[0], singletons[0], singletons[1], singletons[2], 0],
        ));
    }

    Ok(score(HandCategory::HighCard, distinct_ranks_desc))
}

fn score(category: HandCategory, ranks: [u8; 5]) -> HandScore {
    HandScore::from_evaluated_components(category, ranks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(rank: u8, suit: u8) -> u8 {
        rank * 4 + suit
    }

    fn evaluate(cards: [u8; 5]) -> Result<HandScore, PokerError> {
        eval5(cards)
    }

    #[test]
    fn exact_category_examples_and_padding() -> Result<(), PokerError> {
        let cases = [
            (
                [
                    card(12, 0),
                    card(11, 0),
                    card(10, 0),
                    card(9, 0),
                    card(8, 0),
                ],
                HandCategory::StraightFlush,
                [12, 0, 0, 0, 0],
            ),
            (
                [card(6, 0), card(6, 1), card(6, 2), card(6, 3), card(12, 0)],
                HandCategory::FourOfAKind,
                [6, 12, 0, 0, 0],
            ),
            (
                [card(9, 0), card(9, 1), card(9, 2), card(3, 0), card(3, 1)],
                HandCategory::FullHouse,
                [9, 3, 0, 0, 0],
            ),
            (
                [card(12, 2), card(10, 2), card(7, 2), card(3, 2), card(0, 2)],
                HandCategory::Flush,
                [12, 10, 7, 3, 0],
            ),
            (
                [card(10, 0), card(9, 1), card(8, 2), card(7, 3), card(6, 0)],
                HandCategory::Straight,
                [10, 0, 0, 0, 0],
            ),
            (
                [card(8, 0), card(8, 1), card(8, 2), card(12, 3), card(2, 0)],
                HandCategory::ThreeOfAKind,
                [8, 12, 2, 0, 0],
            ),
            (
                [card(11, 0), card(11, 1), card(4, 2), card(4, 3), card(9, 0)],
                HandCategory::TwoPair,
                [11, 4, 9, 0, 0],
            ),
            (
                [card(5, 0), card(5, 1), card(12, 2), card(8, 3), card(1, 0)],
                HandCategory::OnePair,
                [5, 12, 8, 1, 0],
            ),
            (
                [card(12, 0), card(10, 1), card(7, 2), card(3, 3), card(0, 0)],
                HandCategory::HighCard,
                [12, 10, 7, 3, 0],
            ),
        ];

        for (cards, category, ranks) in cases {
            let result = evaluate(cards)?;
            assert_eq!(result.category(), category);
            assert_eq!(result.rank_components(), ranks);
            assert_eq!(HandScore::try_from(result.as_u32()), Ok(result));
        }
        Ok(())
    }

    #[test]
    fn wheel_has_five_high_and_loses_to_six_high() -> Result<(), PokerError> {
        let wheel = evaluate([card(12, 0), card(0, 1), card(1, 2), card(2, 3), card(3, 0)])?;
        let six_high = evaluate([card(0, 0), card(1, 1), card(2, 2), card(3, 3), card(4, 0)])?;
        let wheel_flush = evaluate([card(12, 2), card(0, 2), card(1, 2), card(2, 2), card(3, 2)])?;

        assert_eq!(wheel.rank_components(), [3, 0, 0, 0, 0]);
        assert_eq!(wheel_flush.category(), HandCategory::StraightFlush);
        assert_eq!(wheel_flush.rank_components(), [3, 0, 0, 0, 0]);
        assert!(six_high > wheel);
        Ok(())
    }

    #[test]
    fn category_and_kicker_ordering_are_numeric() -> Result<(), PokerError> {
        let pair_aces = evaluate([
            card(12, 0),
            card(12, 1),
            card(10, 0),
            card(8, 1),
            card(7, 2),
        ])?;
        let pair_kings = evaluate([
            card(11, 0),
            card(11, 1),
            card(12, 0),
            card(10, 1),
            card(9, 2),
        ])?;
        let better_last_kicker =
            evaluate([card(6, 0), card(6, 1), card(12, 0), card(11, 1), card(9, 2)])?;
        let worse_last_kicker =
            evaluate([card(6, 0), card(6, 1), card(12, 0), card(11, 1), card(8, 2)])?;
        let two_pair_twos_threes =
            evaluate([card(1, 0), card(1, 1), card(0, 0), card(0, 1), card(2, 2)])?;

        assert!(pair_aces > pair_kings);
        assert!(better_last_kicker > worse_last_kicker);
        assert!(two_pair_twos_threes > pair_aces);
        Ok(())
    }

    #[test]
    fn full_house_and_flush_ordering_use_all_required_components() -> Result<(), PokerError> {
        let aces_over_twos = evaluate([
            card(12, 0),
            card(12, 1),
            card(12, 2),
            card(0, 0),
            card(0, 1),
        ])?;
        let kings_over_aces = evaluate([
            card(11, 0),
            card(11, 1),
            card(11, 2),
            card(12, 0),
            card(12, 1),
        ])?;
        let flush_ten_kicker =
            evaluate([card(12, 0), card(10, 0), card(8, 0), card(6, 0), card(4, 0)])?;
        let flush_nine_kicker =
            evaluate([card(12, 1), card(10, 1), card(8, 1), card(6, 1), card(3, 1)])?;

        assert!(aces_over_twos > kings_over_aces);
        assert!(flush_ten_kicker > flush_nine_kicker);
        Ok(())
    }

    #[test]
    fn card_order_and_suit_permutation_do_not_change_scores() -> Result<(), PokerError> {
        let original = [card(7, 0), card(7, 1), card(12, 2), card(9, 3), card(2, 0)];
        let reordered = [
            original[3],
            original[0],
            original[4],
            original[2],
            original[1],
        ];
        let suit_permuted = [card(7, 2), card(7, 3), card(12, 1), card(9, 0), card(2, 2)];
        assert_eq!(evaluate(original)?, evaluate(reordered)?);
        assert_eq!(evaluate(original)?, evaluate(suit_permuted)?);
        Ok(())
    }

    #[test]
    fn duplicate_and_invalid_cards_are_rejected() {
        assert_eq!(
            eval5([0, 1, 2, 3, 0]),
            Err(PokerError::DuplicateCard { card_id: 0 })
        );
        assert_eq!(
            eval5([0, 1, 2, 3, 52]),
            Err(PokerError::InvalidCard { card_id: 52 })
        );
    }

    #[test]
    fn exhaustive_five_card_category_frequencies() -> Result<(), PokerError> {
        let mut frequencies = [0_u32; 9];
        let mut hands = 0_u32;

        for a in 0_u8..48 {
            for b in (a + 1)..49 {
                for c in (b + 1)..50 {
                    for d in (c + 1)..51 {
                        for e in (d + 1)..52 {
                            let hand = [a, b, c, d, e];
                            let result = eval5(hand)?;
                            let reference = independent_reference_score(hand);
                            assert_eq!(result.as_u32(), reference, "hand {hand:?}");
                            assert_eq!(HandScore::try_from(result.as_u32()), Ok(result));

                            let reversed = [e, d, c, b, a];
                            assert_eq!(eval5(reversed), Ok(result), "reordered hand {hand:?}");

                            let permuted_suits = hand.map(|card_id| {
                                let rank = card_id / 4;
                                let suit = card_id % 4;
                                rank * 4 + (suit + 1) % 4
                            });
                            assert_eq!(
                                eval5(permuted_suits),
                                Ok(result),
                                "suit-permuted hand {hand:?}"
                            );
                            frequencies[usize::from(result.category().as_u8())] += 1;
                            hands += 1;
                        }
                    }
                }
            }
        }

        assert_eq!(hands, 2_598_960);
        assert_eq!(
            frequencies,
            [
                1_302_540, // high card
                1_098_240, // one pair
                123_552,   // two pair
                54_912,    // three of a kind
                10_200,    // straight
                5_108,     // flush
                3_744,     // full house
                624,       // four of a kind
                40,        // straight flush
            ]
        );
        Ok(())
    }

    // This test-only evaluator intentionally takes a different route from
    // `eval5`: it sorts ranks, forms adjacent run groups, and orders those
    // groups by multiplicity. It is the independent oracle used for all
    // 2,598,960 hands above.
    fn independent_reference_score(cards: [u8; 5]) -> u32 {
        let mut ranks = cards.map(|card_id| card_id / 4);
        let suits = cards.map(|card_id| card_id % 4);
        ranks.sort_unstable();
        let flush = suits.iter().all(|suit| *suit == suits[0]);
        let straight_high = if ranks == [0, 1, 2, 3, 12] {
            Some(3)
        } else if ranks.windows(2).all(|pair| pair[1] == pair[0] + 1) {
            Some(ranks[4])
        } else {
            None
        };

        if let (Some(high), true) = (straight_high, flush) {
            return reference_pack(HandCategory::StraightFlush, [high, 0, 0, 0, 0]);
        }

        let mut groups = Vec::with_capacity(5);
        let mut start = 0;
        while start < ranks.len() {
            let rank = ranks[start];
            let mut end = start + 1;
            while end < ranks.len() && ranks[end] == rank {
                end += 1;
            }
            groups.push((end - start, rank));
            start = end;
        }
        groups.sort_unstable_by(|left, right| right.cmp(left));

        let (category, components) = match groups.as_slice() {
            [(4, quads), (1, kicker)] => (HandCategory::FourOfAKind, [*quads, *kicker, 0, 0, 0]),
            [(3, trips), (2, pair)] => (HandCategory::FullHouse, [*trips, *pair, 0, 0, 0]),
            _ if flush => {
                ranks.reverse();
                (HandCategory::Flush, ranks)
            }
            _ if straight_high.is_some() => (
                HandCategory::Straight,
                [straight_high.unwrap_or_default(), 0, 0, 0, 0],
            ),
            [(3, trips), (1, kicker_1), (1, kicker_2)] => (
                HandCategory::ThreeOfAKind,
                [*trips, *kicker_1, *kicker_2, 0, 0],
            ),
            [(2, high_pair), (2, low_pair), (1, kicker)] => (
                HandCategory::TwoPair,
                [*high_pair, *low_pair, *kicker, 0, 0],
            ),
            [(2, pair), (1, kicker_1), (1, kicker_2), (1, kicker_3)] => (
                HandCategory::OnePair,
                [*pair, *kicker_1, *kicker_2, *kicker_3, 0],
            ),
            _ => {
                ranks.reverse();
                (HandCategory::HighCard, ranks)
            }
        };
        reference_pack(category, components)
    }

    fn reference_pack(category: HandCategory, ranks: [u8; 5]) -> u32 {
        (u32::from(category.as_u8()) << 20)
            | (u32::from(ranks[0]) << 16)
            | (u32::from(ranks[1]) << 12)
            | (u32::from(ranks[2]) << 8)
            | (u32::from(ranks[3]) << 4)
            | u32::from(ranks[4])
    }
}
