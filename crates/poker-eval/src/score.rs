//! Canonical six-nibble BP52 hand scores.

use crate::PokerError;

/// Hand categories in increasing poker strength.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum HandCategory {
    /// Five unequal ranks that are neither a straight nor a flush.
    HighCard = 0,
    /// Exactly one pair.
    OnePair = 1,
    /// Exactly two pairs.
    TwoPair = 2,
    /// Exactly three cards of one rank, without a pair.
    ThreeOfAKind = 3,
    /// Five consecutive ranks, including the ace-low wheel.
    Straight = 4,
    /// Five cards of one suit that are not a straight.
    Flush = 5,
    /// Three cards of one rank plus two cards of another rank.
    FullHouse = 6,
    /// Four cards of one rank.
    FourOfAKind = 7,
    /// Five consecutive ranks of one suit.
    StraightFlush = 8,
}

impl HandCategory {
    /// Return the category nibble used by BP52's packed score.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::HighCard => 0,
            Self::OnePair => 1,
            Self::TwoPair => 2,
            Self::ThreeOfAKind => 3,
            Self::Straight => 4,
            Self::Flush => 5,
            Self::FullHouse => 6,
            Self::FourOfAKind => 7,
            Self::StraightFlush => 8,
        }
    }
}

impl TryFrom<u8> for HandCategory {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::HighCard),
            1 => Ok(Self::OnePair),
            2 => Ok(Self::TwoPair),
            3 => Ok(Self::ThreeOfAKind),
            4 => Ok(Self::Straight),
            5 => Ok(Self::Flush),
            6 => Ok(Self::FullHouse),
            7 => Ok(Self::FourOfAKind),
            8 => Ok(Self::StraightFlush),
            _ => Err(()),
        }
    }
}

/// A validated BP52 comparison score.
///
/// Its numeric representation is `(category, r1, r2, r3, r4, r5)` packed as
/// six big-endian nibbles. Consequently the derived integer ordering is the
/// poker ordering. A player may deliberately encode a weaker category whose
/// positive pattern is present; for example, straight ranks are valid in a
/// flush or high-card claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandScore(u32);

impl HandScore {
    /// Width of the packed score and Alice's score OTS message.
    pub const BIT_WIDTH: u8 = 24;
    /// Length of the strict big-endian byte encoding.
    pub const ENCODED_LEN: usize = 3;
    /// Largest integer representable by the encoding (not necessarily valid).
    pub const MAX_PACKED: u32 = (1 << Self::BIT_WIDTH) - 1;

    /// Construct a score while enforcing the category-specific padding and
    /// rank-order requirements for a positive lower-bound claim.
    ///
    /// # Errors
    ///
    /// Returns [`PokerError::InvalidHandScore`] if a rank is above 12 or the
    /// rank fields do not have the category's required order and padding.
    pub fn from_components(category: HandCategory, ranks: [u8; 5]) -> Result<Self, PokerError> {
        let score = pack(category, ranks);
        if ranks.iter().any(|rank| *rank > 12) || !valid_layout(category, ranks) {
            return Err(PokerError::InvalidHandScore { score });
        }
        Ok(Self(score))
    }

    pub(crate) fn from_evaluated_components(category: HandCategory, ranks: [u8; 5]) -> Self {
        debug_assert!(ranks.iter().all(|rank| *rank <= 12));
        debug_assert!(valid_layout(category, ranks));
        Self(pack(category, ranks))
    }

    /// Parse a strict three-byte score encoding.
    ///
    /// # Errors
    ///
    /// Returns [`PokerError::InvalidHandScore`] when the encoded components
    /// are not a canonical score.
    pub fn from_be_bytes(bytes: [u8; Self::ENCODED_LEN]) -> Result<Self, PokerError> {
        Self::try_from(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    /// Return the exact three-byte score encoding signed by the score OTS.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; Self::ENCODED_LEN] {
        let bytes = self.0.to_be_bytes();
        [bytes[1], bytes[2], bytes[3]]
    }

    /// Return the packed score as a positive 24-bit integer.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Return this score's poker category.
    #[must_use]
    pub fn category(self) -> HandCategory {
        match self.0 >> 20 {
            0 => HandCategory::HighCard,
            1 => HandCategory::OnePair,
            2 => HandCategory::TwoPair,
            3 => HandCategory::ThreeOfAKind,
            4 => HandCategory::Straight,
            5 => HandCategory::Flush,
            6 => HandCategory::FullHouse,
            7 => HandCategory::FourOfAKind,
            8 => HandCategory::StraightFlush,
            _ => unreachable!("HandScore construction enforces category 0..=8"),
        }
    }

    /// Return `(r1, r2, r3, r4, r5)` in canonical comparison order.
    #[must_use]
    pub fn rank_components(self) -> [u8; 5] {
        [
            nibble(self.0, 16),
            nibble(self.0, 12),
            nibble(self.0, 8),
            nibble(self.0, 4),
            nibble(self.0, 0),
        ]
    }
}

impl From<HandScore> for u32 {
    fn from(score: HandScore) -> Self {
        score.as_u32()
    }
}

impl TryFrom<u32> for HandScore {
    type Error = PokerError;

    fn try_from(score: u32) -> Result<Self, Self::Error> {
        if score == 0 || score > Self::MAX_PACKED {
            return Err(PokerError::InvalidHandScore { score });
        }

        let category_code =
            u8::try_from(score >> 20).map_err(|_| PokerError::InvalidHandScore { score })?;
        let category = HandCategory::try_from(category_code)
            .map_err(|()| PokerError::InvalidHandScore { score })?;
        let ranks = [
            nibble(score, 16),
            nibble(score, 12),
            nibble(score, 8),
            nibble(score, 4),
            nibble(score, 0),
        ];

        if ranks.iter().any(|rank| *rank > 12) || !valid_layout(category, ranks) {
            return Err(PokerError::InvalidHandScore { score });
        }

        Ok(Self(score))
    }
}

fn pack(category: HandCategory, ranks: [u8; 5]) -> u32 {
    (u32::from(category.as_u8()) << 20)
        | (u32::from(ranks[0]) << 16)
        | (u32::from(ranks[1]) << 12)
        | (u32::from(ranks[2]) << 8)
        | (u32::from(ranks[3]) << 4)
        | u32::from(ranks[4])
}

fn nibble(score: u32, shift: u32) -> u8 {
    // Masking makes conversion infallible; the fallback keeps this helper
    // panic-free even if its implementation is changed later.
    u8::try_from((score >> shift) & 0x0f).unwrap_or_default()
}

fn valid_layout(category: HandCategory, ranks: [u8; 5]) -> bool {
    match category {
        HandCategory::StraightFlush | HandCategory::Straight => {
            (3..=12).contains(&ranks[0]) && ranks[1..] == [0, 0, 0, 0]
        }
        HandCategory::FourOfAKind | HandCategory::FullHouse => {
            ranks[0] != ranks[1] && ranks[2..] == [0, 0, 0]
        }
        HandCategory::Flush | HandCategory::HighCard => strictly_descending(ranks),
        HandCategory::ThreeOfAKind => {
            ranks[1] > ranks[2]
                && ranks[0] != ranks[1]
                && ranks[0] != ranks[2]
                && ranks[3..] == [0, 0]
        }
        HandCategory::TwoPair => {
            ranks[0] > ranks[1]
                && ranks[2] != ranks[0]
                && ranks[2] != ranks[1]
                && ranks[3..] == [0, 0]
        }
        HandCategory::OnePair => {
            ranks[1] > ranks[2]
                && ranks[2] > ranks[3]
                && ranks[0] != ranks[1]
                && ranks[0] != ranks[2]
                && ranks[0] != ranks[3]
                && ranks[4] == 0
        }
    }
}

fn strictly_descending(ranks: [u8; 5]) -> bool {
    ranks.windows(2).all(|pair| pair[0] > pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bytes_round_trip_strictly() -> Result<(), PokerError> {
        let score = HandScore::from_components(HandCategory::TwoPair, [12, 11, 10, 0, 0])?;
        assert_eq!(score.as_u32(), 0x2c_ba00);
        assert_eq!(score.to_be_bytes(), [0x2c, 0xba, 0x00]);
        assert_eq!(HandScore::from_be_bytes(score.to_be_bytes()), Ok(score));
        Ok(())
    }

    #[test]
    fn integer_order_is_poker_order() -> Result<(), PokerError> {
        let pair_aces = HandScore::from_components(HandCategory::OnePair, [12, 9, 8, 7, 0])?;
        let pair_kings = HandScore::from_components(HandCategory::OnePair, [11, 12, 8, 7, 0])?;
        let two_pair = HandScore::from_components(HandCategory::TwoPair, [1, 0, 2, 0, 0])?;
        assert!(pair_aces > pair_kings);
        assert!(two_pair > pair_aces);
        assert!(two_pair.as_u32() > pair_aces.as_u32());
        Ok(())
    }

    #[test]
    fn malformed_and_noncanonical_scores_are_rejected() {
        for score in [0, 1 << 24, 0x90_0000, 0x8c_0001, 0x52_3456, 0x1c_cb_a0] {
            assert_eq!(
                HandScore::try_from(score),
                Err(PokerError::InvalidHandScore { score })
            );
        }
    }

    #[test]
    fn weaker_distinct_rank_claims_may_retain_straight_ranks() -> Result<(), PokerError> {
        let ranks = [12, 11, 10, 9, 8];
        assert_eq!(
            HandScore::from_components(HandCategory::Flush, ranks)?.as_u32(),
            0x5c_ba98
        );
        assert_eq!(
            HandScore::from_components(HandCategory::HighCard, ranks)?.as_u32(),
            0x0c_ba98
        );
        Ok(())
    }
}
