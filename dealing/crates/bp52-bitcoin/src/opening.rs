//! Native Rust share and card opening predicates.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// The fixed preimage length corresponding to share value zero.
pub const BASE_PREIMAGE_LENGTH: usize = 16;

/// The largest preimage accepted by the version 1 protocol.
pub const MAX_PREIMAGE_LENGTH: usize = 67;

/// The fixed deck size used by the version 1 protocol.
pub const DECK_SIZE: u8 = 52;

/// An error returned while checking a share or card opening.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OpeningError {
    /// A preimage was outside the inclusive version 1 range `16..=67`.
    #[error("invalid preimage length {actual}; expected 16..=67 bytes")]
    InvalidPreimageLength {
        /// The length of the rejected preimage.
        actual: usize,
    },

    /// A preimage did not hash to its committed SHA-256 digest.
    #[error("preimage SHA-256 digest does not match the expected hash")]
    HashMismatch,

    /// A claimed card was not a card identifier in `0..=51`.
    #[error("invalid claimed card {claimed_card}; expected 0..=51")]
    InvalidClaimedCard {
        /// The rejected card identifier.
        claimed_card: u8,
    },

    /// The claimed card was not the sum of the two shares modulo 52.
    #[error("claimed card {claimed_card} does not match raw share sum {raw_sum}")]
    CardMismatch {
        /// The rejected card identifier.
        claimed_card: u8,
        /// The sum of the two opened share values before reduction modulo 52.
        raw_sum: u16,
    },
}

/// Verify a preimage against a share commitment and recover its share value.
///
/// Version 1 encodes a share `v` as a SHA-256 preimage of exactly `16 + v`
/// bytes. Consequently, accepted preimages have lengths in `16..=67` and the
/// returned value is always in `0..=51`.
///
/// # Errors
///
/// Returns [`OpeningError::InvalidPreimageLength`] when `preimage` is outside
/// the permitted range, or [`OpeningError::HashMismatch`] when its SHA-256
/// digest differs from `expected_hash`.
pub fn verify_share_opening(expected_hash: &[u8; 32], preimage: &[u8]) -> Result<u8, OpeningError> {
    if !(BASE_PREIMAGE_LENGTH..=MAX_PREIMAGE_LENGTH).contains(&preimage.len()) {
        return Err(OpeningError::InvalidPreimageLength {
            actual: preimage.len(),
        });
    }

    let actual_hash: [u8; 32] = Sha256::digest(preimage).into();
    if actual_hash != *expected_hash {
        return Err(OpeningError::HashMismatch);
    }

    // The range check above guarantees this difference is in 0..=51.
    u8::try_from(preimage.len() - BASE_PREIMAGE_LENGTH).map_err(|_| {
        OpeningError::InvalidPreimageLength {
            actual: preimage.len(),
        }
    })
}

/// Verify both share openings and a claimed card identifier.
///
/// The card predicate deliberately performs two comparisons instead of a
/// modulo operation: if `a` and `b` are the recovered share values, the raw
/// sum must equal either `claimed_card` or `claimed_card + 52`.
///
/// # Errors
///
/// Returns the first share-opening error encountered, then rejects a claimed
/// card outside `0..=51`, and finally rejects a valid identifier that does not
/// equal the share sum modulo 52.
pub fn verify_card_opening(
    expected_hash_a: &[u8; 32],
    preimage_a: &[u8],
    expected_hash_b: &[u8; 32],
    preimage_b: &[u8],
    claimed_card: u8,
) -> Result<(), OpeningError> {
    let a = verify_share_opening(expected_hash_a, preimage_a)?;
    let b = verify_share_opening(expected_hash_b, preimage_b)?;

    if claimed_card >= DECK_SIZE {
        return Err(OpeningError::InvalidClaimedCard { claimed_card });
    }

    let raw_sum = u16::from(a) + u16::from(b);
    let claimed_card_wide = u16::from(claimed_card);
    if raw_sum == claimed_card_wide || raw_sum == claimed_card_wide + u16::from(DECK_SIZE) {
        Ok(())
    } else {
        Err(OpeningError::CardMismatch {
            claimed_card,
            raw_sum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASE_PREIMAGE_LENGTH, DECK_SIZE, MAX_PREIMAGE_LENGTH, OpeningError, verify_card_opening,
        verify_share_opening,
    };
    use bitcoin_hashes::{Hash as BitcoinHash, sha256};
    use sha2::{Digest, Sha256};

    fn hash(preimage: &[u8]) -> [u8; 32] {
        Sha256::digest(preimage).into()
    }

    #[test]
    fn rustcrypto_and_rust_bitcoin_sha256_agree_for_every_permitted_length() {
        for length in BASE_PREIMAGE_LENGTH..=MAX_PREIMAGE_LENGTH {
            let preimage = vec![u8::try_from(length).unwrap_or(0); length];
            assert_eq!(
                hash(&preimage),
                sha256::Hash::hash(&preimage).to_byte_array()
            );
        }
    }

    #[test]
    fn share_opening_accepts_both_length_boundaries() {
        let shortest = [0x11; BASE_PREIMAGE_LENGTH];
        assert_eq!(verify_share_opening(&hash(&shortest), &shortest), Ok(0));

        let longest = [0x22; MAX_PREIMAGE_LENGTH];
        assert_eq!(
            verify_share_opening(&hash(&longest), &longest),
            Ok(DECK_SIZE - 1)
        );
    }

    #[test]
    fn share_opening_rejects_lengths_outside_both_boundaries() {
        let too_short = [0x33; BASE_PREIMAGE_LENGTH - 1];
        assert_eq!(
            verify_share_opening(&hash(&too_short), &too_short),
            Err(OpeningError::InvalidPreimageLength {
                actual: BASE_PREIMAGE_LENGTH - 1,
            })
        );

        let too_long = [0x44; MAX_PREIMAGE_LENGTH + 1];
        assert_eq!(
            verify_share_opening(&hash(&too_long), &too_long),
            Err(OpeningError::InvalidPreimageLength {
                actual: MAX_PREIMAGE_LENGTH + 1,
            })
        );
    }

    #[test]
    fn share_opening_rejects_a_hash_mismatch() {
        let preimage = [0x55; BASE_PREIMAGE_LENGTH + 17];
        let mut wrong_hash = hash(&preimage);
        wrong_hash[31] ^= 1;

        assert_eq!(
            verify_share_opening(&wrong_hash, &preimage),
            Err(OpeningError::HashMismatch)
        );
    }

    #[test]
    fn complete_length_and_card_matrix() {
        let preimages: Vec<Vec<u8>> = (0_u8..DECK_SIZE)
            .map(|share| vec![share; BASE_PREIMAGE_LENGTH + usize::from(share)])
            .collect();
        let hashes: Vec<[u8; 32]> = preimages.iter().map(|preimage| hash(preimage)).collect();

        for a in 0_u8..DECK_SIZE {
            for b in 0_u8..DECK_SIZE {
                let raw_sum = u16::from(a) + u16::from(b);
                let expected = if raw_sum >= u16::from(DECK_SIZE) {
                    raw_sum - u16::from(DECK_SIZE)
                } else {
                    raw_sum
                };

                for claimed_card in 0_u8..DECK_SIZE {
                    let result = verify_card_opening(
                        &hashes[usize::from(a)],
                        &preimages[usize::from(a)],
                        &hashes[usize::from(b)],
                        &preimages[usize::from(b)],
                        claimed_card,
                    );

                    if u16::from(claimed_card) == expected {
                        assert_eq!(result, Ok(()), "a={a}, b={b}, claim={claimed_card}");
                    } else {
                        assert_eq!(
                            result,
                            Err(OpeningError::CardMismatch {
                                claimed_card,
                                raw_sum,
                            }),
                            "a={a}, b={b}, claim={claimed_card}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn card_opening_rejects_out_of_range_card_identifiers() {
        let preimage_a = [0x66; BASE_PREIMAGE_LENGTH];
        let preimage_b = [0x77; BASE_PREIMAGE_LENGTH];
        let hash_a = hash(&preimage_a);
        let hash_b = hash(&preimage_b);

        for claimed_card in DECK_SIZE..=u8::MAX {
            assert_eq!(
                verify_card_opening(&hash_a, &preimage_a, &hash_b, &preimage_b, claimed_card,),
                Err(OpeningError::InvalidClaimedCard { claimed_card })
            );
        }
    }

    #[test]
    fn card_opening_propagates_each_share_failure() {
        let preimage_a = [0x88; BASE_PREIMAGE_LENGTH + 3];
        let preimage_b = [0x99; BASE_PREIMAGE_LENGTH + 5];
        let hash_a = hash(&preimage_a);
        let hash_b = hash(&preimage_b);
        let wrong_hash = [0_u8; 32];

        assert_eq!(
            verify_card_opening(&wrong_hash, &preimage_a, &hash_b, &preimage_b, 8,),
            Err(OpeningError::HashMismatch)
        );
        assert_eq!(
            verify_card_opening(&hash_a, &preimage_a, &wrong_hash, &preimage_b, 8,),
            Err(OpeningError::HashMismatch)
        );

        let too_short = [0xaa; BASE_PREIMAGE_LENGTH - 1];
        assert_eq!(
            verify_card_opening(&hash(&too_short), &too_short, &hash_b, &preimage_b, 8,),
            Err(OpeningError::InvalidPreimageLength {
                actual: BASE_PREIMAGE_LENGTH - 1,
            })
        );

        let too_long = [0xbb; MAX_PREIMAGE_LENGTH + 1];
        assert_eq!(
            verify_card_opening(&hash_a, &preimage_a, &hash(&too_long), &too_long, 8,),
            Err(OpeningError::InvalidPreimageLength {
                actual: MAX_PREIMAGE_LENGTH + 1,
            })
        );
    }

    #[test]
    fn share_errors_take_precedence_over_an_invalid_claim() {
        let preimage = [0xcc; BASE_PREIMAGE_LENGTH];
        let valid_hash = hash(&preimage);

        assert_eq!(
            verify_card_opening(&[0_u8; 32], &preimage, &valid_hash, &preimage, DECK_SIZE,),
            Err(OpeningError::HashMismatch)
        );
    }
}
