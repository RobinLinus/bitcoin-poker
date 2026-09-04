//! Deterministic statistical regression for the accepted-deal distribution.

use bp52_protocol::N_SLOTS;

const CARD_COUNT: usize = 52;
const POSITION_PAIR_COUNT: usize = N_SLOTS * (N_SLOTS - 1) / 2;
const PAIR_CELL_COUNT: usize = CARD_COUNT * CARD_COUNT;
const ATTEMPTS: u32 = 200_000;
const EXPECTED_ACCEPTANCE_RATE: f64 = 0.480_254_705_4;

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn uniform_card(&mut self) -> u8 {
        loop {
            let candidate = self.next_u64().to_le_bytes()[0];
            if candidate < 208 {
                return candidate % 52;
            }
        }
    }

    fn honest_vector(&mut self) -> [u8; N_SLOTS] {
        core::array::from_fn(|_| self.uniform_card())
    }
}

fn cards_are_distinct(cards: &[u8; N_SLOTS]) -> bool {
    let mut seen = [false; CARD_COUNT];
    for card in cards {
        let entry = &mut seen[usize::from(*card)];
        if *entry {
            return false;
        }
        *entry = true;
    }
    true
}

#[test]
fn fixed_adversary_conditioned_deals_match_uniform_without_replacement() {
    const ADVERSARIAL_SHARES: [u8; N_SLOTS] = [0, 51, 17, 17, 4, 38, 12, 29, 7];

    let mut rng = SplitMix64::new(0x4250_3532_d15c_a11e);
    let mut accepted = 0_u32;
    let mut position_counts = [[0_u32; CARD_COUNT]; N_SLOTS];
    let mut pair_counts = vec![[0_u32; PAIR_CELL_COUNT]; POSITION_PAIR_COUNT];

    for _ in 0..ATTEMPTS {
        let honest = rng.honest_vector();
        let cards =
            core::array::from_fn(|position| (ADVERSARIAL_SHARES[position] + honest[position]) % 52);
        if !cards_are_distinct(&cards) {
            continue;
        }
        accepted += 1;
        for (position, card) in cards.iter().enumerate() {
            position_counts[position][usize::from(*card)] += 1;
        }
        let mut position_pair = 0;
        for left in 0..N_SLOTS {
            for right in (left + 1)..N_SLOTS {
                let cell = usize::from(cards[left]) * CARD_COUNT + usize::from(cards[right]);
                pair_counts[position_pair][cell] += 1;
                position_pair += 1;
            }
        }
        assert_eq!(position_pair, POSITION_PAIR_COUNT);
    }

    let attempts = f64::from(ATTEMPTS);
    let expected_accepted = attempts * EXPECTED_ACCEPTANCE_RATE;
    let acceptance_sigma =
        (attempts * EXPECTED_ACCEPTANCE_RATE * (1.0 - EXPECTED_ACCEPTANCE_RATE)).sqrt();
    assert!(
        (f64::from(accepted) - expected_accepted).abs() <= 8.0 * acceptance_sigma,
        "accepted {accepted} of {ATTEMPTS}; expected approximately {expected_accepted}"
    );

    let marginal_probability = 1.0 / 52.0;
    let expected_marginal = f64::from(accepted) * marginal_probability;
    let marginal_sigma =
        (f64::from(accepted) * marginal_probability * (1.0 - marginal_probability)).sqrt();
    for (position, counts) in position_counts.iter().enumerate() {
        for (card, count) in counts.iter().enumerate() {
            assert!(
                (f64::from(*count) - expected_marginal).abs() <= 8.0 * marginal_sigma,
                "position {position}, card {card}: observed {count}, expected {expected_marginal}"
            );
        }
    }

    let expected_pair_cell = f64::from(accepted) / (52.0 * 51.0);
    let pair_degrees_of_freedom = 52_u32 * 51 - 1;
    let chi_square_bound = f64::from(pair_degrees_of_freedom)
        + 10.0 * (2.0 * f64::from(pair_degrees_of_freedom)).sqrt();
    for (position_pair, counts) in pair_counts.iter().enumerate() {
        assert_eq!(counts.iter().sum::<u32>(), accepted);
        let mut chi_square = 0.0;
        for first in 0..CARD_COUNT {
            assert_eq!(counts[first * CARD_COUNT + first], 0);
            for second in 0..CARD_COUNT {
                if first == second {
                    continue;
                }
                let observed = f64::from(counts[first * CARD_COUNT + second]);
                let residual = observed - expected_pair_cell;
                chi_square += residual * residual / expected_pair_cell;
            }
        }
        assert!(
            chi_square <= chi_square_bound,
            "position pair {position_pair}: chi-square {chi_square} exceeds {chi_square_bound}"
        );
    }
}
