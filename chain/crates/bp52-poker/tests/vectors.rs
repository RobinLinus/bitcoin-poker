//! Published cross-implementation score-vector regression.

use bp52_poker::evaluate_five_cards;

const VECTORS: &str = include_str!("../../../test-vectors/poker-v1.txt");

#[test]
fn published_poker_vectors_match_the_reference_evaluator() -> Result<(), Box<dyn std::error::Error>>
{
    let mut count = 0_usize;
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('|').map(str::trim).collect();
        if fields.len() != 3 {
            return Err(format!("malformed vector line `{line}`").into());
        }
        let cards: Vec<u8> = fields[0]
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        let cards: [u8; 5] = cards
            .try_into()
            .map_err(|_| format!("wrong card count in `{line}`"))?;
        let decimal: u32 = fields[1].parse()?;
        let hexadecimal = u32::from_str_radix(fields[2], 16)?;
        if decimal != hexadecimal {
            return Err(format!("decimal/hex score mismatch in `{line}`").into());
        }
        assert_eq!(evaluate_five_cards(cards)?, decimal, "{line}");
        count += 1;
    }
    assert_eq!(count, 8);
    Ok(())
}
