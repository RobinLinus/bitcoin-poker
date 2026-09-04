//! Small, fail-closed development CLI for the BP52-CHAIN-v1 workspace.

#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

use bp52_chain_compiler::{
    REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT, REFERENCE_TRANSACTION_COUNT,
};
use bp52_poker::{evaluate_five_cards, selected_five};

const USAGE: &str = "\
bp52-chain-cli profile
bp52-chain-cli eval5 <card0> <card1> <card2> <card3> <card4>
bp52-chain-cli subset <subset-id> <card0> <card1> ... <card6>

Card identifiers are decimal values in 0..=51. This research CLI never
constructs or broadcasts mainnet transactions.";

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| "missing command".to_owned())?;
    let remaining: Vec<_> = arguments.collect();
    match command.as_str() {
        "profile" => {
            require_count(&remaining, 0)?;
            Ok(format!(
                "BP52-CHAIN-v1\nimplicit_all_in=true\n\
                 profile_nodes={REFERENCE_TOTAL_NODE_COUNT}\n\
                 profile_gameplay_transactions={REFERENCE_TRANSACTION_COUNT}\n\
                 profile_max_path={REFERENCE_MAX_PATH_LENGTH}"
            ))
        }
        "eval5" => {
            require_count(&remaining, 5)?;
            let cards = parse_cards::<5>(&remaining)?;
            let score = evaluate_five_cards(cards).map_err(|error| error.to_string())?;
            Ok(format!("score={score} (0x{score:06x})"))
        }
        "subset" => {
            require_count(&remaining, 8)?;
            let subset_id = parse_u8(&remaining[0], "subset-id")?;
            let cards = parse_cards::<7>(&remaining[1..])?;
            let selected = selected_five(cards, subset_id).map_err(|error| error.to_string())?;
            Ok(selected
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(" "))
        }
        _ => Err(format!("unknown command `{command}`")),
    }
}

fn require_count(arguments: &[String], expected: usize) -> Result<(), String> {
    if arguments.len() == expected {
        Ok(())
    } else {
        Err(format!(
            "wrong argument count: expected {expected}, got {}",
            arguments.len()
        ))
    }
}

fn parse_cards<const N: usize>(arguments: &[String]) -> Result<[u8; N], String> {
    if arguments.len() != N {
        return Err(format!(
            "wrong card count: expected {N}, got {}",
            arguments.len()
        ));
    }
    let mut cards = [0_u8; N];
    for (index, argument) in arguments.iter().enumerate() {
        cards[index] = parse_u8(argument, "card")?;
    }
    Ok(cards)
}

fn parse_u8(value: &str, field: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("invalid decimal {field} `{value}`"))
}

#[cfg(test)]
mod tests {
    use super::run;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn profile_reports_descriptor_derived_all_in_and_bounds() -> Result<(), String> {
        let output = run(strings(&["profile"]))?;
        assert!(output.contains("implicit_all_in=true"));
        assert!(output.contains("profile_nodes=56132"));
        assert!(output.contains("profile_gameplay_transactions=56131"));
        assert!(output.contains("profile_max_path=33"));
        Ok(())
    }

    #[test]
    fn evaluator_and_subset_commands_are_strict() -> Result<(), String> {
        let score = run(strings(&["eval5", "8", "9", "10", "11", "12"]))?;
        assert!(score.starts_with("score="));
        assert_eq!(
            run(strings(&[
                "subset", "20", "0", "1", "2", "3", "4", "5", "6"
            ]))?,
            "2 3 4 5 6"
        );
        assert!(run(strings(&["eval5", "0"])).is_err());
        assert!(
            run(strings(&[
                "subset", "21", "0", "1", "2", "3", "4", "5", "6"
            ]))
            .is_err()
        );
        Ok(())
    }
}
