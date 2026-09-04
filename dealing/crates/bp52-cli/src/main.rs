#![forbid(unsafe_code)]
#![doc = "Development CLI and deterministic-vector utility for BP52-DEAL-v1."]

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("generator") => match bp52_group::ProtocolGenerators::derive() {
            Ok(generators) => println!(
                "{}",
                encode_hex(&generators.message().compress().to_bytes())
            ),
            Err(error) => {
                eprintln!("generator derivation failed: {error}");
                std::process::exit(1);
            }
        },
        Some("circuit-id") => match bp52_circuit::hash_length::CircuitManifest::v1()
            .and_then(|manifest| manifest.circuit_id())
        {
            Ok(circuit_id) => println!("{}", encode_hex(&circuit_id)),
            Err(error) => {
                eprintln!("circuit manifest failed: {error}");
                std::process::exit(1);
            }
        },
        _ => println!("usage: bp52-cli <generator|circuit-id>"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        if write!(&mut encoded, "{byte:02x}").is_err() {
            return String::new();
        }
    }
    encoded
}
