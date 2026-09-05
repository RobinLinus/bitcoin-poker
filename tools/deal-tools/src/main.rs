#![forbid(unsafe_code)]
//! Minimal public parameter inspection CLI.

fn main() {
    let parameters = dealer_group::protocol_parameters();
    println!("protocol=DLOG52-DEAL-v1");
    println!("params_id={}", hex::encode(parameters.params_id));
    println!("manifest_bytes={}", parameters.manifest.len());
}
