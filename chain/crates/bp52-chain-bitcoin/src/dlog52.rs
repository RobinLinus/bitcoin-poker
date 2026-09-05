//! Strict bridge from DLOG52 accepted deals to the research-only chain profile.

use bitcoin::Network;
use dlog52_bitcoin::{BitcoinError, RegtestGateManifest};
use dlog52_protocol::VerifiedAcceptedDeal;

/// Compile the nine independent single-slot card gates defined by the DLOG52
/// implementation specification.
///
/// The input cannot be assembled from unchecked wire data: it must first pass
/// the DLOG52 public-certificate replay verifier. The profile deliberately
/// rejects every network except regtest and is not a poker settlement graph.
pub fn compile_regtest_card_gates(
    network: Network,
    accepted: &VerifiedAcceptedDeal,
) -> Result<RegtestGateManifest, BitcoinError> {
    dlog52_bitcoin::require_regtest(network)?;
    dlog52_bitcoin::build_regtest_gate(accepted)
}

pub use dlog52_bitcoin::{
    GateLeaf, SlotGateManifest, assemble_gate_witness, gate_tapscript_sighash,
};
