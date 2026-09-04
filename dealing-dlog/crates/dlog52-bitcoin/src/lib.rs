#![forbid(unsafe_code)]
//! Regtest-only single-slot tapscript gate primitives.

use bitcoin::{
    ScriptBuf,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP},
    script::Builder,
};
use thiserror::Error;

/// Bitcoin demonstration profile failure.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// The profile is intentionally unavailable outside regtest.
    #[error("DLOG52 card gates are restricted to regtest")]
    RealFundsDisabled,
    /// Slot/raw-sum/card metadata is inconsistent.
    #[error("invalid card-gate metadata")]
    Metadata,
}

/// Build the exact leaf script for one candidate.
pub fn build_candidate_leaf(
    deal_id: [u8; 32],
    slot: u8,
    raw_sum: u8,
    candidate_key: [u8; 32],
    authorizer: [u8; 32],
) -> Result<ScriptBuf, BitcoinError> {
    if slot > 8 || raw_sum > 102 {
        return Err(BitcoinError::Metadata);
    }
    Ok(Builder::new()
        .push_slice(deal_id)
        .push_opcode(OP_DROP)
        .push_int(i64::from(slot))
        .push_opcode(OP_DROP)
        .push_int(i64::from(raw_sum))
        .push_opcode(OP_DROP)
        .push_int(i64::from(raw_sum % 52))
        .push_opcode(OP_DROP)
        .push_slice(candidate_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(authorizer)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// Enforce the hard real-funds prohibition at the public construction boundary.
pub fn require_regtest(network: bitcoin::Network) -> Result<(), BitcoinError> {
    if network == bitcoin::Network::Regtest {
        Ok(())
    } else {
        Err(BitcoinError::RealFundsDisabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_metadata_and_network_are_checked() {
        assert!(build_candidate_leaf([1; 32], 8, 102, [2; 32], [3; 32]).is_ok());
        assert!(build_candidate_leaf([1; 32], 9, 0, [2; 32], [3; 32]).is_err());
        assert!(require_regtest(bitcoin::Network::Regtest).is_ok());
        assert!(require_regtest(bitcoin::Network::Bitcoin).is_err());
    }
}
