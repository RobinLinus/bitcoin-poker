//! Reveal programs.
use super::{BitcoinBackendError, ScriptBuf};

/// Exact candidate-adaptor checks for one on-chain dlog reveal obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealProgram {
    pub(super) script: ScriptBuf,
    pub(super) elements: usize,
}

impl RevealProgram {
    /// Bind the accepted deal, node, actor, and distinct per-slot authorizers.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn new(
        deal_id: [u8; 32],
        node_id: [u8; 32],
        actor: [u8; 32],
        slots: &[(u8, [u8; 32])],
    ) -> Result<Self, BitcoinBackendError> {
        let script = dealer_bitcoin::reveal::reveal_tapscript(deal_id, node_id, actor, slots)
            .map_err(|_| BitcoinBackendError::InvalidBitcoinSignature)?;
        Ok(Self {
            script,
            elements: 1 + slots.len(),
        })
    }
}
