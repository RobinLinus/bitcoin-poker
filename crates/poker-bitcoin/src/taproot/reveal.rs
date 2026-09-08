//! Reveal programs.
use super::{BitcoinBackendError, ScriptBuf, append_length_prefixed};

/// Exact candidate-adaptor checks for one on-chain dlog reveal obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealProgram {
    deal_id: [u8; 32],
    node_id: [u8; 32],
    slots: Vec<u8>,
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
            deal_id,
            node_id,
            slots: slots.iter().map(|(slot, _)| *slot).collect(),
            script,
            elements: 1 + slots.len(),
        })
    }

    pub(super) fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(5);
        encoded.extend_from_slice(&self.deal_id);
        encoded.extend_from_slice(&self.node_id);
        append_length_prefixed(encoded, &self.slots);
        encoded.extend_from_slice(self.script.as_bytes());
    }
}
