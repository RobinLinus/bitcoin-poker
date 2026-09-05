//! Timeout programs.
use super::{
    BitcoinBackendError, Builder, OP_CSV, OP_DROP, ScriptBuf, append_keys,
    append_terminal_signature_checks, validate_authorizers, validate_identifier,
};

/// Both canonical player signatures gated by a block-height CSV delay.
///
/// The opponent supplies an exact-transaction preauthorization before play;
/// the beneficiary supplies their signature after maturity. Consensus sees
/// both signatures in canonical Alice/Bob order, independent of timing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutProgram {
    pub(super) chain_game_id: [u8; 32],
    pub(super) node_id: [u8; 32],
    pub(super) csv: u16,
    pub(super) authorizers: [[u8; 32]; 2],
}

impl TimeoutProgram {
    /// Construct a nonzero block-height timeout program.
    ///
    /// # Errors
    ///
    /// `authorizers` must be ordered as Alice then Bob.
    ///
    /// Rejects a zero delay or either malformed x-only identity key.
    pub fn new(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        csv: u16,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "timeout chain game id")?;
        validate_identifier(node_id, "timeout node id")?;
        if csv == 0 {
            return Err(BitcoinBackendError::InvalidTransactionTemplate {
                reason: "timeout CSV must be nonzero",
            });
        }
        validate_authorizers(&authorizers)?;
        Ok(Self {
            chain_game_id,
            node_id,
            csv,
            authorizers,
        })
    }

    /// Return the exact BIP68 block delay.
    #[must_use]
    pub const fn csv(&self) -> u16 {
        self.csv
    }

    pub(super) fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(2);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        encoded.extend_from_slice(&self.csv.to_le_bytes());
        append_keys(encoded, &self.authorizers);
    }

    pub(super) fn to_tapscript(&self) -> ScriptBuf {
        let builder = Builder::new()
            .push_int(i64::from(self.csv))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);
        append_terminal_signature_checks(builder, &self.authorizers).into_script()
    }
}
