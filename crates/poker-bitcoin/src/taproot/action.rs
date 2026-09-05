//! Action programs.
use super::{
    Action, BitcoinBackendError, Builder, OP_DROP, ScriptBuf, append_keys,
    append_terminal_signature_checks, validate_authorizers, validate_identifier,
};

/// Specialized action authorization program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionProgram {
    pub(super) chain_game_id: [u8; 32],
    pub(super) node_id: [u8; 32],
    pub(super) action: Action,
    pub(super) authorizers: [[u8; 32]; 2],
}

impl ActionProgram {
    /// Bind one action branch to its exact game/node and both identity keys.
    ///
    /// The opponent distributes their transaction-specific signature in
    /// advance. The acting player selects this branch by supplying their own
    /// live signature. Both signatures remain in canonical Alice/Bob witness
    /// order regardless of which player acts.
    ///
    /// # Errors
    ///
    /// Rejects zero game/node identifiers and malformed x-only authorizer keys.
    pub fn new(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        action: Action,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "action chain game id")?;
        validate_identifier(node_id, "action node id")?;
        validate_authorizers(&authorizers)?;
        Ok(Self {
            chain_game_id,
            node_id,
            action,
            authorizers,
        })
    }

    pub(super) fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(0);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        encoded.push(self.action.code());
        append_keys(encoded, &self.authorizers);
    }

    pub(super) fn to_tapscript(&self) -> ScriptBuf {
        let builder = Builder::new()
            .push_int(i64::from(self.action.code()))
            .push_opcode(OP_DROP);
        append_terminal_signature_checks(builder, &self.authorizers).into_script()
    }
}
