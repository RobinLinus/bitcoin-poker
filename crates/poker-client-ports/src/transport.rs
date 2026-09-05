//! Transport contracts.
use super::{MAX_PEER_MESSAGE_BYTES, MAX_PEER_MESSAGE_KIND_BYTES, PortError};

/// One authenticated, ordered, opaque message exchanged by the two players.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMessage {
    message_id: [u8; 32],
    sequence: u64,
    kind: String,
    payload: Vec<u8>,
}

impl PeerMessage {
    /// Construct a bounded peer message.
    ///
    /// # Errors
    ///
    /// Rejects a zero identifier or sequence, an invalid kind, or an oversized payload.
    pub fn new(
        message_id: [u8; 32],
        sequence: u64,
        kind: String,
        payload: Vec<u8>,
    ) -> Result<Self, PortError> {
        if message_id == [0; 32] || sequence == 0 {
            return Err(PortError::InvalidPeerMessage(
                "identifier and sequence must be nonzero",
            ));
        }
        if kind.is_empty()
            || kind.len() > MAX_PEER_MESSAGE_KIND_BYTES
            || !kind.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
            })
        {
            return Err(PortError::InvalidPeerMessage("message kind is invalid"));
        }
        if payload.len() > MAX_PEER_MESSAGE_BYTES {
            return Err(PortError::ObjectSize);
        }
        Ok(Self {
            message_id,
            sequence,
            kind,
            payload,
        })
    }

    /// Stable id used to suppress retries.
    #[must_use]
    pub const fn message_id(&self) -> [u8; 32] {
        self.message_id
    }
    /// Sender-local contiguous sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Application-owned opaque artifact kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    /// Application-owned opaque artifact bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
