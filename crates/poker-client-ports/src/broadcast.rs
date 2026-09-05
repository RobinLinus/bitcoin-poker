//! Backend-neutral Bitcoin broadcasting port.
use bitcoin::{Transaction, Txid};
use std::fmt;
/// Redacted failure returned by a node/RPC broadcaster.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BroadcastError {
    reason: &'static str,
}

impl BroadcastError {
    /// Construct a redacted broadcast failure.
    #[must_use]
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl fmt::Display for BroadcastError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason)
    }
}

impl std::error::Error for BroadcastError {}

/// Minimal backend capable of submitting one fully witnessed transaction.
pub trait Broadcaster {
    /// Query the connected node's exact chain-network identifier.
    ///
    /// Implementations must obtain this from the same RPC/session used by
    /// [`Self::broadcast`], not from a caller-supplied network setting. For a
    /// signet, the identifier must bind the signet challenge rather than
    /// reporting only the shared signet genesis hash.
    ///
    /// # Errors
    ///
    /// Returns a redacted RPC or transport failure.
    fn network_id(&self) -> Result<[u8; 32], BroadcastError>;

    /// Submit a transaction and return the node-reported txid.
    ///
    /// # Errors
    ///
    /// Returns a redacted RPC, transport, or policy failure.
    fn broadcast(&self, transaction: &Transaction) -> Result<Txid, BroadcastError>;
}
