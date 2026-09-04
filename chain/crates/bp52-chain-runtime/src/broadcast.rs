//! Mainnet-disabled transaction broadcast boundary.

use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};

use crate::backend::reject_mainnet;
use crate::{ConfirmedActiveNode, PreparedTransaction, RuntimeError};

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

/// Broadcast a validated, active-state transaction only on non-mainnet.
///
/// The network gate runs before the broadcaster is invoked. The returned txid
/// must exactly equal the local witness-independent transaction identifier.
///
/// # Errors
///
/// Rejects mainnet, an external broadcast failure, or a mismatched txid.
pub fn broadcast_non_mainnet(
    active: &ConfirmedActiveNode<'_>,
    prepared: &PreparedTransaction,
    broadcaster: &dyn Broadcaster,
) -> Result<Txid, RuntimeError> {
    active.validate_prepared(prepared)?;
    broadcast_prepared_non_mainnet(prepared, broadcaster)
}

fn broadcast_prepared_non_mainnet(
    prepared: &PreparedTransaction,
    broadcaster: &dyn Broadcaster,
) -> Result<Txid, RuntimeError> {
    reject_mainnet(prepared.network)?;
    let connected_network_id = broadcaster.network_id()?;
    if connected_network_id != prepared.network_id {
        return Err(RuntimeError::BroadcastNetworkMismatch);
    }
    let transaction = prepared.transaction();
    let expected = transaction.compute_txid();
    if expected.to_byte_array() != prepared.template_txid() {
        return Err(RuntimeError::InconsistentGraph {
            reason: "prepared transaction differs from its fixed template txid",
        });
    }
    let reported = broadcaster.broadcast(transaction)?;
    if reported != expected {
        return Err(RuntimeError::BroadcastTxidMismatch);
    }
    // Force the representation through the fixed byte array used elsewhere;
    // this also documents that witness data cannot affect this identifier.
    let _ = reported.to_byte_array();
    Ok(reported)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use bitcoin::absolute;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Network, ScriptBuf, Transaction, Txid};
    use bp52_chain_bitcoin::custom_signet_network_id;

    use super::{BroadcastError, Broadcaster, broadcast_prepared_non_mainnet};
    use crate::{PreparedTransaction, RuntimeError};

    struct CountingBroadcaster {
        calls: Cell<usize>,
        network_id: [u8; 32],
    }

    impl Broadcaster for CountingBroadcaster {
        fn network_id(&self) -> Result<[u8; 32], BroadcastError> {
            Ok(self.network_id)
        }

        fn broadcast(&self, transaction: &Transaction) -> Result<Txid, BroadcastError> {
            self.calls.set(self.calls.get() + 1);
            Ok(transaction.compute_txid())
        }
    }

    fn transaction() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    fn prepared(network: Network, network_id: [u8; 32]) -> PreparedTransaction {
        let transaction = transaction();
        PreparedTransaction {
            template_txid: transaction.compute_txid().to_byte_array(),
            transaction,
            network,
            network_id,
            chain_game_id: [1; 32],
            graph_root: [4; 32],
            parent_node_id: [2; 32],
            child_node_id: [3; 32],
        }
    }

    #[test]
    fn mainnet_fails_before_external_broadcast() {
        let broadcaster = CountingBroadcaster {
            calls: Cell::new(0),
            network_id: [0x01; 32],
        };
        assert!(matches!(
            broadcast_prepared_non_mainnet(&prepared(Network::Bitcoin, [0x01; 32]), &broadcaster),
            Err(RuntimeError::MainnetDisabled)
        ));
        assert_eq!(broadcaster.calls.get(), 0);
    }

    #[test]
    fn non_mainnet_requires_matching_reported_txid() -> Result<(), RuntimeError> {
        let broadcaster = CountingBroadcaster {
            calls: Cell::new(0),
            network_id: [0x02; 32],
        };
        let prepared = prepared(Network::Regtest, [0x02; 32]);
        assert_eq!(
            broadcast_prepared_non_mainnet(&prepared, &broadcaster)?,
            prepared.transaction().compute_txid()
        );
        assert_eq!(broadcaster.calls.get(), 1);
        Ok(())
    }

    #[test]
    fn connected_node_network_id_must_match_prepared_network_id() {
        let broadcaster = CountingBroadcaster {
            calls: Cell::new(0),
            network_id: [0x03; 32],
        };
        assert!(matches!(
            broadcast_prepared_non_mainnet(&prepared(Network::Regtest, [0x02; 32]), &broadcaster),
            Err(RuntimeError::BroadcastNetworkMismatch)
        ));
        assert_eq!(broadcaster.calls.get(), 0);
    }

    #[test]
    fn raw_shared_signet_genesis_cannot_impersonate_a_custom_signet() {
        let default_signet_network_id = genesis_block(Network::Signet).block_hash().to_byte_array();
        let broadcaster = CountingBroadcaster {
            calls: Cell::new(0),
            network_id: default_signet_network_id,
        };
        let network_id = custom_signet_network_id(ScriptBuf::from_bytes(vec![0x51]).as_script());
        let prepared = prepared(Network::Signet, network_id);
        assert_ne!(prepared.network_id(), default_signet_network_id);
        assert!(matches!(
            broadcast_prepared_non_mainnet(&prepared, &broadcaster),
            Err(RuntimeError::BroadcastNetworkMismatch)
        ));
        assert_eq!(broadcaster.calls.get(), 0);
    }
}
