//! Backend-neutral ports used by the BP52 client application.
//!
//! These types intentionally carry raw consensus bytes and hashes rather than
//! backend-specific JSON, RPC objects, URLs, or wallet handles. External
//! services report observations; the protocol engine remains responsible for
//! interpreting and validating them.

#![forbid(unsafe_code)]

use std::fmt;

use bitcoin::Network;
use bitcoin::Script;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::hashes::{Hash, sha256d};
use sha2::{Digest, Sha256};

mod deployment;

pub use deployment::{
    BrowserChainConfig, BrowserDeploymentConfig, ChainBackendName, ChainDeploymentConfig,
    CheckpointConfig, ConfirmationConfig, DeploymentConfig, DeploymentConfigError,
    FeeScheduleConfig, GameDeploymentConfig, NetworkName, ProtocolProfileName, RelayBrowserConfig,
    RelayKinds, RevealOrderConfig, RoleName, TimeoutPolicyName,
};

const CUSTOM_SIGNET_NETWORK_ID_TAG: &[u8] = b"BP52/custom-signet-network-id/v1";

/// Maximum custom-Signet challenge script retained in a chain profile.
pub const MAX_SIGNET_CHALLENGE_BYTES: usize = 10_000;
/// Maximum complete Bitcoin consensus transaction accepted by any client boundary.
pub const MAX_RAW_TRANSACTION_BYTES: usize = 4_000_000;
/// Maximum raw transaction or PSBT accepted across a client port.
pub const MAX_RAW_OBJECT_BYTES: usize = MAX_RAW_TRANSACTION_BYTES;
/// Maximum opaque session checkpoint accepted by the storage port.
pub const MAX_SESSION_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// Maximum opaque peer-to-peer protocol artifact accepted by a transport.
pub const MAX_PEER_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum UTF-8 peer message-kind length.
pub const MAX_PEER_MESSAGE_KIND_BYTES: usize = 32;

/// Portable value-validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PortError {
    /// Chain profile failed a structural check.
    #[error("invalid chain profile: {0}")]
    InvalidChainProfile(&'static str),
    /// Backend observations do not match the expected profile.
    #[error("chain identity mismatch")]
    ChainIdentityMismatch,
    /// Raw object was empty or exceeded its fixed bound.
    #[error("raw object size is invalid")]
    ObjectSize,
    /// Session checkpoint was malformed.
    #[error("invalid session snapshot: {0}")]
    InvalidSnapshot(&'static str),
    /// Peer transport message was malformed.
    #[error("invalid peer message: {0}")]
    InvalidPeerMessage(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Result<ChainProfile, PortError> {
        ChainProfile::custom_signet(
            genesis_block(Network::Signet).block_hash().to_byte_array(),
            vec![0x51],
            Some(BlockRef {
                height: 4,
                hash: [5; 32],
            }),
        )
    }

    #[test]
    fn exact_profile_observations_mint_identity() -> Result<(), PortError> {
        let profile = profile()?;
        let checkpoint = profile.checkpoint();
        let identity = profile.verify_observations(
            profile.genesis_hash(),
            checkpoint,
            BlockRef {
                height: 7,
                hash: [8; 32],
            },
        )?;
        assert_eq!(identity.profile_id(), profile.profile_id());
        assert_eq!(identity.matched_checkpoint(), checkpoint);
        Ok(())
    }

    #[test]
    fn profile_mismatch_never_mints_identity() -> Result<(), PortError> {
        let profile = profile()?;
        assert_eq!(
            profile.verify_observations(
                [9; 32],
                profile.checkpoint(),
                BlockRef {
                    height: 7,
                    hash: [8; 32],
                },
            ),
            Err(PortError::ChainIdentityMismatch)
        );
        Ok(())
    }

    #[test]
    fn custom_signet_requires_magic_and_bounded_challenge() {
        let signet_genesis = genesis_block(Network::Signet).block_hash().to_byte_array();
        assert!(matches!(
            ChainProfile::custom_signet(signet_genesis, Vec::new(), None),
            Err(PortError::InvalidChainProfile(_))
        ));
        assert!(matches!(
            ChainProfile::custom_signet(
                signet_genesis,
                vec![1; MAX_SIGNET_CHALLENGE_BYTES + 1],
                None,
            ),
            Err(PortError::InvalidChainProfile(_))
        ));
        assert!(matches!(
            ChainProfile::standard(signet_genesis, None),
            Err(PortError::InvalidChainProfile(_))
        ));
        assert!(matches!(
            ChainProfile::custom_signet([2; 32], vec![0x51], None),
            Err(PortError::InvalidChainProfile(_))
        ));
    }

    #[test]
    fn snapshots_are_bounded_and_revisioned() -> Result<(), PortError> {
        let snapshot = SessionSnapshot::new(1, b"state".to_vec())?;
        assert_eq!(snapshot.revision(), 1);
        assert_eq!(snapshot.bytes(), b"state");
        assert!(matches!(
            SessionSnapshot::new(0, Vec::new()),
            Err(PortError::InvalidSnapshot(_))
        ));
        Ok(())
    }

    #[test]
    fn peer_messages_are_bounded_and_canonical() -> Result<(), PortError> {
        let message = PeerMessage::new([1; 32], 1, "deal-envelope".to_owned(), vec![2, 3])?;
        assert_eq!(message.message_id(), [1; 32]);
        assert_eq!(message.sequence(), 1);
        assert_eq!(message.kind(), "deal-envelope");
        assert_eq!(message.payload(), [2, 3]);
        assert!(PeerMessage::new([0; 32], 1, "deal-envelope".to_owned(), vec![]).is_err());
        assert!(PeerMessage::new([1; 32], 0, "deal-envelope".to_owned(), vec![]).is_err());
        assert!(PeerMessage::new([1; 32], 1, "Bad Kind".to_owned(), vec![]).is_err());
        Ok(())
    }

    #[test]
    fn raw_transactions_share_one_exact_boundary_limit() {
        assert_eq!(MAX_RAW_OBJECT_BYTES, MAX_RAW_TRANSACTION_BYTES);
        assert!(RawTransaction::new([1; 32], vec![0; MAX_RAW_TRANSACTION_BYTES]).is_ok());
        assert_eq!(
            RawTransaction::new([1; 32], vec![0; MAX_RAW_TRANSACTION_BYTES + 1]),
            Err(PortError::ObjectSize),
        );
    }
}

/// Backend-neutral Bitcoin transaction broadcasting.
pub mod broadcast;
pub use broadcast::{BroadcastError, Broadcaster};

/// Transport contracts.
pub mod transport;
pub use transport::*;

/// Chain contracts.
pub mod chain;
pub use chain::*;

/// Wallet contracts.
pub mod wallet;
pub use wallet::*;

/// Storage contracts.
pub mod storage;
pub use storage::*;
