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

/// One best-chain block reference using consensus-order hash bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockRef {
    /// Zero-based block height.
    pub height: u32,
    /// Consensus-order block hash bytes.
    pub hash: [u8; 32],
}

/// Exact chain profile signed by the protocol and checked by an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainProfile {
    profile_id: [u8; 32],
    genesis_hash: [u8; 32],
    signet_challenge: Option<Vec<u8>>,
    p2p_magic: Option<[u8; 4]>,
    checkpoint: Option<BlockRef>,
    mainnet: bool,
}

impl ChainProfile {
    /// Construct a standard non-Signet chain profile.
    ///
    /// # Errors
    ///
    /// Rejects a zero genesis or a height-zero checkpoint differing from it.
    pub fn standard(
        genesis_hash: [u8; 32],
        checkpoint: Option<BlockRef>,
    ) -> Result<Self, PortError> {
        if genesis_hash == genesis_block(Network::Signet).block_hash().to_byte_array() {
            return Err(PortError::InvalidChainProfile(
                "Signet profiles require an exact challenge",
            ));
        }
        Self::from_parts(genesis_hash, genesis_hash, None, None, checkpoint)
    }

    /// Construct a custom-Signet profile derived from its complete challenge.
    ///
    /// The profile identifier and P2P message start are derived internally,
    /// preventing callers from pairing contradictory consensus identifiers.
    ///
    /// # Errors
    ///
    /// Rejects zero genesis, an empty/oversized challenge, a height-zero
    /// checkpoint mismatch, or custom-Signet data attached to mainnet.
    pub fn custom_signet(
        genesis_hash: [u8; 32],
        signet_challenge: Vec<u8>,
        checkpoint: Option<BlockRef>,
    ) -> Result<Self, PortError> {
        if genesis_hash != genesis_block(Network::Signet).block_hash().to_byte_array() {
            return Err(PortError::InvalidChainProfile(
                "custom Signet must use the shared Signet genesis",
            ));
        }
        if signet_challenge.is_empty() || signet_challenge.len() > MAX_SIGNET_CHALLENGE_BYTES {
            return Err(PortError::InvalidChainProfile(
                "Signet challenge length is invalid",
            ));
        }
        let script = Script::from_bytes(&signet_challenge);
        let serialized_challenge = serialize(script);
        let tag_hash = Sha256::digest(CUSTOM_SIGNET_NETWORK_ID_TAG);
        let mut network_hasher = Sha256::new();
        network_hasher.update(tag_hash);
        network_hasher.update(tag_hash);
        network_hasher.update(genesis_hash);
        network_hasher.update(&serialized_challenge);
        let profile_id = network_hasher.finalize().into();
        let magic_hash = sha256d::Hash::hash(&serialized_challenge).to_byte_array();
        Self::from_parts(
            profile_id,
            genesis_hash,
            Some(signet_challenge),
            Some([magic_hash[0], magic_hash[1], magic_hash[2], magic_hash[3]]),
            checkpoint,
        )
    }

    fn from_parts(
        profile_id: [u8; 32],
        genesis_hash: [u8; 32],
        signet_challenge: Option<Vec<u8>>,
        p2p_magic: Option<[u8; 4]>,
        checkpoint: Option<BlockRef>,
    ) -> Result<Self, PortError> {
        if profile_id == [0; 32] || genesis_hash == [0; 32] {
            return Err(PortError::InvalidChainProfile(
                "profile and genesis identifiers must be nonzero",
            ));
        }
        if let Some(block) = checkpoint {
            if block.hash == [0; 32] {
                return Err(PortError::InvalidChainProfile(
                    "checkpoint hash must be nonzero",
                ));
            }
            if block.height == 0 && block.hash != genesis_hash {
                return Err(PortError::InvalidChainProfile(
                    "height-zero checkpoint differs from genesis",
                ));
            }
        }
        let mainnet = genesis_hash == genesis_block(Network::Bitcoin).block_hash().to_byte_array();
        if mainnet && (signet_challenge.is_some() || p2p_magic.is_some()) {
            return Err(PortError::InvalidChainProfile(
                "mainnet cannot carry custom-Signet parameters",
            ));
        }
        Ok(Self {
            profile_id,
            genesis_hash,
            signet_challenge,
            p2p_magic,
            checkpoint,
            mainnet,
        })
    }

    /// Exact profile identifier committed by the game descriptor.
    #[must_use]
    pub const fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    /// Consensus-order genesis hash.
    #[must_use]
    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Complete custom-Signet challenge script, when applicable.
    #[must_use]
    pub fn signet_challenge(&self) -> Option<&[u8]> {
        self.signet_challenge.as_deref()
    }

    /// Challenge-derived P2P magic, when applicable.
    #[must_use]
    pub const fn p2p_magic(&self) -> Option<[u8; 4]> {
        self.p2p_magic
    }

    /// Stable checkpoint used to distinguish networks sharing a genesis.
    #[must_use]
    pub const fn checkpoint(&self) -> Option<BlockRef> {
        self.checkpoint
    }

    /// Whether this profile represents Bitcoin mainnet.
    #[must_use]
    pub const fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    /// Validate endpoint observations and mint an exact chain binding.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched genesis/checkpoint or a tip below the checkpoint.
    pub fn verify_observations(
        &self,
        observed_genesis: [u8; 32],
        observed_checkpoint: Option<BlockRef>,
        checked_tip: BlockRef,
    ) -> Result<VerifiedChainIdentity, PortError> {
        if observed_genesis != self.genesis_hash {
            return Err(PortError::ChainIdentityMismatch);
        }
        match (self.checkpoint, observed_checkpoint) {
            (Some(expected), Some(observed)) if expected == observed => {
                if checked_tip.height < expected.height {
                    return Err(PortError::ChainIdentityMismatch);
                }
            }
            (None, None) => {}
            _ => return Err(PortError::ChainIdentityMismatch),
        }
        Ok(VerifiedChainIdentity {
            profile_id: self.profile_id,
            genesis_hash: self.genesis_hash,
            checked_tip,
            matched_checkpoint: observed_checkpoint,
            mainnet: self.mainnet,
        })
    }
}

/// Opaque evidence that one adapter matched an exact chain profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedChainIdentity {
    profile_id: [u8; 32],
    genesis_hash: [u8; 32],
    checked_tip: BlockRef,
    matched_checkpoint: Option<BlockRef>,
    mainnet: bool,
}

impl VerifiedChainIdentity {
    /// Exact signed profile identifier.
    #[must_use]
    pub const fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    /// Verified consensus-order genesis hash.
    #[must_use]
    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Tip checked while the identity was established.
    #[must_use]
    pub const fn checked_tip(&self) -> BlockRef {
        self.checked_tip
    }

    /// Exact matched checkpoint, when required by the profile.
    #[must_use]
    pub const fn matched_checkpoint(&self) -> Option<BlockRef> {
        self.matched_checkpoint
    }

    /// Whether the verified profile represents Bitcoin mainnet.
    #[must_use]
    pub const fn is_mainnet(&self) -> bool {
        self.mainnet
    }
}

/// Bitcoin outpoint represented without an SDK- or backend-specific wrapper.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutPointRef {
    /// Consensus-order transaction identifier bytes.
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

/// Bounded raw Bitcoin transaction and its independently checked txid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawTransaction {
    txid: [u8; 32],
    consensus: Vec<u8>,
}

impl RawTransaction {
    /// Construct a bounded raw transaction container.
    ///
    /// The adapter must independently decode the bytes and verify this txid.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized consensus bytes.
    pub fn new(txid: [u8; 32], consensus: Vec<u8>) -> Result<Self, PortError> {
        if consensus.is_empty() || consensus.len() > MAX_RAW_TRANSACTION_BYTES {
            return Err(PortError::ObjectSize);
        }
        Ok(Self { txid, consensus })
    }

    /// Consensus-order transaction identifier.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Complete consensus serialization including witness.
    #[must_use]
    pub fn consensus(&self) -> &[u8] {
        &self.consensus
    }
}

/// Transaction's observed chain placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStatus {
    /// Endpoint has no transaction record.
    Unknown,
    /// Transaction is currently unconfirmed.
    Mempool,
    /// Transaction is included in the reported best chain.
    Confirmed {
        /// Block containing the transaction.
        block: BlockRef,
    },
}

/// Observed status of one exact outpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutpointStatus {
    /// Endpoint cannot identify the creating transaction/output.
    Unknown,
    /// Output is currently unspent.
    Unspent {
        /// Placement of the creating transaction.
        creating_status: TransactionStatus,
    },
    /// Output has been spent by a known transaction input.
    Spent {
        /// Spending transaction identifier.
        spending_txid: [u8; 32],
        /// Input index spending the requested output.
        vin: u32,
        /// Placement of the spending transaction.
        status: TransactionStatus,
    },
}

/// Best-chain observation bound to one verified profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TipObservation {
    /// Exact profile identifier.
    pub profile_id: [u8; 32],
    /// Current reported tip.
    pub block: BlockRef,
}

/// Fully located root UTXO observation passed to protocol validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtxoConfirmation {
    /// Exact profile identifier.
    pub profile_id: [u8; 32],
    /// Confirmed outpoint.
    pub outpoint: OutPointRef,
    /// Output value in satoshis.
    pub output_value_sat: u64,
    /// Consensus scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
    /// Complete creating transaction.
    pub creating_transaction: RawTransaction,
    /// Best-chain block containing the creating transaction.
    pub confirmed_in: BlockRef,
}

/// Confirmed transaction spending one watched outpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedSpend {
    /// Exact profile identifier.
    pub profile_id: [u8; 32],
    /// Outpoint consumed.
    pub spent_outpoint: OutPointRef,
    /// Complete spending transaction including witness.
    pub spending_transaction: RawTransaction,
    /// Input index consuming the watched outpoint.
    pub input_index: u32,
    /// Best-chain block containing the spend.
    pub confirmed_in: BlockRef,
}

/// Read-only chain-service capability.
pub trait ChainReader {
    /// Adapter-specific redacted failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Authenticate the configured endpoint against an expected chain.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure or identity mismatch.
    fn verify_chain_identity(
        &mut self,
        expected: &ChainProfile,
    ) -> Result<VerifiedChainIdentity, Self::Error>;
    /// Return a fresh best-chain tip observation.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure or inconsistent observation.
    fn tip(&mut self, chain: &VerifiedChainIdentity) -> Result<TipObservation, Self::Error>;
    /// Return the current best-chain block hash at a height.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure or inconsistent observation.
    fn block_hash(
        &mut self,
        chain: &VerifiedChainIdentity,
        height: u32,
    ) -> Result<Option<[u8; 32]>, Self::Error>;
    /// Return a complete raw transaction when known.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure or malformed transaction response.
    fn raw_transaction(
        &mut self,
        chain: &VerifiedChainIdentity,
        txid: [u8; 32],
    ) -> Result<Option<RawTransaction>, Self::Error>;
    /// Return the current placement of a transaction.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure or malformed status response.
    fn transaction_status(
        &mut self,
        chain: &VerifiedChainIdentity,
        txid: [u8; 32],
    ) -> Result<TransactionStatus, Self::Error>;
    /// Return the current placement/spend status of an outpoint.
    ///
    /// # Errors
    ///
    /// Returns an adapter failure or malformed outpoint response.
    fn outpoint_status(
        &mut self,
        chain: &VerifiedChainIdentity,
        outpoint: OutPointRef,
    ) -> Result<OutpointStatus, Self::Error>;
}

/// Transaction-submission capability, separate from observation and wallets.
pub trait TransactionPublisher {
    /// Adapter-specific redacted failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Submit one already validated raw transaction.
    ///
    /// # Errors
    ///
    /// Returns a policy, transport, or endpoint rejection.
    fn broadcast(
        &mut self,
        chain: &VerifiedChainIdentity,
        transaction: &RawTransaction,
    ) -> Result<[u8; 32], Self::Error>;
}

/// Purpose for a newly allocated wallet script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletScriptPurpose {
    /// Change from the jointly constructed origin transaction.
    FundingChange,
    /// Player's exact output in the pre-activation abort refund.
    OriginRefund,
    /// Terminal payout destination.
    TerminalPayout,
}

/// Funding-wallet capability kept separate from chain observation.
pub trait FundingWallet {
    /// Wallet-specific redacted failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocate a fresh consensus scriptPubKey for one purpose.
    ///
    /// # Errors
    ///
    /// Returns a wallet policy, custody, or storage failure.
    fn fresh_script(
        &mut self,
        profile_id: [u8; 32],
        purpose: WalletScriptPurpose,
    ) -> Result<Vec<u8>, Self::Error>;
    /// Select coins and populate a bounded unsigned PSBT supplied by the
    /// origin-package coordinator.
    ///
    /// # Errors
    ///
    /// Returns insufficient funds or a wallet policy/custody failure.
    fn select_funding(
        &mut self,
        profile_id: [u8; 32],
        required_value_sat: u64,
        unsigned_psbt: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
    /// Sign only inputs owned by this wallet without changing PSBT globals,
    /// inputs, or outputs.
    ///
    /// # Errors
    ///
    /// Returns a malformed request or wallet policy/custody failure.
    fn sign_owned_inputs(
        &mut self,
        profile_id: [u8; 32],
        fixed_psbt: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Stable 32-byte client session identifier.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Construct from already domain-separated bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the stable identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(..)")
    }
}

/// One bounded opaque durable session checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    revision: u64,
    bytes: Vec<u8>,
}

impl SessionSnapshot {
    /// Construct a durable checkpoint returned by a store.
    ///
    /// # Errors
    ///
    /// Rejects revision zero or oversized checkpoint bytes.
    pub fn new(revision: u64, bytes: Vec<u8>) -> Result<Self, PortError> {
        if revision == 0 {
            return Err(PortError::InvalidSnapshot("revision must be nonzero"));
        }
        if bytes.len() > MAX_SESSION_SNAPSHOT_BYTES {
            return Err(PortError::ObjectSize);
        }
        Ok(Self { revision, bytes })
    }

    /// Monotonically increasing revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Opaque application bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Storage-port failures shared across implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Backend failed without exposing database internals.
    #[error("session store operation failed")]
    Backend,
    /// Optimistic revision changed before the commit.
    #[error("session revision conflict")]
    Conflict,
    /// Snapshot exceeded the fixed application bound.
    #[error("session snapshot is too large")]
    SnapshotTooLarge,
    /// Durable bytes cannot be interpreted as a valid checkpoint.
    #[error("session store record is corrupt")]
    Corrupt,
}

impl StoreError {
    /// Construct a redacted backend failure while discarding implementation
    /// details from the portable boundary.
    #[must_use]
    pub const fn new(_reason: &'static str) -> Self {
        Self::Backend
    }
}

/// Optimistic transactional store for opaque client snapshots.
pub trait SessionStore {
    /// Load the current durable checkpoint, if any.
    ///
    /// # Errors
    ///
    /// Returns a redacted storage/corruption failure.
    fn load(&mut self, session_id: SessionId) -> Result<Option<SessionSnapshot>, StoreError>;
    /// Atomically commit the next checkpoint if the expected revision still
    /// matches. `None` means the session must not exist.
    ///
    /// # Errors
    ///
    /// Returns conflict, size, corruption, or redacted backend failure.
    fn commit(
        &mut self,
        session_id: SessionId,
        expected_revision: Option<u64>,
        snapshot: &[u8],
    ) -> Result<SessionSnapshot, StoreError>;
}

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
