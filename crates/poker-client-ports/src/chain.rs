//! Chain contracts.
use super::{
    CUSTOM_SIGNET_NETWORK_ID_TAG, Digest, Hash, MAX_RAW_TRANSACTION_BYTES,
    MAX_SIGNET_CHALLENGE_BYTES, Network, PortError, Script, Sha256, genesis_block, serialize,
    sha256d,
};

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
