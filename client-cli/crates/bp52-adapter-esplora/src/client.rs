use std::str::FromStr;
use std::sync::Arc;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{Address, BlockHash, Transaction, Txid};
use bp52_chain_runtime::{BroadcastError, Broadcaster};
use bp52_client_ports::{
    BlockRef, ChainProfile, ChainReader, MAX_RAW_TRANSACTION_BYTES, OutPointRef, OutpointStatus,
    PortError, RawTransaction, TipObservation, TransactionPublisher, TransactionStatus,
    VerifiedChainIdentity,
};
use serde::Deserialize;

use crate::EsploraError;
use crate::config::EsploraConfig;
use crate::transport::{HttpTransport, UreqTransport};
use crate::wire::{
    WireAddressUtxo, WireBlock, WireOutspend, WireStatus, parse_block_hash, parse_txid,
};

/// One confirmed, independently checked output paying an exact address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressUtxo {
    /// Transaction identifier in consensus byte order.
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
    /// Output value in satoshis.
    pub value_sat: u64,
}

/// Maximum accepted small text or JSON response.
const MAX_METADATA_RESPONSE_BYTES: usize = 32 * 1024;
/// Synchronous Esplora implementation of the BP52 chain ports.
#[derive(Clone)]
pub struct EsploraClient {
    config: EsploraConfig,
    transport: Arc<dyn HttpTransport>,
}

impl std::fmt::Debug for EsploraClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EsploraClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl EsploraClient {
    /// Construct an adapter using bounded HTTPS requests and no redirects.
    #[must_use]
    pub fn new(config: EsploraConfig) -> Self {
        Self {
            config,
            transport: Arc::new(UreqTransport::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_transport(
        config: EsploraConfig,
        transport: impl HttpTransport + 'static,
    ) -> Self {
        Self {
            config,
            transport: Arc::new(transport),
        }
    }

    /// Return the immutable endpoint configuration.
    #[must_use]
    pub const fn config(&self) -> &EsploraConfig {
        &self.config
    }

    /// Verify genesis and checkpoint before using an endpoint for a session.
    ///
    /// # Errors
    ///
    /// Rejects transport failures or any mismatch with the pinned profile.
    pub fn verify_profile(&self) -> Result<VerifiedChainIdentity, EsploraError> {
        let genesis = self
            .block_hash_at(0)?
            .ok_or(EsploraError::ChainIdentityMismatch)?;
        if genesis != self.config.profile.genesis_hash() {
            return Err(EsploraError::ChainIdentityMismatch);
        }
        let observed_checkpoint = self
            .config
            .profile
            .checkpoint()
            .map(|expected| {
                self.block_hash_at(expected.height).and_then(|hash| {
                    hash.map(|hash| BlockRef {
                        height: expected.height,
                        hash,
                    })
                    .ok_or(EsploraError::ChainIdentityMismatch)
                })
            })
            .transpose()?;
        if observed_checkpoint != self.config.profile.checkpoint() {
            return Err(EsploraError::ChainIdentityMismatch);
        }
        let tip = self.tip_observation()?;
        self.config
            .profile
            .verify_observations(genesis, observed_checkpoint, tip.block)
            .map_err(|error| match error {
                PortError::ChainIdentityMismatch => EsploraError::ChainIdentityMismatch,
                other => EsploraError::Profile(other),
            })
    }

    /// List confirmed unspent outputs paying exactly `address`.
    ///
    /// Every returned value and script is rechecked against the raw creating
    /// transaction; the address-index response is never trusted by itself.
    pub fn confirmed_address_utxos(
        &self,
        address: &Address,
    ) -> Result<Vec<AddressUtxo>, EsploraError> {
        self.verify_profile()?;
        let wire: Vec<WireAddressUtxo> = self.get_json(&format!("/address/{address}/utxo"))?;
        if wire.len() > 128 {
            return Err(EsploraError::InvalidResponse(
                "address UTXO list is too large",
            ));
        }
        let expected_script = address.script_pubkey();
        let mut outputs = Vec::new();
        for candidate in wire {
            if !candidate.status.is_confirmed() {
                continue;
            }
            let txid = parse_txid(&candidate.txid)?;
            let raw = self
                .raw_transaction_by_id(txid)?
                .ok_or(EsploraError::InvalidResponse(
                    "address UTXO transaction is missing",
                ))?;
            let transaction: Transaction = deserialize(raw.consensus())
                .map_err(|_| EsploraError::InvalidResponse("invalid raw Bitcoin transaction"))?;
            let output =
                transaction
                    .output
                    .get(usize::try_from(candidate.vout).map_err(|_| {
                        EsploraError::InvalidResponse("address UTXO index is invalid")
                    })?)
                    .ok_or(EsploraError::InvalidResponse(
                        "address UTXO index is absent",
                    ))?;
            if output.value.to_sat() != candidate.value || output.script_pubkey != expected_script {
                return Err(EsploraError::InvalidResponse(
                    "address UTXO differs from its creating transaction",
                ));
            }
            outputs.push(AddressUtxo {
                txid,
                vout: candidate.vout,
                value_sat: candidate.value,
            });
        }
        Ok(outputs)
    }

    fn ensure_chain(&self, chain: &VerifiedChainIdentity) -> Result<(), EsploraError> {
        if chain.profile_id() != self.config.profile.profile_id()
            || chain.genesis_hash() != self.config.profile.genesis_hash()
            || chain.matched_checkpoint() != self.config.profile.checkpoint()
            || chain.is_mainnet() != self.config.profile.is_mainnet()
        {
            return Err(EsploraError::ChainIdentityMismatch);
        }
        Ok(())
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url)
    }

    fn get(&self, path: &str, maximum: usize) -> Result<Vec<u8>, EsploraError> {
        self.transport.get(&self.endpoint(path), maximum)
    }

    fn get_text(&self, path: &str) -> Result<String, EsploraError> {
        let bytes = self.get(path, MAX_METADATA_RESPONSE_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| EsploraError::InvalidResponse("response is not UTF-8"))?;
        Ok(text.trim().to_owned())
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, EsploraError> {
        let bytes = self.get(path, MAX_METADATA_RESPONSE_BYTES)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| EsploraError::InvalidResponse("invalid JSON response"))
    }

    fn block_hash_at(&self, height: u32) -> Result<Option<[u8; 32]>, EsploraError> {
        let text = match self.get_text(&format!("/block-height/{height}")) {
            Ok(text) => text,
            Err(EsploraError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(parse_block_hash(&text)?))
    }

    fn block_ref_at_hash(&self, expected_hash: [u8; 32]) -> Result<Option<BlockRef>, EsploraError> {
        let display_hash = BlockHash::from_byte_array(expected_hash);
        let response: WireBlock = match self.get_json(&format!("/block/{display_hash}")) {
            Ok(response) => response,
            Err(EsploraError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let response_hash = parse_block_hash(&response.id)?;
        if response_hash != expected_hash {
            return Ok(None);
        }
        Ok(Some(BlockRef {
            height: response.height,
            hash: response_hash,
        }))
    }

    fn tip_observation(&self) -> Result<TipObservation, EsploraError> {
        const COHERENCE_ATTEMPTS: usize = 3;

        for _ in 0..COHERENCE_ATTEMPTS {
            let hash = parse_block_hash(&self.get_text("/blocks/tip/hash")?)?;
            let Some(block) = self.block_ref_at_hash(hash)? else {
                continue;
            };
            if self
                .block_hash_at(block.height)?
                .is_some_and(|height_hash| block.hash == height_hash)
            {
                return Ok(TipObservation {
                    profile_id: self.config.profile.profile_id(),
                    block,
                });
            }
        }
        Err(EsploraError::InvalidResponse(
            "tip hash and canonical block endpoints remained inconsistent after bounded retries",
        ))
    }

    pub(crate) fn raw_transaction_by_id(
        &self,
        txid_bytes: [u8; 32],
    ) -> Result<Option<RawTransaction>, EsploraError> {
        let txid = Txid::from_byte_array(txid_bytes);
        let bytes = match self.get(&format!("/tx/{txid}/raw"), MAX_RAW_TRANSACTION_BYTES) {
            Ok(bytes) => bytes,
            Err(EsploraError::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let transaction: Transaction = deserialize(&bytes)
            .map_err(|_| EsploraError::InvalidResponse("invalid raw Bitcoin transaction"))?;
        if transaction.compute_txid() != txid {
            return Err(EsploraError::InvalidResponse(
                "raw transaction does not match requested txid",
            ));
        }
        RawTransaction::new(txid_bytes, bytes)
            .map(Some)
            .map_err(EsploraError::Profile)
    }

    fn transaction_status_by_id(
        &self,
        txid_bytes: [u8; 32],
    ) -> Result<TransactionStatus, EsploraError> {
        let txid = Txid::from_byte_array(txid_bytes);
        let status: WireStatus = match self.get_json(&format!("/tx/{txid}/status")) {
            Ok(status) => status,
            Err(EsploraError::NotFound) => return Ok(TransactionStatus::Unknown),
            Err(error) => return Err(error),
        };
        let status = status.try_into_status()?;
        if status == TransactionStatus::Mempool && self.raw_transaction_by_id(txid_bytes)?.is_none()
        {
            return Ok(TransactionStatus::Unknown);
        }
        Ok(status)
    }

    pub(crate) fn outpoint_status_by_ref(
        &self,
        outpoint: OutPointRef,
    ) -> Result<OutpointStatus, EsploraError> {
        let txid = Txid::from_byte_array(outpoint.txid);
        let response: WireOutspend =
            match self.get_json(&format!("/tx/{txid}/outspend/{}", outpoint.vout)) {
                Ok(response) => response,
                Err(EsploraError::NotFound) => return Ok(OutpointStatus::Unknown),
                Err(error) => return Err(error),
            };
        if !response.spent {
            if response.txid.is_some() || response.vin.is_some() || response.status.is_some() {
                return Err(EsploraError::InvalidResponse(
                    "unspent output has spending metadata",
                ));
            }
            let creating_status = self.transaction_status_by_id(outpoint.txid)?;
            return if creating_status == TransactionStatus::Unknown {
                Ok(OutpointStatus::Unknown)
            } else {
                Ok(OutpointStatus::Unspent { creating_status })
            };
        }
        let spending_txid = response
            .txid
            .as_deref()
            .ok_or(EsploraError::InvalidResponse("spent output has no txid"))
            .and_then(parse_txid)?;
        let vin = response.vin.ok_or(EsploraError::InvalidResponse(
            "spent output has no input index",
        ))?;
        let status = response
            .status
            .ok_or(EsploraError::InvalidResponse("spent output has no status"))?
            .try_into_status()?;
        Ok(OutpointStatus::Spent {
            spending_txid,
            vin,
            status,
        })
    }

    pub(crate) fn publish_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<Txid, EsploraError> {
        if !self.config.allow_broadcast {
            return Err(EsploraError::BroadcastDisabled);
        }
        if self.config.profile.is_mainnet() {
            return Err(EsploraError::MainnetBroadcastDisabled);
        }
        self.verify_profile()?;
        let transaction_hex = serialize(transaction).to_lower_hex_string();
        let response = self.transport.post_text(
            &self.endpoint("/tx"),
            &transaction_hex,
            MAX_METADATA_RESPONSE_BYTES,
        )?;
        let text = std::str::from_utf8(&response)
            .map_err(|_| EsploraError::InvalidResponse("broadcast txid is not UTF-8"))?
            .trim();
        let txid = Txid::from_str(text)
            .map_err(|_| EsploraError::InvalidResponse("invalid broadcast txid"))?;
        if txid != transaction.compute_txid() {
            return Err(EsploraError::InvalidResponse(
                "broadcast response txid differs from submitted transaction",
            ));
        }
        Ok(txid)
    }
}

impl ChainReader for EsploraClient {
    type Error = EsploraError;

    fn verify_chain_identity(
        &mut self,
        expected: &ChainProfile,
    ) -> Result<VerifiedChainIdentity, Self::Error> {
        if expected != &self.config.profile {
            return Err(EsploraError::ChainIdentityMismatch);
        }
        self.verify_profile()
    }

    fn tip(&mut self, chain: &VerifiedChainIdentity) -> Result<TipObservation, Self::Error> {
        self.ensure_chain(chain)?;
        self.tip_observation()
    }

    fn block_hash(
        &mut self,
        chain: &VerifiedChainIdentity,
        height: u32,
    ) -> Result<Option<[u8; 32]>, Self::Error> {
        self.ensure_chain(chain)?;
        self.block_hash_at(height)
    }

    fn raw_transaction(
        &mut self,
        chain: &VerifiedChainIdentity,
        txid: [u8; 32],
    ) -> Result<Option<RawTransaction>, Self::Error> {
        self.ensure_chain(chain)?;
        self.raw_transaction_by_id(txid)
    }

    fn transaction_status(
        &mut self,
        chain: &VerifiedChainIdentity,
        txid: [u8; 32],
    ) -> Result<TransactionStatus, Self::Error> {
        self.ensure_chain(chain)?;
        self.transaction_status_by_id(txid)
    }

    fn outpoint_status(
        &mut self,
        chain: &VerifiedChainIdentity,
        outpoint: OutPointRef,
    ) -> Result<OutpointStatus, Self::Error> {
        self.ensure_chain(chain)?;
        self.outpoint_status_by_ref(outpoint)
    }
}

impl TransactionPublisher for EsploraClient {
    type Error = EsploraError;

    fn broadcast(
        &mut self,
        chain: &VerifiedChainIdentity,
        raw: &RawTransaction,
    ) -> Result<[u8; 32], Self::Error> {
        self.ensure_chain(chain)?;
        let transaction: Transaction = deserialize(raw.consensus())
            .map_err(|_| EsploraError::InvalidResponse("invalid raw Bitcoin transaction"))?;
        if transaction.compute_txid().to_byte_array() != raw.txid() {
            return Err(EsploraError::InvalidResponse(
                "raw transaction container has an incorrect txid",
            ));
        }
        Ok(self.publish_transaction(&transaction)?.to_byte_array())
    }
}

impl Broadcaster for EsploraClient {
    fn network_id(&self) -> Result<[u8; 32], BroadcastError> {
        self.verify_profile()
            .map(|identity| identity.profile_id())
            .map_err(|_| BroadcastError::new("Esplora chain identity verification failed"))
    }

    fn broadcast(&self, transaction: &Transaction) -> Result<Txid, BroadcastError> {
        self.publish_transaction(transaction)
            .map_err(|_| BroadcastError::new("Esplora transaction submission failed"))
    }
}
