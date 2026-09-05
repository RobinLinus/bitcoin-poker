use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use poker_client_ports::{BlockRef, TransactionStatus};
use serde::Deserialize;

use crate::EsploraError;

#[derive(Debug, Deserialize)]
pub(crate) struct WireBlock {
    pub(crate) id: String,
    pub(crate) height: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
    #[serde(rename = "block_time")]
    _block_time: Option<u64>,
}

impl WireStatus {
    pub(crate) fn try_into_status(self) -> Result<TransactionStatus, EsploraError> {
        if !self.confirmed {
            if self.block_height.is_some() || self.block_hash.is_some() {
                return Err(EsploraError::InvalidResponse(
                    "unconfirmed transaction has block metadata",
                ));
            }
            return Ok(TransactionStatus::Mempool);
        }
        let height = self.block_height.ok_or(EsploraError::InvalidResponse(
            "confirmed status has no height",
        ))?;
        let hash = self
            .block_hash
            .as_deref()
            .ok_or(EsploraError::InvalidResponse(
                "confirmed status has no hash",
            ))
            .and_then(parse_block_hash)?;
        Ok(TransactionStatus::Confirmed {
            block: BlockRef { height, hash },
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireOutspend {
    pub(crate) spent: bool,
    pub(crate) txid: Option<String>,
    pub(crate) vin: Option<u32>,
    pub(crate) status: Option<WireStatus>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireAddressUtxo {
    pub(crate) txid: String,
    pub(crate) vout: u32,
    pub(crate) value: u64,
    pub(crate) status: WireStatus,
}

impl WireStatus {
    pub(crate) const fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

pub(crate) fn parse_block_hash(text: &str) -> Result<[u8; 32], EsploraError> {
    BlockHash::from_str(text.trim())
        .map(Hash::to_byte_array)
        .map_err(|_| EsploraError::InvalidResponse("invalid block hash"))
}

pub(crate) fn parse_txid(text: &str) -> Result<[u8; 32], EsploraError> {
    Txid::from_str(text.trim())
        .map(Hash::to_byte_array)
        .map_err(|_| EsploraError::InvalidResponse("invalid txid"))
}
