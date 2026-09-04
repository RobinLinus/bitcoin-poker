//! Canonical Bitcoin transaction inspection behind a raw WebAssembly ABI.
//!
//! JavaScript supplies opaque consensus bytes. This crate delegates the full
//! decode, canonical reserialization, transaction-id calculation, and field
//! extraction to `rust-bitcoin`, then returns a bounded Serde JSON view. No
//! Bitcoin consensus codec, metadata frame, or hashing implementation lives in
//! JavaScript.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", allow(unsafe_code))]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use std::sync::Mutex;

use bitcoin::Transaction;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hex::DisplayHex;
use bp52_client_ports::MAX_RAW_TRANSACTION_BYTES;
use serde::Serialize;

const ABI_VERSION: u32 = 2;
const MAX_METADATA_JSON_BYTES: usize = 32_000_000;
const MAX_ERROR_BYTES: usize = 2_048;

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionMetadata {
    display_txid_hex: String,
    has_witness: bool,
    version: i32,
    lock_time: u32,
    inputs: Vec<TransactionInputMetadata>,
    outputs: Vec<TransactionOutputMetadata>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionInputMetadata {
    previous_outpoint: OutpointMetadata,
    script_sig_hex: String,
    sequence: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutpointMetadata {
    display_txid_hex: String,
    vout: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionOutputMetadata {
    value_sat: u64,
    script_pubkey_hex: String,
}

static MODULE: Mutex<ModuleState> = Mutex::new(ModuleState::new());

struct ModuleState {
    input: Vec<u8>,
    output: Vec<u8>,
    error: Vec<u8>,
}

impl ModuleState {
    const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            error: Vec::new(),
        }
    }

    fn fail(&mut self, code: i32, message: impl AsRef<str>) -> i32 {
        self.output.clear();
        self.error.clear();
        self.error.extend_from_slice(message.as_ref().as_bytes());
        self.error.truncate(MAX_ERROR_BYTES);
        code
    }

    fn succeed(&mut self, output: Vec<u8>) -> i32 {
        self.output = output;
        self.error.clear();
        0
    }
}

fn inspect_transaction(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.is_empty() || raw.len() > MAX_RAW_TRANSACTION_BYTES {
        return Err(format!(
            "raw transaction is empty or exceeds the {MAX_RAW_TRANSACTION_BYTES}-byte bound"
        ));
    }

    let transaction: Transaction =
        deserialize(raw).map_err(|error| format!("invalid Bitcoin transaction: {error}"))?;
    if transaction.input.is_empty() {
        return Err("raw transaction has no inputs".to_owned());
    }
    if transaction.output.is_empty() {
        return Err("raw transaction has no outputs".to_owned());
    }
    if serialize(&transaction) != raw {
        return Err("raw transaction is not canonically encoded".to_owned());
    }

    let mut total_output_value = 0_u64;
    for output in &transaction.output {
        let value = output.value.to_sat();
        total_output_value = total_output_value
            .checked_add(value)
            .ok_or_else(|| "raw transaction output value overflows".to_owned())?;
        if value > bitcoin::Amount::MAX_MONEY.to_sat()
            || total_output_value > bitcoin::Amount::MAX_MONEY.to_sat()
        {
            return Err("raw transaction output value exceeds Bitcoin's money range".to_owned());
        }
    }

    let metadata = TransactionMetadata {
        display_txid_hex: transaction.compute_txid().to_string(),
        has_witness: transaction
            .input
            .iter()
            .any(|input| !input.witness.is_empty()),
        version: transaction.version.0,
        lock_time: transaction.lock_time.to_consensus_u32(),
        inputs: transaction
            .input
            .iter()
            .map(|input| TransactionInputMetadata {
                previous_outpoint: OutpointMetadata {
                    display_txid_hex: input.previous_output.txid.to_string(),
                    vout: input.previous_output.vout,
                },
                script_sig_hex: input.script_sig.as_bytes().as_hex().to_string(),
                sequence: input.sequence.to_consensus_u32(),
            })
            .collect(),
        outputs: transaction
            .output
            .iter()
            .map(|output| TransactionOutputMetadata {
                value_sat: output.value.to_sat(),
                script_pubkey_hex: output.script_pubkey.as_bytes().as_hex().to_string(),
            })
            .collect(),
    };
    let json = serde_json::to_vec(&metadata)
        .map_err(|error| format!("could not serialize transaction metadata: {error}"))?;
    if json.is_empty() || json.len() > MAX_METADATA_JSON_BYTES {
        return Err("transaction metadata exceeds the fixed Wasm JSON bound".to_owned());
    }
    Ok(json)
}

fn with_module(operation: impl FnOnce(&mut ModuleState) -> i32) -> i32 {
    match MODULE.lock() {
        Ok(mut state) => operation(&mut state),
        Err(_) => -127,
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_exports {
    use super::*;

    /// Return the raw transaction-inspector ABI version.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_abi_version() -> u32 {
        ABI_VERSION
    }

    /// Return the largest accepted raw consensus transaction.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_max_input_len() -> u32 {
        u32::try_from(MAX_RAW_TRANSACTION_BYTES).unwrap_or(0)
    }

    /// Return the largest transaction metadata JSON result.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_max_output_len() -> u32 {
        u32::try_from(MAX_METADATA_JSON_BYTES).unwrap_or(0)
    }

    /// Return the largest diagnostic result.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_max_error_len() -> u32 {
        u32::try_from(MAX_ERROR_BYTES).unwrap_or(0)
    }

    /// Resize the bounded opaque-consensus-byte input region.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_begin_input(length: u32) -> i32 {
        with_module(|state| {
            state.error.clear();
            let Ok(length) = usize::try_from(length) else {
                return state.fail(2, "input length overflow");
            };
            if length == 0 || length > MAX_RAW_TRANSACTION_BYTES {
                return state.fail(
                    2,
                    format!(
                        "raw transaction is empty or exceeds the {MAX_RAW_TRANSACTION_BYTES}-byte bound"
                    ),
                );
            }
            state.input.clear();
            state.input.resize(length, 0);
            0
        })
    }

    /// Return the staged input pointer. Copy bytes before calling inspect.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_input_ptr() -> u32 {
        match MODULE.lock() {
            Ok(mut state) => u32::try_from(state.input.as_mut_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Decode, canonically reserialize, hash, and project the staged transaction.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_inspect() -> i32 {
        with_module(|state| {
            state.error.clear();
            let input = std::mem::take(&mut state.input);
            match inspect_transaction(&input) {
                Ok(frame) => state.succeed(frame),
                Err(error) => state.fail(3, error),
            }
        })
    }

    /// Return the current metadata JSON pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_output_ptr() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.output.as_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Return the current metadata JSON length.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_output_len() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.output.len()).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }

    /// Return the latest bounded diagnostic-region pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_last_error_ptr() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.error.as_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Return the latest bounded diagnostic-region length.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_last_error_len() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.error.len()).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }

    /// Clear every transient input, output, and diagnostic byte.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_transaction_clear() {
        if let Ok(mut state) = MODULE.lock() {
            state.input.clear();
            state.output.clear();
            state.error.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    use super::*;

    fn fixture(witness: bool) -> Transaction {
        let mut input_witness = Witness::new();
        if witness {
            input_witness.push([0x12, 0x34]);
        }
        Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x44; 32]),
                    vout: 9,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: input_witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(19_500),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0xab]),
            }],
        }
    }

    #[test]
    fn rust_bitcoin_projects_canonical_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let transaction = fixture(false);
        let raw = serialize(&transaction);
        let json = inspect_transaction(&raw)?;
        let value: serde_json::Value = serde_json::from_slice(&json)?;
        assert_eq!(
            value["displayTxidHex"],
            transaction.compute_txid().to_string()
        );
        assert_eq!(value["hasWitness"], false);
        assert_eq!(value["version"], 2);
        assert_eq!(value["lockTime"], 0);
        assert_eq!(value["inputs"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            value["inputs"][0]["previousOutpoint"]["displayTxidHex"],
            "44".repeat(32)
        );
        assert_eq!(value["inputs"][0]["previousOutpoint"]["vout"], 9);
        assert_eq!(value["inputs"][0]["scriptSigHex"], "");
        assert_eq!(value["inputs"][0]["sequence"], u32::MAX);
        assert_eq!(value["outputs"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["outputs"][0]["valueSat"], 19_500);
        assert_eq!(value["outputs"][0]["scriptPubkeyHex"], "5120ab");
        Ok(())
    }

    #[test]
    fn rust_bitcoin_projects_witness_txid_without_witness_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let transaction = fixture(true);
        let json = inspect_transaction(&serialize(&transaction))?;
        let value: serde_json::Value = serde_json::from_slice(&json)?;
        assert_eq!(value["hasWitness"], true);
        assert_eq!(
            value["displayTxidHex"],
            transaction.compute_txid().to_string()
        );
        Ok(())
    }

    #[test]
    fn malformed_and_out_of_range_transactions_fail_closed() {
        assert!(inspect_transaction(&[]).is_err());
        assert!(inspect_transaction(&[0; 8]).is_err());

        let mut transaction = fixture(false);
        transaction.output[0].value = Amount::from_sat(Amount::MAX_MONEY.to_sat() + 1);
        assert!(inspect_transaction(&serialize(&transaction)).is_err());

        assert!(inspect_transaction(&vec![0; MAX_RAW_TRANSACTION_BYTES + 1]).is_err());
    }
}
