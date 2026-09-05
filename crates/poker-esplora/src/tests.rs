use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::absolute;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, BlockHash, Network, ScriptBuf, Transaction, TxOut, Txid};
use poker_client_ports::{
    BlockRef, ChainProfile, OutPointRef, OutpointStatus, PortError, TransactionStatus,
};

use crate::transport::HttpTransport;
use crate::{EsploraClient, EsploraConfig, EsploraError};

#[derive(Default)]
struct FakeTransport {
    get: Mutex<BTreeMap<String, Vec<u8>>>,
    get_sequences: Mutex<BTreeMap<String, VecDeque<Vec<u8>>>>,
    post_response: Mutex<Vec<u8>>,
    post_calls: Arc<AtomicUsize>,
}

impl FakeTransport {
    fn response(self, url: &str, response: impl Into<Vec<u8>>) -> Self {
        if let Ok(mut responses) = self.get.lock() {
            responses.insert(url.to_owned(), response.into());
        }
        self
    }

    fn response_sequence<I, B>(self, url: &str, responses: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<Vec<u8>>,
    {
        if let Ok(mut sequences) = self.get_sequences.lock() {
            sequences.insert(
                url.to_owned(),
                responses.into_iter().map(Into::into).collect(),
            );
        }
        self
    }
}

impl HttpTransport for FakeTransport {
    fn get(&self, url: &str, maximum: usize) -> Result<Vec<u8>, EsploraError> {
        if let Some(response) = self
            .get_sequences
            .lock()
            .map_err(|_| EsploraError::Transport)?
            .get_mut(url)
            .and_then(VecDeque::pop_front)
        {
            if response.len() > maximum {
                return Err(EsploraError::ResponseTooLarge { maximum });
            }
            return Ok(response);
        }
        let responses = self.get.lock().map_err(|_| EsploraError::Transport)?;
        let response = responses.get(url).ok_or(EsploraError::NotFound)?.clone();
        if response.len() > maximum {
            return Err(EsploraError::ResponseTooLarge { maximum });
        }
        Ok(response)
    }

    fn post_text(&self, _url: &str, _body: &str, maximum: usize) -> Result<Vec<u8>, EsploraError> {
        self.post_calls.fetch_add(1, Ordering::Relaxed);
        let response = self
            .post_response
            .lock()
            .map_err(|_| EsploraError::Transport)?
            .clone();
        if response.len() > maximum {
            return Err(EsploraError::ResponseTooLarge { maximum });
        }
        Ok(response)
    }
}

fn test_profile() -> Result<ChainProfile, PortError> {
    ChainProfile::custom_signet(
        genesis_block(Network::Signet).block_hash().to_byte_array(),
        vec![0x51],
        Some(BlockRef {
            height: 100,
            hash: [4; 32],
        }),
    )
}

fn configured_client(transport: FakeTransport) -> Result<EsploraClient, EsploraError> {
    let profile = test_profile().map_err(EsploraError::Profile)?;
    let config = EsploraConfig::new("https://example.test/api/", profile, true)?;
    Ok(EsploraClient::with_transport(config, transport))
}

#[test]
fn identity_check_requires_genesis_checkpoint_and_consistent_tip() -> Result<(), Box<dyn Error>> {
    let tip = BlockHash::from_byte_array([5; 32]).to_string();
    let transport = FakeTransport::default()
        .response(
            "https://example.test/api/block-height/0",
            BlockHash::from_byte_array(test_profile()?.genesis_hash()).to_string(),
        )
        .response(
            "https://example.test/api/block-height/100",
            BlockHash::from_byte_array([4; 32]).to_string(),
        )
        .response("https://example.test/api/blocks/tip/hash", tip.clone())
        .response(
            &format!("https://example.test/api/block/{tip}"),
            format!(r#"{{"id":"{tip}","height":120}}"#),
        )
        .response("https://example.test/api/block-height/120", tip);
    let client = configured_client(transport)?;
    let identity = client.verify_profile()?;
    assert_eq!(
        identity.profile_id(),
        client.config().profile().profile_id()
    );
    assert_eq!(identity.checked_tip().height, 120);
    Ok(())
}

#[test]
fn identity_check_ignores_a_persistently_stale_tip_height() -> Result<(), Box<dyn Error>> {
    let advanced_tip = BlockHash::from_byte_array([6; 32]).to_string();
    let transport = FakeTransport::default()
        .response(
            "https://example.test/api/block-height/0",
            BlockHash::from_byte_array(test_profile()?.genesis_hash()).to_string(),
        )
        .response(
            "https://example.test/api/block-height/100",
            BlockHash::from_byte_array([4; 32]).to_string(),
        )
        .response(
            "https://example.test/api/blocks/tip/height",
            b"120".to_vec(),
        )
        .response(
            "https://example.test/api/blocks/tip/hash",
            advanced_tip.clone(),
        )
        .response(
            &format!("https://example.test/api/block/{advanced_tip}"),
            format!(r#"{{"id":"{advanced_tip}","height":121}}"#),
        )
        .response(
            "https://example.test/api/block-height/121",
            advanced_tip.clone(),
        );
    let identity = configured_client(transport)?.verify_profile()?;
    assert_eq!(identity.checked_tip().height, 121);
    assert_eq!(
        identity.checked_tip().hash,
        BlockHash::from_byte_array([6; 32]).to_byte_array()
    );
    Ok(())
}

#[test]
fn identity_check_retries_hash_metadata_until_canonical_mapping_stabilizes()
-> Result<(), Box<dyn Error>> {
    let prior_tip = BlockHash::from_byte_array([5; 32]).to_string();
    let advanced_tip = BlockHash::from_byte_array([6; 32]).to_string();
    let transport = FakeTransport::default()
        .response(
            "https://example.test/api/block-height/0",
            BlockHash::from_byte_array(test_profile()?.genesis_hash()).to_string(),
        )
        .response(
            "https://example.test/api/block-height/100",
            BlockHash::from_byte_array([4; 32]).to_string(),
        )
        .response_sequence(
            "https://example.test/api/blocks/tip/hash",
            [
                advanced_tip.clone(),
                advanced_tip.clone(),
                advanced_tip.clone(),
            ],
        )
        .response(
            &format!("https://example.test/api/block/{advanced_tip}"),
            format!(r#"{{"id":"{advanced_tip}","height":121}}"#),
        )
        .response_sequence(
            "https://example.test/api/block-height/121",
            [prior_tip.clone(), prior_tip, advanced_tip.clone()],
        );
    let identity = configured_client(transport)?.verify_profile()?;
    assert_eq!(identity.checked_tip().height, 121);
    assert_eq!(
        identity.checked_tip().hash,
        BlockHash::from_byte_array([6; 32]).to_byte_array()
    );
    Ok(())
}

#[test]
fn identity_check_rejects_persistently_inconsistent_tip_endpoints() -> Result<(), Box<dyn Error>> {
    let transport = FakeTransport::default()
        .response(
            "https://example.test/api/block-height/0",
            BlockHash::from_byte_array(test_profile()?.genesis_hash()).to_string(),
        )
        .response(
            "https://example.test/api/block-height/100",
            BlockHash::from_byte_array([4; 32]).to_string(),
        )
        .response(
            "https://example.test/api/blocks/tip/hash",
            BlockHash::from_byte_array([6; 32]).to_string(),
        )
        .response(
            &format!(
                "https://example.test/api/block/{}",
                BlockHash::from_byte_array([6; 32])
            ),
            format!(
                r#"{{"id":"{}","height":120}}"#,
                BlockHash::from_byte_array([6; 32])
            ),
        )
        .response(
            "https://example.test/api/block-height/120",
            BlockHash::from_byte_array([5; 32]).to_string(),
        );
    assert!(matches!(
        configured_client(transport)?.verify_profile(),
        Err(EsploraError::InvalidResponse(
            "tip hash and canonical block endpoints remained inconsistent after bounded retries"
        ))
    ));
    Ok(())
}

#[test]
fn checkpoint_mismatch_fails_closed() -> Result<(), Box<dyn Error>> {
    let transport = FakeTransport::default()
        .response(
            "https://example.test/api/block-height/0",
            BlockHash::from_byte_array(test_profile()?.genesis_hash()).to_string(),
        )
        .response(
            "https://example.test/api/block-height/100",
            BlockHash::from_byte_array([9; 32]).to_string(),
        );
    let client = configured_client(transport)?;
    assert!(matches!(
        client.verify_profile(),
        Err(EsploraError::ChainIdentityMismatch)
    ));
    Ok(())
}

#[test]
fn strict_outspend_parsing_preserves_confirmation() -> Result<(), Box<dyn Error>> {
    let spending_txid = Txid::from_byte_array([5; 32]);
    let block_hash = BlockHash::from_byte_array([6; 32]);
    let wire = format!(
        r#"{{"spent":true,"txid":"{spending_txid}","vin":0,"status":{{"confirmed":true,"block_height":7,"block_hash":"{block_hash}","block_time":8}}}}"#
    );
    let parent = Txid::from_byte_array([7; 32]);
    let transport = FakeTransport::default().response(
        &format!("https://example.test/api/tx/{parent}/outspend/1"),
        wire,
    );
    let client = configured_client(transport)?;
    let status = client.outpoint_status_by_ref(OutPointRef {
        txid: parent.to_byte_array(),
        vout: 1,
    })?;
    assert_eq!(
        status,
        OutpointStatus::Spent {
            spending_txid: spending_txid.to_byte_array(),
            vin: 0,
            status: TransactionStatus::Confirmed {
                block: BlockRef {
                    height: 7,
                    hash: block_hash.to_byte_array(),
                },
            },
        }
    );
    Ok(())
}

#[test]
fn mainnet_or_disabled_profiles_cannot_broadcast() -> Result<(), Box<dyn Error>> {
    let mainnet_genesis = genesis_block(Network::Bitcoin).block_hash().to_byte_array();
    let mainnet = ChainProfile::standard(
        mainnet_genesis,
        Some(BlockRef {
            height: 0,
            hash: mainnet_genesis,
        }),
    )?;
    assert!(matches!(
        EsploraConfig::new("https://blockstream.info/api", mainnet, true),
        Err(EsploraError::MainnetBroadcastDisabled)
    ));

    let disabled = EsploraConfig::new("https://example.test/api", test_profile()?, false)?;
    let client = EsploraClient::with_transport(disabled, FakeTransport::default());
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    assert!(matches!(
        client.publish_transaction(&transaction),
        Err(EsploraError::BroadcastDisabled)
    ));
    Ok(())
}

#[test]
fn profile_mismatch_prevents_any_post() -> Result<(), Box<dyn Error>> {
    let transport = FakeTransport::default().response(
        "https://example.test/api/block-height/0",
        BlockHash::from_byte_array([9; 32]).to_string(),
    );
    let post_calls = Arc::clone(&transport.post_calls);
    let client = configured_client(transport)?;
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    assert!(matches!(
        client.publish_transaction(&transaction),
        Err(EsploraError::ChainIdentityMismatch)
    ));
    assert_eq!(post_calls.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn base_url_validation_rejects_unsafe_forms() -> Result<(), PortError> {
    for url in [
        "http://example.test/api",
        "https://user@example.test/api",
        "https://example.test/api?token=secret",
        "https://example.test/a/../api",
    ] {
        assert!(matches!(
            EsploraConfig::new(url, test_profile()?, false),
            Err(EsploraError::InvalidConfiguration(_))
        ));
    }
    Ok(())
}

#[test]
fn raw_transaction_wrapper_uses_consensus_txid_order() -> Result<(), Box<dyn Error>> {
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = transaction.compute_txid();
    let transport = FakeTransport::default().response(
        &format!("https://example.test/api/tx/{txid}/raw"),
        serialize(&transaction),
    );
    let client = configured_client(transport)?;
    let raw = client
        .raw_transaction_by_id(txid.to_byte_array())?
        .ok_or(EsploraError::NotFound)?;
    assert_eq!(raw.txid(), txid.to_byte_array());
    assert_eq!(raw.consensus(), serialize(&transaction));
    Ok(())
}
