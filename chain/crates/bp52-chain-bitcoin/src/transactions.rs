//! Witness-independent version-2 transaction templates.

use bitcoin::absolute;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bp52_chain_types::{LogicalOutput, LogicalTransaction};
use sha2::{Digest, Sha256};

use crate::{BitcoinBackendError, MAX_CONSENSUS_SCRIPT_BYTES};

const MAX_TEMPLATE_OUTPUTS: usize = 4;
const CUSTOM_SIGNET_NETWORK_ID_TAG: &[u8] = b"BP52/custom-signet-network-id/v1";

/// A fixed non-witness transaction plus the exact parent output it spends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionTemplate {
    transaction: Transaction,
    parent_output: TxOut,
    fee_sat: u64,
}

impl TransactionTemplate {
    /// Build a normal final-sequence transition.
    ///
    /// # Errors
    ///
    /// Rejects mainnet, malformed output shapes, amount mismatch, oversized
    /// scripts, or invalid/null parent outpoints.
    pub fn normal(
        network: Network,
        parent_outpoint: OutPoint,
        parent_output: TxOut,
        outputs: Vec<TxOut>,
        fee_sat: u64,
    ) -> Result<Self, BitcoinBackendError> {
        Self::build(
            network,
            parent_outpoint,
            parent_output,
            outputs,
            fee_sat,
            Sequence::MAX,
        )
    }

    /// Build a timeout transition with one exact nonzero block-height CSV.
    ///
    /// # Errors
    ///
    /// Returns the normal template errors and rejects a zero CSV delay.
    pub fn timeout(
        network: Network,
        parent_outpoint: OutPoint,
        parent_output: TxOut,
        outputs: Vec<TxOut>,
        fee_sat: u64,
        csv: u16,
    ) -> Result<Self, BitcoinBackendError> {
        if csv == 0 {
            return Err(BitcoinBackendError::InvalidTransactionTemplate {
                reason: "timeout CSV must be nonzero",
            });
        }
        Self::build(
            network,
            parent_outpoint,
            parent_output,
            outputs,
            fee_sat,
            Sequence::from_height(csv),
        )
    }

    fn build(
        network: Network,
        parent_outpoint: OutPoint,
        parent_output: TxOut,
        outputs: Vec<TxOut>,
        fee_sat: u64,
        sequence: Sequence,
    ) -> Result<Self, BitcoinBackendError> {
        ensure_non_mainnet(network)?;
        if parent_outpoint.is_null() {
            return Err(BitcoinBackendError::InvalidTransactionTemplate {
                reason: "state parent outpoint is null",
            });
        }
        validate_parent_output(&parent_output)?;
        validate_outputs(&outputs)?;
        validate_amounts(parent_output.value, &outputs, fee_sat)?;

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: parent_outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: outputs,
        };
        Ok(Self {
            transaction,
            parent_output,
            fee_sat,
        })
    }

    /// Return the exact witness-free transaction.
    #[must_use]
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Return the parent output required for BIP341 sighash construction.
    #[must_use]
    pub const fn parent_output(&self) -> &TxOut {
        &self.parent_output
    }

    /// Return the exact fixed fee.
    #[must_use]
    pub const fn fee_sat(&self) -> u64 {
        self.fee_sat
    }

    /// Return the stable txid, which excludes all future witnesses.
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        self.transaction.compute_txid().to_byte_array()
    }

    /// Return the fixed consensus serialization with no witness marker/data.
    #[must_use]
    pub fn non_witness_serialization(&self) -> Vec<u8> {
        serialize(&self.transaction)
    }

    /// Convert to the canonical logical transaction record used by the compiler.
    #[must_use]
    pub fn to_logical_transaction(&self) -> LogicalTransaction {
        let input = &self.transaction.input[0];
        LogicalTransaction {
            version: u32::from_le_bytes(self.transaction.version.0.to_le_bytes()),
            lock_time: self.transaction.lock_time.to_consensus_u32(),
            input_outpoint: outpoint_consensus_bytes(input.previous_output),
            sequence: input.sequence.to_consensus_u32(),
            outputs: self
                .transaction
                .output
                .iter()
                .map(|output| LogicalOutput {
                    value_sat: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                })
                .collect(),
            fee_sat: self.fee_sat,
            txid: self.txid(),
            non_witness_serialization: self.non_witness_serialization(),
        }
    }

    /// Attach a runtime witness without changing the template's txid.
    ///
    /// # Errors
    ///
    /// Rejects an empty witness; all template transactions have exactly one input.
    pub fn with_witness(&self, witness: Witness) -> Result<Transaction, BitcoinBackendError> {
        if witness.is_empty() {
            return Err(BitcoinBackendError::InvalidTransactionTemplate {
                reason: "runtime witness is empty",
            });
        }
        let mut transaction = self.transaction.clone();
        transaction.input[0].witness = witness;
        Ok(transaction)
    }
}

/// Reparse and validate a compiler logical transaction against its parent output.
///
/// # Errors
///
/// Rejects noncanonical serialization, any embedded witness, wrong duplicated
/// fields/txid, invalid value conservation, or a non-v2/nonzero-locktime shape.
pub fn verify_logical_transaction(
    logical: &LogicalTransaction,
    parent_output: &TxOut,
) -> Result<Transaction, BitcoinBackendError> {
    let transaction: Transaction =
        deserialize(&logical.non_witness_serialization).map_err(|_| {
            BitcoinBackendError::InvalidTransactionTemplate {
                reason: "invalid non-witness transaction serialization",
            }
        })?;
    if serialize(&transaction) != logical.non_witness_serialization {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "noncanonical transaction serialization",
        });
    }
    if transaction.version != Version::TWO || transaction.lock_time != absolute::LockTime::ZERO {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "transaction is not version 2 with zero locktime",
        });
    }
    if transaction.input.len() != 1 || transaction.input[0].witness.iter().next().is_some() {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "transaction must have one witness-free input",
        });
    }
    let input = &transaction.input[0];
    if input.previous_output.is_null()
        || !input.script_sig.is_empty()
        || logical.version != 2
        || logical.lock_time != 0
        || logical.input_outpoint != outpoint_consensus_bytes(input.previous_output)
        || logical.sequence != input.sequence.to_consensus_u32()
        || logical.txid != transaction.compute_txid().to_byte_array()
        || logical.non_witness_serialization != serialize(&transaction)
    {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "logical transaction fields disagree with consensus bytes",
        });
    }
    validate_sequence(input.sequence)?;
    if logical.outputs.len() != transaction.output.len()
        || logical
            .outputs
            .iter()
            .zip(&transaction.output)
            .any(|(logical_output, output)| {
                logical_output.value_sat != output.value.to_sat()
                    || logical_output.script_pubkey != output.script_pubkey.as_bytes()
            })
    {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "logical outputs disagree with consensus bytes",
        });
    }
    validate_outputs(&transaction.output)?;
    validate_parent_output(parent_output)?;
    validate_amounts(parent_output.value, &transaction.output, logical.fee_sat)?;
    Ok(transaction)
}

/// Serialize an outpoint exactly as it appears in a transaction input.
#[must_use]
pub fn outpoint_consensus_bytes(outpoint: OutPoint) -> [u8; 36] {
    let encoded = serialize(&outpoint);
    let mut bytes = [0_u8; 36];
    bytes.copy_from_slice(&encoded);
    bytes
}

/// Decode an exact 36-byte consensus outpoint.
///
/// # Errors
///
/// Returns an error only if the consensus decoder rejects the fixed-size input.
pub fn outpoint_from_consensus_bytes(bytes: [u8; 36]) -> Result<OutPoint, BitcoinBackendError> {
    deserialize(&bytes).map_err(|_| BitcoinBackendError::InvalidTransactionTemplate {
        reason: "invalid outpoint consensus bytes",
    })
}

/// Reject real-funds mainnet construction in every released prototype build.
///
/// # Errors
///
/// Returns [`BitcoinBackendError::MainnetDisabled`] for `Network::Bitcoin`.
pub const fn ensure_non_mainnet(network: Network) -> Result<(), BitcoinBackendError> {
    if matches!(network, Network::Bitcoin) {
        Err(BitcoinBackendError::MainnetDisabled)
    } else {
        Ok(())
    }
}

/// Resolve a descriptor's consensus-order genesis hash to a non-signet v1
/// network.
///
/// The identifier is compared with [`bitcoin::BlockHash::to_byte_array`], the
/// same consensus byte order used by the canonical chain descriptor. Mainnet
/// is deliberately recognizable here so callers can produce a precise policy
/// error by subsequently calling [`ensure_non_mainnet`].
///
/// # Errors
///
/// Returns [`BitcoinBackendError::UnknownNetworkGenesis`] unless the hash is
/// exactly Bitcoin mainnet, testnet3, or regtest's genesis hash. A raw signet
/// genesis is deliberately rejected because every BIP325 signet shares it;
/// use [`custom_signet_network_id`] instead.
pub fn network_from_genesis_id(genesis_id: [u8; 32]) -> Result<Network, BitcoinBackendError> {
    [Network::Bitcoin, Network::Testnet, Network::Regtest]
        .into_iter()
        .find(|network| genesis_block(*network).block_hash().to_byte_array() == genesis_id)
        .ok_or(BitcoinBackendError::UnknownNetworkGenesis)
}

/// Derive an exact identifier for one custom signet consensus domain.
///
/// BIP325 custom signets deliberately share Bitcoin signet's genesis block.
/// This BIP340-style tagged hash commits to that genesis identifier followed
/// by the consensus serialization of the complete signet challenge script.
/// Including the script's canonical `CompactSize` length prevents ambiguous
/// concatenations and makes this identifier stable across implementations.
#[must_use]
pub fn custom_signet_network_id(signet_challenge: &Script) -> [u8; 32] {
    let tag_hash = Sha256::digest(CUSTOM_SIGNET_NETWORK_ID_TAG);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(genesis_block(Network::Signet).block_hash().to_byte_array());
    hasher.update(serialize(signet_challenge));
    hasher.finalize().into()
}

/// Validate an exact consensus-domain identifier against its configured
/// Bitcoin transaction/address parameter family.
///
/// Standard networks use their consensus-order genesis hash as the identifier.
/// A Signet identifier must instead be a nonzero challenge-bound identifier;
/// the configuration layer is responsible for deriving it from the complete
/// challenge script with [`custom_signet_network_id`]. This keeps the generic
/// transaction backend independent of any particular public Signet.
///
/// # Errors
///
/// Rejects an all-zero identifier, a raw shared Signet genesis hash, or an
/// identifier that contradicts the configured Bitcoin network family. This
/// function does not select a mainnet policy; callers that prohibit mainnet
/// must separately call [`ensure_non_mainnet`].
pub fn validate_network_identity(
    network_id: [u8; 32],
    network: Network,
) -> Result<(), BitcoinBackendError> {
    if network_id == [0; 32] {
        return Err(BitcoinBackendError::ZeroIdentifier {
            field: "network identifier",
        });
    }
    if network == Network::Signet {
        let raw_signet_id = genesis_block(Network::Signet).block_hash().to_byte_array();
        if network_id == raw_signet_id {
            return Err(BitcoinBackendError::UnknownNetworkGenesis);
        }
        for standard in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Regtest,
        ] {
            if network_id == genesis_block(standard).block_hash().to_byte_array() {
                return Err(BitcoinBackendError::NetworkIdentityMismatch);
            }
        }
        return Ok(());
    }
    if network_id != genesis_block(network).block_hash().to_byte_array() {
        return Err(BitcoinBackendError::NetworkIdentityMismatch);
    }
    Ok(())
}

fn validate_outputs(outputs: &[TxOut]) -> Result<(), BitcoinBackendError> {
    if outputs.is_empty() {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "transaction has no outputs",
        });
    }
    if outputs.len() > MAX_TEMPLATE_OUTPUTS {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "transaction has more than four outputs",
        });
    }
    for output in outputs {
        if output.script_pubkey.is_empty() {
            return Err(BitcoinBackendError::InvalidTransactionTemplate {
                reason: "transaction output script is empty",
            });
        }
        if output.script_pubkey.len() > MAX_CONSENSUS_SCRIPT_BYTES {
            return Err(BitcoinBackendError::OversizedConsensusScript {
                actual: output.script_pubkey.len(),
                maximum: MAX_CONSENSUS_SCRIPT_BYTES,
            });
        }
    }
    Ok(())
}

fn validate_parent_output(parent_output: &TxOut) -> Result<(), BitcoinBackendError> {
    if parent_output.script_pubkey.is_empty() {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "parent output script is empty",
        });
    }
    if parent_output.script_pubkey.len() > MAX_CONSENSUS_SCRIPT_BYTES {
        return Err(BitcoinBackendError::OversizedConsensusScript {
            actual: parent_output.script_pubkey.len(),
            maximum: MAX_CONSENSUS_SCRIPT_BYTES,
        });
    }
    Ok(())
}

fn validate_sequence(sequence: Sequence) -> Result<(), BitcoinBackendError> {
    if sequence == Sequence::MAX {
        return Ok(());
    }
    let raw = sequence.to_consensus_u32();
    let height =
        u16::try_from(raw).map_err(|_| BitcoinBackendError::InvalidTransactionTemplate {
            reason: "unsupported transaction sequence",
        })?;
    if height == 0 || Sequence::from_height(height) != sequence {
        return Err(BitcoinBackendError::InvalidTransactionTemplate {
            reason: "sequence is neither final nor a nonzero block-height CSV",
        });
    }
    Ok(())
}

fn validate_amounts(
    parent_value: Amount,
    outputs: &[TxOut],
    fee_sat: u64,
) -> Result<(), BitcoinBackendError> {
    if parent_value > Amount::MAX_MONEY {
        return Err(BitcoinBackendError::InvalidTransactionAmount);
    }
    let output_sum = outputs.iter().try_fold(0_u64, |total, output| {
        if output.value > Amount::MAX_MONEY {
            return Err(BitcoinBackendError::InvalidTransactionAmount);
        }
        total
            .checked_add(output.value.to_sat())
            .ok_or(BitcoinBackendError::InvalidTransactionAmount)
    })?;
    let spent = output_sum
        .checked_add(fee_sat)
        .ok_or(BitcoinBackendError::InvalidTransactionAmount)?;
    if spent != parent_value.to_sat() || output_sum > Amount::MAX_MONEY.to_sat() {
        return Err(BitcoinBackendError::InvalidTransactionAmount);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid, Witness};

    use super::{
        TransactionTemplate, custom_signet_network_id, ensure_non_mainnet, network_from_genesis_id,
        outpoint_consensus_bytes, outpoint_from_consensus_bytes, validate_network_identity,
        verify_logical_transaction,
    };
    use crate::BitcoinBackendError;

    fn outpoint() -> OutPoint {
        OutPoint::new(Txid::from_byte_array([7_u8; 32]), 3)
    }

    fn output(value: u64, marker: u8) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x20, marker]),
        }
    }

    fn template() -> Result<TransactionTemplate, BitcoinBackendError> {
        TransactionTemplate::normal(
            Network::Regtest,
            outpoint(),
            output(1_000, 1),
            vec![output(600, 2), output(300, 3)],
            100,
        )
    }

    #[test]
    fn normal_template_is_exact_v2_and_round_trips_logically() -> Result<(), BitcoinBackendError> {
        let template = template()?;
        assert_eq!(
            template.transaction().version,
            bitcoin::transaction::Version::TWO
        );
        assert_eq!(
            template.transaction().lock_time,
            bitcoin::absolute::LockTime::ZERO
        );
        assert_eq!(template.transaction().input.len(), 1);
        assert_eq!(
            template.transaction().input[0].sequence,
            bitcoin::Sequence::MAX
        );
        assert!(template.transaction().input[0].witness.is_empty());

        let logical = template.to_logical_transaction();
        assert_eq!(
            verify_logical_transaction(&logical, template.parent_output())?,
            *template.transaction()
        );
        assert_eq!(logical.txid, template.txid());
        Ok(())
    }

    #[test]
    fn runtime_witness_never_changes_txid() -> Result<(), BitcoinBackendError> {
        let template = template()?;
        let txid = template.transaction().compute_txid();
        let witnessed = template.with_witness(Witness::from_slice(&[b"runtime data"]))?;
        assert_eq!(witnessed.compute_txid(), txid);
        assert_ne!(
            witnessed.compute_wtxid().to_byte_array(),
            txid.to_byte_array()
        );
        Ok(())
    }

    #[test]
    fn timeout_uses_exact_block_csv() -> Result<(), BitcoinBackendError> {
        let template = TransactionTemplate::timeout(
            Network::Regtest,
            outpoint(),
            output(1_000, 1),
            vec![output(900, 2)],
            100,
            144,
        )?;
        assert_eq!(
            template.transaction().input[0].sequence,
            bitcoin::Sequence::from_height(144)
        );
        Ok(())
    }

    #[test]
    fn outpoint_codec_is_exact_and_strict() -> Result<(), BitcoinBackendError> {
        let bytes = outpoint_consensus_bytes(outpoint());
        assert_eq!(bytes.len(), 36);
        assert_eq!(outpoint_from_consensus_bytes(bytes)?, outpoint());
        Ok(())
    }

    #[test]
    fn mainnet_and_invalid_amounts_fail_closed() {
        assert_eq!(
            ensure_non_mainnet(Network::Bitcoin),
            Err(BitcoinBackendError::MainnetDisabled)
        );
        assert_eq!(ensure_non_mainnet(Network::Regtest), Ok(()));
        assert_eq!(
            TransactionTemplate::normal(
                Network::Bitcoin,
                outpoint(),
                output(1_000, 1),
                vec![output(900, 2)],
                100,
            ),
            Err(BitcoinBackendError::MainnetDisabled)
        );
        assert_eq!(
            TransactionTemplate::normal(
                Network::Regtest,
                outpoint(),
                output(1_000, 1),
                vec![output(901, 2)],
                100,
            ),
            Err(BitcoinBackendError::InvalidTransactionAmount)
        );
    }

    #[test]
    fn genesis_id_mapping_is_exact_and_keeps_mainnet_policy_separate()
    -> Result<(), BitcoinBackendError> {
        for network in [Network::Bitcoin, Network::Testnet, Network::Regtest] {
            let block_hash = genesis_block(network).block_hash();
            let genesis_id = block_hash.to_byte_array();
            assert_eq!(serialize(&block_hash), genesis_id);
            assert_eq!(network_from_genesis_id(genesis_id), Ok(network));
        }

        let mainnet_id = genesis_block(Network::Bitcoin).block_hash().to_byte_array();
        assert_eq!(
            ensure_non_mainnet(network_from_genesis_id(mainnet_id)?),
            Err(BitcoinBackendError::MainnetDisabled)
        );

        let raw_signet_id = genesis_block(Network::Signet).block_hash().to_byte_array();
        assert_eq!(
            network_from_genesis_id(raw_signet_id),
            Err(BitcoinBackendError::UnknownNetworkGenesis)
        );

        let mut reversed = genesis_block(Network::Signet).block_hash().to_byte_array();
        reversed.reverse();
        assert_eq!(
            network_from_genesis_id(reversed),
            Err(BitcoinBackendError::UnknownNetworkGenesis)
        );
        assert_eq!(
            network_from_genesis_id([0x42; 32]),
            Err(BitcoinBackendError::UnknownNetworkGenesis)
        );
        assert_eq!(
            network_from_genesis_id(
                genesis_block(Network::Testnet4)
                    .block_hash()
                    .to_byte_array()
            ),
            Err(BitcoinBackendError::UnknownNetworkGenesis)
        );
        Ok(())
    }

    #[test]
    fn custom_signet_id_commits_to_the_complete_challenge() {
        let raw_signet_id = genesis_block(Network::Signet).block_hash().to_byte_array();
        let challenge = ScriptBuf::from_bytes(vec![0x51, 0x21, 0x02, 0x7a, 0x51, 0xae]);
        let challenge_id = custom_signet_network_id(challenge.as_script());
        assert_ne!(challenge_id, raw_signet_id);

        let mut substituted = challenge.into_bytes();
        substituted[3] ^= 1;
        let substituted_id =
            custom_signet_network_id(ScriptBuf::from_bytes(substituted).as_script());
        assert_ne!(substituted_id, challenge_id);
    }

    #[test]
    fn configured_network_identity_accepts_any_challenge_bound_signet() {
        let alternate = custom_signet_network_id(ScriptBuf::from_bytes(vec![0x51]).as_script());
        assert_eq!(
            validate_network_identity(alternate, Network::Signet),
            Ok(())
        );
        assert_eq!(
            validate_network_identity(
                genesis_block(Network::Bitcoin).block_hash().to_byte_array(),
                Network::Bitcoin,
            ),
            Ok(())
        );
        assert_eq!(
            validate_network_identity(
                genesis_block(Network::Regtest).block_hash().to_byte_array(),
                Network::Signet,
            ),
            Err(BitcoinBackendError::NetworkIdentityMismatch)
        );
        assert_eq!(
            validate_network_identity(
                genesis_block(Network::Signet).block_hash().to_byte_array(),
                Network::Signet,
            ),
            Err(BitcoinBackendError::UnknownNetworkGenesis)
        );
        assert_eq!(
            validate_network_identity(alternate, Network::Regtest),
            Err(BitcoinBackendError::NetworkIdentityMismatch)
        );
    }

    #[test]
    fn duplicated_logical_fields_cannot_disagree_with_bytes() -> Result<(), BitcoinBackendError> {
        let template = template()?;
        let mut logical = template.to_logical_transaction();
        logical.txid[0] ^= 1;
        assert!(matches!(
            verify_logical_transaction(&logical, template.parent_output()),
            Err(BitcoinBackendError::InvalidTransactionTemplate { .. })
        ));
        Ok(())
    }

    #[test]
    fn null_parents_and_unsupported_sequences_fail_closed() -> Result<(), BitcoinBackendError> {
        assert!(matches!(
            TransactionTemplate::normal(
                Network::Regtest,
                OutPoint::null(),
                output(1_000, 1),
                vec![output(900, 2)],
                100,
            ),
            Err(BitcoinBackendError::InvalidTransactionTemplate { .. })
        ));

        let template = template()?;
        for sequence in [
            bitcoin::Sequence::ZERO,
            bitcoin::Sequence::from_consensus((1 << 22) | 1),
        ] {
            let mut transaction = template.transaction().clone();
            transaction.input[0].sequence = sequence;
            let mut logical = template.to_logical_transaction();
            logical.sequence = sequence.to_consensus_u32();
            logical.txid = transaction.compute_txid().to_byte_array();
            logical.non_witness_serialization = serialize(&transaction);
            assert!(matches!(
                verify_logical_transaction(&logical, template.parent_output()),
                Err(BitcoinBackendError::InvalidTransactionTemplate { .. })
            ));
        }
        Ok(())
    }
}
