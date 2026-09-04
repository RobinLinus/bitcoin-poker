//! Backend-neutral BP52 client orchestration.
//!
//! This crate understands neither HTTP nor JSON-RPC. It cross-checks raw
//! observations from a [`bp52_client_ports::ChainReader`] and emits facts that
//! the chain protocol runtime can validate against its compiled graph.

#![forbid(unsafe_code)]

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, Txid};
use bp52_client_ports::{
    BlockRef, ChainProfile, ChainReader, ConfirmedSpend, OutPointRef, OutpointStatus,
    RawTransaction, TipObservation, TransactionStatus, UtxoConfirmation, VerifiedChainIdentity,
};

/// Result of polling a watched origin or gameplay outpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutpointObservation {
    /// Backend does not yet know the creating transaction/output.
    Unknown,
    /// Creating transaction is known but not yet confirmed.
    CreatingTransactionUnconfirmed,
    /// Exact output is confirmed and currently unspent.
    ConfirmedUnspent(UtxoConfirmation),
    /// A spending transaction is in the mempool.
    MempoolSpend {
        /// Consensus-order spending transaction identifier.
        txid: [u8; 32],
    },
    /// A complete witness-bearing spend is confirmed.
    ConfirmedSpend(ConfirmedSpend),
}

/// Chain follower bound to one verified profile and continuously checked tip.
#[derive(Clone, Debug)]
pub struct ChainFollower {
    profile: ChainProfile,
    identity: VerifiedChainIdentity,
    last_tip: BlockRef,
    halted: bool,
}

impl ChainFollower {
    /// Authenticate a reader against the expected profile.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend failure or profile mismatch.
    pub fn connect<R: ChainReader>(
        reader: &mut R,
        profile: ChainProfile,
    ) -> Result<Self, ClientError> {
        let identity = reader
            .verify_chain_identity(&profile)
            .map_err(|_| ClientError::Backend)?;
        if identity.profile_id() != profile.profile_id()
            || identity.genesis_hash() != profile.genesis_hash()
            || identity.matched_checkpoint() != profile.checkpoint()
            || identity.is_mainnet() != profile.is_mainnet()
        {
            return Err(ClientError::ChainIdentityMismatch);
        }
        let last_tip = identity.checked_tip();
        Ok(Self {
            profile,
            identity,
            last_tip,
            halted: false,
        })
    }

    /// Exact verified adapter identity.
    #[must_use]
    pub const fn identity(&self) -> &VerifiedChainIdentity {
        &self.identity
    }

    /// Most recently cross-checked best-chain tip.
    #[must_use]
    pub const fn last_tip(&self) -> BlockRef {
        self.last_tip
    }

    /// Whether a chain inconsistency permanently halted this follower.
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        self.halted
    }

    /// Refresh and cross-check the best-chain tip.
    ///
    /// A higher tip is accepted only if the prior tip's block remains at its
    /// original height. Same-height hash changes and height regressions halt
    /// the follower.
    ///
    /// # Errors
    ///
    /// Returns backend failure, profile mismatch, or detected reorganization.
    pub fn refresh_tip<R: ChainReader>(
        &mut self,
        reader: &mut R,
    ) -> Result<TipObservation, ClientError> {
        self.ensure_live()?;
        self.recheck_checkpoint(reader)?;
        let observed = reader
            .tip(&self.identity)
            .map_err(|_| ClientError::Backend)?;
        if observed.profile_id != self.profile.profile_id() {
            return self.halt(ClientError::ChainIdentityMismatch);
        }
        let observed_hash = reader
            .block_hash(&self.identity, observed.block.height)
            .map_err(|_| ClientError::Backend)?;
        if observed_hash != Some(observed.block.hash) {
            return self.halt(ClientError::InvalidObservation);
        }
        if observed.block.height < self.last_tip.height
            || (observed.block.height == self.last_tip.height
                && observed.block.hash != self.last_tip.hash)
        {
            return self.halt(ClientError::ReorgDetected);
        }
        if observed.block.height > self.last_tip.height {
            let prior_hash = reader
                .block_hash(&self.identity, self.last_tip.height)
                .map_err(|_| ClientError::Backend)?;
            if prior_hash != Some(self.last_tip.hash) {
                return self.halt(ClientError::ReorgDetected);
            }
        }
        self.last_tip = observed.block;
        Ok(observed)
    }

    /// Poll one exact outpoint and recover complete confirmed transactions.
    ///
    /// Returned raw transactions are decoded again, txid-checked, and matched
    /// to the requested output/input before being promoted to a higher-level
    /// observation.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend error or halts on inconsistent raw data,
    /// profile substitution, or reorganization.
    pub fn poll_outpoint<R: ChainReader>(
        &mut self,
        reader: &mut R,
        outpoint: OutPointRef,
    ) -> Result<OutpointObservation, ClientError> {
        self.refresh_tip(reader)?;
        let status = reader
            .outpoint_status(&self.identity, outpoint)
            .map_err(|_| ClientError::Backend)?;
        match status {
            OutpointStatus::Unknown => Ok(OutpointObservation::Unknown),
            OutpointStatus::Unspent { creating_status } => {
                self.promote_unspent(reader, outpoint, creating_status)
            }
            OutpointStatus::Spent {
                spending_txid,
                vin,
                status,
            } => self.promote_spend(reader, outpoint, spending_txid, vin, status),
        }
    }

    fn promote_unspent<R: ChainReader>(
        &mut self,
        reader: &mut R,
        outpoint: OutPointRef,
        status: TransactionStatus,
    ) -> Result<OutpointObservation, ClientError> {
        let block = match status {
            TransactionStatus::Unknown => return Ok(OutpointObservation::Unknown),
            TransactionStatus::Mempool => None,
            TransactionStatus::Confirmed { block } => {
                self.ensure_confirmation_is_current(reader, block)?;
                Some(block)
            }
        };
        let (raw, transaction) = self.recover_transaction(reader, outpoint.txid)?;
        let Ok(output_index) = usize::try_from(outpoint.vout) else {
            return self.halt(ClientError::InvalidObservation);
        };
        let Some(output) = transaction.output.get(output_index) else {
            return self.halt(ClientError::InvalidObservation);
        };
        let Some(confirmed_in) = block else {
            return Ok(OutpointObservation::CreatingTransactionUnconfirmed);
        };
        Ok(OutpointObservation::ConfirmedUnspent(UtxoConfirmation {
            profile_id: self.profile.profile_id(),
            outpoint,
            output_value_sat: output.value.to_sat(),
            script_pubkey: output.script_pubkey.as_bytes().to_vec(),
            creating_transaction: raw,
            confirmed_in,
        }))
    }

    fn promote_spend<R: ChainReader>(
        &mut self,
        reader: &mut R,
        outpoint: OutPointRef,
        spending_txid: [u8; 32],
        vin: u32,
        status: TransactionStatus,
    ) -> Result<OutpointObservation, ClientError> {
        let block = match status {
            TransactionStatus::Unknown => return self.halt(ClientError::InvalidObservation),
            TransactionStatus::Mempool => None,
            TransactionStatus::Confirmed { block } => {
                self.ensure_confirmation_is_current(reader, block)?;
                Some(block)
            }
        };
        let (raw, transaction) = self.recover_transaction(reader, spending_txid)?;
        let Ok(input_index) = usize::try_from(vin) else {
            return self.halt(ClientError::InvalidObservation);
        };
        let Some(input) = transaction.input.get(input_index) else {
            return self.halt(ClientError::InvalidObservation);
        };
        let expected = OutPoint {
            txid: Txid::from_byte_array(outpoint.txid),
            vout: outpoint.vout,
        };
        if input.previous_output != expected {
            return self.halt(ClientError::InvalidObservation);
        }
        let Some(confirmed_in) = block else {
            return Ok(OutpointObservation::MempoolSpend {
                txid: spending_txid,
            });
        };
        Ok(OutpointObservation::ConfirmedSpend(ConfirmedSpend {
            profile_id: self.profile.profile_id(),
            spent_outpoint: outpoint,
            spending_transaction: raw,
            input_index: vin,
            confirmed_in,
        }))
    }

    fn recover_transaction<R: ChainReader>(
        &mut self,
        reader: &mut R,
        txid: [u8; 32],
    ) -> Result<(RawTransaction, Transaction), ClientError> {
        let raw = match self.required_raw_transaction(reader, txid) {
            Ok(raw) => raw,
            Err(ClientError::Backend) => return Err(ClientError::Backend),
            Err(error) => return self.halt(error),
        };
        let transaction = match decode_checked_transaction(&raw) {
            Ok(transaction) => transaction,
            Err(error) => return self.halt(error),
        };
        Ok((raw, transaction))
    }

    fn required_raw_transaction<R: ChainReader>(
        &mut self,
        reader: &mut R,
        txid: [u8; 32],
    ) -> Result<RawTransaction, ClientError> {
        reader
            .raw_transaction(&self.identity, txid)
            .map_err(|_| ClientError::Backend)?
            .ok_or(ClientError::MissingRawTransaction)
    }

    fn ensure_confirmation_is_current<R: ChainReader>(
        &mut self,
        reader: &mut R,
        block: BlockRef,
    ) -> Result<(), ClientError> {
        if block.height > self.last_tip.height {
            return self.halt(ClientError::InvalidObservation);
        }
        let current = reader
            .block_hash(&self.identity, block.height)
            .map_err(|_| ClientError::Backend)?;
        if current != Some(block.hash) {
            return self.halt(ClientError::ReorgDetected);
        }
        Ok(())
    }

    fn recheck_checkpoint<R: ChainReader>(&mut self, reader: &mut R) -> Result<(), ClientError> {
        if let Some(checkpoint) = self.profile.checkpoint() {
            let current = reader
                .block_hash(&self.identity, checkpoint.height)
                .map_err(|_| ClientError::Backend)?;
            if current != Some(checkpoint.hash) {
                return self.halt(ClientError::ChainIdentityMismatch);
            }
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), ClientError> {
        if self.halted {
            Err(ClientError::Halted)
        } else {
            Ok(())
        }
    }

    fn halt<T>(&mut self, error: ClientError) -> Result<T, ClientError> {
        self.halted = true;
        Err(error)
    }
}

fn decode_checked_transaction(raw: &RawTransaction) -> Result<Transaction, ClientError> {
    let transaction: Transaction =
        deserialize(raw.consensus()).map_err(|_| ClientError::InvalidObservation)?;
    if transaction.compute_txid().to_byte_array() != raw.txid() {
        return Err(ClientError::InvalidObservation);
    }
    Ok(transaction)
}

/// Backend-neutral client orchestration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// External service failed; implementation details remain adapter-local.
    #[error("external chain service failed")]
    Backend,
    /// Adapter or observation is bound to another network profile.
    #[error("chain identity mismatch")]
    ChainIdentityMismatch,
    /// A best-chain reorganization invalidated prior observations.
    #[error("best-chain reorganization detected")]
    ReorgDetected,
    /// Outpoint status referenced a transaction that could not be recovered.
    #[error("required raw transaction is unavailable")]
    MissingRawTransaction,
    /// Raw transaction, txid, input, output, or block placement disagreed.
    #[error("chain service returned an inconsistent observation")]
    InvalidObservation,
    /// Follower is fail-stopped after an earlier chain inconsistency.
    #[error("chain follower is halted")]
    Halted,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::absolute;
    use bitcoin::consensus::serialize;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use bp52_client_ports::{PortError, TipObservation};

    use super::*;

    struct FakeReader {
        profile: ChainProfile,
        tip: BlockRef,
        blocks: BTreeMap<u32, [u8; 32]>,
        transactions: BTreeMap<[u8; 32], RawTransaction>,
        outpoint_status: OutpointStatus,
    }

    impl ChainReader for FakeReader {
        type Error = PortError;

        fn verify_chain_identity(
            &mut self,
            expected: &ChainProfile,
        ) -> Result<VerifiedChainIdentity, Self::Error> {
            let checkpoint = expected.checkpoint();
            expected.verify_observations(expected.genesis_hash(), checkpoint, self.tip)
        }

        fn tip(&mut self, _chain: &VerifiedChainIdentity) -> Result<TipObservation, Self::Error> {
            Ok(TipObservation {
                profile_id: self.profile.profile_id(),
                block: self.tip,
            })
        }

        fn block_hash(
            &mut self,
            _chain: &VerifiedChainIdentity,
            height: u32,
        ) -> Result<Option<[u8; 32]>, Self::Error> {
            Ok(self.blocks.get(&height).copied())
        }

        fn raw_transaction(
            &mut self,
            _chain: &VerifiedChainIdentity,
            txid: [u8; 32],
        ) -> Result<Option<RawTransaction>, Self::Error> {
            Ok(self.transactions.get(&txid).cloned())
        }

        fn transaction_status(
            &mut self,
            _chain: &VerifiedChainIdentity,
            _txid: [u8; 32],
        ) -> Result<TransactionStatus, Self::Error> {
            Ok(TransactionStatus::Unknown)
        }

        fn outpoint_status(
            &mut self,
            _chain: &VerifiedChainIdentity,
            _outpoint: OutPointRef,
        ) -> Result<OutpointStatus, Self::Error> {
            Ok(self.outpoint_status)
        }
    }

    fn profile() -> Result<ChainProfile, PortError> {
        ChainProfile::custom_signet(
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet)
                .block_hash()
                .to_byte_array(),
            vec![0x51],
            Some(BlockRef {
                height: 10,
                hash: [10; 32],
            }),
        )
    }

    fn reader(profile: ChainProfile) -> FakeReader {
        FakeReader {
            profile,
            tip: BlockRef {
                height: 20,
                hash: [20; 32],
            },
            blocks: BTreeMap::from([(10, [10; 32]), (20, [20; 32])]),
            transactions: BTreeMap::new(),
            outpoint_status: OutpointStatus::Unknown,
        }
    }

    #[test]
    fn higher_tip_must_retain_prior_tip() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile()?;
        let mut reader = reader(profile.clone());
        let mut follower = ChainFollower::connect(&mut reader, profile)?;
        reader.tip = BlockRef {
            height: 21,
            hash: [21; 32],
        };
        reader.blocks.insert(21, [21; 32]);
        assert_eq!(follower.refresh_tip(&mut reader)?.block.height, 21);

        reader.tip = BlockRef {
            height: 22,
            hash: [22; 32],
        };
        reader.blocks.insert(22, [22; 32]);
        reader.blocks.insert(21, [99; 32]);
        assert_eq!(
            follower.refresh_tip(&mut reader),
            Err(ClientError::ReorgDetected)
        );
        assert!(follower.is_halted());
        Ok(())
    }

    #[test]
    fn reported_tip_must_match_block_at_height() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile()?;
        let mut reader = reader(profile.clone());
        let mut follower = ChainFollower::connect(&mut reader, profile)?;
        reader.tip = BlockRef {
            height: 21,
            hash: [21; 32],
        };
        reader.blocks.insert(21, [99; 32]);
        assert_eq!(
            follower.refresh_tip(&mut reader),
            Err(ClientError::InvalidObservation)
        );
        assert!(follower.is_halted());
        Ok(())
    }

    #[test]
    fn confirmed_spend_is_recovered_from_raw_transaction() -> Result<(), Box<dyn std::error::Error>>
    {
        let profile = profile()?;
        let mut reader = reader(profile.clone());
        let parent_txid = Txid::from_byte_array([30; 32]);
        let parent = OutPointRef {
            txid: parent_txid.to_byte_array(),
            vout: 1,
        };
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txid = transaction.compute_txid().to_byte_array();
        reader
            .transactions
            .insert(txid, RawTransaction::new(txid, serialize(&transaction))?);
        reader.outpoint_status = OutpointStatus::Spent {
            spending_txid: txid,
            vin: 0,
            status: TransactionStatus::Confirmed { block: reader.tip },
        };
        let mut follower = ChainFollower::connect(&mut reader, profile)?;
        let observation = follower.poll_outpoint(&mut reader, parent)?;
        assert!(matches!(
            observation,
            OutpointObservation::ConfirmedSpend(ConfirmedSpend {
                spent_outpoint,
                input_index: 0,
                ..
            }) if spent_outpoint == parent
        ));
        Ok(())
    }

    #[test]
    fn substituted_spending_input_halts() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile()?;
        let mut reader = reader(profile.clone());
        let watched = OutPointRef {
            txid: [30; 32],
            vout: 1,
        };
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: Vec::new(),
        };
        let txid = transaction.compute_txid().to_byte_array();
        reader
            .transactions
            .insert(txid, RawTransaction::new(txid, serialize(&transaction))?);
        reader.outpoint_status = OutpointStatus::Spent {
            spending_txid: txid,
            vin: 0,
            status: TransactionStatus::Confirmed { block: reader.tip },
        };
        let mut follower = ChainFollower::connect(&mut reader, profile)?;
        assert_eq!(
            follower.poll_outpoint(&mut reader, watched),
            Err(ClientError::InvalidObservation)
        );
        assert!(follower.is_halted());
        Ok(())
    }

    #[test]
    fn missing_confirmed_transaction_halts() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile()?;
        let mut reader = reader(profile.clone());
        let watched = OutPointRef {
            txid: [40; 32],
            vout: 0,
        };
        reader.outpoint_status = OutpointStatus::Unspent {
            creating_status: TransactionStatus::Confirmed { block: reader.tip },
        };
        let mut follower = ChainFollower::connect(&mut reader, profile)?;
        assert_eq!(
            follower.poll_outpoint(&mut reader, watched),
            Err(ClientError::MissingRawTransaction)
        );
        assert!(follower.is_halted());
        Ok(())
    }

    #[test]
    fn substituted_mempool_spend_halts() -> Result<(), Box<dyn std::error::Error>> {
        let profile = profile()?;
        let mut reader = reader(profile.clone());
        let watched = OutPointRef {
            txid: [41; 32],
            vout: 0,
        };
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: Vec::new(),
        };
        let txid = transaction.compute_txid().to_byte_array();
        reader
            .transactions
            .insert(txid, RawTransaction::new(txid, serialize(&transaction))?);
        reader.outpoint_status = OutpointStatus::Spent {
            spending_txid: txid,
            vin: 0,
            status: TransactionStatus::Mempool,
        };
        let mut follower = ChainFollower::connect(&mut reader, profile)?;
        assert_eq!(
            follower.poll_outpoint(&mut reader, watched),
            Err(ClientError::InvalidObservation)
        );
        assert!(follower.is_halted());
        Ok(())
    }
}
