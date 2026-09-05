//! Activation.

use super::{
    DisplayTxid, FundingError, InputTemplate, OutputTemplate, PlayerFundingInput, SignatureShare,
    SignedTransaction, serialize_transaction, signature_with_sighash_byte, verify_signature,
};

/// Exact two-party transaction that activates the first gameplay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationPackage {
    pub(super) origin_package_id: [u8; 32],
    pub(super) participants: [PlayerFundingInput; 2],
    pub(super) origin_witness_script: Vec<u8>,
    pub(super) gameplay_root_script_pubkey: [u8; 34],
    pub(super) input: InputTemplate,
    pub(super) output: OutputTemplate,
    pub(super) unsigned_transaction: Vec<u8>,
    pub(super) txid: DisplayTxid,
    pub(super) sighash: [u8; 32],
    pub(super) activation_id: [u8; 32],
}

impl ActivationPackage {
    /// Identifier of the origin/refund package this activation spends.
    #[must_use]
    pub const fn origin_package_id(&self) -> [u8; 32] {
        self.origin_package_id
    }

    /// Context- and root-bound activation identifier.
    #[must_use]
    pub const fn activation_id(&self) -> [u8; 32] {
        self.activation_id
    }

    /// Canonical P2TR gameplay-root scriptPubKey.
    #[must_use]
    pub const fn gameplay_root_script_pubkey(&self) -> [u8; 34] {
        self.gameplay_root_script_pubkey
    }

    /// Consensus serialization without witnesses.
    #[must_use]
    pub fn unsigned_transaction_bytes(&self) -> &[u8] {
        &self.unsigned_transaction
    }

    /// Witness-independent activation transaction identifier.
    #[must_use]
    pub const fn txid(&self) -> DisplayTxid {
        self.txid
    }

    /// Shared BIP143 `SIGHASH_ALL` digest signed by both participants.
    #[must_use]
    pub const fn sighash(&self) -> [u8; 32] {
        self.sighash
    }

    /// Verifies a participant's activation signature.
    ///
    /// # Errors
    ///
    /// Rejects an unknown participant or invalid signature.
    pub fn verify_signature(&self, share: SignatureShare) -> Result<(), FundingError> {
        let index = self
            .participants
            .iter()
            .position(|participant| participant.participant_id == share.signer)
            .ok_or(FundingError::UnknownSigner)?;
        verify_signature(
            self.participants[index].compressed_public_key,
            self.sighash,
            share.signature,
        )
    }

    /// Verifies both participants and assembles the complete activation.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, missing, unknown, or invalid signatures and any
    /// internal serialization invariant failure.
    pub fn assemble_signed(
        &self,
        shares: [SignatureShare; 2],
    ) -> Result<SignedTransaction, FundingError> {
        if shares[0].signer == shares[1].signer {
            return Err(FundingError::DuplicateSignature);
        }
        let mut ordered: [Option<SignatureShare>; 2] = [None, None];
        for share in shares {
            let index = self
                .participants
                .iter()
                .position(|participant| participant.participant_id == share.signer)
                .ok_or(FundingError::UnknownSigner)?;
            self.verify_signature(share)?;
            ordered[index] = Some(share);
        }
        let [Some(first), Some(second)] = ordered else {
            return Err(FundingError::MissingSignature);
        };
        let witnesses = [vec![
            signature_with_sighash_byte(second.signature)?,
            signature_with_sighash_byte(first.signature)?,
            self.origin_witness_script.clone(),
        ]];
        Ok(SignedTransaction {
            consensus_bytes: serialize_transaction(
                core::slice::from_ref(&self.input),
                core::slice::from_ref(&self.output),
                Some(&witnesses),
            )?,
            txid: self.txid,
        })
    }
}
