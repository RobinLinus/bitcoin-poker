//! Worker receipts authenticate verification under a fresh, locally delegated key.
//! A peer never receives this key. Local checkpoint keys must be protected separately
//! from checkpoint bytes; unauthenticated imports still require full verification.
use super::{Artifact, SettlementPreparation, invalid, number, take};
use crate::{CompilerError, settlement::AuthorizationRequest};
use bitcoin::secp256k1::{Message, Secp256k1, VerifyOnly, XOnlyPublicKey, schnorr::Signature};
use bitcoin::{
    Network, Transaction, TxOut,
    consensus::{deserialize, serialize},
};
use dealer_bitcoin::reveal::{REVEAL_PACKAGE_BYTES, RevealContext, VerifiedRevealPackage};
use dealer_codec::Reader;
use hmac::{Hmac, Mac};
use poker_bitcoin::{DefaultSighashSignature, TransactionTemplate};
use poker_settlement_types::Role;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroizing;

const MAX_INVENTORY: usize = 100_000;
const MAX_BATCH: usize = 256 * 1024;
const RECEIPT: &[u8] = b"POKER/verification-batch/v1";
const CHECKPOINT: &[u8] = b"POKER/local-checkpoint/v1";

fn put_len(out: &mut Vec<u8>, length: usize) -> Result<(), CompilerError> {
    out.extend(u32::try_from(length).map_err(|_| invalid())?.to_le_bytes());
    Ok(())
}
fn frame(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CompilerError> {
    put_len(out, bytes.len())?;
    out.extend(bytes);
    Ok(())
}
fn read_frame<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], CompilerError> {
    let length = number(input)?;
    take(input, length)
}
fn array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], CompilerError> {
    take(input, N)?.try_into().map_err(|_| invalid())
}
fn role(input: &mut &[u8]) -> Result<Role, CompilerError> {
    match take(input, 1)?[0] {
        0 => Ok(Role::Alice),
        1 => Ok(Role::Bob),
        _ => Err(invalid()),
    }
}
fn mac(
    key: &[u8; 32],
    domain: &[u8],
    binding: &[u8],
    bytes: &[u8],
) -> Result<Hmac<Sha256>, CompilerError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| invalid())?;
    mac.update(domain);
    mac.update(binding);
    mac.update(bytes);
    Ok(mac)
}
fn entries(bytes: &[u8], count: usize) -> Result<Vec<(usize, &[u8])>, CompilerError> {
    let mut input = bytes;
    let mut previous = None;
    let mut result = Vec::new();
    while !input.is_empty() {
        let index = number(&mut input)?;
        if index >= count || previous.is_some_and(|p| index <= p) {
            return Err(invalid());
        }
        let data = read_frame(&mut input)?;
        if data.len() > REVEAL_PACKAGE_BYTES {
            return Err(invalid());
        }
        result.push((index, data));
        previous = Some(index);
    }
    if result.is_empty() {
        return Err(invalid());
    }
    Ok(result)
}

impl SettlementPreparation {
    /// Canonical public work description for local workers. This contains no secrets.
    ///
    /// # Errors
    /// Rejects oversized inventories.
    pub fn encode_inventory(&self) -> Result<Vec<u8>, CompilerError> {
        let delayed = self.activation.transaction().input[0].sequence != bitcoin::Sequence::MAX;
        let mut out = if delayed { b"PSTRINV2".to_vec() } else { b"PSTRINV1".to_vec() };
        frame(&mut out, &serialize(self.activation.transaction()))?;
        frame(&mut out, &serialize(self.activation.parent_output()))?;
        out.extend(self.activation.fee_sat().to_le_bytes());
        out.extend(self.identities.concat());
        put_len(&mut out, self.requests.len())?;
        for request in &self.requests {
            match request {
                AuthorizationRequest::Signature {
                    node_id,
                    edge_index,
                    signer,
                    sighash,
                } => {
                    out.push(0);
                    out.extend(node_id);
                    put_len(&mut out, *edge_index)?;
                    out.push(signer.code());
                    out.extend(sighash);
                }
                AuthorizationRequest::Reveal(c) => {
                    out.push(1);
                    out.extend(c.deal_id);
                    out.extend(c.graph_id);
                    out.extend(c.node_id);
                    out.extend([c.revealer, c.slot]);
                    out.extend(c.authorizer);
                    out.extend(c.sighash);
                    dealer_group::encode_point(&c.commitment, &mut out);
                }
            }
        }
        Ok(out)
    }
    /// Decode a local worker's public inventory with an empty artifact set.
    /// The owner must compare its digest with its independently derived inventory.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical descriptions; this does not verify a peer's graph.
    pub fn from_inventory(bytes: &[u8], network: Network) -> Result<Self, CompilerError> {
        let mut input = bytes;
        let magic = take(&mut input, 8)?;
        if magic != b"PSTRINV1" && magic != b"PSTRINV2" {
            return Err(invalid());
        }
        let tx: Transaction = deserialize(read_frame(&mut input)?).map_err(|_| invalid())?;
        let parent: TxOut = deserialize(read_frame(&mut input)?).map_err(|_| invalid())?;
        let fee = u64::from_le_bytes(array(&mut input)?);
        if tx.input.len() != 1 {
            return Err(invalid());
        }
        let activation = if magic == b"PSTRINV2" {
            let csv = u16::try_from(tx.input[0].sequence.to_consensus_u32()).map_err(|_| invalid())?;
            TransactionTemplate::timeout(network, tx.input[0].previous_output, parent, tx.output.clone(), fee, csv)?
        } else { TransactionTemplate::normal(
            network,
            tx.input[0].previous_output,
            parent,
            tx.output.clone(),
            fee,
        )? };
        if activation.transaction() != &tx {
            return Err(invalid());
        }
        let identities = [array(&mut input)?, array(&mut input)?];
        for key in identities {
            XOnlyPublicKey::from_slice(&key).map_err(|_| invalid())?;
        }
        let count = number(&mut input)?;
        if count == 0 || count > MAX_INVENTORY || count > input.len() {
            return Err(invalid());
        }
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            requests.push(match take(&mut input, 1)?[0] {
                0 => AuthorizationRequest::Signature {
                    node_id: array(&mut input)?,
                    edge_index: number(&mut input)?,
                    signer: role(&mut input)?,
                    sighash: array(&mut input)?,
                },
                1 => {
                    let deal_id = array(&mut input)?;
                    let graph_id = array(&mut input)?;
                    let node_id = array(&mut input)?;
                    let revealer = role(&mut input)?.code();
                    let slot = take(&mut input, 1)?[0];
                    if slot > 8 {
                        return Err(invalid());
                    }
                    let authorizer = array(&mut input)?;
                    let sighash = array(&mut input)?;
                    let commitment =
                        dealer_group::decode_point(&mut Reader::new(take(&mut input, 33)?), false)
                            .map_err(|_| invalid())?;
                    AuthorizationRequest::Reveal(Box::new(RevealContext {
                        deal_id,
                        graph_id,
                        node_id,
                        revealer,
                        slot,
                        authorizer,
                        sighash,
                        commitment,
                    }))
                }
                _ => return Err(invalid()),
            });
        }
        if !input.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            activation,
            identities,
            requests,
            artifacts: (0..count).map(|_| None).collect(),
            inventory_hash: OnceLock::new(),
        })
    }
    /// Digest binding each worker receipt to the exact local inventory.
    ///
    /// # Errors
    /// Rejects oversized inventory encodings.
    pub fn inventory_binding(&self) -> Result<[u8; 32], CompilerError> {
        if let Some(binding) = self.inventory_hash.get() {
            return Ok(*binding);
        }
        let binding = Sha256::digest(self.encode_inventory()?).into();
        let _ = self.inventory_hash.set(binding);
        Ok(binding)
    }
    /// Install a batch verified by a locally delegated worker, without redoing crypto.
    /// The fresh session key must never be shared with the counterparty.
    ///
    /// # Errors
    /// Rejects wrong keys, bindings, malformed batches, and conflicting duplicates atomically.
    pub fn accept_verified_batch(
        &mut self,
        key: &[u8; 32],
        receipt: &[u8],
    ) -> Result<(), CompilerError> {
        if receipt.len() < 32 || receipt.len() > MAX_BATCH + 32 {
            return Err(invalid());
        }
        let (payload, tag) = receipt.split_at(receipt.len() - 32);
        mac(key, RECEIPT, &self.inventory_binding()?, payload)?
            .verify_slice(tag)
            .map_err(|_| invalid())?;
        self.install_authenticated(payload)
    }
    fn install_authenticated(&mut self, payload: &[u8]) -> Result<(), CompilerError> {
        let mut pending = Vec::new();
        for (index, bytes) in entries(payload, self.requests.len())? {
            if let Some(existing) = &self.artifacts[index] {
                if super::artifact_bytes(existing) != bytes {
                    return Err(invalid());
                }
                continue;
            }
            let artifact = match &self.requests[index] {
                AuthorizationRequest::Signature { .. } => {
                    Artifact::Signature(DefaultSighashSignature::from_slice(bytes)?)
                }
                AuthorizationRequest::Reveal(_) => {
                    if bytes.len() != REVEAL_PACKAGE_BYTES {
                        return Err(invalid());
                    }
                    Artifact::Reveal {
                        bytes: bytes.to_vec(),
                        decoded: OnceLock::new(),
                    }
                }
            };
            pending.push((index, artifact));
        }
        for (index, artifact) in pending {
            self.artifacts[index] = Some(artifact);
        }
        Ok(())
    }
    /// Seal a complete, verified local checkpoint. Protect the key independently.
    ///
    /// # Errors
    /// Rejects incomplete preparation or oversized encodings.
    pub fn seal_checkpoint(&self, key: &[u8; 32]) -> Result<Vec<u8>, CompilerError> {
        if self.missing_count() != 0 {
            return Err(invalid());
        }
        self.seal_progress_checkpoint(key)
    }
    /// Persist verified progress without granting activation readiness.
    pub fn seal_progress_checkpoint(&self, key: &[u8;32]) -> Result<Vec<u8>, CompilerError> {
        let mut out = b"PSTRCP01".to_vec();
        frame(&mut out, &self.encode_inventory()?)?;
        frame(&mut out, &self.encode_snapshot()?)?;
        let tag = mac(key, CHECKPOINT, &[], &out)?.finalize().into_bytes();
        out.extend(tag);
        Ok(out)
    }
    /// Restore a checkpoint created by this trusted local key, preserving its verification.
    /// Chain freshness and one-time-key usage must still be reconciled by the application.
    ///
    /// # Errors
    /// Rejects unauthenticated, incompatible, incomplete or malformed checkpoints.
    pub fn open_checkpoint(
        key: &[u8; 32],
        bytes: &[u8],
        network: Network,
    ) -> Result<Self, CompilerError> {
        let preparation = Self::open_progress_checkpoint(key, bytes, network)?;
        if preparation.missing_count() != 0 { return Err(invalid()); }
        Ok(preparation)
    }
    /// Restore authenticated progress; callers must still enforce completeness.
    pub fn open_progress_checkpoint(key: &[u8;32], bytes: &[u8], network: Network) -> Result<Self, CompilerError> {
        if bytes.len() < 40 {
            return Err(invalid());
        }
        let (payload, tag) = bytes.split_at(bytes.len() - 32);
        mac(key, CHECKPOINT, &[], payload)?
            .verify_slice(tag)
            .map_err(|_| invalid())?;
        let mut input = payload;
        if take(&mut input, 8)? != b"PSTRCP01" {
            return Err(invalid());
        }
        let mut preparation = Self::from_inventory(read_frame(&mut input)?, network)?;
        let mut snapshot = read_frame(&mut input)?;
        if !input.is_empty()
            || take(&mut snapshot, 8)? != b"DL52PRE1"
            || read_frame(&mut snapshot)? != serialize(preparation.activation.transaction())
        {
            return Err(invalid());
        }
        if !snapshot.is_empty() { preparation.install_authenticated(snapshot)?; }
        Ok(preparation)
    }
    /// Export canonical indexed responses from a public snapshot for parallel import verification.
    ///
    /// # Errors
    /// Rejects a wrong activation or malformed snapshot.
    pub fn snapshot_entries<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u8], CompilerError> {
        let mut input = bytes;
        if take(&mut input, 8)? != b"DL52PRE1"
            || read_frame(&mut input)? != serialize(self.activation.transaction())
        {
            return Err(invalid());
        }
        entries(input, self.requests.len())?;
        Ok(input)
    }
}

/// A verifier with a local receipt key and an immutable inventory.
pub struct BatchVerifier {
    preparation: SettlementPreparation,
    key: Zeroizing<[u8; 32]>,
    binding: [u8; 32],
    secp: Secp256k1<VerifyOnly>,
    identities: [XOnlyPublicKey; 2],
}
impl BatchVerifier {
    /// Delegate this exact inventory under a fresh local session key.
    ///
    /// # Errors
    /// Rejects malformed identities/inventories.
    pub fn new(preparation: SettlementPreparation, key: [u8; 32]) -> Result<Self, CompilerError> {
        let identities = [
            XOnlyPublicKey::from_slice(&preparation.identities[0]).map_err(|_| invalid())?,
            XOnlyPublicKey::from_slice(&preparation.identities[1]).map_err(|_| invalid())?,
        ];
        Ok(Self {
            binding: preparation.inventory_binding()?,
            preparation,
            key: Zeroizing::new(key),
            secp: Secp256k1::verification_only(),
            identities,
        })
    }
    /// Public requests assigned by the local owner.
    #[must_use]
    pub fn requests(&self) -> &[AuthorizationRequest] {
        self.preparation.requests()
    }
    /// Verify every indexed response before issuing a receipt; no partial receipts.
    ///
    /// # Errors
    /// Rejects malformed, misbound or cryptographically invalid responses.
    pub fn verify_batch(&self, bytes: &[u8]) -> Result<Vec<u8>, CompilerError> {
        if bytes.len() > MAX_BATCH {
            return Err(invalid());
        }
        for (index, bytes) in entries(bytes, self.requests().len())? {
            match &self.requests()[index] {
                AuthorizationRequest::Signature {
                    signer, sighash, ..
                } => {
                    let signature = Signature::from_slice(bytes).map_err(|_| invalid())?;
                    self.secp
                        .verify_schnorr(
                            &signature,
                            &Message::from_digest(*sighash),
                            &self.identities[usize::from(signer.code())],
                        )
                        .map_err(|_| invalid())?;
                }
                AuthorizationRequest::Reveal(context) => {
                    VerifiedRevealPackage::verify(context.as_ref().clone(), bytes)
                        .map_err(|_| invalid())?;
                }
            }
        }
        self.receipt_for_local_batch(bytes)
    }

    /// Authenticate bytes just generated by a trusted local signing worker.
    /// Never use this for peer input: that must go through `verify_batch`.
    pub fn receipt_for_local_batch(&self, bytes: &[u8]) -> Result<Vec<u8>, CompilerError> {
        if bytes.len() > MAX_BATCH { return Err(invalid()); }
        let mut receipt = bytes.to_vec();
        receipt.extend(
            mac(&self.key, RECEIPT, &self.binding, bytes)?
                .finalize()
                .into_bytes(),
        );
        Ok(receipt)
    }
}
