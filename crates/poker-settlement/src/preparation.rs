//! Public preparation snapshots contain no wallet keys or dealing entropy.
//! Restoring a snapshot reconstructs the local inventory and re-verifies every
//! signature and adaptor package. A stored ready flag is never trusted.
/// Authenticated parallel verification and local checkpoint formats.
pub mod batches;
use crate::{
    CompilerError,
    settlement::{AuthorizationRequest, SettlementGraph},
};
use bitcoin::secp256k1::Secp256k1;
use dealer_bitcoin::reveal::VerifiedRevealPackage;
use poker_bitcoin::{DefaultSighashSignature, TransactionTemplate, verify_sighash_default};
use poker_settlement_types::{NodeId, Role};
use std::{collections::HashMap, sync::OnceLock};

fn invalid() -> CompilerError {
    CompilerError::Preparation {
        reason: "malformed or mismatched preparation artifact",
    }
}

enum Artifact {
    Signature(DefaultSighashSignature),
    Reveal {
        bytes: Vec<u8>,
        decoded: OnceLock<Result<Box<VerifiedRevealPackage>, ()>>,
    },
}

/// Exact complete inventory awaiting authenticated counterparty responses.
pub struct SettlementPreparation {
    activation: TransactionTemplate,
    identities: [[u8; 32]; 2],
    requests: Vec<AuthorizationRequest>,
    artifacts: Vec<Option<Artifact>>,
    inventory_hash: OnceLock<[u8; 32]>,
}

impl SettlementPreparation {
    /// Rebind only terminal digests from an authenticated local construction cache.
    /// The caller must first validate unchanged hand, topology and total value.
    pub fn rebind_payouts(graph: &SettlementGraph, activation: TransactionTemplate, previous: Self, cache: &[u8]) -> Result<(Self,usize),CompilerError> {
        let mut requests=previous.requests.clone();
        graph.rebind_payout_requests(&mut requests,cache)?;
        let mut next=Self { activation, identities:graph.identities(),
            artifacts:(0..requests.len()).map(|_|None).collect(),requests,inventory_hash:OnceLock::new() };
        let reused=next.reuse_unchanged(previous)?;
        Ok((next,reused))
    }
    /// Indices still requiring a signature or adaptor package.
    pub fn missing_indices(&self) -> Vec<usize> {
        self.artifacts.iter().enumerate().filter_map(|(i, a)| a.is_none().then_some(i)).collect()
    }

    /// Move verified artifacts only when the complete signing context is identical.
    /// This never copies a signature onto a modified payout digest.
    pub fn reuse_unchanged(&mut self, previous: Self) -> Result<usize, CompilerError> {
        if self.identities != previous.identities || self.activation.transaction() != previous.activation.transaction()
            || self.activation.parent_output() != previous.activation.parent_output()
            || self.requests.len() != previous.requests.len() {
            return Err(invalid());
        }
        let mut reused = 0;
        for (i, (old, artifact)) in previous.requests.iter().zip(previous.artifacts).enumerate() {
            let same = match (&self.requests[i], old) {
                (AuthorizationRequest::Signature {node_id:a,edge_index:b,signer:c,sighash:d},
                 AuthorizationRequest::Signature {node_id:e,edge_index:f,signer:g,sighash:h}) => a==e && b==f && c==g && d==h,
                (AuthorizationRequest::Reveal(a), AuthorizationRequest::Reveal(b)) =>
                    a.deal_id==b.deal_id && a.graph_id==b.graph_id && a.node_id==b.node_id
                    && a.revealer==b.revealer && a.slot==b.slot && a.authorizer==b.authorizer
                    && a.sighash==b.sighash && a.commitment==b.commitment,
                _ => false,
            };
            if same && artifact.is_some() { self.artifacts[i]=artifact; reused+=1; }
        }
        Ok(reused)
    }

    /// Independently derive every request from the agreed graph and activation.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn new(
        graph: &SettlementGraph,
        activation: TransactionTemplate,
    ) -> Result<Self, CompilerError> {
        Self::with_progress(graph, activation, |_| {})
    }

    /// Derive the same inventory while reporting each completed request count.
    /// The callback observes progress only; it cannot alter authorization requests.
    ///
    /// # Errors
    /// Rejects an invalid graph or activation transaction, as [`Self::new`] does.
    pub fn with_progress(
        graph: &SettlementGraph,
        activation: TransactionTemplate,
        mut progress: impl FnMut(usize),
    ) -> Result<Self, CompilerError> {
        let mut requests = Vec::new();
        graph.visit_authorizations(&activation, |request| {
            requests.push(request);
            progress(requests.len());
            Ok(())
        })?;
        let artifacts = (0..requests.len()).map(|_| None).collect();
        Ok(Self {
            activation,
            identities: graph.identities(),
            requests,
            artifacts,
            inventory_hash: OnceLock::new(),
        })
    }

    /// Canonical request order. Responses use this index, never peer metadata.
    #[must_use]
    pub fn requests(&self) -> &[AuthorizationRequest] {
        &self.requests
    }

    /// Number of missing responses; activation requires exactly zero.
    #[must_use]
    pub fn missing_count(&self) -> usize {
        self.artifacts.iter().filter(|a| a.is_none()).count()
    }

    /// Verify a response against its independently derived transaction context.
    /// An exact duplicate is idempotent; conflicting duplicates are rejected.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn accept_response(&mut self, index: usize, bytes: &[u8]) -> Result<(), CompilerError> {
        let request = self.requests.get(index).ok_or(CompilerError::Preparation {
            reason: "response index is outside the request inventory",
        })?;
        if let Some(existing) = &self.artifacts[index] {
            return if artifact_bytes(existing) == bytes {
                Ok(())
            } else {
                Err(CompilerError::Preparation {
                    reason: "conflicting response for an already verified request",
                })
            };
        }
        let artifact = match request {
            AuthorizationRequest::Signature {
                signer, sighash, ..
            } => {
                let signature = DefaultSighashSignature::from_slice(bytes)?;
                verify_sighash_default(
                    &Secp256k1::verification_only(),
                    self.identities[usize::from(signer.code())],
                    *sighash,
                    signature,
                )?;
                Artifact::Signature(signature)
            }
            AuthorizationRequest::Reveal(context) => {
                let package = VerifiedRevealPackage::verify(context.as_ref().clone(), bytes)
                    .map_err(|_| invalid())?;
                Artifact::Reveal {
                    bytes: bytes.to_vec(),
                    decoded: OnceLock::from(Ok(Box::new(package))),
                }
            }
        };
        self.artifacts[index] = Some(artifact);
        Ok(())
    }

    /// Serialize public artifacts with the exact activation transaction binding.
    /// The caller persists this before sending a response or activating funding.
    ///
    /// # Errors
    /// Rejects an inventory that exceeds the canonical u32 encoding bounds.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, CompilerError> {
        let mut bytes = b"DL52PRE1".to_vec();
        let transaction = bitcoin::consensus::serialize(self.activation.transaction());
        bytes.extend(
            u32::try_from(transaction.len())
                .map_err(|_| invalid())?
                .to_le_bytes(),
        );
        bytes.extend(transaction);
        for (index, artifact) in self.artifacts.iter().enumerate() {
            if let Some(artifact) = artifact {
                let response = artifact_bytes(artifact);
                bytes.extend(u32::try_from(index).map_err(|_| invalid())?.to_le_bytes());
                bytes.extend(
                    u32::try_from(response.len())
                        .map_err(|_| invalid())?
                        .to_le_bytes(),
                );
                bytes.extend(response);
            }
        }
        Ok(bytes)
    }

    /// Restore only into a freshly derived inventory for this same activation.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn restore_verified_snapshot(&mut self, bytes: &[u8]) -> Result<(), CompilerError> {
        self.restore_verified_snapshot_with_progress(bytes, |_| {})
    }

    /// Restore transactionally, reporting the number of snapshot entries verified.
    /// Progress does not imply installation: artifacts become available only on success.
    ///
    /// # Errors
    /// Rejects malformed or conflicting snapshots, as [`Self::restore_verified_snapshot`] does.
    pub fn restore_verified_snapshot_with_progress(
        &mut self,
        bytes: &[u8],
        mut progress: impl FnMut(usize),
    ) -> Result<(), CompilerError> {
        let mut input = bytes;
        if take(&mut input, 8)? != b"DL52PRE1" {
            return Err(invalid());
        }
        let length = number(&mut input)?;
        if take(&mut input, length)? != bitcoin::consensus::serialize(self.activation.transaction())
        {
            return Err(invalid());
        }
        // Validate transactionally: a corrupted suffix cannot partially install
        // earlier entries into the live preparation state.
        let mut restored = Self {
            activation: self.activation.clone(),
            identities: self.identities,
            requests: self.requests.clone(),
            artifacts: (0..self.requests.len()).map(|_| None).collect(),
            inventory_hash: self.inventory_hash.clone(),
        };
        let mut previous = None;
        let mut verified = 0;
        while !input.is_empty() {
            let index = number(&mut input)?;
            if previous.is_some_and(|p| index <= p) {
                return Err(invalid());
            }
            previous = Some(index);
            let length = number(&mut input)?;
            if length > dealer_bitcoin::reveal::REVEAL_PACKAGE_BYTES {
                return Err(invalid());
            }
            restored.accept_response(index, take(&mut input, length)?)?;
            verified += 1;
            progress(verified);
        }
        // Existing verified artifacts must agree with the restored snapshot.
        for (index, artifact) in self.artifacts.iter().enumerate() {
            if let Some(artifact) = artifact {
                restored.accept_response(index, &artifact_bytes(artifact))?;
            }
        }
        self.artifacts = restored.artifacts;
        Ok(())
    }

    /// Cross the activation boundary only with a complete verified inventory.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn into_prepared_authorizations(self) -> Result<PreparedAuthorizations, CompilerError> {
        if self.missing_count() != 0 {
            return Err(CompilerError::Preparation {
                reason: "required authorizations are missing",
            });
        }
        let mut signatures = HashMap::new();
        let mut reveals = HashMap::new();
        for (index, request) in self.requests.iter().enumerate() {
            let duplicate = match request {
                AuthorizationRequest::Signature {
                    node_id,
                    edge_index,
                    ..
                } => signatures.insert((*node_id, *edge_index), index).is_some(),
                AuthorizationRequest::Reveal(context) => reveals
                    .insert((context.node_id, context.slot), index)
                    .is_some(),
            };
            if duplicate {
                return Err(invalid());
            }
        }
        Ok(PreparedAuthorizations {
            preparation: self,
            signatures,
            reveals,
        })
    }
}

/// Complete authorizations required for unilateral on-chain play.
pub struct PreparedAuthorizations {
    preparation: SettlementPreparation,
    signatures: HashMap<(NodeId, usize), usize>,
    reveals: HashMap<(NodeId, u8), usize>,
}
impl PreparedAuthorizations {
    /// Exact transaction now eligible for both funding signatures.
    #[must_use]
    pub fn activation(&self) -> &TransactionTemplate {
        &self.preparation.activation
    }
    /// Persist the public inventory before signing activation.
    ///
    /// # Errors
    /// Rejects an inventory that exceeds the canonical u32 encoding bounds.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, CompilerError> {
        self.preparation.encode_snapshot()
    }
    /// Retrieve the fixed opponent signature for one locally derived edge.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn signature(
        &self,
        node: NodeId,
        edge: usize,
    ) -> Result<(Role, DefaultSighashSignature), CompilerError> {
        let index = *self.signatures.get(&(node, edge)).ok_or_else(invalid)?;
        match (
            &self.preparation.requests[index],
            &self.preparation.artifacts[index],
        ) {
            (
                AuthorizationRequest::Signature { signer, .. },
                Some(Artifact::Signature(signature)),
            ) => Ok((*signer, *signature)),
            _ => Err(invalid()),
        }
    }
    /// Retrieve a verified package for completing or extracting a reveal.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn reveal(&self, node: NodeId, slot: u8) -> Result<&VerifiedRevealPackage, CompilerError> {
        let index = *self.reveals.get(&(node, slot)).ok_or_else(invalid)?;
        match (
            &self.preparation.requests[index],
            &self.preparation.artifacts[index],
        ) {
            (AuthorizationRequest::Reveal(context), Some(Artifact::Reveal { bytes, decoded })) => {
                decoded
                    .get_or_init(|| {
                        VerifiedRevealPackage::verify(context.as_ref().clone(), bytes)
                            .map(Box::new)
                            .map_err(|_| ())
                    })
                    .as_ref()
                    .map(Box::as_ref)
                    .map_err(|()| invalid())
            }
            _ => Err(invalid()),
        }
    }
}
fn artifact_bytes(artifact: &Artifact) -> Vec<u8> {
    match artifact {
        Artifact::Signature(s) => s.to_bytes().to_vec(),
        Artifact::Reveal { bytes, .. } => bytes.clone(),
    }
}
fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], CompilerError> {
    let (head, tail) = input.split_at_checked(len).ok_or_else(invalid)?;
    *input = tail;
    Ok(head)
}
fn number(input: &mut &[u8]) -> Result<usize, CompilerError> {
    Ok(u32::from_le_bytes(take(input, 4)?.try_into().map_err(|_| invalid())?) as usize)
}
