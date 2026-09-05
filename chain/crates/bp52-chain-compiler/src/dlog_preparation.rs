//! Public preparation snapshots contain no wallet keys or dealing entropy.
//! Restoring a snapshot reconstructs the local inventory and re-verifies every
//! signature and adaptor package. A stored ready flag is never trusted.
use crate::{
    CompilerError,
    dlog::{DlogAuthorizationRequest, DlogGraph},
};
use bitcoin::secp256k1::Secp256k1;
use bp52_chain_bitcoin::{DefaultSighashSignature, TransactionTemplate, verify_sighash_default};
use bp52_chain_types::{NodeId, Role};
use dlog52_bitcoin::reveal::VerifiedRevealPackage;

fn invalid() -> CompilerError {
    CompilerError::DealMismatch
}

enum Artifact {
    Signature(DefaultSighashSignature),
    Reveal(Box<VerifiedRevealPackage>),
}

/// Exact complete inventory awaiting authenticated counterparty responses.
pub struct DlogPreparation {
    activation: TransactionTemplate,
    identities: [[u8; 32]; 2],
    requests: Vec<DlogAuthorizationRequest>,
    artifacts: Vec<Option<Artifact>>,
}

impl DlogPreparation {
    /// Independently derive every request from the agreed graph and activation.
    pub fn new(
        graph: &DlogGraph<'_>,
        activation: TransactionTemplate,
    ) -> Result<Self, CompilerError> {
        let mut requests = Vec::new();
        graph.visit_authorizations(&activation, |request| {
            requests.push(request);
            Ok(())
        })?;
        let artifacts = (0..requests.len()).map(|_| None).collect();
        Ok(Self {
            activation,
            identities: graph.identities(),
            requests,
            artifacts,
        })
    }

    /// Canonical request order. Responses use this index, never peer metadata.
    pub fn requests(&self) -> &[DlogAuthorizationRequest] {
        &self.requests
    }

    /// Number of missing responses; activation requires exactly zero.
    pub fn missing(&self) -> usize {
        self.artifacts.iter().filter(|a| a.is_none()).count()
    }

    /// Verify a response against its independently derived transaction context.
    /// An exact duplicate is idempotent; conflicting duplicates are rejected.
    pub fn accept(&mut self, index: usize, bytes: &[u8]) -> Result<(), CompilerError> {
        let request = self.requests.get(index).ok_or_else(invalid)?;
        if let Some(existing) = &self.artifacts[index] {
            return if artifact_bytes(existing) == bytes {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        let artifact = match request {
            DlogAuthorizationRequest::Signature {
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
            DlogAuthorizationRequest::Reveal(context) => Artifact::Reveal(Box::new(
                VerifiedRevealPackage::verify(context.as_ref().clone(), bytes)
                    .map_err(|_| invalid())?,
            )),
        };
        self.artifacts[index] = Some(artifact);
        Ok(())
    }

    /// Serialize public artifacts with the exact activation transaction binding.
    /// The caller persists this before sending a response or activating funding.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = b"DL52PRE1".to_vec();
        let transaction = bitcoin::consensus::serialize(self.activation.transaction());
        bytes.extend((transaction.len() as u32).to_le_bytes());
        bytes.extend(transaction);
        for (index, artifact) in self.artifacts.iter().enumerate() {
            if let Some(artifact) = artifact {
                let response = artifact_bytes(artifact);
                bytes.extend((index as u32).to_le_bytes());
                bytes.extend((response.len() as u32).to_le_bytes());
                bytes.extend(response);
            }
        }
        bytes
    }

    /// Restore only into a freshly derived inventory for this same activation.
    pub fn restore(&mut self, bytes: &[u8]) -> Result<(), CompilerError> {
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
        };
        let mut previous = None;
        while !input.is_empty() {
            let index = number(&mut input)?;
            if previous.is_some_and(|p| index <= p) {
                return Err(invalid());
            }
            previous = Some(index);
            let length = number(&mut input)?;
            if length > dlog52_bitcoin::reveal::REVEAL_PACKAGE_BYTES {
                return Err(invalid());
            }
            restored.accept(index, take(&mut input, length)?)?;
        }
        // Existing verified artifacts must agree with the restored snapshot.
        for (index, artifact) in self.artifacts.iter().enumerate() {
            if let Some(artifact) = artifact {
                restored.accept(index, &artifact_bytes(artifact))?;
            }
        }
        self.artifacts = restored.artifacts;
        Ok(())
    }

    /// Cross the activation boundary only with a complete verified inventory.
    pub fn ready(self) -> Result<ReadyDlogGame, CompilerError> {
        if self.missing() != 0 {
            return Err(invalid());
        }
        Ok(ReadyDlogGame { preparation: self })
    }
}

/// Complete authorizations required for unilateral on-chain play.
pub struct ReadyDlogGame {
    preparation: DlogPreparation,
}
impl ReadyDlogGame {
    /// Exact transaction now eligible for both funding signatures.
    pub fn activation(&self) -> &TransactionTemplate {
        &self.preparation.activation
    }
    /// Persist the public inventory before signing activation.
    pub fn snapshot(&self) -> Vec<u8> {
        self.preparation.snapshot()
    }
    /// Retrieve the fixed opponent signature for one locally derived edge.
    pub fn signature(
        &self,
        node: NodeId,
        edge: usize,
    ) -> Result<(Role, DefaultSighashSignature), CompilerError> {
        for (request, artifact) in self
            .preparation
            .requests
            .iter()
            .zip(&self.preparation.artifacts)
        {
            if let (
                DlogAuthorizationRequest::Signature {
                    node_id,
                    edge_index,
                    signer,
                    ..
                },
                Some(Artifact::Signature(signature)),
            ) = (request, artifact)
            {
                if *node_id == node && *edge_index == edge {
                    return Ok((*signer, *signature));
                }
            }
        }
        Err(invalid())
    }
    /// Retrieve a verified package for completing or extracting a reveal.
    pub fn reveal(&self, node: NodeId, slot: u8) -> Result<&VerifiedRevealPackage, CompilerError> {
        for (request, artifact) in self
            .preparation
            .requests
            .iter()
            .zip(&self.preparation.artifacts)
        {
            if let (DlogAuthorizationRequest::Reveal(context), Some(Artifact::Reveal(package))) =
                (request, artifact)
            {
                if context.node_id == node && context.slot == slot {
                    return Ok(package);
                }
            }
        }
        Err(invalid())
    }
}
fn artifact_bytes(artifact: &Artifact) -> Vec<u8> {
    match artifact {
        Artifact::Signature(s) => s.to_bytes().to_vec(),
        Artifact::Reveal(p) => p.to_bytes(),
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
