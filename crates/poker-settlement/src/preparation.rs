//! Public preparation snapshots contain no wallet keys or dealing entropy.
//! Restoring a snapshot reconstructs the local inventory and re-verifies every
//! signature and adaptor package. A stored ready flag is never trusted.
use crate::{
    CompilerError,
    settlement::{AuthorizationRequest, SettlementGraph},
};
use bitcoin::secp256k1::Secp256k1;
use dealer_bitcoin::reveal::VerifiedRevealPackage;
use poker_bitcoin::{DefaultSighashSignature, TransactionTemplate, verify_sighash_default};
use poker_settlement_types::{NodeId, Role};

fn invalid() -> CompilerError {
    CompilerError::Preparation {
        reason: "malformed or mismatched preparation artifact",
    }
}

enum Artifact {
    Signature(DefaultSighashSignature),
    Reveal(Box<VerifiedRevealPackage>),
}

/// Exact complete inventory awaiting authenticated counterparty responses.
pub struct SettlementPreparation {
    activation: TransactionTemplate,
    identities: [[u8; 32]; 2],
    requests: Vec<AuthorizationRequest>,
    artifacts: Vec<Option<Artifact>>,
}

impl SettlementPreparation {
    /// Independently derive every request from the agreed graph and activation.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn new(
        graph: &SettlementGraph<'_>,
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
            AuthorizationRequest::Reveal(context) => Artifact::Reveal(Box::new(
                VerifiedRevealPackage::verify(context.as_ref().clone(), bytes)
                    .map_err(|_| invalid())?,
            )),
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
            if length > dealer_bitcoin::reveal::REVEAL_PACKAGE_BYTES {
                return Err(invalid());
            }
            restored.accept_response(index, take(&mut input, length)?)?;
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
        Ok(PreparedAuthorizations { preparation: self })
    }
}

/// Complete authorizations required for unilateral on-chain play.
pub struct PreparedAuthorizations {
    preparation: SettlementPreparation,
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
        for (request, artifact) in self
            .preparation
            .requests
            .iter()
            .zip(&self.preparation.artifacts)
        {
            if let (
                AuthorizationRequest::Signature {
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
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn reveal(&self, node: NodeId, slot: u8) -> Result<&VerifiedRevealPackage, CompilerError> {
        for (request, artifact) in self
            .preparation
            .requests
            .iter()
            .zip(&self.preparation.artifacts)
        {
            if let (AuthorizationRequest::Reveal(context), Some(Artifact::Reveal(package))) =
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
