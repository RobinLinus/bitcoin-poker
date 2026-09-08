//! Local worker capabilities. No peer is given signing material or receipt keys.
use super::*;
use dealer_bitcoin::reveal::GeneratedRevealPackage;
use poker_settlement::preparation::batches::BatchVerifier;
use poker_settlement::settlement::AuthorizationRequest;
pub struct CryptoWorker {
    verifier: BatchVerifier,
    material: SigningMaterial,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    signer: Keypair,
    auxiliary: [u8; 32],
}
impl CryptoWorker {
    pub fn new(
        inventory: &[u8],
        network: Network,
        key: [u8; 32],
        material: SigningMaterial,
    ) -> Result<Self> {
        if material.role > 1 {
            return Err("invalid worker role".into());
        }
        Ok(Self {
            secp: Secp256k1::new(),
            signer: keypair(material.identity)?,
            auxiliary: derive(&material.identity, b"adaptor-aux"),
            verifier: BatchVerifier::new(
                SettlementPreparation::from_inventory(inventory, network)?,
                key,
            )?,
            material,
        })
    }
    pub fn manifest(&self) -> Vec<u8> {
        self.verifier
            .requests()
            .iter()
            .flat_map(|r| match r {
                AuthorizationRequest::Signature { signer, .. } => [signer.code(), 0],
                AuthorizationRequest::Reveal(c) => [1 - c.revealer, 1],
            })
            .collect()
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(self.verifier.verify_batch(bytes)?)
    }
    /// Sign locally assigned requests and authenticate their installation in the
    /// parent session without another round of public-key verification.
    pub fn sign_receipt(&self, indices: &[u32]) -> Result<Vec<u8>> {
        Ok(self.verifier.receipt_for_local_batch(&self.sign(indices)?)?)
    }
    pub fn sign(&self, indices: &[u32]) -> Result<Vec<u8>> {
        if indices.is_empty() || indices.len() > 2048 || indices.windows(2).any(|w| w[0] >= w[1]) {
            return Err("invalid indices".into());
        }
        let mut out = vec![];
        for &index in indices {
            let bytes = match self
                .verifier
                .requests()
                .get(index as usize)
                .ok_or("index out of range")?
            {
                AuthorizationRequest::Signature {
                    signer: role,
                    sighash,
                    ..
                } => {
                    if role.code() != self.material.role {
                        return Err("wrong signer role".into());
                    }
                    sign_sighash_default(&self.secp, &self.signer, *sighash)
                        .to_bytes()
                        .to_vec()
                }
                AuthorizationRequest::Reveal(c) => {
                    if 1 - c.revealer != self.material.role {
                        return Err("wrong reveal role".into());
                    }
                    GeneratedRevealPackage::create(
                        c.as_ref(),
                        &self.material.reveal[usize::from(c.slot)],
                        &self.auxiliary,
                    )?
                    .to_bytes()
                }
            };
            out.extend(index.to_le_bytes());
            out.extend(u32::try_from(bytes.len())?.to_le_bytes());
            out.extend(bytes);
            if out.len() > 256 * 1024 {
                return Err("batch too large".into());
            }
        }
        Ok(out)
    }
}
