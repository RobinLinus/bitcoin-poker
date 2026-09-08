//! Retire a completed hand only against an enforceable, locally attested successor.
use super::*;
use hmac::{Hmac, Mac};
use poker_bitcoin::channel::retirement_commitment;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Handoff {
    certificate: Vec<u8>,
    pub next: [u8; 32],
    pub peer_secret: Option<[u8; 32]>,
    pub watched: bool,
    pub peer_ack: bool,
}

#[derive(Serialize, Deserialize)]
struct Successor {
    terms: Terms,
    hand: [u8; 32],
}

impl ChannelHand {
    fn successor_mac(&self, bytes: &[u8]) -> Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&derive(&self.sessions[0].seed, b"hand-successor"))?;
        mac.update(b"POKER/local-enforceable-successor/v1");
        mac.update(bytes);
        Ok(mac)
    }

    /// Local-only attestation. The worker persists this hand and its watch receipt
    /// before passing the certificate to the previous hand's private worker.
    pub fn successor_certificate(&self) -> Result<Vec<u8>> {
        if !self.entered || !self.peer_ready || self.root.is_none() || self.pending.is_some()
            || self.closing || !self.accepted.is_empty() || self.handoff.is_some() {
            return Err("successor not ready for retirement".into());
        }
        let mut bytes = serde_json::to_vec(&Successor { terms: self.sessions[0].terms.clone(), hand: self.hand()? })?;
        let tag = self.successor_mac(&bytes)?.finalize().into_bytes();
        bytes.extend_from_slice(&tag);
        Ok(bytes)
    }

    fn verify_successor(&self, certificate: &[u8]) -> Result<[u8; 32]> {
        if certificate.len() < 32 || certificate.len() > 16_384 || self.pending.is_some()
            || self.closing || !self.sessions.iter().all(|s| s.terminal) {
            return Err("hand not ready for successor".into());
        }
        let (bytes, tag) = certificate.split_at(certificate.len() - 32);
        self.successor_mac(bytes)?.verify_slice(tag)?;
        let next: Successor = serde_json::from_slice(bytes)?;
        self.check_successor(&super::slot::Candidate{terms:next.terms,hand:next.hand})?;
        if self.selection.is_none() {return Err("successor not selected".into());}
        Ok(next.hand)
    }

    pub fn begin_handoff(&mut self, certificate: &[u8]) -> Result<Frame> {
        let next = self.verify_successor(certificate)?;
        if let Some(old) = &self.handoff {
            if old.next != next || old.certificate != certificate { return Err("conflicting successor".into()); }
        } else {
            self.handoff = Some(Handoff { certificate: certificate.to_vec(), next,
                peer_secret: None, watched: false, peer_ack: false });
        }
        let session = &self.sessions[usize::from(self.role().code())];
        Ok(Frame::Retire { hand: self.hand()?, next,
            secret: session.retirement_secret(RetirementLevel::Hand, session.graph()?.plan().root_node_id)? })
    }

    fn verify_hand_secret(&self, secret: [u8; 32]) -> Result<()> {
        let session = &self.sessions[usize::from(self.role().other().code())];
        if retirement_commitment(secret) != session.channel_materialization.as_ref().ok_or("missing protection")?.hand_commitment {
            return Err("invalid hand retirement secret".into());
        }
        Ok(())
    }

    pub(super) fn receive_retirement(&mut self, hand: [u8; 32], next: [u8; 32], secret: [u8; 32]) -> Result<Option<Frame>> {
        if hand != self.hand()? { return Err("foreign hand retirement".into()); }
        self.verify_hand_secret(secret)?;
        let target = self.handoff.as_mut().ok_or("successor not prepared")?;
        if next != target.next || target.peer_secret.is_some_and(|old| old != secret) { return Err("conflicting successor".into()); }
        target.peer_secret = Some(secret);
        Ok(target.watched.then_some(Frame::Retired { hand, next }))
    }

    pub(super) fn validate_handoff(&self) -> Result<()> {
        if let Some(h) = &self.handoff {
            if self.verify_successor(&h.certificate)? != h.next || (h.watched && h.peer_secret.is_none()) {
                return Err("invalid recovered successor".into());
            }
            if let Some(secret) = h.peer_secret { self.verify_hand_secret(secret)?; }
        }
        Ok(())
    }

    pub(super) fn hand_penalty(&self, secret: [u8; 32]) -> Result<Vec<u8>> {
        self.verify_hand_secret(secret)?;
        let session = &self.sessions[usize::from(self.role().other().code())];
        let graph = session.graph()?;
        let root = graph.hand_commitment(session.terms.origin_output()?, session.terms.scaled_fee(500))?;
        let gate = graph.hand_gate()?;
        let secp = Secp256k1::new();
        let signer = keypair(derive(&session.seed, b"identity"))?;
        let profile = session.channel_materialization.as_ref().ok_or("missing hand guard")?;
        let guard = poker_bitcoin::channel::RevocationGuard { contest_blocks: profile.contest_blocks,
            commitment: profile.hand_commitment, counterparty: signer.x_only_public_key().0 };
        let leaf = gate.leaf(guard.predicate_id()).ok_or("missing hand justice leaf")?;
        let parent = root.transaction().output[0].clone();
        let fee = session.terms.scaled_fee(500);
        let template = poker_bitcoin::TransactionTemplate::normal(session.terms.network(),
            OutPoint::new(root.transaction().compute_txid(), 0), parent.clone(),
            vec![TxOut { value: Amount::from_sat(parent.value.to_sat().checked_sub(fee).ok_or("insufficient justice funds")?),
                script_pubkey: ScriptBuf::new_p2tr(&secp, signer.x_only_public_key().0, None) }], fee)?;
        let mut tx = template.transaction().clone();
        let digest = taproot_script_sighash_default(&tx, 0, &[parent], leaf.script())?;
        tx.input[0].witness = leaf.assemble_witness(&[sign_sighash_default(&secp, &signer, digest).to_bytes().to_vec(), secret.to_vec()])?;
        Ok(serialize(&tx))
    }
}
