//! A terminal channel close pays both wallets in one funding spend.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Cashout {
    scripts: [Vec<u8>; 2],
    peer_signature: Option<Vec<u8>>,
}

impl ChannelHand {
    fn cashout_template(&self, scripts: &[Vec<u8>; 2]) -> Result<Transaction> {
        if self.handoff.is_some() || self.selection.is_some() || self.pending.is_some() || !self.entered
            || !self.peer_ready || !self.sessions.iter().all(|s| s.terminal) {
            return Err("cashout requires a settled, unretired hand".into());
        }
        let session = &self.sessions[0];
        let stacks: [u64; 2] = serde_json::from_value(session.view()?["nextStacks"].clone())?;
        let destinations = scripts.clone().map(ScriptBuf::from_bytes);
        if destinations.iter().any(|s| !s.is_p2tr()) { return Err("cashout requires Taproot wallets".into()); }
        let origin = session.terms.origin_output()?;
        let state = build_origin_escrow(session.terms.identities)?;
        let leaf = &state.leaves()[0];
        let build = |fee: u64| -> Result<Transaction> {
            let reserve = origin.value.to_sat().checked_sub(stacks[0]).and_then(|n| n.checked_sub(stacks[1]))
                .and_then(|n| n.checked_sub(fee)).ok_or("insufficient cashout funds")?;
            let amounts = [stacks[0] + reserve / 2 + reserve % 2, stacks[1] + reserve / 2];
            if amounts.iter().any(|n| *n < 330) { return Err("cashout would be dust".into()); }
            Ok(poker_bitcoin::TransactionTemplate::normal(session.terms.network(), session.terms.origin.parse()?,
                origin.clone(), (0..2).map(|i| TxOut { value: Amount::from_sat(amounts[i]), script_pubkey: destinations[i].clone() }).collect(), fee)?.transaction().clone())
        };
        let mut sized = build(0)?;
        sized.input[0].witness = leaf.assemble_witness(&[vec![0;64],vec![0;64]])?;
        build((sized.vsize() as u64).div_ceil(10))
    }

    fn cashout_signature(&self, scripts: &[Vec<u8>; 2]) -> Result<Vec<u8>> {
        let session = &self.sessions[0];
        let state = build_origin_escrow(session.terms.identities)?;
        let digest = taproot_script_sighash_default(&self.cashout_template(scripts)?, 0,
            &[session.terms.origin_output()?], state.leaves()[0].script())?;
        Ok(sign_sighash_default(&Secp256k1::new(), &keypair(derive(&session.seed,b"identity"))?, digest).to_bytes().to_vec())
    }

    /// Persist the journal before sending this signature. Closing freezes redeals.
    pub fn begin_cashout(&mut self, scripts: [Vec<u8>; 2]) -> Result<Vec<u8>> {
        if let Some(old) = &self.cashout {
            if old.scripts != scripts { return Err("conflicting cashout destinations".into()); }
        } else if self.closing { return Err("channel already closing".into()); }
        let signature = self.cashout_signature(&scripts)?;
        if self.cashout.is_none() { self.cashout = Some(Cashout {scripts,peer_signature:None}); }
        self.closing = true;
        Ok(signature)
    }

    pub fn accept_cashout(&mut self, signature: &[u8]) -> Result<()> {
        let close = self.cashout.as_ref().ok_or("cashout not requested")?;
        self.verify_cashout_signature(&close.scripts, signature)?;
        self.cashout.as_mut().unwrap().peer_signature = Some(signature.to_vec());
        Ok(())
    }

    fn verify_cashout_signature(&self, scripts: &[Vec<u8>; 2], signature: &[u8]) -> Result<()> {
        let session = &self.sessions[0];
        let state = build_origin_escrow(session.terms.identities)?;
        let digest = taproot_script_sighash_default(&self.cashout_template(scripts)?,0,
            &[session.terms.origin_output()?],state.leaves()[0].script())?;
        poker_bitcoin::verify_sighash_default(&Secp256k1::verification_only(),
            session.terms.identities[usize::from(self.role().other().code())], digest,
            poker_bitcoin::DefaultSighashSignature::from_slice(signature)?)?;
        Ok(())
    }

    pub(super) fn cashout_transaction(&self) -> Result<Option<Vec<u8>>> {
        let Some(close) = &self.cashout else { return Ok(None) };
        let Some(peer) = &close.peer_signature else { return Ok(None) };
        let own = self.cashout_signature(&close.scripts)?;
        let signatures = if self.role() == Role::Alice { [own,peer.clone()] } else { [peer.clone(),own] };
        let state = build_origin_escrow(self.sessions[0].terms.identities)?;
        let mut tx = self.cashout_template(&close.scripts)?;
        tx.input[0].witness = state.leaves()[0].assemble_witness(&signatures)?;
        Ok(Some(serialize(&tx)))
    }

    pub(super) fn validate_cashout(&self) -> Result<()> {
        if let Some(close) = &self.cashout {
            if !self.closing { return Err("unfrozen cashout journal".into()); }
            self.cashout_template(&close.scripts)?;
            if let Some(peer) = &close.peer_signature { self.verify_cashout_signature(&close.scripts,peer)?; }
        }
        Ok(())
    }
}
