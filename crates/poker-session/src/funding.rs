//! Narrow sponsor funding for the disposable MutinyNet test campaign.
use super::*;
use bitcoin::{
    Address, Sequence, TapSighashType, TxIn, absolute,
    key::TweakedPublicKey,
    sighash::{Prevouts, SighashCache},
    transaction,
};
pub fn sponsor_script(secret: [u8; 32]) -> Result<ScriptBuf> {
    Ok(ScriptBuf::new_p2tr_tweaked(
        TweakedPublicKey::dangerous_assume_tweaked(keypair(secret)?.x_only_public_key().0),
    ))
}
pub fn sponsor_address(secret: [u8; 32]) -> Result<String> {
    Ok(Address::from_script(&sponsor_script(secret)?, Network::Signet)?.to_string())
}
/// The faucet uses the raw x-only public key as its Taproot output key, with no
/// internal-key tweak. Sign only a verified matching output, preserving change.
pub fn fund(
    secret: [u8; 32],
    previous: &[u8],
    vout: u32,
    identities: [[u8; 32]; 2],
    value: u64,
    fee: u64,
) -> Result<Vec<u8>> {
    if !(1000..=250_000).contains(&value) || fee == 0 || fee > 20_000 {
        return Err("test funding budget exceeded".into());
    }
    let prev: Transaction = deserialize(previous)?;
    let output = prev
        .output
        .get(vout as usize)
        .ok_or("funding output missing")?;
    let script = sponsor_script(secret)?;
    if output.script_pubkey != script {
        return Err("funding key does not control selected output".into());
    }
    let change = output
        .value
        .to_sat()
        .checked_sub(value + fee)
        .ok_or("insufficient funding")?;
    if change < 330 {
        return Err("select a larger UTXO to preserve change".into());
    }
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: build_origin_escrow(identities)?.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(change),
                script_pubkey: script,
            },
        ],
    };
    let hash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(output)),
            TapSighashType::Default,
        )?
        .to_byte_array();
    tx.input[0]
        .witness
        .push(sign_sighash_default(&Secp256k1::new(), &keypair(secret)?, hash).to_bytes());
    Ok(serialize(&tx))
}
impl Session {
    fn refund_template(&self, destination: &[u8]) -> Result<Transaction> {
        let script = ScriptBuf::from_bytes(destination.to_vec());
        if !script.is_p2tr() {
            return Err("refund requires a Taproot destination".into());
        }
        if self.current.is_some() {
            return Err("origin already activated".into());
        }
        Ok(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.terms.origin.parse()?,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(
                    self.terms
                        .origin_value
                        .checked_sub(self.terms.scaled_fee(500))
                        .ok_or("refund amount")?,
                ),
                script_pubkey: script,
            }],
        })
    }
    pub fn refund_signature(&self, destination: &[u8]) -> Result<Vec<u8>> {
        let tx = self.refund_template(destination)?;
        self.sign_return(&tx)
    }
    fn sign_return(&self, tx: &Transaction) -> Result<Vec<u8>> {
        let origin = build_origin_escrow(self.terms.identities)?;
        let hash = taproot_script_sighash_default(
            tx,
            0,
            &[self.terms.origin_output()?],
            origin.leaves()[0].script(),
        )?;
        Ok(sign_sighash_default(
            &Secp256k1::new(),
            &keypair(derive(&self.seed, b"identity"))?,
            hash,
        )
        .to_bytes()
        .to_vec())
    }
    pub fn refund(&self, destination: &[u8], peer: &[u8]) -> Result<Vec<u8>> {
        self.assemble_return(self.refund_template(destination)?, peer)
    }
    pub fn rollover_refund_signature(&self, r: &crate::rollover::Rollover) -> Result<Vec<u8>> {
        self.sign_return(&self.rollover_refund_template(r)?)
    }
    pub fn rollover_refund(&self, r: &crate::rollover::Rollover, peer: &[u8]) -> Result<Vec<u8>> {
        self.assemble_return(self.rollover_refund_template(r)?, peer)
    }
    fn rollover_refund_template(&self, r: &crate::rollover::Rollover) -> Result<Transaction> {
        let (funding, _) = r.template()?;
        if r.identities != self.terms.identities
            || r.value != self.terms.origin_value
            || self.terms.origin != format!("{}:0", funding.compute_txid())
        {
            return Err("rollover refund terms mismatch".into());
        }
        let mut tx = self.refund_template(&hex::decode(&r.sponsor_script)?)?;
        tx.output = r.return_outputs(self.terms.scaled_fee(500))?;
        Ok(tx)
    }
    fn buyin_return_template(&self, b: &crate::buyin::BuyIn) -> Result<Transaction> {
        let (funding, prevouts) = b.template()?;
        if b.identities != self.terms.identities
            || b.value != self.terms.origin_value
            || self.terms.origin != format!("{}:0", funding.compute_txid())
        {
            return Err("buy-in return terms mismatch".into());
        }
        let mut tx = self.refund_template(prevouts[0].script_pubkey.as_bytes())?;
        let amount = (b.value - self.terms.scaled_fee(500)) / 2;
        tx.output = prevouts
            .iter()
            .map(|o| TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: o.script_pubkey.clone(),
            })
            .collect();
        Ok(tx)
    }
    pub fn buyin_refund_signature(&self, b: &crate::buyin::BuyIn) -> Result<Vec<u8>> {
        self.sign_return(&self.buyin_return_template(b)?)
    }
    pub fn buyin_refund(&self, b: &crate::buyin::BuyIn, peer: &[u8]) -> Result<Vec<u8>> {
        self.assemble_return(self.buyin_return_template(b)?, peer)
    }
    fn assemble_return(&self, mut tx: Transaction, peer: &[u8]) -> Result<Vec<u8>> {
        let own = self.sign_return(&tx)?;
        let origin = build_origin_escrow(self.terms.identities)?;
        let leaf = &origin.leaves()[0];
        let hash =
            taproot_script_sighash_default(&tx, 0, &[self.terms.origin_output()?], leaf.script())?;
        Secp256k1::verification_only().verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(peer)?,
            &bitcoin::secp256k1::Message::from_digest(hash),
            &bitcoin::secp256k1::XOnlyPublicKey::from_slice(
                &self.terms.identities[usize::from(self.role.other().code())],
            )?,
        )?;
        let sigs = if self.role == Role::Alice {
            [own, peer.to_vec()]
        } else {
            [peer.to_vec(), own]
        };
        tx.input[0].witness = leaf.assemble_witness(&sigs)?;
        Ok(serialize(&tx))
    }
}
