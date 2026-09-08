//! Re-fund a fresh hand from both confirmed payouts plus a sponsor fee top-up.
use super::*;
use bitcoin::{
    Sequence, TapSighashType, TxIn, absolute,
    key::TapTweak,
    sighash::{Prevouts, SighashCache},
    transaction,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Rollover {
    pub previous: String,
    pub sponsor_previous: String,
    pub sponsor_vout: u32,
    pub sponsor_script: String,
    pub identities: [[u8; 32]; 2],
    pub value: u64,
    pub fee: u64,
}
impl Rollover {
    pub fn template(&self) -> Result<(Transaction, Vec<TxOut>)> {
        if !(1_000..=250_000).contains(&self.value) || !(1..=20_000).contains(&self.fee) {
            return Err("rollover budget exceeded".into());
        }
        let previous: Transaction = deserialize(&hex::decode(&self.previous)?)?;
        let sponsor: Transaction = deserialize(&hex::decode(&self.sponsor_previous)?)?;
        if previous.output.len() != 2 || previous.output.iter().any(|o| !o.script_pubkey.is_p2tr())
        {
            return Err("rollover requires both player payouts".into());
        }
        let coin = sponsor
            .output
            .get(self.sponsor_vout as usize)
            .ok_or("sponsor output missing")?;
        if hex::encode(coin.script_pubkey.as_bytes()) != self.sponsor_script
            || !coin.script_pubkey.is_p2tr()
        {
            return Err("wrong sponsor output".into());
        }
        let mut prevouts = previous.output.clone();
        prevouts.push(coin.clone());
        let total = prevouts.iter().try_fold(0u64, |sum, o| {
            sum.checked_add(o.value.to_sat()).ok_or("rollover overflow")
        })?;
        let change = total
            .checked_sub(self.value + self.fee)
            .ok_or("insufficient rollover funds")?;
        if change < 330 {
            return Err("rollover change is dust".into());
        }
        let input = [
            OutPoint {
                txid: previous.compute_txid(),
                vout: 0,
            },
            OutPoint {
                txid: previous.compute_txid(),
                vout: 1,
            },
            OutPoint {
                txid: sponsor.compute_txid(),
                vout: self.sponsor_vout,
            },
        ]
        .into_iter()
        .map(|previous_output| TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        })
        .collect();
        Ok((
            Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input,
                output: vec![
                    TxOut {
                        value: Amount::from_sat(self.value),
                        script_pubkey: build_origin_escrow(self.identities)?.script_pubkey(),
                    },
                    TxOut {
                        value: Amount::from_sat(change),
                        script_pubkey: coin.script_pubkey.clone(),
                    },
                ],
            },
            prevouts,
        ))
    }
    fn hash(&self, index: usize) -> Result<[u8; 32]> {
        let (tx, prevouts) = self.template()?;
        Ok(SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )?
            .to_byte_array())
    }
    pub fn sponsor_signature(&self, secret: [u8; 32]) -> Result<Vec<u8>> {
        if hex::encode(funding::sponsor_script(secret)?.as_bytes()) != self.sponsor_script {
            return Err("wrong sponsor key".into());
        }
        Ok(
            sign_sighash_default(&Secp256k1::new(), &keypair(secret)?, self.hash(2)?)
                .to_bytes()
                .to_vec(),
        )
    }
    pub fn finish(&self, signatures: &[Vec<u8>]) -> Result<Vec<u8>> {
        if signatures.len() != 3 {
            return Err("three rollover signatures required".into());
        }
        let (mut tx, prevouts) = self.template()?;
        for (index, signature) in signatures.iter().enumerate() {
            let key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
                &prevouts[index].script_pubkey.as_bytes()[2..],
            )?;
            Secp256k1::verification_only().verify_schnorr(
                &bitcoin::secp256k1::schnorr::Signature::from_slice(signature)?,
                &bitcoin::secp256k1::Message::from_digest(self.hash(index)?),
                &key,
            )?;
            tx.input[index].witness.push(signature);
        }
        Ok(serialize(&tx))
    }
    /// On cancellation each old payout is restored; the sponsor recovers its top-up less fees.
    pub fn return_outputs(&self, fee: u64) -> Result<Vec<TxOut>> {
        let (_, prevouts) = self.template()?;
        let mut outputs = prevouts[..2].to_vec();
        let refund = self
            .value
            .checked_sub(prevouts[0].value.to_sat() + prevouts[1].value.to_sat() + fee)
            .ok_or("insufficient rollover return reserve")?;
        if refund < 330 {
            return Err("rollover return is dust".into());
        }
        outputs.push(TxOut {
            value: Amount::from_sat(refund),
            script_pubkey: prevouts[2].script_pubkey.clone(),
        });
        Ok(outputs)
    }
}
impl Session {
    pub fn rollover_info(&self) -> Result<serde_json::Value> {
        if !self.terminal {
            return Err("hand is not settled".into());
        }
        let mut view = self.view()?;
        view["previous"] = serde_json::json!(hex::encode(
            &self
                .chain
                .last()
                .ok_or("missing confirmed payout")?
                .transaction
        ));
        view["button"] = serde_json::json!(self.terms.button.unwrap_or(0));
        view["identities"] = serde_json::json!(self.terms.identities);
        Ok(view)
    }
    pub fn rollover_signature(&self, rollover: &Rollover) -> Result<Vec<u8>> {
        if !self.terminal
            || hex::decode(&rollover.previous)?
                != self.chain.last().ok_or("missing payout")?.transaction
        {
            return Err("rollover must spend this confirmed settlement".into());
        }
        let index = usize::from(self.role.code());
        let (_, prevouts) = rollover.template()?;
        let secp = Secp256k1::new();
        let key = keypair(derive(&self.seed, b"identity"))?
            .tap_tweak(&secp, None)
            .to_keypair();
        let script = ScriptBuf::new_p2tr(
            &secp,
            keypair(derive(&self.seed, b"identity"))?
                .x_only_public_key()
                .0,
            None,
        );
        if prevouts[index].script_pubkey != script {
            return Err("payout identity mismatch".into());
        }
        Ok(sign_sighash_default(&secp, &key, rollover.hash(index)?)
            .to_bytes()
            .to_vec())
    }
}

impl Session {
    /// Sweep only this seat's confirmed payout to its local wallet.
    pub fn cashout(&self, destination: &[u8], fee: u64) -> Result<Vec<u8>> {
        if !self.terminal || !(1..=20000).contains(&fee) {
            return Err("cashout requires settlement and a bounded fee".into());
        }
        let script = ScriptBuf::from_bytes(destination.to_vec());
        if !script.is_p2tr() {
            return Err("cashout wallet must be Taproot".into());
        }
        let previous: Transaction =
            deserialize(&self.chain.last().ok_or("missing payout")?.transaction)?;
        let index = usize::from(self.role.code());
        let coin = previous.output.get(index).ok_or("payout missing")?.clone();
        let secp = Secp256k1::new();
        let identity = keypair(derive(&self.seed, b"identity"))?;
        if coin.script_pubkey != ScriptBuf::new_p2tr(&secp, identity.x_only_public_key().0, None) {
            return Err("payout identity mismatch".into());
        }
        let amount = coin
            .value
            .to_sat()
            .checked_sub(fee)
            .ok_or("payout cannot cover fee")?;
        if amount < 330 {
            return Err("cashout would be dust".into());
        }
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: previous.compute_txid(),
                    vout: index as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: script,
            }],
        };
        let hash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[coin]), TapSighashType::Default)?
            .to_byte_array();
        tx.input[0].witness.push(
            sign_sighash_default(&secp, &identity.tap_tweak(&secp, None).to_keypair(), hash)
                .to_bytes(),
        );
        Ok(serialize(&tx))
    }
}
