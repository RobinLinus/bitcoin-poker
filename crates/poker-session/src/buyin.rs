//! Two independently funded wallet inputs, with change and cancellation returns.
use super::*;
use bitcoin::{
    Sequence, TapSighashType, TxIn, absolute,
    sighash::{Prevouts, SighashCache},
    transaction,
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Coin {
    pub previous: String,
    pub vout: u32,
    pub script: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct BuyIn {
    pub coins: [Coin; 2],
    pub identities: [[u8; 32]; 2],
    pub value: u64,
    pub fee: u64,
}
impl BuyIn {
    pub fn template(&self) -> Result<(Transaction, Vec<TxOut>)> {
        if !(1000..=250000).contains(&self.value)
            || !(1..=20000).contains(&self.fee)
            || self.value % 2 != 0
        {
            return Err("invalid buy-in budget".into());
        }
        let mut input = vec![];
        let mut prevouts = vec![];
        let mut output = vec![TxOut {
            value: Amount::from_sat(self.value),
            script_pubkey: build_origin_escrow(self.identities)?.script_pubkey(),
        }];
        for (index, coin) in self.coins.iter().enumerate() {
            let previous: Transaction = deserialize(&hex::decode(&coin.previous)?)?;
            let prev = previous
                .output
                .get(coin.vout as usize)
                .ok_or("buy-in coin missing")?
                .clone();
            if !prev.script_pubkey.is_p2tr()
                || hex::encode(prev.script_pubkey.as_bytes()) != coin.script
            {
                return Err("buy-in wallet mismatch".into());
            }
            let change = prev
                .value
                .to_sat()
                .checked_sub(
                    self.value / 2 + self.fee / 2 + if index == 1 { self.fee % 2 } else { 0 },
                )
                .ok_or("insufficient buy-in funds")?;
            if change < 330 {
                return Err("buy-in change is dust".into());
            }
            input.push(TxIn {
                previous_output: OutPoint {
                    txid: previous.compute_txid(),
                    vout: coin.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
            output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: prev.script_pubkey.clone(),
            });
            prevouts.push(prev);
        }
        if input[0].previous_output == input[1].previous_output {
            return Err("duplicate buy-in coin".into());
        }
        Ok((
            Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input,
                output,
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
    pub fn sign(&self, secret: [u8; 32], index: usize) -> Result<Vec<u8>> {
        let (_, prevouts) = self.template()?;
        if prevouts
            .get(index)
            .ok_or("invalid buy-in seat")?
            .script_pubkey
            != funding::sponsor_script(secret)?
        {
            return Err("buy-in coin is not yours".into());
        }
        Ok(
            sign_sighash_default(&Secp256k1::new(), &keypair(secret)?, self.hash(index)?)
                .to_bytes()
                .to_vec(),
        )
    }
    pub fn finish(&self, signatures: &[Vec<u8>]) -> Result<Vec<u8>> {
        if signatures.len() != 2 {
            return Err("two buy-in signatures required".into());
        }
        let (mut tx, prevouts) = self.template()?;
        for (i, sig) in signatures.iter().enumerate() {
            Secp256k1::verification_only().verify_schnorr(
                &bitcoin::secp256k1::schnorr::Signature::from_slice(sig)?,
                &bitcoin::secp256k1::Message::from_digest(self.hash(i)?),
                &bitcoin::secp256k1::XOnlyPublicKey::from_slice(
                    &prevouts[i].script_pubkey.as_bytes()[2..],
                )?,
            )?;
            tx.input[i].witness.push(sig);
        }
        Ok(serialize(&tx))
    }
}
