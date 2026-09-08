use bitcoin::{Amount, Transaction, TxOut, consensus::{serialize,deserialize}, transaction, absolute, sighash::{Prevouts,SighashCache}, TapSighashType, hashes::Hash};
use poker_session::{*,buyin::{BuyIn,Coin}};
fn previous(secret:[u8;32],amount:u64)->Transaction {
 Transaction{version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,input:vec![],output:vec![TxOut{value:Amount::from_sat(amount),script_pubkey:funding::sponsor_script(secret).unwrap()}]}
}
#[test]
fn independent_buyins_preserve_change_and_require_both_wallets()->Result<()> {
 std::thread::Builder::new().stack_size(32*1024*1024).spawn(||run().map_err(|e|e.to_string())).unwrap().join().unwrap().map_err(Into::into)
}
fn run()->Result<()> {
 let secrets=[[11;32],[12;32]];
 let mut seeds=[[3;32],[5;32]];seeds.sort_by_key(|s|public_keys(s).unwrap().identity);
 let keys=[public_keys(&seeds[0])?,public_keys(&seeds[1])?];
 let b=BuyIn{coins:secrets.map(|secret|{let tx=previous(secret,200000);Coin{previous:hex::encode(serialize(&tx)),vout:0,script:hex::encode(tx.output[0].script_pubkey.as_bytes())}}),identities:[keys[0].identity,keys[1].identity],value:85500,fee:255};
 let signatures=[b.sign(secrets[0],0)?,b.sign(secrets[1],1)?];
 assert!(b.sign(secrets[0],1).is_err());
 let tx:Transaction=deserialize(&b.finish(&signatures)?)?;
 assert_eq!(tx.vsize(),255);
 assert_eq!(tx.output[0].value.to_sat(),85500);
 assert_eq!(tx.output[1].value.to_sat(),200000-42750-127);
 assert_eq!(tx.output[2].value.to_sat(),200000-42750-128);
 assert_eq!(400000-tx.output.iter().map(|o|o.value.to_sat()).sum::<u64>(),255);
 let mut changed=b.clone();changed.value+=2;
 assert!(changed.finish(&signatures).is_err());
 changed=b.clone();changed.coins[1]=changed.coins[0].clone();assert!(changed.template().is_err());
 let terms=Terms{slot:None,predeal_anchor:None,fee_reserve:None,regtest:true,identities:b.identities,reveal_keys:[keys[1].reveal,keys[0].reveal],origin:format!("{}:0",tx.compute_txid()),origin_value:b.value,nonce:[7;32],full:true,fee_multiplier:1.0,csv:12,stacks:Some([20000,20000]),button:Some(0)};
 let mut cheap=terms.clone(); cheap.fee_multiplier=0.1;
 let reserve=poker_settlement::graph::required_fee_reserve(&cheap.parameters()?.rules,&cheap.fees()?)?;
 assert!(reserve>0 && reserve<4500);
 assert_eq!(cheap.scaled_fee(500),50);
 cheap.fee_reserve=Some(reserve);cheap.origin_value=40000+reserve+50;
 Session::new(seeds[0],cheap)?;
 let players=[Session::new(seeds[0],terms.clone())?,Session::new(seeds[1],terms)?];
 let peer=players[1].buyin_refund_signature(&b)?;
 let refund:Transaction=deserialize(&players[0].buyin_refund(&b,&peer)?)?;
 assert_eq!(refund.output.len(),2);
 for i in 0..2 {
  assert_eq!(refund.output[i].value.to_sat(),42500);
  assert_eq!(refund.output[i].script_pubkey,funding::sponsor_script(secrets[i])?);
 }
 assert!(players[0].cashout(funding::sponsor_script(secrets[0])?.as_bytes(),111).is_err());
 // Wallet signatures commit to all inputs and outputs.
 let (_,prevouts)=b.template()?;
 for i in 0..2 {
  let hash=SighashCache::new(&tx).taproot_key_spend_signature_hash(i,&Prevouts::All(&prevouts),TapSighashType::Default)?.to_byte_array();
  bitcoin::secp256k1::Secp256k1::verification_only().verify_schnorr(&bitcoin::secp256k1::schnorr::Signature::from_slice(&signatures[i])?,&bitcoin::secp256k1::Message::from_digest(hash),&keypair(secrets[i])?.x_only_public_key().0)?;
 }
 Ok(())
}
