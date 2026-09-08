//! Bounded, secret-owning Wasm ABI. The host supplies CSPRNG seed bytes and
//! encrypts private checkpoint output before durable storage.
#![deny(unsafe_code)]
use poker_session::{
    Result, Session, SigningMaterial, Terms, channel::ChannelHand, crypto::CryptoWorker,
};
use serde::Deserialize;
use std::cell::RefCell;
use zeroize::Zeroize;
#[cfg(target_arch = "wasm32")]
fn unavailable(_: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(unavailable);
thread_local! {
static INPUT:RefCell<Vec<u8>>=const{RefCell::new(vec![])};
static OUTPUT:RefCell<Vec<u8>>=const{RefCell::new(vec![])};
static ERROR:RefCell<Vec<u8>>=const{RefCell::new(vec![])};
static SESSION:RefCell<Option<Session>>=const{RefCell::new(None)};
static CRYPTO:RefCell<Option<CryptoWorker>>=const{RefCell::new(None)};
static DEALS:RefCell<std::collections::HashMap<[u8;32],ChannelHand>>=RefCell::new(std::collections::HashMap::new());
static CHANNEL:RefCell<Option<ChannelHand>>=const{RefCell::new(None)};
}
// no_mangle is an unsafe attribute, not an unsafe operation; the ABI never
// dereferences host pointers. Buffers are owned and bounded by this module.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_checkpoint_parts_version() -> u32 {
    1
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_input(len: usize) -> *mut u8 {
    INPUT.with(|i| {
        let mut i = i.borrow_mut();
        i.zeroize();
        if len > 128 * 1024 * 1024 {
            return std::ptr::null_mut();
        }
        i.resize(len, 0);
        i.as_mut_ptr()
    })
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_output_ptr() -> *const u8 {
    OUTPUT.with(|o| o.borrow().as_ptr())
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_output_len() -> usize {
    OUTPUT.with(|o| o.borrow().len())
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_error_ptr() -> *const u8 {
    ERROR.with(|o| o.borrow().as_ptr())
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_error_len() -> usize {
    ERROR.with(|o| o.borrow().len())
}
#[derive(Deserialize)]
struct Init {
    seed: [u8; 32],
    terms: Terms,
}
#[derive(Deserialize)]
struct CryptoInit {
    #[serde(default)]
    inventory: String,
    key: [u8; 32],
    material: SigningMaterial,
    regtest: bool,
}
#[derive(Deserialize)]
struct Action {
    edge: Option<usize>,
    height: u32,
}
#[derive(Deserialize)]
struct Fund {
    secret: [u8; 32],
    previous: String,
    vout: u32,
    identities: [[u8; 32]; 2],
    value: u64,
    fee: u64,
}
fn json<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(v)?)
}
fn session_operation(s: &mut Session, op: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    match op {
        3 => Ok(s.outgoing()?.unwrap_or_default()),
        4 => {
            s.confirm_outgoing(bytes)?;
            Ok(vec![])
        }
        5 => {
            s.accept_peer(bytes)?;
            Ok(vec![])
        }
        6 => {
            s.retry(serde_json::from_slice(bytes)?)?;
            Ok(vec![])
        }
        7 => json(&s.dealer_status()),
        8 => s.score_public(),
        9 => {
            s.accept_score(bytes)?;
            Ok(vec![])
        }
        10 => {
            s.prepare()?;
            Ok(vec![])
        }
        11 => s.inventory(),
        12 => json(&s.signing_material()),
        13 => Ok(s.receipt_key().to_vec()),
        14 => {
            s.accept_batch(bytes)?;
            Ok(vec![])
        }
        15 => {
            s.finish_preparation()?;
            Ok(vec![])
        }
        16 => Ok(s.checkpoint()?.to_vec()),
        36 => s.construction_receipt(),
        37 => { s.accept_construction(bytes)?; Ok(vec![]) }
        38 => json(&s.preparation_work()?),
        39 => s.construction_job(),
        50 => Ok(s.checkpoint_journal()?.to_vec()),
        51 => Ok(s.checkpoint_artifact().to_vec()),
        52 => s.channel_commitments(),
        53 => {
            s.accept_channel_commitments(bytes)?;
            Ok(vec![])
        }
        18 => s.activation_signature(),
        19 => s.activation(bytes),
        20 => {
            let a: Action = serde_json::from_slice(bytes)?;
            s.action(a.edge, a.height)
        }
        21 => {
            s.observe(serde_json::from_slice(bytes)?)?;
            Ok(vec![])
        }
        22 => json(&s.view()?),
        23 => s.refund_signature(bytes),
        24 => {
            if bytes.len() < 64 {
                return Err("missing refund signature".into());
            }
            s.refund(&bytes[64..], &bytes[..64])
        }
        25 => json(&s.rollover_info()?),
        26 => s.rollover_signature(&serde_json::from_slice(bytes)?),
        27 => s.rollover_refund_signature(&serde_json::from_slice(bytes)?),
        29 => {
            s.bind_predeal(serde_json::from_slice(bytes)?)?;
            Ok(vec![])
        }
        28 => {
            #[derive(Deserialize)]
            struct Input {
                rollover: poker_session::rollover::Rollover,
                peer: String,
            }
            let i: Input = serde_json::from_slice(bytes)?;
            s.rollover_refund(&i.rollover, &hex::decode(i.peer)?)
        }
        80 => s.buyin_refund_signature(&serde_json::from_slice(bytes)?),
        81 => {
            #[derive(Deserialize)]
            struct Input {
                buyin: poker_session::buyin::BuyIn,
                peer: String,
            }
            let i: Input = serde_json::from_slice(bytes)?;
            s.buyin_refund(&i.buyin, &hex::decode(i.peer)?)
        }
        82 => {
            #[derive(Deserialize)]
            struct Input {
                script: String,
                fee: u64,
            }
            let i: Input = serde_json::from_slice(bytes)?;
            s.cashout(&hex::decode(i.script)?, i.fee)
        }
        _ => Err("unknown command".into()),
    }
}
fn call(op: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    match op {
        54 => Session::construct_local(bytes),
        60 => {
            #[derive(Deserialize)]
            struct ChannelInit {
                seed: [u8; 32],
                terms: Terms,
                contest_blocks: u16,
            }
            let init: ChannelInit = serde_json::from_slice(bytes)?;
            let hand = ChannelHand::new(init.seed, init.terms, init.contest_blocks)?;
            CHANNEL.with(|p| *p.borrow_mut() = Some(hand));
            Ok(vec![])
        }
        71 => {
            let length = u32::from_le_bytes(
                bytes
                    .get(..4)
                    .ok_or("missing channel journal length")?
                    .try_into()?,
            ) as usize;
            let (journal, artifact) = bytes
                .get(4..)
                .ok_or("missing channel checkpoint")?
                .split_at_checked(length)
                .ok_or("truncated channel checkpoint")?;
            let hand = ChannelHand::restore(journal, artifact)?;
            CHANNEL.with(|p| *p.borrow_mut() = Some(hand));
            Ok(vec![])
        }
        61..=70 | 72..=77 | 90..=103 => CHANNEL.with(|p| {
            let mut p = p.borrow_mut();
            let hand = p.as_mut().ok_or("channel not initialized")?;
            match op {
                61 => {
                    let owner = usize::from(*bytes.first().ok_or("missing setup owner")?);
                    let setup_op = u32::from(*bytes.get(1).ok_or("missing setup operation")?);
                    if !matches!(setup_op, 3..=16 | 29 | 37..=39 | 52..=53) {
                        return Err("operation not allowed during channel setup".into());
                    }
                    session_operation(hand.setup_session(owner)?, setup_op, &bytes[2..])
                }
                62 => json(&hand.entry_frame()?),
                63 => json(&hand.receive(serde_json::from_slice(bytes)?)?),
                64 => json(&hand.propose(serde_json::from_slice(bytes)?)?),
                65 => json(&hand.watch_package()?),
                66 => Ok(hand.watch_digest()?.to_vec()),
                67 => json(&hand.authorize_watch(bytes.try_into()?)?),
                68 => json(&hand.view()?),
                69 => Ok(hand.checkpoint_journal()?.to_vec()),
                70 => hand.checkpoint_artifact(),
                72 => hand.begin_close(),
                73 => json(&hand.needs_watch()),
                101 => { hand.defer_payouts()?; Ok(vec![]) },
                103 => {hand.share_accepted_dealer()?; Ok(vec![])},
                102 => json(&hand.bind_payouts(serde_json::from_slice(bytes)?)?),
                99 => json(&hand.launch_signatures()?),
                100 => {hand.accept_prepared_launches(serde_json::from_slice(bytes)?)?;Ok(vec![])},
                90 => { #[derive(Deserialize)] struct Future {index:u32,anchor:[u8;32],stacks:[u64;2]}
                    let f:Future=serde_json::from_slice(bytes)?;json(&hand.future_terms(f.index,f.anchor,f.stacks)?) },
                91 => hand.prepared_certificate(),
                92 => hand.select_candidate(bytes),
                93 => {hand.authorize_entry(bytes)?;Ok(vec![])},
                94 => hand.play_certificate(),
                95 => {hand.authorize_play(bytes)?;Ok(vec![])},
                96 => json(&hand.reachable_balances()?),
                97 => {let terms:Terms=serde_json::from_slice(bytes)?;let anchor=terms.predeal_anchor.ok_or("missing slot")?;
                    let fork=hand.fork_predeal(terms)?;DEALS.with(|d|{d.borrow_mut().insert(anchor,fork);});Ok(vec![])},
                98 => {let terms:Terms=serde_json::from_slice(bytes)?;let anchor=terms.predeal_anchor.ok_or("missing slot")?;
                    let next=DEALS.with(|d|d.borrow().get(&anchor).ok_or("accepted slot not cached")?.fork_predeal(terms))?;
                    *hand=next;Ok(vec![])},
                74 => hand.successor_certificate(),
                75 => json(&hand.begin_handoff(bytes)?),
                76 => hand.begin_cashout(serde_json::from_slice(bytes)?),
                77 => { hand.accept_cashout(bytes)?; Ok(vec![]) },
                _ => Err("unknown channel command".into()),
            }
        }),
        1 => {
            let init: Init = serde_json::from_slice(bytes)?;
            let s = Session::new(init.seed, init.terms)?;
            SESSION.with(|p| *p.borrow_mut() = Some(s));
            Ok(vec![])
        }
        2 => json(&poker_session::public_keys(&bytes.try_into()?)?),
        17 => {
            let s = Session::restore(bytes)?;
            SESSION.with(|p| *p.borrow_mut() = Some(s));
            Ok(vec![])
        }
        34 => {
            let length =
                u32::from_le_bytes(bytes.get(..4).ok_or("missing crypto header")?.try_into()?)
                    as usize;
            if length > 4096 {
                return Err("crypto header too large".into());
            }
            let end = 4 + length;
            let i: CryptoInit =
                serde_json::from_slice(bytes.get(4..end).ok_or("truncated crypto header")?)?;
            let w = CryptoWorker::new(
                bytes.get(end..).ok_or("missing inventory")?,
                if i.regtest {
                    bitcoin::Network::Regtest
                } else {
                    bitcoin::Network::Signet
                },
                i.key,
                i.material,
            )?;
            CRYPTO.with(|p| *p.borrow_mut() = Some(w));
            Ok(vec![])
        }
        30 => {
            let i: CryptoInit = serde_json::from_slice(bytes)?;
            let w = CryptoWorker::new(
                &hex::decode(i.inventory)?,
                if i.regtest {
                    bitcoin::Network::Regtest
                } else {
                    bitcoin::Network::Signet
                },
                i.key,
                i.material,
            )?;
            CRYPTO.with(|p| *p.borrow_mut() = Some(w));
            Ok(vec![])
        }
        31..=33 | 35 => CRYPTO.with(|w| {
            let w = w.borrow();
            let w = w.as_ref().ok_or("crypto worker not initialized")?;
            match op {
                31 | 35 => {
                    if bytes.len() % 4 != 0 {
                        return Err("malformed indices".into());
                    }
                    let indices = bytes
                        .chunks_exact(4)
                        .map(|b| Ok(u32::from_le_bytes(b.try_into()?)))
                        .collect::<Result<Vec<_>>>()?;
                    if op == 35 { w.sign_receipt(&indices) } else { w.sign(&indices) }
                }
                32 => w.verify(bytes),
                _ => Ok(w.manifest()),
            }
        }),
        86 => {
            let terms:Terms=serde_json::from_slice(bytes)?;
            json(&poker_settlement::graph::required_fee_reserve(&terms.parameters()?.rules,&terms.fees()?)?)
        }
        83 => {
            let b: poker_session::buyin::BuyIn = serde_json::from_slice(bytes)?;
            Ok(bitcoin::consensus::serialize(&b.template()?.0))
        }
        84 => {
            #[derive(Deserialize)]
            struct Input {
                buyin: poker_session::buyin::BuyIn,
                secret: [u8; 32],
                index: usize,
            }
            let i: Input = serde_json::from_slice(bytes)?;
            i.buyin.sign(i.secret, i.index)
        }
        85 => {
            #[derive(Deserialize)]
            struct Input {
                buyin: poker_session::buyin::BuyIn,
                signatures: Vec<String>,
            }
            let i: Input = serde_json::from_slice(bytes)?;
            i.buyin.finish(
                &i.signatures
                    .iter()
                    .map(hex::decode)
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )
        }
        40 => {
            let secret = bytes.try_into()?;
            json(
                &serde_json::json!({"address":poker_session::funding::sponsor_address(secret)?,"script":hex::encode(poker_session::funding::sponsor_script(secret)?.as_bytes())}),
            )
        }
        41 => {
            let f: Fund = serde_json::from_slice(bytes)?;
            poker_session::funding::fund(
                f.secret,
                &hex::decode(f.previous)?,
                f.vout,
                f.identities,
                f.value,
                f.fee,
            )
        }
        42 => {
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(bytes)?;
            json(
                &serde_json::json!({"txid":tx.compute_txid().to_string(),"vsize":tx.vsize(),"outputs":tx.output.iter().map(|o|serde_json::json!({"value":o.value.to_sat(),"script":hex::encode(o.script_pubkey.as_bytes())})).collect::<Vec<_>>()}),
            )
        }
        43 => {
            #[derive(Deserialize)]
            struct Input {
                rollover: poker_session::rollover::Rollover,
                secret: [u8; 32],
            }
            let i: Input = serde_json::from_slice(bytes)?;
            let (tx, _) = i.rollover.template()?;
            json(
                &serde_json::json!({"funding":hex::encode(bitcoin::consensus::serialize(&tx)),"signature":hex::encode(i.rollover.sponsor_signature(i.secret)?)}),
            )
        }
        44 => {
            #[derive(Deserialize)]
            struct Input {
                rollover: poker_session::rollover::Rollover,
                signatures: Vec<String>,
            }
            let i: Input = serde_json::from_slice(bytes)?;
            i.rollover.finish(
                &i.signatures
                    .iter()
                    .map(hex::decode)
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )
        }
        45 => {
            let r: poker_session::rollover::Rollover = serde_json::from_slice(bytes)?;
            Ok(bitcoin::consensus::serialize(&r.template()?.0))
        }
        _ => SESSION.with(|p| {
            let mut p = p.borrow_mut();
            let s = p.as_mut().ok_or("session not initialized")?;
            session_operation(s, op, bytes)
        }),
    }
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_call(op: u32) -> u32 {
    let result = INPUT.with(|i| call(op, &i.borrow()));
    INPUT.with(|i| i.borrow_mut().zeroize());
    OUTPUT.with(|o| o.borrow_mut().zeroize());
    match result {
        Ok(b) => {
            OUTPUT.with(|o| *o.borrow_mut() = b);
            1
        }
        Err(e) => {
            ERROR.with(|o| *o.borrow_mut() = e.to_string().into_bytes());
            0
        }
    }
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn session_clear() {
    SESSION.with(|s| *s.borrow_mut() = None);
    CRYPTO.with(|s| *s.borrow_mut() = None);
    CHANNEL.with(|s| *s.borrow_mut() = None);
    DEALS.with(|s| s.borrow_mut().clear());
    INPUT.with(|b| b.borrow_mut().zeroize());
    OUTPUT.with(|b| b.borrow_mut().zeroize());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_crypto_header_is_bounded_and_complete() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                assert!(call(34, &[]).is_err());
                assert!(call(34, &4097u32.to_le_bytes()).is_err());
                assert!(call(34, &100u32.to_le_bytes()).is_err());
                let mut empty = 2u32.to_le_bytes().to_vec();
                empty.extend_from_slice(b"{}");
                assert!(call(34, &empty).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
