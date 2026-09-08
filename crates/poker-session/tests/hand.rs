use bitcoin::{Amount, consensus::deserialize};
use poker_core_test_support::{CoreCli, PathExecutor};
use poker_session::crypto::CryptoWorker;
use poker_session::*;
use poker_settlement::settlement::build_origin_escrow;
fn hand(core: Option<CoreCli>, scenario: &str) -> Result<()> {
    let mut seeds = [[3; 32], [5; 32]];
    seeds.sort_by_key(|s| public_keys(s).map(|k| k.identity).unwrap_or([0; 32]));
    let a = public_keys(&seeds[0])?;
    let b = public_keys(&seeds[1])?;
    let mut t = Terms {
        slot: None,
        predeal_anchor: None,
        fee_reserve: None,
        regtest: true,
        identities: [a.identity, b.identity],
        reveal_keys: [b.reveal, a.reveal],
        origin: format!("{}:0", "01".repeat(32)),
        origin_value: 45_900,
        nonce: [7; 32],
        full: false,
        fee_multiplier: 1.0,
        csv: 2,
        stacks: None,
        button: None,
    };
    if matches!(scenario, "showdown" | "predeal") {
        t.stacks = Some([400, 600]);
        t.origin_value = 46_500;
    }
    let mut path = None;
    let mining = core.as_ref().map(|c| c.new_address()).transpose()?;
    if let Some(c) = &core {
        c.assert_regtest()?;
        let mining = mining.as_ref().ok_or("mining address")?;
        c.mine(101, mining)?;
        let p = PathExecutor::fund(
            c,
            mining,
            &build_origin_escrow(t.identities)?.script_pubkey(),
            Amount::from_sat(t.origin_value),
        )?;
        t.origin = p.tip().ok_or("no origin")?.outpoint().to_string();
        path = Some(p);
    }
    let final_terms = if scenario == "predeal" {
        t.predeal_anchor = Some([42; 32]);
        let final_terms = t.clone();
        t.origin = format!("{}:1", "02".repeat(32));
        t.stacks = Some([200, 200]);
        t.origin_value = 45_900;
        Some(final_terms)
    } else {
        None
    };
    let mut players = [
        Session::new(seeds[0], t.clone())?,
        Session::new(seeds[1], t)?,
    ];
    if scenario == "refund" {
        let destination = funding::sponsor_script([9; 32])?;
        let peer = players[1].refund_signature(destination.as_bytes())?;
        let tx = players[0].refund(destination.as_bytes(), &peer)?;
        if let Some(p) = &mut path {
            p.finish(&deserialize(&tx)?, "session refund")?;
        }
        return Ok(());
    }

    if let Some(final_terms) = final_terms {
        deal_players(&mut players)?;
        for player in &mut players {
            assert_eq!(player.dealer_status()["accepted"], true);
            for changed in 0..4 {
                let mut invalid = final_terms.clone();
                match changed {
                    0 => invalid.nonce[0] ^= 1,
                    1 => invalid.predeal_anchor = Some([43; 32]),
                    2 => invalid.csv += 1,
                    _ => invalid.button = Some(1),
                }
                assert!(player.bind_predeal(invalid).is_err());
            }
            player.bind_predeal(final_terms.clone())?;
            *player = Session::restore(&player.checkpoint()?)?;
            assert_eq!(player.dealer_status()["accepted"], true);
        }
    }
    prepare_players(&mut players)?;
    let sigs = [
        players[0].activation_signature()?,
        players[1].activation_signature()?,
    ];
    let mut tx = players[0].activation(&sigs[1])?;
    assert_eq!(tx, players[1].activation(&sigs[0])?);
    for step in 0..40 {
        let terminal = if let Some(p) = &mut path {
            let transaction = deserialize(&tx)?;
            if transaction_outputs(&tx)? > 1 {
                p.finish(&transaction, "session payout")?;
                true
            } else {
                p.advance(&transaction, 0, "session transition")?;
                false
            }
        } else {
            false
        };
        let record = ChainRecord {
            transaction: tx.clone(),
            height: 110 + step * 3,
            block_hash: "01".repeat(32),
        };
        for p in &mut players {
            p.observe(record.clone())?;
        }
        let displays = [players[0].view()?, players[1].view()?];
        assert_eq!(
            displays[0]["board"], displays[1]["board"],
            "community cards must become public together"
        );
        if displays[0]["phase"] == "Some(DealAlice)" {
            assert_eq!(displays[0]["holeCards"], serde_json::json!([null, null]));
            assert_eq!(displays[1]["holeCards"], serde_json::json!([null, null]));
        }
        if displays[0]["phase"] == "Some(DealBob)" {
            assert!(
                displays[0]["holeCards"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|c| c.is_u64())
            );
            assert_eq!(displays[1]["holeCards"], serde_json::json!([null, null]));
        }
        if displays[0]["phase"] == "Some(FlopRevealSecond)" {
            assert_eq!(
                displays[0]["board"],
                serde_json::json!([null, null, null, null, null])
            );
        }
        if players[0].view()?["terminal"] == true {
            if matches!(scenario, "showdown" | "predeal") {
                assert_eq!(
                    players[0].view()?["opponentCards"],
                    players[1].view()?["holeCards"]
                );
                assert_eq!(
                    players[1].view()?["opponentCards"],
                    players[0].view()?["holeCards"]
                );
            }
            if path.is_some() {
                assert!(terminal);
            }
            assert_eq!(players[0].view()?["tip"], players[1].view()?["tip"]);
            let settled: bitcoin::Transaction = deserialize(&tx)?;
            for (role, player) in players.iter().enumerate() {
                let script = funding::sponsor_script([role as u8 + 11; 32])?;
                let cashout:bitcoin::Transaction = deserialize(&player.cashout(script.as_bytes(),111)?)?;
                assert_eq!(cashout.vsize(),111);
                assert_eq!(cashout.input[0].previous_output.vout,role as u32);
                assert_eq!(cashout.input[0].previous_output.txid,settled.compute_txid());
                assert_eq!(cashout.output[0].script_pubkey,script);
                assert_eq!(cashout.output[0].value.to_sat(),settled.output[role].value.to_sat()-111);
                use bitcoin::{sighash::{SighashCache,Prevouts},TapSighashType,hashes::Hash};
                let digest=SighashCache::new(&cashout).taproot_key_spend_signature_hash(0,&Prevouts::All(&[settled.output[role].clone()]),TapSighashType::Default)?.to_byte_array();
                bitcoin::secp256k1::Secp256k1::verification_only().verify_schnorr(&bitcoin::secp256k1::schnorr::Signature::from_slice(cashout.input[0].witness.iter().next().unwrap())?,&bitcoin::secp256k1::Message::from_digest(digest),&bitcoin::secp256k1::XOnlyPublicKey::from_slice(&settled.output[role].script_pubkey.as_bytes()[2..])?)?;
            }

            rollover_check(
                &players,
                core.as_ref(),
                mining.as_deref(),
                scenario == "showdown",
            )?;
            return Ok(());
        }
        let view = players[0].view()?;
        let mut role = view["actor"].as_u64().ok_or("actor")? as usize;
        let mut edge = None;
        let mut height = 110 + step * 3;
        if scenario == "fold" {
            edge = view["actions"]
                .as_array()
                .ok_or("actions")?
                .iter()
                .find(|e| e["kind"].as_str().is_some_and(|s| s.contains("Fold")))
                .and_then(|e| e["index"].as_u64())
                .map(|i| i as usize);
        }
        if scenario == "timeout" {
            let e = view["actions"]
                .as_array()
                .ok_or("actions")?
                .iter()
                .find(|e| e["timeoutHeight"].is_number())
                .ok_or("timeout")?;
            role = e["beneficiary"].as_u64().ok_or("beneficiary")? as usize;
            edge = e["index"].as_u64().map(|i| i as usize);
            assert!(players[role].action(edge, height).is_err());
            height = e["timeoutHeight"].as_u64().ok_or("height")? as u32;
            if let Some(p) = &mut path {
                p.mine_empty_blocks(2)?;
            }
        }
        if matches!(scenario, "showdown" | "predeal") {
            let before = players[1 - role].checkpoint()?;
            assert!(players[1 - role].action(None, height).is_err());
            assert_eq!(*before, *players[1 - role].checkpoint()?);
            if view["phase"] == "Some(AliceShowdown)" {
                edge = Some(0);
            }
        }
        tx = players[role].action(edge, height)?;
        // A persisted pending action is replayed byte-for-byte after reload.
        players[role] = Session::restore(&players[role].checkpoint()?)?;
        assert_eq!(tx, players[role].action(None, 110 + step)?);
    }
    Err("hand did not finish".into())
}
fn transaction_outputs(bytes: &[u8]) -> Result<usize> {
    Ok(deserialize::<bitcoin::Transaction>(bytes)?.output.len())
}
#[test]
fn predealt_players_bind_final_funding_and_complete() -> Result<()> {
    large_stack(false, "predeal")
}
#[test]
fn isolated_players_complete_and_restore() -> Result<()> {
    large_stack(false, "showdown")
}
#[test]
#[ignore = "requires managed Bitcoin Core"]
fn core_players_complete_and_restore() -> Result<()> {
    large_stack(true, "showdown")
}
fn large_stack(core: bool, scenario: &'static str) -> Result<()> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(move || {
            hand(
                if core {
                    Some(
                        CoreCli::from_environment()
                            .map_err(|e| e.to_string())?
                            .ok_or("Core environment required")?,
                    )
                } else {
                    None
                },
                scenario,
            )
            .map_err(|e| e.to_string())
        })?
        .join()
        .map_err(|_| "test thread panicked")?
        .map_err(Into::into)
}

#[test]
#[ignore = "requires managed Bitcoin Core"]
fn core_refund() -> Result<()> {
    large_stack(true, "refund")
}
#[test]
#[ignore = "requires managed Bitcoin Core"]
fn core_timeout() -> Result<()> {
    large_stack(true, "timeout")
}
#[test]
#[ignore = "requires managed Bitcoin Core"]
fn core_fold() -> Result<()> {
    large_stack(true, "fold")
}

fn rollover_check(
    players: &[Session; 2],
    core: Option<&CoreCli>,
    mining: Option<&str>,
    play: bool,
) -> Result<()> {
    use bitcoin::{ScriptBuf, Transaction, TxOut, absolute, consensus::serialize, transaction};
    let secret = [19; 32];
    let script = funding::sponsor_script(secret)?;
    let (previous, vout) = if let Some(c) = core {
        let coin = c.fund_script(&script, Amount::from_sat(100_000), mining.ok_or("mining")?)?;
        (
            serde_json::from_str::<serde_json::Value>(
                &c.rpc("gettransaction", &[coin.outpoint().txid.to_string()])?,
            )?["hex"]
                .as_str()
                .ok_or("wallet transaction bytes")?
                .to_owned(),
            coin.outpoint().vout,
        )
    } else {
        (
            hex::encode(serialize(&Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: script.clone(),
                }],
            })),
            0,
        )
    };
    let mut seeds = [[23; 32], [29; 32]];
    seeds.sort_by_key(|s| public_keys(s).unwrap().identity);
    let keys = [public_keys(&seeds[0])?, public_keys(&seeds[1])?];
    let info = players[0].rollover_info()?;
    let r = rollover::Rollover {
        previous: info["previous"].as_str().ok_or("previous")?.into(),
        sponsor_previous: previous,
        sponsor_vout: vout,
        sponsor_script: hex::encode(script.as_bytes()),
        identities: [keys[0].identity, keys[1].identity],
        value: 46_500,
        fee: 1000,
    };
    let signatures = [
        players[0].rollover_signature(&r)?,
        players[1].rollover_signature(&r)?,
        r.sponsor_signature(secret)?,
    ];
    let raw = r.finish(&signatures)?;
    let tx: Transaction = deserialize(&raw)?;
    let mut corrupt = signatures.clone();
    corrupt[0][0] ^= 1;
    assert!(r.finish(&corrupt).is_err());
    let mut wrong = r.clone();
    wrong.previous = r.sponsor_previous.clone();
    assert!(players[0].rollover_signature(&wrong).is_err());
    let terms = Terms {
        slot: None,
        predeal_anchor: None,
        fee_reserve: None,
        regtest: true,
        identities: r.identities,
        reveal_keys: [keys[1].reveal, keys[0].reveal],
        origin: format!("{}:0", tx.compute_txid()),
        origin_value: r.value,
        nonce: [31; 32],
        full: false,
        fee_multiplier: 1.0,
        csv: 2,
        stacks: Some(if play {
            serde_json::from_value(info["nextStacks"].clone())?
        } else {
            [400, 600]
        }),
        button: Some(1),
    };
    assert_eq!(
        terms.parameters()?.rules.button,
        poker_settlement_types::Role::Bob
    );
    let a = Session::new(seeds[0], terms.clone())?;
    let b = Session::new(seeds[1], terms)?;
    let return_sig = b.rollover_refund_signature(&r)?;
    let refund: Transaction = deserialize(&a.rollover_refund(&r, &return_sig)?)?;
    let old: Transaction = deserialize(&hex::decode(&r.previous)?)?;
    assert_eq!(&refund.output[..2], old.output.as_slice());
    assert_eq!(
        refund.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
        r.value - 500
    );
    assert_ne!(refund.output[2].script_pubkey, ScriptBuf::new());
    assert!(
        a.rollover_signature(&r).is_err(),
        "unsettled sessions cannot roll over"
    );
    if let Some(c) = core {
        let id = c.accept_and_broadcast(&tx, "rollover funding")?;
        c.mine_and_assert_included(id, mining.ok_or("mining")?)?;
        if !play {
            let id =
                c.accept_and_broadcast(&refund, "rollover cancellation restores both payouts")?;
            c.mine_and_assert_included(id, mining.ok_or("mining")?)?;
        }
    }
    if play {
        let mut next = [a, b];
        prepare_players(&mut next)?;
        let mut raw = next[0].activation(&next[1].activation_signature()?)?;
        for step in 0..6 {
            if let Some(c) = core {
                let id = c.accept_and_broadcast(&deserialize(&raw)?, "second hand transition")?;
                c.mine_and_assert_included(id, mining.ok_or("mining")?)?;
            }
            for p in &mut next {
                p.observe(ChainRecord {
                    transaction: raw.clone(),
                    height: 500 + step,
                    block_hash: "01".repeat(32),
                })?;
            }
            let view = next[0].view()?;
            if view["terminal"] == true {
                return Ok(());
            }
            let role = view["actor"].as_u64().ok_or("second actor")? as usize;
            let edge = if view["betting"] == true {
                assert_eq!(
                    role, 1,
                    "the second seat is now dealer and acts first preflop"
                );
                Some(
                    view["actions"]
                        .as_array()
                        .ok_or("actions")?
                        .iter()
                        .find(|e| e["kind"] == "Action(Fold)")
                        .ok_or("fold")?["index"]
                        .as_u64()
                        .ok_or("fold index")? as usize,
                )
            } else {
                None
            };
            raw = next[role].action(edge, 500 + step)?;
            next[role] = Session::restore(&next[role].checkpoint()?)?;
            assert_eq!(raw, next[role].action(None, 500 + step)?);
        }
        return Err("second hand did not settle".into());
    }

    Ok(())
}

fn deal_players(players: &mut [Session; 2]) -> Result<()> {
    for _ in 0..100 {
        if players[0].dealer_status()["accepted"] == true {
            break;
        }
        if players[0].dealer_status()["retry"] == true
            && players[1].dealer_status()["retry"] == true
        {
            let attempt = players[0].dealer_status()["attempt"]
                .as_u64()
                .ok_or("attempt")? as u32
                + 1;
            for p in players.iter_mut() {
                p.retry(attempt)?;
            }
            continue;
        }
        let messages = [players[0].outgoing()?, players[1].outgoing()?];
        for i in 0..2 {
            if let Some(b) = &messages[i] {
                players[i].confirm_outgoing(b)?;
            }
        }
        for i in 0..2 {
            if let Some(b) = &messages[i] {
                players[1 - i].accept_peer(b)?;
            }
        }
    }
    Ok(())
}
fn prepare_players(players: &mut [Session; 2]) -> Result<()> {
    deal_players(players)?;
    let scores = [players[0].score_public()?, players[1].score_public()?];
    for i in 0..2 {
        players[i].accept_score(&scores[1 - i])?;
        players[i].prepare()?;
    }
    let inventory = players[0].inventory()?;
    assert_eq!(inventory, players[1].inventory()?);
    let workers = [
        CryptoWorker::new(
            &inventory,
            bitcoin::Network::Regtest,
            players[0].receipt_key(),
            players[0].signing_material(),
        )?,
        CryptoWorker::new(
            &inventory,
            bitcoin::Network::Regtest,
            players[1].receipt_key(),
            players[1].signing_material(),
        )?,
    ];
    for role in 0..2 {
        let manifest = workers[role].manifest();
        let indices: Vec<_> = manifest
            .chunks_exact(2)
            .enumerate()
            .filter(|(_, m)| m[0] == role as u8)
            .map(|(i, _)| i as u32)
            .collect();
        let bytes = workers[role].sign(&indices)?;
        for i in 0..2 {
            players[i].accept_batch(&workers[i].verify(&bytes)?)?;
        }
    }
    for p in players.iter_mut() {
        p.finish_preparation()?;
        let mut split = p.checkpoint_journal()?;
        assert!(!p.checkpoint_artifact().is_empty());
        split.extend_from_slice(p.checkpoint_artifact());
        assert_eq!(*split, *p.checkpoint()?);
        *p = Session::restore(&split)?;
    }
    Ok(())
}
