use bitcoin::Network;
use poker_session::{
    channel::{ChannelHand, Frame},
    crypto::CryptoWorker,
    public_keys, Result, Terms,
};

#[test]
fn cooperative_complete_hand_both_roots_without_chain_observations() -> Result<()> {
    std::thread::Builder::new()
        .stack_size(128 * 1024 * 1024)
        .spawn(|| run().map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "channel test panicked")?
        .map_err(Into::into)
}

fn run() -> Result<()> {
    let mut seeds = [[3; 32], [5; 32]];
    seeds.sort_by_key(|s| public_keys(s).map(|k| k.identity).unwrap_or([0; 32]));
    let a = public_keys(&seeds[0])?;
    let b = public_keys(&seeds[1])?;
    let terms = Terms {
        slot: None,
        predeal_anchor: Some([9;32]),
        fee_reserve: None,
        regtest: true,
        identities: [a.identity, b.identity],
        reveal_keys: [b.reveal, a.reveal],
        origin: format!("{}:0", "01".repeat(32)),
        origin_value: 46_800,
        nonce: [7; 32],
        full: false,
        fee_multiplier: 1.0,
        csv: 2,
        stacks: Some([400, 400]),
        button: None,
    };
    let mut players = prepare_players(seeds, terms.clone())?;
    let mut restored_bet = false;
    let mut restored_reveal = false;
    for _ in 0..40 {
        let view = players[0].view()?;
        assert_eq!(view["node"], players[1].view()?["node"]);
        assert_eq!(view["height"], 0);
        assert_eq!(view["feeReserve"], 45_000);
        if view["terminal"] == true {
            assert_eq!(view["nextStacks"], players[1].view()?["nextStacks"]);
            for player in &mut players {
                restore_at_cut(player)?;
            }
            qualify_cashout(&players, &terms)?;
            return qualify_handoff(&mut players, seeds);
        }
        let restore = (view["betting"] == true && !restored_bet)
            || (view["revealing"] == true && !restored_reveal);
        let role = view["actor"].as_u64().ok_or("actor")? as usize;
        let before = view["node"].clone();
        players[role].propose(None)?;
        if restore {
            restore_at_cut(&mut players[role])?;
        }
        assert!(players[role].authorize_watch([0; 32]).is_err());
        let frame = players[role]
            .authorize_watch(players[role].watch_digest()?)?
            .ok_or("move")?;
        if restore {
            restore_at_cut(&mut players[role])?;
        }
        assert_eq!(players[role].view()?["node"], before);
        if let Frame::Move {
            mut authorization,
            retirement,
        } = frame.clone()
        {
            if view["betting"] == true {
                assert_eq!(authorization.witness_elements[0].len(), 1);
                assert_eq!(authorization.witness_elements[1].len(), 1);
                assert_eq!(authorization.witness_elements[0][0].len(), 64);
            }
            if let Some(byte) = authorization.witness_elements[0]
                .iter_mut()
                .find_map(|element| element.first_mut())
            {
                *byte ^= 1;
            }
            assert!(players[1 - role]
                .receive(Frame::Move {
                    authorization,
                    retirement
                })
                .is_err());
            assert_eq!(players[1 - role].view()?["node"], before);
        }
        players[1 - role].receive(frame.clone())?;
        if restore {
            restore_at_cut(&mut players[1 - role])?;
        }
        assert_eq!(players[1 - role].view()?["node"], before);
        let ack = players[1 - role]
            .authorize_watch(players[1 - role].watch_digest()?)?
            .ok_or("ack")?;
        players[role].receive(ack.clone())?;
        if restore {
            restore_at_cut(&mut players[role])?;
        }
        players[role].authorize_watch(players[role].watch_digest()?)?;
        assert!(players[1 - role].receive(frame)?.is_some());
        players[role].receive(ack)?;
        restored_bet |= view["betting"] == true;
        restored_reveal |= view["revealing"] == true;
    }
    Err("channel hand did not finish".into())
}

fn restore_at_cut(player: &mut ChannelHand) -> Result<()> {
    let before = player.view()?;
    let digest = player.watch_digest()?;
    let journal = player.checkpoint_journal()?;
    let artifact = player.checkpoint_artifact()?;
    *player = ChannelHand::restore(&journal, &artifact)?;
    assert_eq!(player.view()?, before);
    assert_eq!(player.watch_digest()?, digest);
    Ok(())
}

fn prepare_players(seeds: [[u8; 32]; 2], terms: Terms) -> Result<[ChannelHand; 2]> {
    let mut players = prepare_candidates(seeds, terms)?;
    enter_players(&mut players)?;
    Ok(players)
}
fn prepare_candidates(seeds: [[u8; 32]; 2], terms: Terms) -> Result<[ChannelHand; 2]> {
    prepare_candidates_inner(seeds,terms,false)
}
fn prepare_candidates_inner(seeds: [[u8; 32]; 2], terms: Terms, deferred:bool) -> Result<[ChannelHand; 2]> {
    let mut players = [
        ChannelHand::new(seeds[0], terms.clone(), 3)?,
        ChannelHand::new(seeds[1], terms, 3)?,
    ];
    if deferred { for p in &mut players {p.defer_payouts()?;} }
    for owner in 0..2 {
        for _ in 0..100 {
            if players[0].setup_session(owner)?.dealer_status()["accepted"] == true {
                break;
            }
            if players[0].setup_session(owner)?.dealer_status()["retry"] == true
                && players[1].setup_session(owner)?.dealer_status()["retry"] == true
            {
                let attempt = players[0].setup_session(owner)?.dealer_status()["attempt"]
                    .as_u64()
                    .ok_or("attempt")? as u32
                    + 1;
                for player in &mut players {
                    player.setup_session(owner)?.retry(attempt)?;
                }
                continue;
            }
            let messages = [
                players[0].setup_session(owner)?.outgoing()?,
                players[1].setup_session(owner)?.outgoing()?,
            ];
            for i in 0..2 {
                if let Some(bytes) = &messages[i] {
                    players[i].setup_session(owner)?.confirm_outgoing(bytes)?;
                    players[1 - i].setup_session(owner)?.accept_peer(bytes)?;
                }
            }
        }
        if owner==0 {for player in &mut players {player.share_accepted_dealer()?;}}
        let scores = [
            players[0].setup_session(owner)?.score_public()?,
            players[1].setup_session(owner)?.score_public()?,
        ];
        for i in 0..2 {
            players[i]
                .setup_session(owner)?
                .accept_score(&scores[1 - i])?;
        }
        let commitments = [
            players[0].setup_session(owner)?.channel_commitments()?,
            players[1].setup_session(owner)?.channel_commitments()?,
        ];
        let nodes = u32::from_le_bytes(commitments[0][42..46].try_into()?) as usize;
        assert_eq!(commitments[0].len() + commitments[1].len(), 92 + nodes * 32);
        for i in 0..2 {
            let peer = &commitments[1 - i];
            let mut extra = peer.clone(); extra.push(0);
            let mut foreign = peer.clone(); foreign[8] ^= 1;
            let mut wrong_owner = peer.clone(); wrong_owner[40] ^= 1;
            let mut zero = peer.clone(); zero[46..78].fill(0);
            for invalid in [&peer[..peer.len()-1], &extra, &foreign, &wrong_owner, &zero, &commitments[i]] {
                assert!(players[i].setup_session(owner)?.accept_channel_commitments(invalid).is_err());
            }
            players[i]
                .setup_session(owner)?
                .accept_channel_commitments(peer)?;
            if i == 0 {
                players[i].setup_session(owner)?.prepare()?;
            } else {
                let snapshot = players[i].setup_session(owner)?.checkpoint()?;
                let mut worker = poker_session::Session::restore(&snapshot)?;
                worker.prepare()?;
                let receipt = worker.construction_receipt()?;
                let job=players[i].setup_session(owner)?.construction_job()?;
                let delegated=poker_session::Session::construct_local(&job)?;
                assert_eq!(delegated,receipt,"local delegation must construct identical transactions");
                let mut tampered=job.clone();
                *tampered.last_mut().ok_or("empty job")?^=1;
                assert!(poker_session::Session::construct_local(&tampered).is_err());
                assert!(poker_session::Session::construct_local(&job[..job.len()-1]).is_err());
                let mut corrupt = receipt.clone();
                corrupt[20] ^= 1;
                assert!(players[i]
                    .setup_session(owner)?
                    .accept_construction(&corrupt)
                    .is_err());
                assert!(players[i]
                    .setup_session(1 - owner)?
                    .accept_construction(&receipt)
                    .is_err());
                players[i]
                    .setup_session(owner)?
                    .accept_construction(&receipt)?;
                assert!(players[i]
                    .setup_session(owner)?
                    .accept_construction(&receipt)
                    .is_err());
            }
        }
        let inventory = players[0].setup_session(owner)?.inventory()?;
        assert_eq!(inventory, players[1].setup_session(owner)?.inventory()?);
        let workers = [0, 1].map(|i| {
            let session = players[i].setup_session(owner)?;
            CryptoWorker::new(
                &inventory,
                Network::Regtest,
                session.receipt_key(),
                session.signing_material(),
            )
        });
        let [a, b] = workers;
        let workers = [a?, b?];
        for role in 0..2 {
            let work=players[role].setup_session(owner)?.preparation_work()?;
            let manifest = workers[role].manifest();
            let indices: Vec<_> = manifest
                .chunks_exact(2)
                .enumerate()
                .filter(|(i, m)| m[0] == role as u8 && work.contains(i))
                .map(|(i, _)| i as u32)
                .collect();
            let mut batches=vec![];let mut batch=vec![];let mut weight=0;
            for index in indices {
                let w=if manifest[index as usize*2+1]==0 {1}else{64};
                if weight+w>2048 {batches.push(std::mem::take(&mut batch));weight=0;}
                batch.push(index);weight+=w;
            }
            if !batch.is_empty() {batches.push(batch);}
            for batch in batches {
                let receipt = workers[role].sign_receipt(&batch)?;
                let signatures = receipt[..receipt.len() - 32].to_vec();
                assert_eq!(receipt, workers[role].verify(&signatures)?);
                for i in 0..2 {
                    players[i].setup_session(owner)?.accept_batch(&workers[i].verify(&signatures)?)?;
                }
            }
        }
        for player in &mut players {
            player.setup_session(owner)?.finish_preparation()?;
        }
        assert!(players[owner]
            .setup_session(owner)?
            .peer_root_signature()
            .is_err());
    }
    if deferred {return Ok(players);}
    let launches = [
        players[0].launch_signatures()?,
        players[1].launch_signatures()?,
    ];
    for i in 0..2 {
        players[i].accept_prepared_launches(launches[1 - i].clone())?;
    }
    Ok(players)
}
fn enter_players(players: &mut [ChannelHand; 2]) -> Result<()> {
    let entries = [players[0].entry_frame()?, players[1].entry_frame()?];
    for i in 0..2 {
        players[i].receive(entries[1 - i].clone())?;
    }
    for player in players.iter_mut() {
        restore_at_cut(player)?;
    }
    let ready = [
        players[0]
            .authorize_watch(players[0].watch_digest()?)?
            .ok_or("ready")?,
        players[1]
            .authorize_watch(players[1].watch_digest()?)?
            .ok_or("ready")?,
    ];
    for i in 0..2 {
        players[i].receive(ready[1 - i].clone())?;
    }
    Ok(())
}

fn qualify_handoff(players: &mut [ChannelHand; 2], seeds: [[u8; 32]; 2]) -> Result<()> {
    let stacks = serde_json::from_value(players[0].view()?["nextStacks"].clone())?;
    let terms = players[0].future_terms(1, [9; 32], stacks)?;
    let later = players[0].future_terms(2, [10; 32], stacks)?;
    assert_eq!(later.slot.as_ref().unwrap().index, 2);
    let mut next = prepare_candidates(seeds, terms.clone())?;
    for i in 0..2 {
        assert!(next[i].entry_frame().is_err());
        let prepared = next[i].prepared_certificate()?;
        let certificate = players[i].select_candidate(&prepared)?;
        restore_at_cut(&mut players[i])?;
        let mut closing = ChannelHand::restore(
            &players[i].checkpoint_journal()?,
            &players[i].checkpoint_artifact()?,
        )?;
        closing.begin_close()?;
        restore_at_cut(&mut closing)?;
        assert!(closing.select_candidate(&prepared).is_err());
        next[i].authorize_entry(&certificate)?;
        restore_at_cut(&mut next[i])?;
    }
    enter_players(&mut next)?;
    assert!(next[0].propose(None).is_err());
    assert_eq!(next[0].view()?["height"], 0);
    let certificates = [
        next[0].successor_certificate()?,
        next[1].successor_certificate()?,
    ];
    let mut bad = certificates[0].clone();
    bad[20] ^= 1;
    assert!(players[0].begin_handoff(&bad).is_err());
    let frames = [
        players[0].begin_handoff(&certificates[0])?,
        players[1].begin_handoff(&certificates[1])?,
    ];
    for player in players.iter_mut() {
        restore_at_cut(player)?;
        assert!(player.begin_close().is_err());
    }
    for i in 0..2 {
        if let Frame::Retire {
            hand,
            next,
            mut secret,
        } = frames[1 - i].clone()
        {
            secret[0] ^= 1;
            assert!(players[i]
                .receive(Frame::Retire { hand, next, secret })
                .is_err());
        }
        players[i].receive(frames[1 - i].clone())?;
        assert_eq!(players[i].view()?["handoffComplete"], false);
        assert!(players[i].needs_watch());
        let package = players[i].watch_package()?;
        assert!(package.paths.iter().all(Vec::is_empty));
        assert_eq!(package.penalties.len(), 1);
        let peer_root = &package.roots[1 - i];
        assert!(package
            .penalties
            .iter()
            .any(
                |raw| bitcoin::consensus::deserialize::<bitcoin::Transaction>(raw)
                    .is_ok_and(|tx| tx.input[0].previous_output.txid.to_string() == *peer_root)
            ));
        restore_at_cut(&mut players[i])?;
    }
    let ack = [
        players[0]
            .authorize_watch(players[0].watch_digest()?)?
            .ok_or("ack")?,
        players[1]
            .authorize_watch(players[1].watch_digest()?)?
            .ok_or("ack")?,
    ];
    for i in 0..2 {
        players[i].receive(ack[1 - i].clone())?;
        restore_at_cut(&mut players[i])?;
        assert_eq!(players[i].view()?["handoffComplete"], true);
        assert!(players[i].receive(frames[1 - i].clone())?.is_some());
    }
    for i in 0..2 {
        next[i].authorize_play(&players[i].play_certificate()?)?;
        restore_at_cut(&mut next[i])?;
    }
    // New-hand cards remain playable under the same funding after retirement.
    let role = next[0].view()?["actor"].as_u64().ok_or("actor")? as usize;
    next[role].propose(None)?;
    let frame = next[role]
        .authorize_watch(next[role].watch_digest()?)?
        .ok_or("move")?;
    next[1 - role].receive(frame)?;
    let ack = next[1 - role]
        .authorize_watch(next[1 - role].watch_digest()?)?
        .ok_or("ack")?;
    next[role].receive(ack)?;
    next[role].authorize_watch(next[role].watch_digest()?)?;
    assert_eq!(next[0].view()?["node"], next[1].view()?["node"]);
    assert_eq!(
        next[0].watch_package()?.funding,
        players[0].watch_package()?.funding
    );
    Ok(())
}

fn qualify_cashout(players: &[ChannelHand; 2], terms: &Terms) -> Result<()> {
    use bitcoin::{consensus::deserialize, ScriptBuf, Transaction};
    let mut a = ChannelHand::restore(
        &players[0].checkpoint_journal()?,
        &players[0].checkpoint_artifact()?,
    )?;
    let mut b = ChannelHand::restore(
        &players[1].checkpoint_journal()?,
        &players[1].checkpoint_artifact()?,
    )?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let scripts = terms.identities.map(|key| {
        ScriptBuf::new_p2tr(
            &secp,
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&key).unwrap(),
            None,
        )
        .into_bytes()
    });
    let sa = a.begin_cashout(scripts.clone())?;
    restore_at_cut(&mut a)?;
    let sb = b.begin_cashout(scripts.clone())?;
    assert!(a.successor_certificate().is_err());
    let mut wrong = scripts.clone();
    wrong.swap(0, 1);
    assert!(a.begin_cashout(wrong).is_err());
    let mut bad = sb.clone();
    bad[0] ^= 1;
    assert!(a.accept_cashout(&bad).is_err());
    a.accept_cashout(&sb)?;
    b.accept_cashout(&sa)?;
    restore_at_cut(&mut a)?;
    restore_at_cut(&mut b)?;
    a.accept_cashout(&sb)?;
    assert_eq!(a.view()?["cashout"], b.view()?["cashout"]);
    let tx: Transaction = deserialize(&hex::decode(
        a.view()?["cashout"].as_str().ok_or("missing cashout")?,
    )?)?;
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.input[0].previous_output.to_string(), terms.origin);
    let fee = (tx.vsize() as u64).div_ceil(10);
    let stacks: [u64; 2] = serde_json::from_value(players[0].view()?["nextStacks"].clone())?;
    let reserve = terms.origin_value - stacks.iter().sum::<u64>() - fee;
    assert_eq!(
        tx.output[0].value.to_sat(),
        stacks[0] + reserve / 2 + reserve % 2
    );
    assert_eq!(tx.output[1].value.to_sat(), stacks[1] + reserve / 2);
    for i in 0..2 {
        assert_eq!(tx.output[i].script_pubkey.as_bytes(), scripts[i]);
    }
    assert_eq!(tx.input[0].witness.len(), 4);
    Ok(())
}

#[test]
fn future_slots_share_dealing_but_not_score_secrets() -> Result<()> {
    let mut seeds = [[3; 32], [5; 32]];
    seeds.sort_by_key(|s| public_keys(s).unwrap().identity);
    let keys = [public_keys(&seeds[0])?, public_keys(&seeds[1])?];
    let initial = Terms {
        slot: None,
        regtest: true,
        identities: [keys[0].identity, keys[1].identity],
        reveal_keys: [keys[1].reveal, keys[0].reveal],
        origin: format!("{}:0", "01".repeat(32)),
        origin_value: 46800,
        nonce: [7; 32],
        predeal_anchor: None,
        fee_reserve: None,
        full: false,
        fee_multiplier: 1.0,
        csv: 2,
        stacks: Some([400, 400]),
        button: None,
    };
    let parent = ChannelHand::new(seeds[0], initial, 3)?;
    let terms = parent.future_terms(1, [9; 32], [400, 400])?;
    let mut decks = [
        ChannelHand::new(seeds[0], terms.clone(), 3)?,
        ChannelHand::new(seeds[1], terms.clone(), 3)?,
    ];
    for owner in 0..2 {
        for _ in 0..100 {
            if decks
                .iter_mut()
                .all(|p| p.setup_session(owner).unwrap().dealer_status()["accepted"] == true)
            {
                break;
            }
            if decks
                .iter_mut()
                .all(|p| p.setup_session(owner).unwrap().dealer_status()["retry"] == true)
            {
                let attempt = decks[0].setup_session(owner)?.dealer_status()["attempt"]
                    .as_u64()
                    .unwrap() as u32
                    + 1;
                for p in &mut decks {
                    p.setup_session(owner)?.retry(attempt)?;
                }
                continue;
            }
            let messages = [
                decks[0].setup_session(owner)?.outgoing()?,
                decks[1].setup_session(owner)?.outgoing()?,
            ];
            for i in 0..2 {
                if let Some(bytes) = &messages[i] {
                    decks[i].setup_session(owner)?.confirm_outgoing(bytes)?;
                    decks[1 - i].setup_session(owner)?.accept_peer(bytes)?;
                }
            }
        }
    }
    let mut a = decks[0].fork_predeal(terms.clone())?;
    let variant = parent.future_terms(1, [9; 32], [300, 500])?;
    let mut b = decks[0].fork_predeal(variant)?;
    assert!(a.entry_frame().is_err());
    assert!(b.entry_frame().is_err());
    assert!(a.propose(None).is_err());
    assert_eq!(a.view()?["holeCards"], serde_json::Value::Null);
    let ka = poker_score_ots::LamportPublicKey::decode(&a.setup_session(0)?.score_public()?)?;
    let kb = poker_score_ots::LamportPublicKey::decode(&b.setup_session(0)?.score_public()?)?;
    assert_ne!(ka.public_hash_pairs(), kb.public_hash_pairs());
    assert_eq!(
        a.setup_session(0)?.dealer_status(),
        b.setup_session(0)?.dealer_status()
    );
    let later = parent.future_terms(2, [10; 32], [300, 500])?;
    assert_ne!(later.nonce, terms.nonce);
    assert_eq!(later.slot.as_ref().unwrap().index, 2);
    assert!(decks[0].fork_predeal(later).is_err());
    Ok(())
}

#[test]
fn deferred_payouts_reuse_all_internal_authorizations_and_restore() -> Result<()> {
    std::thread::Builder::new().stack_size(128*1024*1024).spawn(|| deferred_run().map_err(|e|e.to_string()))?
        .join().map_err(|_|"deferred test panicked")?.map_err(Into::into)
}
fn deferred_run() -> Result<()> {
    use poker_settlement::{preparation::SettlementPreparation,settlement::AuthorizationRequest};
    let mut seeds=[[3;32],[5;32]];seeds.sort_by_key(|s|public_keys(s).unwrap().identity);
    let keys=[public_keys(&seeds[0])?,public_keys(&seeds[1])?];
    let terms=Terms{slot:None,predeal_anchor:None,fee_reserve:None,regtest:true,
        identities:[keys[0].identity,keys[1].identity],reveal_keys:[keys[1].reveal,keys[0].reveal],
        origin:format!("{}:0","01".repeat(32)),origin_value:86_000,nonce:[7;32],full:true,
        fee_multiplier:1.0,csv:2,stacks:Some([20000,20000]),button:None};
    let parent=ChannelHand::new(seeds[0],terms,3)?;
    let next=parent.future_terms(1,[9;32],[20000,20000])?;
    let mut players=prepare_candidates_inner(seeds,next,true)?;
    let old=SettlementPreparation::from_inventory(&players[0].setup_session(0)?.inventory()?,Network::Regtest)?;
    for (i,player) in players.iter_mut().enumerate() {
        assert!(player.entry_frame().is_err());assert!(player.launch_signatures().is_err());
        assert!(player.prepared_certificate().is_err());
        // Cold restoration uses full reconstruction; the hot delegated worker uses cached payout templates.
        // Their complete inventories must remain byte-identical below.
        if i==0 {*player=ChannelHand::restore(&player.checkpoint_journal()?,&player.checkpoint_artifact()?)?;}
        assert!(player.entry_frame().is_err());
        assert!(player.bind_payouts([20100,20000]).is_err());
        assert!(player.bind_payouts([200,39800]).is_err());
        let started=std::time::Instant::now();
        let reused=player.bind_payouts([20100,19900])?;assert!(reused.iter().all(|n|*n>0));
        eprintln!("Payout binding seat {i}: {:?}",started.elapsed());
        assert!(player.bind_payouts([20200,19800]).is_err());
        *player=ChannelHand::restore(&player.checkpoint_journal()?,&player.checkpoint_artifact()?)?;
        assert!(player.entry_frame().is_err());
    }
    let new=SettlementPreparation::from_inventory(&players[0].setup_session(0)?.inventory()?,Network::Regtest)?;
    let work=players[0].setup_session(0)?.preparation_work()?;
    let mut reveals=0;
    for (i,(a,b)) in old.requests().iter().zip(new.requests()).enumerate() {
        match (a,b) {
            (AuthorizationRequest::Reveal(a),AuthorizationRequest::Reveal(b)) => {
                assert_eq!(a.sighash,b.sighash);assert_eq!(a.node_id,b.node_id);assert!(!work.contains(&i));reveals+=1;
            },
            (AuthorizationRequest::Signature{node_id:a,edge_index:e,sighash:x,..},AuthorizationRequest::Signature{node_id:b,edge_index:f,sighash:y,..}) => {
                assert_eq!(a,b);assert_eq!(e,f);assert_eq!(x!=y,work.contains(&i));
            }, _=>panic!("topology changed"),
        }
    }
    assert!(reveals>0 && !work.is_empty());
    eprintln!("Payout binding: {} reused, {} payout signatures, {} unchanged adaptor packages per owner",new.requests().len()-work.len(),work.len(),reveals);
    for owner in 0..2 {
        let inventory=players[0].setup_session(owner)?.inventory()?;
        assert_eq!(inventory,players[1].setup_session(owner)?.inventory()?);
        for role in 0..2 {
            let session=players[role].setup_session(owner)?;
            let indices=session.preparation_work()?;
            let worker=CryptoWorker::new(&inventory,Network::Regtest,session.receipt_key(),session.signing_material())?;
            let manifest=worker.manifest();
            let indices:Vec<_>=indices.into_iter().filter(|i|manifest[2*i]==role as u8).map(|i|i as u32).collect();
            assert!(players[role].setup_session(owner)?.finish_preparation().is_err());
            for chunk in indices.chunks(2000) {
                let receipt=worker.sign_receipt(chunk)?;
                for player in &mut players {
                    let session=player.setup_session(owner)?;
                    let verifier=CryptoWorker::new(&inventory,Network::Regtest,session.receipt_key(),session.signing_material())?;
                    session.accept_batch(&verifier.verify(&receipt[..receipt.len()-32])?)?;
                }
            }
        }
        for player in &mut players {player.setup_session(owner)?.finish_preparation()?;}
    }
    let launches=[players[0].launch_signatures()?,players[1].launch_signatures()?];
    for i in 0..2 {players[i].accept_prepared_launches(launches[1-i].clone())?;players[i].prepared_certificate()?;}
    Ok(())
}

#[test]
fn opening_predeal_binds_final_funding_and_preserves_the_dealer_context() -> Result<()> {
    let mut seeds=[[3;32],[5;32]];
    seeds.sort_by_key(|s|public_keys(s).unwrap().identity);
    let a=public_keys(&seeds[0])?;let b=public_keys(&seeds[1])?;
    let terms=Terms{slot:None,predeal_anchor:Some([9;32]),fee_reserve:None,regtest:true,
      identities:[a.identity,b.identity],reveal_keys:[b.reveal,a.reveal],origin:format!("{}:0","01".repeat(32)),origin_value:46800,
      nonce:[7;32],full:false,fee_multiplier:1.0,csv:2,stacks:Some([400,400]),button:None};
    let mut hand=ChannelHand::new(seeds[0],terms.clone(),6)?;
    let initial_slot=hand.setup_session(0)?.terms.slot.clone().unwrap();
    let mut final_terms=terms.clone();final_terms.origin=format!("{}:0","02".repeat(32));
    let mut changed=final_terms.clone();changed.nonce=[8;32];
    assert!(hand.setup_session(0)?.bind_predeal(changed).is_err());
    let mut changed=final_terms.clone();changed.predeal_anchor=Some([8;32]);
    assert!(hand.setup_session(0)?.bind_predeal(changed).is_err());
    for owner in 0..2 {hand.setup_session(owner)?.bind_predeal(final_terms.clone())?;}
    let bound=hand.setup_session(0)?.terms.slot.clone().unwrap();
    assert_eq!(bound.index,0);assert_ne!(bound.channel,initial_slot.channel);
    assert_eq!(bound,hand.setup_session(1)?.terms.slot.clone().unwrap());
    assert_eq!(hand.setup_session(0)?.terms.origin,final_terms.origin);
    Ok(())
}
