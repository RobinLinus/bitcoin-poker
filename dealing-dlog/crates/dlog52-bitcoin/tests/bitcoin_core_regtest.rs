//! Managed-Core tests: every successful witness is broadcast and confirmed.
mod common;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bp52_core_test_support::{CoreCli, PathExecutor};
use common::TestResult;
use dlog52_bitcoin::{assemble_gate_witness, build_regtest_gate, gate_tapscript_sighash};
use dlog52_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
use dlog52_protocol::Role;
use k256::schnorr::SigningKey;

#[test]
#[ignore = "requires managed Bitcoin Core; run chain/scripts/bitcoin-core-regtest.sh --suite dlog --require"]
fn bitcoin_core_regtest_dlog52() -> TestResult {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| run().map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "dlog Core test thread panicked")?
        .map_err(Into::into)
}

fn run() -> TestResult {
    let Some(core) = CoreCli::from_environment()? else {
        return Ok(());
    };
    core.assert_regtest()?;
    let mining = core.new_address()?;
    core.mine(101, &mining)?;
    let ([a, b], identities) = common::participants()?;
    let deal = a.accepted()?;
    let manifest = build_regtest_gate(deal)?;
    let payout = core.new_script()?;
    for slot in 0..9_u8 {
        let index = usize::from(slot);
        let sa = &a.setup_secrets()?.openings[index];
        let sb = &b.setup_secrets()?.openings[index];
        let opening_a = verify_share_opening(
            deal,
            Role::A,
            slot,
            ShareOpening {
                value: sa.value(),
                blinding: *sa.gamma(),
            },
        )?;
        let opening_b = verify_share_opening(
            deal,
            Role::B,
            slot,
            ShareOpening {
                value: sb.value(),
                blinding: *sb.gamma(),
            },
        )?;
        let key = derive_card_signing_key(deal, slot, &opening_a, &opening_b)?;
        let gate = &manifest.slots[index];
        let leaf = &gate.leaves[usize::from(key.raw_sum())];
        let mut path = PathExecutor::fund(
            &core,
            &mining,
            &gate.output_script,
            Amount::from_sat(20_000),
        )?;
        let tip = path.tip().ok_or("missing gate output")?;
        let prevouts = [tip.output().clone()];
        let mut tx = spend(tip.outpoint(), payout.clone(), 19_000);
        let digest = gate_tapscript_sighash(&tx, 0, &prevouts, leaf)?;
        let card_sig = key.sign_tapscript_sighash(&digest, &[41; 32])?.to_bytes();
        let authorizer_index =
            usize::from(gate.authorizer.serialize() != deal.game_config().identity_a);
        let auth_key = SigningKey::from_bytes(&identities[authorizer_index])?;
        let auth_sig = auth_key
            .sign_prehash_with_aux_rand(&digest, &[42; 32])?
            .to_bytes();
        tx.input[0].witness = assemble_gate_witness(leaf, &card_sig, &auth_sig);
        let mut wrong = tx.clone();
        let wrong_leaf = &gate.leaves[(usize::from(key.raw_sum()) + 1) % 103];
        let wrong_digest = gate_tapscript_sighash(&wrong, 0, &prevouts, wrong_leaf)?;
        // Both signatures use the wrong leaf's actual sighash. Rejection must
        // come from the wrong candidate key, not merely a changed leaf hash.
        wrong.input[0].witness = assemble_gate_witness(
            wrong_leaf,
            &key.sign_tapscript_sighash(&wrong_digest, &[43; 32])?
                .to_bytes(),
            &auth_key
                .sign_prehash_with_aux_rand(&wrong_digest, &[44; 32])?
                .to_bytes(),
        );
        path.assert_rejected(&wrong, "dlog wrong card candidate")?;
        let mut broken = card_sig;
        broken[40] ^= 1;
        wrong.input[0].witness = assemble_gate_witness(leaf, &broken, &auth_sig);
        path.assert_rejected(&wrong, "dlog invalid card signature")?;
        path.finish(&tx, &format!("dlog slot {slot}, card {}", key.card_id()))?;
    }
    eprintln!("PASS: Core confirmed all nine dlog card gates and rejected wrong candidates");
    for refused in [None, Some(0), Some(1)] {
        qualify_reusable_reveals(&core, &mining, [&a, &b], identities, refused)?;
    }
    eprintln!(
        "PASS: Core confirmed both reusable reveals, a later card spend, and both refusal timeouts"
    );
    Ok(())
}

fn qualify_reusable_reveals(
    core: &CoreCli,
    mining: &str,
    players: [&dlog52_protocol::LiveParticipant; 2],
    identities: [[u8; 32]; 2],
    refused: Option<usize>,
) -> TestResult {
    use bitcoin::{opcodes::all::*, script::Builder, taproot::TaprootBuilder};
    use dlog52_bitcoin::reveal::{RevealContext, VerifiedRevealPackage, reveal_tapscript};
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let idkeys = [
        SigningKey::from_bytes(&identities[0])?,
        SigningKey::from_bytes(&identities[1])?,
    ];
    let public: [[u8; 32]; 2] =
        std::array::from_fn(|i| idkeys[i].verifying_key().to_bytes().into());
    let deal = players[0].accepted()?;
    let gates = build_regtest_gate(deal)?;
    let secrets = [
        [[21_u8; 32], [22_u8; 32], [23_u8; 32]],
        [[31_u8; 32], [32_u8; 32], [33_u8; 32]],
    ];
    let mut reveal_scripts = Vec::new();
    let mut infos = Vec::new();
    let timeout = Builder::new()
        .push_int(2)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice(public[1])
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(public[0])
        .push_opcode(OP_CHECKSIG)
        .into_script();
    for role in 0..2_usize {
        let slots = (0..3)
            .map(|i| {
                Ok((
                    4 + i as u8,
                    <[u8; 32]>::from(
                        SigningKey::from_bytes(&secrets[role][i])?
                            .verifying_key()
                            .to_bytes(),
                    ),
                ))
            })
            .collect::<TestResult<Vec<_>>>()?;
        let script = reveal_tapscript(gates.deal_id, [50 + role as u8; 32], public[role], &slots)?;
        let info = TaprootBuilder::new()
            .add_leaf(1, script.clone())?
            .add_leaf(1, timeout.clone())?
            .finalize(&secp, gates.slots[4].internal_key)
            .map_err(|_| "reveal tree finalization")?;
        reveal_scripts.push(script);
        infos.push(info);
    }
    let scripts: Vec<_> = infos
        .iter()
        .map(|i| ScriptBuf::new_p2tr_tweaked(i.output_key()))
        .collect();
    let mut path = PathExecutor::fund(core, mining, &scripts[0], Amount::from_sat(100_000))?;
    let root = path.tip().ok_or("missing reveal root")?.clone();
    let first = spend(root.outpoint(), scripts[1].clone(), 99_000);
    let second = spend(
        bitcoin::OutPoint::new(first.compute_txid(), 0),
        gates.slots[4].output_script.clone(),
        98_000,
    );
    let mut transactions = [first, second];
    let prevouts = [root.output().clone(), transactions[0].output[0].clone()];
    let mut packages = Vec::new();
    let mut timeouts = Vec::new();
    let payout_script = core.new_script()?;
    // All counterparty artifacts are fixed before activation of this path.
    for role in 0..2_usize {
        let digest = script_digest(&transactions[role], &prevouts[role], &reveal_scripts[role])?;
        let commitments = if role == 0 {
            &deal.as_deal().body.commitments_a
        } else {
            &deal.as_deal().body.commitments_b
        };
        let mut slot_packages = Vec::new();
        for i in 0..3_usize {
            let context = RevealContext {
                deal_id: gates.deal_id,
                graph_id: [60; 32],
                node_id: [50 + role as u8; 32],
                revealer: role as u8,
                slot: 4 + i as u8,
                authorizer: SigningKey::from_bytes(&secrets[role][i])?
                    .verifying_key()
                    .to_bytes()
                    .into(),
                sighash: digest,
                commitment: commitments[4 + i],
            };
            let sent = VerifiedRevealPackage::create(
                context.clone(),
                &secrets[role][i],
                &[70 + i as u8; 32],
            )?;
            slot_packages.push(VerifiedRevealPackage::verify(context, &sent.to_bytes())?);
        }
        packages.push(slot_packages);
        let mut refund = spend(
            transactions[role].input[0].previous_output,
            payout_script.clone(),
            prevouts[role].value.to_sat() - 1_000,
        );
        refund.input[0].sequence = bitcoin::Sequence::from_height(2);
        let refund_digest = script_digest(&refund, &prevouts[role], &timeout)?;
        let timeout_sigs = idkeys
            .iter()
            .map(|key| {
                key.sign_prehash_with_aux_rand(&refund_digest, &[75; 32])
                    .map(|s| s.to_bytes().to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        refund.input[0].witness = with_script(timeout_sigs, &timeout, &infos[role])?;
        timeouts.push(refund);
    }
    let mut extracted = Vec::new();
    for role in 0..2_usize {
        if refused == Some(role) {
            path.assert_rejected(&timeouts[role], "dlog reveal timeout before CSV")?;
            path.mine_empty_blocks(2)?;
            path.finish(
                &timeouts[role],
                &format!("dlog role {role} refusal timeout"),
            )?;
            return Ok(());
        }
        let digest = script_digest(&transactions[role], &prevouts[role], &reveal_scripts[role])?;
        let mut witness = vec![
            idkeys[role]
                .sign_prehash_with_aux_rand(&digest, &[76; 32])?
                .to_bytes()
                .to_vec(),
        ];
        for i in 0..3_usize {
            let opening = &players[role].setup_secrets()?.openings[4 + i];
            witness.push(
                packages[role][i]
                    .complete(opening.value(), *opening.gamma())?
                    .to_vec(),
            );
        }
        let mut swapped = transactions[role].clone();
        let mut bad = witness.clone();
        bad[2] = bad[1].clone();
        swapped.input[0].witness = with_script(bad, &reveal_scripts[role], &infos[role])?;
        path.assert_rejected(&swapped, "reusing one signature for two reveal slots")?;
        transactions[role].input[0].witness =
            with_script(witness, &reveal_scripts[role], &infos[role])?;
        path.advance(
            &transactions[role],
            0,
            &format!("dlog role {role} public reveal"),
        )?;
        // Extraction is from the exact witness accepted and confirmed by Core.
        let sig: [u8; 64] = transactions[role].input[0]
            .witness
            .iter()
            .nth(1)
            .ok_or("missing reveal signature")?
            .try_into()?;
        extracted.push(packages[role][0].extract(&sig)?);
    }
    let a = verify_share_opening(
        deal,
        Role::A,
        4,
        ShareOpening {
            value: extracted[0].0,
            blinding: extracted[0].1,
        },
    )?;
    let b = verify_share_opening(
        deal,
        Role::B,
        4,
        ShareOpening {
            value: extracted[1].0,
            blinding: extracted[1].1,
        },
    )?;
    let card = derive_card_signing_key(deal, 4, &a, &b)?;
    let tip = path.tip().ok_or("missing later card output")?;
    let mut later = spend(tip.outpoint(), payout_script, 97_000);
    let leaf = &gates.slots[4].leaves[usize::from(card.raw_sum())];
    let digest = gate_tapscript_sighash(&later, 0, std::slice::from_ref(tip.output()), leaf)?;
    later.input[0].witness = assemble_gate_witness(
        leaf,
        &card.sign_tapscript_sighash(&digest, &[77; 32])?.to_bytes(),
        &idkeys[0]
            .sign_prehash_with_aux_rand(&digest, &[78; 32])?
            .to_bytes(),
    );
    path.finish(
        &later,
        "dlog later card authentication from extracted openings",
    )?;
    Ok(())
}

fn script_digest(
    tx: &Transaction,
    previous: &TxOut,
    script: &bitcoin::Script,
) -> TestResult<[u8; 32]> {
    Ok(bitcoin::sighash::SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(std::slice::from_ref(previous)),
            bitcoin::TapLeafHash::from_script(script, bitcoin::taproot::LeafVersion::TapScript),
            bitcoin::sighash::TapSighashType::Default,
        )?
        .to_byte_array())
}

fn with_script(
    mut elements: Vec<Vec<u8>>,
    script: &ScriptBuf,
    info: &bitcoin::taproot::TaprootSpendInfo,
) -> TestResult<Witness> {
    elements.push(script.as_bytes().to_vec());
    elements.push(
        info.control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .ok_or("missing control block")?
            .serialize(),
    );
    Ok(Witness::from_slice(&elements))
}

fn spend(outpoint: bitcoin::OutPoint, script: ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        }],
    }
}
