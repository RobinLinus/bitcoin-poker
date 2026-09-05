//! Real-Core qualification of dlog-authenticated seven-card settlement.
#[path = "../../../../dealing-dlog/crates/dlog52-bitcoin/tests/common/mod.rs"]
mod common;

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, TxOut};
use bp52_chain_bitcoin::dlog52::DlogShowdownWitness;
use bp52_chain_bitcoin::{
    AliceShowdownProgram, BobPayoutProgram, CompiledTaprootState, LeafProgram, TransactionTemplate,
    sign_sighash_default, taproot_script_sighash_default,
};
use bp52_chain_types::{Role, ShowdownOutcome, root_node_id};
use bp52_core_test_support::{CoreCli, PathExecutor};
use bp52_lamport::{
    KeyContext, LamportPurpose, Score24, generate_key, issue_alice_score_certificate,
    issue_bob_score_certificate,
};
use common::TestResult;
use dlog52_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
use rand_core::OsRng;

#[test]
#[ignore = "requires managed Bitcoin Core; run chain/scripts/bitcoin-core-regtest.sh --suite dlog --require"]
fn bitcoin_core_regtest_dlog52_showdown() -> TestResult {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| run().map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "dlog showdown test panicked")?
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
    let secp = Secp256k1::new();
    let signers: [Keypair; 2] = common::try_array(|i| {
        Ok(Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&identities[i])?,
        ))
    })?;
    let authorizers = signers.map(|k| k.x_only_public_key().0.serialize());
    let keys = (0..9_u8)
        .map(|slot| {
            let sa = &a.setup_secrets()?.openings[usize::from(slot)];
            let sb = &b.setup_secrets()?.openings[usize::from(slot)];
            let oa = verify_share_opening(
                deal,
                dlog52_protocol::Role::A,
                slot,
                ShareOpening {
                    value: sa.value(),
                    blinding: *sa.gamma(),
                },
            )?;
            let ob = verify_share_opening(
                deal,
                dlog52_protocol::Role::B,
                slot,
                ShareOpening {
                    value: sb.value(),
                    blinding: *sb.gamma(),
                },
            )?;
            Ok(derive_card_signing_key(deal, slot, &oa, &ob)?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    let slots = [
        bp52_chain_bitcoin::ALICE_SEVEN_SLOTS,
        bp52_chain_bitcoin::BOB_SEVEN_SLOTS,
    ];
    let sums = slots.map(|ss| ss.map(|s| keys[usize::from(s)].raw_sum()));
    let scores = sums.map(|ss| {
        (0..21_u8)
            .map(|subset| {
                let selected = bp52_poker::selected_five(ss.map(|s| s % 52), subset)?;
                Ok(bp52_poker::evaluate_five_cards(selected)?)
            })
            .collect::<TestResult<Vec<_>>>()
    });
    let [scores_a, scores_b] = scores;
    let scores = [scores_a?, scores_b?];
    for (case, outcome) in [
        ShowdownOutcome::AliceWin,
        ShowdownOutcome::BobWin,
        ShowdownOutcome::Split,
    ]
    .into_iter()
    .enumerate()
    {
        let (subset_a, subset_b) = (0..21)
            .flat_map(|a| (0..21).map(move |b| (a, b)))
            .find(|&(a, b)| match outcome {
                ShowdownOutcome::AliceWin => scores[0][a] > scores[1][b],
                ShowdownOutcome::BobWin => scores[0][a] < scores[1][b],
                ShowdownOutcome::Split => scores[0][a] == scores[1][b],
            })
            .ok_or("fixture lacks outcome")?;
        let game = [91 + case as u8; 32];
        let (mut secret_a, public_a) = generate_key(
            &mut OsRng,
            KeyContext::new(game, root_node_id(&game), LamportPurpose::AliceScore24Bit),
        )?;
        let (mut secret_b, public_b) = generate_key(
            &mut OsRng,
            KeyContext::new(game, root_node_id(&game), LamportPurpose::BobScore24Bit),
        )?;
        let cert_a =
            issue_alice_score_certificate(&mut secret_a, Score24::new(scores[0][subset_a])?)?;
        let cert_b =
            issue_bob_score_certificate(&mut secret_b, Score24::new(scores[1][subset_b])?)?;
        let alice = LeafProgram::AliceShowdown(AliceShowdownProgram::new_dlog(
            deal,
            game,
            [11; 32],
            public_a.clone(),
            authorizers,
        )?);
        let bob = LeafProgram::BobPayout(BobPayoutProgram::new_dlog(
            deal,
            game,
            [12; 32],
            [11; 32],
            outcome,
            public_a,
            public_b,
            authorizers,
        )?);
        let states = [
            CompiledTaprootState::compile(&secp, [13; 32], &[alice])?,
            CompiledTaprootState::compile(&secp, [14; 32], &[bob])?,
        ];
        let mut path = PathExecutor::fund(
            &core,
            &mining,
            &states[0].script_pubkey(),
            Amount::from_sat(200_000),
        )?;
        for role in 0..2 {
            let tip = path.tip().ok_or("missing settlement output")?;
            let output = if role == 0 {
                states[1].script_pubkey()
            } else {
                core.new_script()?
            };
            let template = TransactionTemplate::normal(
                Network::Regtest,
                tip.outpoint(),
                tip.output().clone(),
                vec![TxOut {
                    value: Amount::from_sat(tip.output().value.to_sat() - 20_000),
                    script_pubkey: output,
                }],
                20_000,
            )?;
            let leaf = &states[role].leaves()[0];
            let digest = taproot_script_sighash_default(
                template.transaction(),
                0,
                &[tip.output().clone()],
                leaf.script(),
            )?;
            let signatures = common::try_array(|i| {
                Ok(keys[usize::from(slots[role][i])]
                    .sign_tapscript_sighash(&digest, &[17; 32])?
                    .to_bytes())
            })?;
            let subset = [subset_a, subset_b][role];
            let hand = DlogShowdownWitness::verify(
                deal,
                [Role::Alice, Role::Bob][role],
                digest,
                sums[role],
                signatures,
                subset as u8,
                scores[role][subset],
            )?;
            let authorizations =
                signers.map(|key| sign_sighash_default(&secp, &key, digest).to_bytes());
            let elements = if role == 0 {
                hand.alice_elements(authorizations, &cert_a)?
            } else {
                hand.bob_elements(authorizations, &cert_a, &cert_b)?
            };
            let mut valid = template.transaction().clone();
            valid.input[0].witness = leaf.assemble_witness(&elements)?;
            let mut bad_elements = elements.clone();
            let index = bad_elements.len() - 2;
            bad_elements[index][0] ^= 1;
            let mut invalid = valid.clone();
            invalid.input[0].witness = leaf.assemble_witness(&bad_elements)?;
            path.assert_rejected(&invalid, "dlog showdown wrong card signature")?;
            eprintln!(
                "dlog {outcome:?} role {role}: script {} bytes, tx {} vbytes",
                leaf.script().len(),
                valid.vsize()
            );
            if role == 0 {
                path.advance(&valid, 0, "dlog Alice showdown")?;
            } else {
                path.finish(&valid, "dlog Bob payout")?;
            }
        }
    }
    Ok(())
}
