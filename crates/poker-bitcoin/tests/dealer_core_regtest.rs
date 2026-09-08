//! Real-Core qualification of dlog-authenticated seven-card settlement.
#[path = "../../dealer-bitcoin/tests/common/mod.rs"]
mod common;

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, TxOut};
use common::TestResult;
use dealer_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
use poker_bitcoin::showdown_witness::{ObservedAliceScoreCertificate, ShowdownWitness};
use poker_bitcoin::{
    AliceShowdownProgram, BobPayoutProgram, CompiledTaprootState, LeafProgram, TransactionTemplate,
    sign_sighash_default, taproot_script_sighash_default,
};
use poker_core_test_support::{CoreCli, PathExecutor};
use poker_score_ots::{
    KeyContext, LamportMessage, LamportPublicKey, LamportPurpose, Score24, generate_key,
    issue_alice_score_certificate, issue_bob_score_certificate,
};
use poker_settlement_types::{Role, ShowdownOutcome, root_node_id};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires managed Bitcoin Core; run scripts/bitcoin-core-regtest.sh --suite dlog --require"]
fn bitcoin_core_regtest_dealer_showdown() -> TestResult {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| run().map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "dlog showdown test panicked")?
        .map_err(Into::into)
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep this complete protocol or integration sequence in its specified order."
)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "Fixture arrays and indices are bounded by the fixed nine-card protocol."
)]
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
                dealer_protocol::Role::A,
                slot,
                ShareOpening {
                    value: sa.value(),
                    blinding: *sa.gamma(),
                },
            )?;
            let ob = verify_share_opening(
                deal,
                dealer_protocol::Role::B,
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
        poker_bitcoin::ALICE_SEVEN_SLOTS,
        poker_bitcoin::BOB_SEVEN_SLOTS,
    ];
    let sums = slots.map(|ss| ss.map(|s| keys[usize::from(s)].raw_sum()));
    let scores = sums.map(|ss| {
        (0..21_u8)
            .map(|subset| {
                let selected = poker_eval::selected_five(ss.map(|s| s % 52), subset)?;
                Ok(poker_eval::evaluate_five_cards(selected)?)
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
        let (mut secret_a, mut public_a) = generate_key(
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
        // Alice may commit to a nonstandard preimage length. Bob must carry
        // the confirmed certificate through payout without a fixed32 codec.
        let nonstandard_preimage = (outcome == ShowdownOutcome::Split).then(|| vec![42; 33]);
        if let Some(preimage) = &nonstandard_preimage {
            let mut pairs = public_a.public_hash_pairs().to_vec();
            let bit = usize::from(LamportMessage::AliceScore(cert_a.score_a()).bits_msb_first()[0]);
            pairs[0][bit] = Sha256::digest(preimage).into();
            public_a = LamportPublicKey::from_parts(public_a.context(), pairs)?;
        }
        let alice = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
            deal,
            game,
            [11; 32],
            public_a.clone(),
            authorizers,
        )?);
        let bob = LeafProgram::BobPayout(BobPayoutProgram::new(
            deal,
            game,
            [12; 32],
            [11; 32],
            outcome,
            public_a.clone(),
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
        let mut observed_alice = None;
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
            let hand = ShowdownWitness::verify(
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
                let mut elements = hand.alice_elements(authorizations, &cert_a)?;
                if let Some(preimage) = &nonstandard_preimage {
                    elements[1].clone_from(preimage);
                }
                elements
            } else {
                hand.bob_elements_with_observed_alice(
                    authorizations,
                    observed_alice
                        .as_ref()
                        .ok_or("Alice certificate not confirmed")?,
                    &cert_b,
                )?
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
                observed_alice = Some(ObservedAliceScoreCertificate::from_witness_elements(
                    &elements[..ObservedAliceScoreCertificate::WITNESS_ELEMENTS],
                    &public_a,
                )?);
            } else {
                path.finish(&valid, "dlog Bob payout")?;
            }
        }
    }
    Ok(())
}
