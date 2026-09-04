//! Opt-in consensus and policy qualification against a real Bitcoin Core node.
//!
//! The normal Rust suite deliberately ignores this test. Run it through
//! `scripts/bitcoin-core-regtest.sh`, which launches an isolated regtest node
//! and sets the private environment contract consumed below.

use std::cmp::Ordering;
use std::error::Error;
use std::io;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Amount, Network, Transaction, TxOut};
use bp52_chain_bitcoin::{
    ALICE_SEVEN_SLOTS, ActionProgram, AliceShowdownProgram, BobPayoutProgram, CardOpeningWitness,
    CompiledTapLeaf, CompiledTaprootState, Eval5ScriptWitness, LeafProgram, RevealPattern,
    RevealProgram, ShareRevealPredicate, ShowdownHandWitness, TimeoutProgram, TransactionTemplate,
    assemble_alice_showdown_witness_elements, assemble_bob_payout_witness_elements,
    encode_script_num, sign_sighash_default, taproot_script_sighash_default, verify_showdown_hand,
};
use bp52_chain_types::{AcceptedDeal, Action, Role, ShowdownOutcome};
use bp52_core_test_support::{CoreCli, PathExecutor};
use bp52_lamport::{
    KeyContext, LamportPurpose, generate_key, issue_alice_score_certificate,
    issue_bob_score_certificate,
};
use bp52_poker::evaluate_five_cards;
use rand_core::OsRng;

const GAME_ID: [u8; 32] = [0x52; 32];
const ACTION_NODE_ID: [u8; 32] = [0x11; 32];
const REVEAL_NODE_ID: [u8; 32] = [0x12; 32];
const TIMEOUT_NODE_ID: [u8; 32] = [0x13; 32];
const ALICE_SHOWDOWN_NODE_ID: [u8; 32] = [0x14; 32];
const BOB_PAYOUT_NODE_ID: [u8; 32] = [0x15; 32];
const STATE_VALUE_SAT: u64 = 100_000;
// The showdown witnesses are several kilobytes. Keep this comfortably above
// Core's default one-sat/vbyte relay floor instead of weakening node policy.
const TRANSITION_FEE_SAT: u64 = 10_000;
const TIMEOUT_CSV: u16 = 2;

type TestIdentityKeys = (
    Secp256k1<bitcoin::secp256k1::All>,
    Keypair,
    Keypair,
    [[u8; 32]; 2],
);

#[test]
#[ignore = "requires an isolated real Bitcoin Core regtest node"]
fn bitcoin_core_regtest_leaf_classes() -> Result<(), Box<dyn Error>> {
    let Some(core) = CoreCli::from_environment()? else {
        return Ok(());
    };
    core.assert_regtest()?;
    let mining_address = core.new_address()?;
    core.mine(101, &mining_address)?;

    qualify_action(&core, &mining_address)?;
    qualify_reveal(&core, &mining_address)?;
    qualify_timeout(&core, &mining_address)?;
    qualify_showdowns(&core, &mining_address)?;

    eprintln!("PASS: real Bitcoin Core accepted every valid BP52 leaf-class spend");
    Ok(())
}

fn qualify_action(core: &CoreCli, mining_address: &str) -> Result<(), Box<dyn Error>> {
    let (secp, alice, bob, authorizers) = identity_keys()?;
    let program = LeafProgram::Action(ActionProgram::new(
        GAME_ID,
        ACTION_NODE_ID,
        Action::Raise,
        authorizers,
    )?);
    let predicate_id = program.predicate_id();
    let state = CompiledTaprootState::compile(&secp, [0xa1_u8; 32], &[program])?;
    let (mut path, template) = funded_template(core, &state, mining_address, None)?;
    let leaf = required_leaf(&state, predicate_id)?;
    let digest = template_digest(&template, leaf)?;
    // Model Bob's preauthorization arriving before Alice selects this branch.
    // Witness order remains canonical Alice/Bob, independent of timing.
    let bob_presignature = sign_sighash_default(&secp, &bob, digest);
    let alice_live_signature = sign_sighash_default(&secp, &alice, digest);
    let elements = vec![
        alice_live_signature.to_bytes().to_vec(),
        bob_presignature.to_bytes().to_vec(),
    ];
    let valid = witnessed_transaction(&template, leaf, &elements)?;

    let mut wrong_bitcoin_signature = elements.clone();
    wrong_bitcoin_signature[0][0] ^= 1;
    path.assert_rejected(
        &witnessed_transaction(&template, leaf, &wrong_bitcoin_signature)?,
        "action with wrong Bitcoin signature",
    )?;
    let mut wrong_opponent_presignature = elements.clone();
    wrong_opponent_presignature[1][0] ^= 1;
    path.assert_rejected(
        &witnessed_transaction(&template, leaf, &wrong_opponent_presignature)?,
        "action with wrong opponent presignature",
    )?;
    path.finish(&valid, "action")?;
    Ok(())
}

fn qualify_reveal(core: &CoreCli, mining_address: &str) -> Result<(), Box<dyn Error>> {
    let (secp, alice, bob, authorizers) = identity_keys()?;
    let preimages = [vec![0x31; 16], vec![0x32; 17]];
    let mut deal = dummy_deal();
    deal.hashes_b[0] = sha256::Hash::hash(&preimages[0]).to_byte_array();
    deal.hashes_b[2] = sha256::Hash::hash(&preimages[1]).to_byte_array();
    let program = LeafProgram::Reveal(RevealProgram::new(
        GAME_ID,
        REVEAL_NODE_ID,
        ShareRevealPredicate::new(&deal, RevealPattern::DealAlice),
        authorizers,
    )?);
    let predicate_id = program.predicate_id();
    let state = CompiledTaprootState::compile(&secp, [0xa2_u8; 32], &[program])?;
    let (mut path, template) = funded_template(core, &state, mining_address, None)?;
    let leaf = required_leaf(&state, predicate_id)?;
    let digest = template_digest(&template, leaf)?;
    let mut elements = signature_elements(&secp, &alice, &bob, digest);
    elements.extend(preimages.iter().cloned());
    let valid = witnessed_transaction(&template, leaf, &elements)?;

    let mut wrong_preimage = elements.clone();
    wrong_preimage[2][0] ^= 1;
    path.assert_rejected(
        &witnessed_transaction(&template, leaf, &wrong_preimage)?,
        "reveal with wrong share preimage",
    )?;
    let mut wrong_signature = elements.clone();
    wrong_signature[1][0] ^= 1;
    path.assert_rejected(
        &witnessed_transaction(&template, leaf, &wrong_signature)?,
        "reveal with wrong Bitcoin signature",
    )?;
    path.finish(&valid, "reveal")?;
    Ok(())
}

fn qualify_timeout(core: &CoreCli, mining_address: &str) -> Result<(), Box<dyn Error>> {
    let (secp, alice, bob, authorizers) = identity_keys()?;
    let program = LeafProgram::Timeout(TimeoutProgram::new(
        GAME_ID,
        TIMEOUT_NODE_ID,
        TIMEOUT_CSV,
        authorizers,
    )?);
    let predicate_id = program.predicate_id();
    let state = CompiledTaprootState::compile(&secp, [0xa3_u8; 32], &[program])?;
    let (mut path, template) = funded_template(core, &state, mining_address, Some(TIMEOUT_CSV))?;
    let leaf = required_leaf(&state, predicate_id)?;
    let digest = template_digest(&template, leaf)?;
    // Alice is the defaulting opponent and fixes her signature before play;
    // Bob adds the live beneficiary signature after maturity.
    let elements = signature_elements(&secp, &alice, &bob, digest);
    let valid = witnessed_transaction(&template, leaf, &elements)?;

    path.assert_rejected(&valid, "timeout before CSV maturity")?;
    path.mine_empty_blocks(TIMEOUT_CSV)?;

    // Even after maturity, Bob cannot redirect the timeout: Alice's fixed
    // SIGHASH_DEFAULT preauthorization commits to the original output.
    let mut altered_output = template.transaction().clone();
    altered_output.output[0].value = Amount::from_sat(STATE_VALUE_SAT / 2);
    let altered_digest = taproot_script_sighash_default(
        &altered_output,
        0,
        std::slice::from_ref(template.parent_output()),
        leaf.script(),
    )?;
    let altered_beneficiary = sign_sighash_default(&secp, &bob, altered_digest);
    altered_output.input[0].witness =
        leaf.assemble_witness(&[elements[0].clone(), altered_beneficiary.to_bytes().to_vec()])?;
    path.assert_rejected(
        &altered_output,
        "mature altered-output timeout without opponent preauthorization",
    )?;

    // Regression for the superseded 65-byte profile: an explicit
    // SIGHASH_NONE signature is valid for this altered-output transaction, but
    // the leaf must reject it at the exact 64-byte signature-size gate.
    let mut none_output = template.transaction().clone();
    none_output.output[0].value = Amount::from_sat(STATE_VALUE_SAT / 2);
    let none_digest = taproot_script_sighash(
        &none_output,
        template.parent_output(),
        leaf,
        TapSighashType::None,
    )?;
    let mut none_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(none_digest), &bob)
        .serialize()
        .to_vec();
    none_signature.push(TapSighashType::None as u8);
    none_output.input[0].witness = leaf.assemble_witness(&[elements[0].clone(), none_signature])?;
    path.assert_rejected(
        &none_output,
        "mature altered-output timeout with explicit SIGHASH_NONE",
    )?;

    let mut wrong_opponent_signature = elements.clone();
    wrong_opponent_signature[0][0] ^= 1;
    path.assert_rejected(
        &witnessed_transaction(&template, leaf, &wrong_opponent_signature)?,
        "mature timeout with wrong opponent preauthorization",
    )?;
    let mut wrong_beneficiary_signature = elements;
    wrong_beneficiary_signature[1][0] ^= 1;
    path.assert_rejected(
        &witnessed_transaction(&template, leaf, &wrong_beneficiary_signature)?,
        "mature timeout with wrong beneficiary signature",
    )?;
    path.finish(&valid, "mature timeout")?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn qualify_showdowns(core: &CoreCli, mining_address: &str) -> Result<(), Box<dyn Error>> {
    let (deal, preimages_a, preimages_b) = showdown_deal();
    let alice_hand = showdown_hand(&preimages_a, &preimages_b, ALICE_SEVEN_SLOTS)?;
    let mut bob_hands = (0..21)
        .map(|subset_id| {
            showdown_hand_for_subset(
                &preimages_a,
                &preimages_b,
                bp52_chain_bitcoin::BOB_SEVEN_SLOTS,
                subset_id,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    bob_hands.sort_unstable_by_key(ShowdownHandWitness::claimed_score);
    let weaker_bob_hand = bob_hands
        .first()
        .ok_or_else(|| io::Error::other("missing weaker Bob hand"))?
        .clone();
    let bob_hand = bob_hands
        .last()
        .ok_or_else(|| io::Error::other("missing Bob hand"))?
        .clone();
    if weaker_bob_hand.claimed_score() >= bob_hand.claimed_score() {
        return Err(io::Error::other("Core fixture lacks distinct Bob scores").into());
    }
    let score_a = alice_hand.claimed_score();
    let score_b = bob_hand.claimed_score();
    let outcome = match score_a.cmp(&score_b) {
        Ordering::Greater => ShowdownOutcome::AliceWin,
        Ordering::Less => ShowdownOutcome::BobWin,
        Ordering::Equal => ShowdownOutcome::Split,
    };
    let (mut alice_score_secret, alice_score_public) = generate_key(
        &mut OsRng,
        KeyContext::new(
            GAME_ID,
            ALICE_SHOWDOWN_NODE_ID,
            LamportPurpose::AliceScore24Bit,
        ),
    )?;
    let alice_certificate = issue_alice_score_certificate(
        &mut alice_score_secret,
        bp52_lamport::Score24::new(score_a)?,
    )?;
    let (mut bob_score_secret, bob_score_public) = generate_key(
        &mut OsRng,
        KeyContext::new(GAME_ID, BOB_PAYOUT_NODE_ID, LamportPurpose::BobScore24Bit),
    )?;
    let bob_certificate =
        issue_bob_score_certificate(&mut bob_score_secret, bp52_lamport::Score24::new(score_b)?)?;
    let (secp, alice, bob, authorizers) = identity_keys()?;

    let alice_program = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
        &deal,
        GAME_ID,
        ALICE_SHOWDOWN_NODE_ID,
        alice_score_public.clone(),
        authorizers,
    )?);
    let alice_predicate = alice_program.predicate_id();
    let alice_state = CompiledTaprootState::compile(&secp, [0xa4_u8; 32], &[alice_program])?;
    let (mut alice_path, alice_template) =
        funded_template(core, &alice_state, mining_address, None)?;
    let alice_leaf = required_leaf(&alice_state, alice_predicate)?;
    let alice_digest = template_digest(&alice_template, alice_leaf)?;
    let alice_elements = assemble_alice_showdown_witness_elements(
        &deal,
        sign_sighash_default(&secp, &alice, alice_digest),
        sign_sighash_default(&secp, &bob, alice_digest),
        &alice_hand,
        &alice_certificate,
    )?;
    let alice_valid = witnessed_transaction(&alice_template, alice_leaf, &alice_elements)?;
    let mut wrong_opening = alice_elements.clone();
    mutate_matching_element(&mut wrong_opening, alice_hand.openings()[0].preimage_a())?;
    alice_path.assert_rejected(
        &witnessed_transaction(&alice_template, alice_leaf, &wrong_opening)?,
        "Alice showdown with wrong card opening",
    )?;
    let mut wrong_score_certificate = alice_elements;
    mutate_matching_element(
        &mut wrong_score_certificate,
        &alice_certificate.lamport_signature().preimages()[0],
    )?;
    alice_path.assert_rejected(
        &witnessed_transaction(&alice_template, alice_leaf, &wrong_score_certificate)?,
        "Alice showdown with wrong score certificate",
    )?;
    alice_path.finish(&alice_valid, "Alice showdown")?;

    let bob_program = LeafProgram::BobPayout(BobPayoutProgram::new(
        &deal,
        GAME_ID,
        BOB_PAYOUT_NODE_ID,
        ALICE_SHOWDOWN_NODE_ID,
        outcome,
        alice_score_public,
        bob_score_public,
        authorizers,
    )?);
    let bob_predicate = bob_program.predicate_id();
    let bob_state = CompiledTaprootState::compile(&secp, [0xa5_u8; 32], &[bob_program])?;
    let (mut bob_path, bob_template) = funded_template(core, &bob_state, mining_address, None)?;
    let bob_leaf = required_leaf(&bob_state, bob_predicate)?;
    let bob_digest = template_digest(&bob_template, bob_leaf)?;
    let bob_elements = assemble_bob_payout_witness_elements(
        &deal,
        outcome,
        sign_sighash_default(&secp, &alice, bob_digest),
        sign_sighash_default(&secp, &bob, bob_digest),
        &bob_hand,
        &alice_certificate,
        &bob_certificate,
    )?;
    let bob_valid = witnessed_transaction(&bob_template, bob_leaf, &bob_elements)?;
    let mut wrong_bob_opening = bob_elements.clone();
    mutate_matching_element(&mut wrong_bob_opening, bob_hand.openings()[0].preimage_a())?;
    bob_path.assert_rejected(
        &witnessed_transaction(&bob_template, bob_leaf, &wrong_bob_opening)?,
        "Bob payout with wrong card opening",
    )?;
    let mut wrong_bob_score_certificate = bob_elements.clone();
    mutate_matching_element(
        &mut wrong_bob_score_certificate,
        &bob_certificate.lamport_signature().preimages()[0],
    )?;
    bob_path.assert_rejected(
        &witnessed_transaction(&bob_template, bob_leaf, &wrong_bob_score_certificate)?,
        "Bob payout with wrong Bob score certificate",
    )?;
    let verified_weaker_bob = verify_showdown_hand(&deal, Role::Bob, &weaker_bob_hand)?;
    let mut weaker_subset_replacement = bob_elements.clone();
    weaker_subset_replacement.truncate(100);
    weaker_subset_replacement.extend(
        Eval5ScriptWitness::from_cards(verified_weaker_bob.selected())?.to_witness_elements(),
    );
    weaker_subset_replacement.push(encode_script_num(i64::from(weaker_bob_hand.subset_id())));
    for opening in weaker_bob_hand.openings() {
        weaker_subset_replacement.push(opening.preimage_a().to_vec());
        weaker_subset_replacement.push(opening.preimage_b().to_vec());
    }
    bob_path.assert_rejected(
        &witnessed_transaction(&bob_template, bob_leaf, &weaker_subset_replacement)?,
        "Bob payout with weaker valid subset replacing Bob's certified score",
    )?;
    let mut wrong_bob_signature = bob_elements;
    let bob_signature = sign_sighash_default(&secp, &bob, bob_digest);
    mutate_matching_element(&mut wrong_bob_signature, bob_signature.as_bytes())?;
    bob_path.assert_rejected(
        &witnessed_transaction(&bob_template, bob_leaf, &wrong_bob_signature)?,
        "Bob payout with wrong live signature",
    )?;
    bob_path.finish(&bob_valid, "Bob payout")?;
    Ok(())
}

fn identity_keys() -> Result<TestIdentityKeys, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let alice = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x21; 32])?);
    let bob = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32])?);
    let authorizers = [
        alice.x_only_public_key().0.serialize(),
        bob.x_only_public_key().0.serialize(),
    ];
    Ok((secp, alice, bob, authorizers))
}

fn funded_template<'a>(
    core: &'a CoreCli,
    state: &CompiledTaprootState,
    mining_address: &'a str,
    timeout_csv: Option<u16>,
) -> Result<(PathExecutor<'a>, TransactionTemplate), Box<dyn Error>> {
    let path = PathExecutor::fund(
        core,
        mining_address,
        &state.script_pubkey(),
        Amount::from_sat(STATE_VALUE_SAT),
    )?;
    let tip = path
        .tip()
        .ok_or_else(|| io::Error::other("newly funded path has no tip"))?;
    let outpoint = tip.outpoint();
    let parent_output = tip.output().clone();
    let child_output = TxOut {
        value: Amount::from_sat(STATE_VALUE_SAT - TRANSITION_FEE_SAT),
        script_pubkey: core.new_script()?,
    };
    let template = match timeout_csv {
        Some(csv) => TransactionTemplate::timeout(
            Network::Regtest,
            outpoint,
            parent_output,
            vec![child_output],
            TRANSITION_FEE_SAT,
            csv,
        )?,
        None => TransactionTemplate::normal(
            Network::Regtest,
            outpoint,
            parent_output,
            vec![child_output],
            TRANSITION_FEE_SAT,
        )?,
    };
    Ok((path, template))
}

fn required_leaf(
    state: &CompiledTaprootState,
    predicate_id: [u8; 32],
) -> Result<&CompiledTapLeaf, Box<dyn Error>> {
    state
        .leaf(predicate_id)
        .ok_or_else(|| io::Error::other("compiled state omitted requested leaf").into())
}

fn template_digest(
    template: &TransactionTemplate,
    leaf: &CompiledTapLeaf,
) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(taproot_script_sighash_default(
        template.transaction(),
        0,
        std::slice::from_ref(template.parent_output()),
        leaf.script(),
    )?)
}

fn signature_elements(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    alice: &Keypair,
    bob: &Keypair,
    digest: [u8; 32],
) -> Vec<Vec<u8>> {
    vec![
        sign_sighash_default(secp, alice, digest)
            .to_bytes()
            .to_vec(),
        sign_sighash_default(secp, bob, digest).to_bytes().to_vec(),
    ]
}

fn taproot_script_sighash(
    transaction: &Transaction,
    parent_output: &TxOut,
    leaf: &CompiledTapLeaf,
    sighash_type: TapSighashType,
) -> Result<[u8; 32], Box<dyn Error>> {
    let leaf_hash = TapLeafHash::from_script(leaf.script(), LeafVersion::TapScript);
    let sighash = SighashCache::new(transaction).taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(std::slice::from_ref(parent_output)),
        leaf_hash,
        sighash_type,
    )?;
    Ok(sighash.to_byte_array())
}

fn witnessed_transaction(
    template: &TransactionTemplate,
    leaf: &CompiledTapLeaf,
    elements: &[Vec<u8>],
) -> Result<Transaction, Box<dyn Error>> {
    Ok(template.with_witness(leaf.assemble_witness(elements)?)?)
}

fn dummy_deal() -> AcceptedDeal {
    AcceptedDeal {
        protocol_version: 1,
        game_id: [0x61; 32],
        attempt: 0,
        hashes_a: [[0x62; 32]; 9],
        hashes_b: [[0x63; 32]; 9],
        verification_transcript_root: [0x64; 32],
        signature_a: [0x65; 64],
        signature_b: [0x66; 64],
    }
}

fn showdown_deal() -> (AcceptedDeal, [Vec<u8>; 9], [Vec<u8>; 9]) {
    let preimages_a =
        std::array::from_fn(|slot| vec![0x70 + u8::try_from(slot).unwrap_or_default(); 16 + slot]);
    let preimages_b =
        std::array::from_fn(|slot| vec![0x90 + u8::try_from(slot).unwrap_or_default(); 16]);
    let mut deal = dummy_deal();
    deal.hashes_a =
        std::array::from_fn(|slot| sha256::Hash::hash(&preimages_a[slot]).to_byte_array());
    deal.hashes_b =
        std::array::from_fn(|slot| sha256::Hash::hash(&preimages_b[slot]).to_byte_array());
    (deal, preimages_a, preimages_b)
}

fn showdown_hand(
    preimages_a: &[Vec<u8>; 9],
    preimages_b: &[Vec<u8>; 9],
    slots: [u8; 7],
) -> Result<ShowdownHandWitness, Box<dyn Error>> {
    showdown_hand_for_subset(preimages_a, preimages_b, slots, 0)
}

fn showdown_hand_for_subset(
    preimages_a: &[Vec<u8>; 9],
    preimages_b: &[Vec<u8>; 9],
    slots: [u8; 7],
    subset_id: u8,
) -> Result<ShowdownHandWitness, Box<dyn Error>> {
    let cards = slots;
    let subset = bp52_poker::SUBSETS_5_OF_7[usize::from(subset_id)];
    let selected = subset.map(|index| cards[usize::from(index)]);
    let score = evaluate_five_cards(selected)?;
    let openings = slots.map(|slot| {
        CardOpeningWitness::new(
            slot,
            preimages_a[usize::from(slot)].clone(),
            preimages_b[usize::from(slot)].clone(),
        )
    });
    Ok(ShowdownHandWitness::new(openings, subset_id, score))
}

fn mutate_matching_element(
    elements: &mut [Vec<u8>],
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let element = elements
        .iter_mut()
        .find(|element| element.as_slice() == expected)
        .ok_or_else(|| io::Error::other("test witness omitted mutation target"))?;
    let first = element
        .first_mut()
        .ok_or_else(|| io::Error::other("test mutation target is empty"))?;
    *first ^= 1;
    Ok(())
}
