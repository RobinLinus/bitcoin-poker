//! Entire on-chain hand with all counterparty artifacts fixed before activation.
#[path = "../../dealer-bitcoin/tests/common/mod.rs"]
mod common;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, Network};
use common::TestResult;
use dealer_bitcoin::reveal::VerifiedRevealPackage;
use dealer_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
use poker_bitcoin::{
    ClassFeePolicy, FeePolicy, sign_sighash_default, taproot_script_sighash_default,
};
use poker_core_test_support::{CoreCli, PathExecutor};
use poker_score_ots::{
    KeyContext, LamportPurpose, Score24, generate_key, issue_alice_score_certificate,
    issue_bob_score_certificate,
};
use poker_settlement::{
    CompilerError,
    graph::PlannedState,
    settlement::{AuthorizationRequest, SettlementConfig, SettlementGraph, build_origin_escrow},
};
use poker_settlement_types::{
    Action, EdgeKind, PokerRules, RevealOrder, Role, ShowdownOutcome, TimeoutSettlementPolicy,
    root_node_id,
};
use rand_core::OsRng;
use std::collections::HashMap;

fn graph_root(id: [u8; 32]) -> [u8; 32] { root_node_id(&id) }
fn branch_secret(owner: Role, node: [u8; 32]) -> [u8; 32] {
    poker_bitcoin::channel::retirement_secret(&[91; 32],
        poker_bitcoin::channel::RetirementLevel::Branch, [92; 32], node, 0, owner == Role::Bob, false)
}
fn justice_template(parent: &bitcoin::Transaction, vout: u32, destination: bitcoin::ScriptBuf)
    -> TestResult<poker_bitcoin::TransactionTemplate> {
    let output = parent.output.get(vout as usize).ok_or("justice output missing")?.clone();
    let value = output.value.to_sat().checked_sub(500).ok_or("justice needs fee rescue")?;
    Ok(poker_bitcoin::TransactionTemplate::normal(Network::Regtest,
        bitcoin::OutPoint::new(parent.compute_txid(), vout), output,
        vec![bitcoin::TxOut { value: Amount::from_sat(value), script_pubkey: destination }], 500)?)
}
fn justice_transaction(parent: &bitcoin::Transaction, vout: u32, leaf: &poker_bitcoin::CompiledTapLeaf,
    signer: &Keypair, secret: [u8; 32], destination: bitcoin::ScriptBuf) -> TestResult<bitcoin::Transaction> {
    let t = justice_template(parent, vout, destination)?;
    let digest = taproot_script_sighash_default(t.transaction(), 0, &[t.parent_output().clone()], leaf.script())?;
    let sig = sign_sighash_default(&Secp256k1::new(), signer, digest);
    let mut tx = t.transaction().clone();
    tx.input[0].witness = leaf.assemble_witness(&[sig.to_bytes().to_vec(), secret.to_vec()])?;
    Ok(tx)
}
fn payout_justice(parent: &bitcoin::Transaction, vout: u32, output: &poker_bitcoin::channel::ContestOutput,
    signer: &Keypair, secret: [u8; 32], destination: bitcoin::ScriptBuf) -> TestResult<bitcoin::Transaction> {
    let t = justice_template(parent, vout, destination)?;
    let digest = taproot_script_sighash_default(t.transaction(), 0, &[t.parent_output().clone()], output.justice_script())?;
    let sig = sign_sighash_default(&Secp256k1::new(), signer, digest);
    let mut tx = t.transaction().clone();
    tx.input[0].witness = output.witness(true, &[sig.to_bytes().to_vec(), secret.to_vec()])?;
    Ok(tx)
}

#[test]
#[ignore = "requires managed Bitcoin Core --suite channel --require"]
fn bitcoin_core_regtest_channel_hand() -> TestResult {
    std::thread::Builder::new().stack_size(32 * 1024 * 1024)
        .spawn(|| {
            for owner in [Role::Alice, Role::Bob] {
                run(Some(owner)).map_err(|e| e.to_string())?;
            }
            Ok::<_, String>(())
        })?.join().map_err(|_| "channel graph test panicked")?.map_err(Into::into)
}

#[test]
#[ignore = "requires managed Bitcoin Core --suite dlog --require"]
fn bitcoin_core_regtest_settlement() -> TestResult {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| run(None).map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "dlog graph test panicked")?
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
fn run(channel_owner: Option<Role>) -> TestResult {
    let Some(core) = CoreCli::from_environment()? else {
        return Ok(());
    };
    core.assert_regtest()?;
    let mining = core.new_address()?;
    core.mine(101, &mining)?;
    let secp = Secp256k1::new();
    let mut secrets = [[3; 32], [5; 32]];
    secrets.sort_by_key(|s| {
        SecretKey::from_slice(s)
            .map(|secret| {
                Keypair::from_secret_key(&secp, &secret)
                    .x_only_public_key()
                    .0
                    .serialize()
            })
            .ok()
    });
    let signers: [Keypair; 2] = common::try_array(|i| {
        Ok(Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secrets[i])?,
        ))
    })?;
    let identities = signers.map(|k| k.x_only_public_key().0.serialize());
    let reveal_secrets: [[[u8; 32]; 9]; 2] =
        std::array::from_fn(|r| std::array::from_fn(|s| [40 + (r * 9 + s) as u8; 32]));
    let reveal_keys = common::try_array(|role| {
        common::try_array(|slot| {
            Ok(Keypair::from_secret_key(
                &secp,
                &SecretKey::from_slice(&reveal_secrets[role][slot])?,
            )
            .x_only_public_key()
            .0
            .serialize())
        })
    })?;
    let fees = ClassFeePolicy::new(500, 700, 11_000, 12_000, 500, 330)?;
    let rules = PokerRules {
        button: Role::Alice,
        unit_sat: 100,
        max_bets_per_street: 4,
        alice_starting_stack_sat: 200,
        bob_starting_stack_sat: 200,
        fee_reserve_sat: 40_000,
        action_csv: 2,
        reveal_csv: 2,
        showdown_csv: 2,
        reveal_order: RevealOrder {
            flop_first: Role::Alice,
            turn_first: Role::Bob,
            river_first: Role::Alice,
        },
        timeout_policy: TimeoutSettlementPolicy::PotOnly,
        split_remainder_recipient: Role::Alice,
    };
    let origin = build_origin_escrow(identities)?;
    let mut path = PathExecutor::fund(
        &core,
        &mining,
        &origin.script_pubkey(),
        Amount::from_sat(rules.total_locked_value()? + if channel_owner.is_some() { 1000 } else { 500 }),
    )?;
    let origin_tip = path.tip().ok_or("origin missing")?.clone();
    let parameters = SettlementConfig {
        predeal_anchor: None,
        network: Network::Regtest,
        network_id: bitcoin::blockdata::constants::genesis_block(Network::Regtest)
            .block_hash()
            .to_byte_array(),
        origin: origin_tip.outpoint(),
        rules,
        fee_policy_id: fees.policy_id(),
        reveal_keys,
    };
    let ([a, b], actual_identities) =
        common::participants_with_context(parameters.session_anchor(), parameters.rules_hash()?)?;
    assert_eq!(actual_identities, secrets);
    let deal = a.accepted()?;
    let id = parameters.chain_id(deal)?;
    let (mut score_a, public_a) = generate_key(
        &mut OsRng,
        KeyContext::new(id, root_node_id(&id), LamportPurpose::AliceScore24Bit),
    )?;
    let (mut score_b, public_b) = generate_key(
        &mut OsRng,
        KeyContext::new(id, root_node_id(&id), LamportPurpose::BobScore24Bit),
    )?;
    let compile = |owner| -> TestResult<SettlementGraph> {
        let graph = SettlementGraph::compile(deal, parameters.clone(), &fees, [public_a.clone(), public_b.clone()])?;
        if let Some(owner) = owner {
            let commitments = graph.plan().nodes.iter().filter(|n| n.node_id != graph.plan().root_node_id)
                .map(|n| poker_bitcoin::channel::retirement_commitment(branch_secret(owner, n.node_id))).collect::<Vec<_>>();
            Ok(graph.with_channel_protection(owner, 3,
                poker_bitcoin::channel::retirement_commitment(branch_secret(owner, graph_root(id))), &commitments)?)
        } else { Ok(graph) }
    };
    let graph = compile(channel_owner)?;
    if let Some(owner) = channel_owner {
        let other = compile(Some(owner.other()))?;
        let roots = [graph.hand_commitment(origin_tip.output().clone(), 500)?,
            other.hand_commitment(origin_tip.output().clone(), 500)?];
        assert_eq!(roots[0].transaction().input[0].previous_output, roots[1].transaction().input[0].previous_output);
        assert_ne!(roots[0].txid(), roots[1].txid());
        let leaf = &origin.leaves()[0];
        for (i, root) in roots.iter().enumerate() {
            let digest = taproot_script_sighash_default(root.transaction(), 0, &[origin_tip.output().clone()], leaf.script())?;
            let sigs = signers.map(|k| sign_sighash_default(&secp, &k, digest).to_bytes().to_vec());
            let mut complete = root.transaction().clone();
            complete.input[0].witness = leaf.assemble_witness(&sigs)?;
            core.assert_package_accepted(&[complete.clone()], "either owner can publish its root")?;
            let publisher = if i == 0 { owner } else { owner.other() };
            let mut withheld = sigs;
            withheld[usize::from(publisher.code())] = vec![0; 64];
            let mut peer_copy = complete.clone();
            peer_copy.input[0].witness = leaf.assemble_witness(&withheld)?;
            core.assert_rejected(&peer_copy, "peer lacks owner funding signature and cannot frame owner")?;
            let gate = if i == 0 { graph.hand_gate()? } else { other.hand_gate()? };
            let guard = poker_bitcoin::channel::RevocationGuard { contest_blocks: 3,
                commitment: poker_bitcoin::channel::retirement_commitment(branch_secret(publisher, graph_root(id))),
                counterparty: signers[usize::from(publisher.other().code())].x_only_public_key().0 };
            let justice_leaf = gate.leaf(guard.predicate_id()).ok_or("hand justice missing")?;
            let justice = justice_transaction(&complete, 0, justice_leaf, &signers[usize::from(publisher.other().code())],
                branch_secret(publisher, graph_root(id)), core.new_script()?)?;
            core.assert_package_accepted(&[complete, justice], "stale hand root permits immediate justice")?;
        }
        let root = &roots[0];
        let digest = taproot_script_sighash_default(root.transaction(), 0, &[origin_tip.output().clone()], leaf.script())?;
        let mut complete = root.transaction().clone();
        complete.input[0].witness = leaf.assemble_witness(&signers.map(|k| sign_sighash_default(&secp, &k, digest).to_bytes().to_vec()))?;
        path.advance(&complete, 0, "channel owner commitment")?;
    }
    let activation = graph.activation(origin_tip.output().clone(), 500)?;
    let mut preparation =
        poker_settlement::preparation::SettlementPreparation::new(&graph, activation.clone())?;
    assert!(preparation.missing_count() > 0);
    for (index, request) in preparation.requests().to_vec().into_iter().enumerate() {
        let bytes = match request {
            AuthorizationRequest::Signature {
                node_id,
                edge_index,
                signer,
                sighash,
            } => {
                let _ = (node_id, edge_index);
                sign_sighash_default(&secp, &signers[usize::from(signer.code())], sighash)
                    .to_bytes()
                    .to_vec()
            }
            AuthorizationRequest::Reveal(context) => {
                let context = *context;
                let package = VerifiedRevealPackage::create(
                    context.clone(),
                    &reveal_secrets[usize::from(context.revealer)][usize::from(context.slot)],
                    &[80; 32],
                )
                .and_then(|p| VerifiedRevealPackage::verify(context.clone(), &p.to_bytes()))
                .map_err(|_| CompilerError::Preparation {
                    reason: "invalid test reveal package",
                })?;
                package.to_bytes()
            }
        };
        let mut corrupt = bytes.clone();
        corrupt[0] ^= 1;
        assert!(preparation.accept_response(index, &corrupt).is_err());
        preparation.accept_response(index, &bytes)?;
        preparation.accept_response(index, &bytes)?;
    }
    let snapshot = preparation.encode_snapshot()?;
    let mut restored =
        poker_settlement::preparation::SettlementPreparation::new(&graph, activation.clone())?;
    let mut corrupt = snapshot.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(restored.restore_verified_snapshot(&corrupt).is_err());
    assert_eq!(restored.missing_count(), restored.requests().len());
    restored.restore_verified_snapshot(&snapshot)?;
    assert_eq!(restored.missing_count(), 0);
    // Exercise authenticated local recovery, including lazy reveal materialization,
    // through the actual confirmed hand below.
    let checkpoint = restored.seal_checkpoint(&[97; 32])?;
    let restored = poker_settlement::preparation::SettlementPreparation::open_checkpoint(
        &[97; 32],
        &checkpoint,
        Network::Regtest,
    )?;
    let ready = restored.into_prepared_authorizations()?;
    assert_eq!(ready.activation().transaction(), activation.transaction());
    eprintln!(
        "complete dlog graph: {} nodes; preparation restored and every artifact reverified",
        graph.plan().nodes.len()
    );
    let gate = if channel_owner.is_some() { graph.hand_gate()? } else { origin };
    let entry_program = poker_bitcoin::LeafProgram::Action(poker_bitcoin::ActionProgram::new(id, root_node_id(&id), Action::Check, identities)?);
    let leaf = if channel_owner.is_some() { gate.leaf(entry_program.predicate_id()).ok_or("entry leaf missing")? } else { &gate.leaves()[0] };
    let digest = taproot_script_sighash_default(
        activation.transaction(),
        0,
        &[activation.parent_output().clone()],
        leaf.script(),
    )?;
    let mut tx = activation.transaction().clone();
    tx.input[0].witness = leaf.assemble_witness(
        &signers.map(|k| sign_sighash_default(&secp, &k, digest).to_bytes().to_vec()),
    )?;
    if channel_owner.is_some() {
        core.assert_rejected(&tx, "hand launch waits for retirement contest")?;
        path.mine_empty_blocks(2)?;
    }
    path.advance(&tx, 0, "dlog activation")?;
    let mut current = graph.plan().root_node_id;
    let mut observed = HashMap::new();
    let mut certificate_a = None;
    loop {
        let node = graph.plan().node(&current).ok_or("node missing")?;
        let state = graph.state(current)?;
        // The absent player's signature was fixed before activation. Verify
        // every timeout encountered on this route both before and after CSV.
        let timeout_index = node
            .edges
            .iter()
            .position(|e| e.timeout.is_some())
            .ok_or("timeout missing")?;
        let timeout_edge = &node.edges[timeout_index];
        let timeout = timeout_edge.timeout.ok_or("timeout metadata missing")?;
        let timeout_template = graph.transition(
            current,
            timeout_index,
            path.tip().ok_or("tip missing")?.outpoint(),
        )?;
        let timeout_leaf = state
            .leaf(graph.program(current, timeout_index)?.predicate_id())
            .ok_or("timeout leaf missing")?;
        let timeout_digest = taproot_script_sighash_default(
            timeout_template.transaction(),
            0,
            &[timeout_template.parent_output().clone()],
            timeout_leaf.script(),
        )?;
        let (absent, fixed) = ready.signature(current, timeout_index)?;
        assert_eq!(absent, timeout.defaulting);
        let beneficiary = sign_sighash_default(
            &secp,
            &signers[usize::from(timeout.beneficiary.code())],
            timeout_digest,
        )
        .to_bytes();
        let timeout_auth = if absent == Role::Alice {
            [fixed.to_bytes(), beneficiary]
        } else {
            [beneficiary, fixed.to_bytes()]
        };
        let mut timeout_tx = timeout_template.transaction().clone();
        timeout_tx.input[0].witness =
            timeout_leaf.assemble_witness(&timeout_auth.map(|s| s.to_vec()))?;
        path.assert_rejected(&timeout_tx, "dlog graph timeout before CSV")?;
        path.mine_empty_blocks(timeout.csv + graph.contest_delay(current))?;
        core.assert_package_accepted(&[timeout_tx.clone()], "mature unilateral dlog graph timeout")?;
        if let Some(owner) = channel_owner {
            let child = timeout_edge.child_node_id;
            let guard = graph.branch_guard(child)?.ok_or("timeout guard missing")?;
            // Timeout splits value; each payout must retain the same justice right.
            let terminal = graph.node(&child).ok_or("timeout child missing")?;
            let PlannedState::Terminal(t) = terminal.state else { return Err("timeout is not terminal".into()); };
            let mut vout = 0;
            for (recipient, amount) in [(Role::Alice, t.alice_output_sat), (Role::Bob, t.bob_output_sat)] {
                if amount == 0 { continue; }
                let payout = graph.guarded_payout(child, recipient)?;
                let justice = payout_justice(&timeout_tx, vout, &payout, &signers[usize::from(timeout.beneficiary.other().code())],
                    branch_secret(owner, child), core.new_script()?)?;
                assert_eq!(poker_bitcoin::channel::retirement_commitment(branch_secret(owner, child)), guard.commitment);
                core.assert_package_accepted(&[timeout_tx.clone(), justice], "retired timeout cannot split funds out of justice")?;
                vout += 1;
            }
        }
        let role = match node.state {
            PlannedState::Reveal { pattern, .. } => pattern.revealer(),
            PlannedState::Betting { state, .. } => state.actor,
            PlannedState::AliceShowdown { .. } => Role::Alice,
            PlannedState::BobTerminal { .. } => Role::Bob,
            PlannedState::Terminal(_) => return Err("terminal entered loop".into()),
        };
        let mut chosen = 0;
        let mut hand_keys = Vec::new();
        let mut subset = 0;
        let mut score = 0;
        if matches!(
            node.state,
            PlannedState::AliceShowdown { .. } | PlannedState::BobTerminal { .. }
        ) {
            let slots = if role == Role::Alice {
                poker_bitcoin::ALICE_SEVEN_SLOTS
            } else {
                poker_bitcoin::BOB_SEVEN_SLOTS
            };
            for slot in slots {
                let owner = usize::from(role.code());
                let peer = 1 - owner;
                let local = &[&a, &b][owner].setup_secrets()?.openings[usize::from(slot)];
                let local_open = ShareOpening {
                    value: local.value(),
                    blinding: *local.gamma(),
                };
                // Counterparty knowledge comes only from confirmed reveal witnesses.
                let &(value, blinding) = observed
                    .get(&(peer as u8, slot))
                    .ok_or("counterparty opening not observed on chain")?;
                let peer_open = ShareOpening { value, blinding };
                let (oa, ob) = if owner == 0 {
                    (local_open, peer_open)
                } else {
                    (peer_open, local_open)
                };
                let oa = verify_share_opening(deal, dealer_protocol::Role::A, slot, oa)?;
                let ob = verify_share_opening(deal, dealer_protocol::Role::B, slot, ob)?;
                hand_keys.push(derive_card_signing_key(deal, slot, &oa, &ob)?);
            }
            let cards: [u8; 7] = std::array::from_fn(|i| hand_keys[i].card_id());
            for candidate in 0..21 {
                let value =
                    poker_eval::evaluate_five_cards(poker_eval::selected_five(cards, candidate)?)?;
                if value > score {
                    score = value;
                    subset = candidate;
                }
            }
            if role == Role::Bob {
                let alice: &poker_score_ots::AliceScoreCertificate =
                    certificate_a.as_ref().ok_or("Alice score missing")?;
                let outcome = match score.cmp(&alice.score_a().get()) {
                    std::cmp::Ordering::Less => ShowdownOutcome::AliceWin,
                    std::cmp::Ordering::Greater => ShowdownOutcome::BobWin,
                    std::cmp::Ordering::Equal => ShowdownOutcome::Split,
                };
                chosen = node
                    .edges
                    .iter()
                    .position(|e| e.kind == EdgeKind::BobPayout(outcome))
                    .ok_or("payout branch missing")?;
            }
        } else if matches!(node.state, PlannedState::Betting { .. }) {
            chosen = node
                .edges
                .iter()
                .position(|e| matches!(e.kind, EdgeKind::Action(Action::Call | Action::Check)))
                .ok_or("passive action missing")?;
        }
        let edge = &node.edges[chosen];
        let template =
            graph.transition(current, chosen, path.tip().ok_or("tip missing")?.outpoint())?;
        let leaf = state
            .leaf(graph.program(current, chosen)?.predicate_id())
            .ok_or("leaf missing")?;
        let digest = taproot_script_sighash_default(
            template.transaction(),
            0,
            &[template.parent_output().clone()],
            leaf.script(),
        )?;
        let live =
            sign_sighash_default(&secp, &signers[usize::from(role.code())], digest).to_bytes();
        let elements = if let PlannedState::Reveal { pattern, .. } = node.state {
            let mut elements = vec![live.to_vec()];
            for &slot in pattern.slots() {
                let opening = &[&a, &b][usize::from(role.code())].setup_secrets()?.openings
                    [usize::from(slot)];
                elements.push(
                    ready
                        .reveal(current, slot)?
                        .complete(opening.value(), *opening.gamma())?
                        .to_vec(),
                );
            }
            elements
        } else {
            let (signer, presigned) = ready.signature(current, chosen)?;
            let presigned = presigned.to_bytes();
            assert_eq!(signer, role.other());
            let auth = if role == Role::Alice {
                [live, presigned]
            } else {
                [presigned, live]
            };
            if hand_keys.is_empty() {
                auth.map(|s| s.to_vec()).to_vec()
            } else {
                let sigs: [[u8; 64]; 7] = common::try_array(|i| {
                    Ok(hand_keys[i]
                        .sign_tapscript_sighash(&digest, &[81; 32])?
                        .to_bytes())
                })?;
                let sums = std::array::from_fn(|i| hand_keys[i].raw_sum());
                let hand = poker_bitcoin::showdown_witness::ShowdownWitness::verify(
                    deal, role, digest, sums, sigs, subset, score,
                )?;
                if role == Role::Alice {
                    let cert = issue_alice_score_certificate(&mut score_a, Score24::new(score)?)?;
                    let elements = hand.alice_elements(auth, &cert)?;
                    certificate_a = Some(cert);
                    elements
                } else {
                    let cert = issue_bob_score_certificate(&mut score_b, Score24::new(score)?)?;
                    hand.bob_elements(
                        auth,
                        certificate_a.as_ref().ok_or("Alice score absent")?,
                        &cert,
                    )?
                }
            }
        };
        let mut tx = template.transaction().clone();
        tx.input[0].witness = leaf.assemble_witness(&elements)?;
        let terminal = matches!(
            graph
                .plan()
                .node(&edge.child_node_id)
                .ok_or("child missing")?
                .state,
            PlannedState::Terminal(_)
        );
        if terminal {
            path.finish(&tx, "dlog graph final payout")?;
            break;
        }
        path.advance(&tx, 0, &format!("dlog graph {:?}", node.state.phase()))?;
        if let PlannedState::Reveal { pattern, .. } = node.state {
            for (i, &slot) in pattern.slots().iter().enumerate() {
                let sig: [u8; 64] = tx.input[0]
                    .witness
                    .iter()
                    .nth(i + 1)
                    .ok_or("confirmed reveal missing")?
                    .try_into()?;
                observed.insert(
                    (role.code(), slot),
                    ready.reveal(current, slot)?.extract(&sig)?,
                );
            }
        }
        current = edge.child_node_id;
    }
    eprintln!(
        "PASS: dlog full graph activation, hole delivery, all-in call, three board reveal pairs, both showdowns and payout confirmed"
    );
    Ok(())
}
