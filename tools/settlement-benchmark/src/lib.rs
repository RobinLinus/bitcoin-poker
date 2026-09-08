//! Browser-only performance harness with public, deterministic TEST keys.
//! This tool never funds or broadcasts transactions and is not a wallet binding.
use bitcoin::hashes::HashEngine;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, OutPoint, TxOut, Txid, hashes::Hash};
use dealer_bitcoin::reveal::VerifiedRevealPackage;
use dealer_protocol::{GameConfig, LiveParticipant};
use poker_bitcoin::{ClassFeePolicy, FeePolicy, sign_sighash_default};
use poker_score_ots::{KeyContext, LamportPurpose, generate_key};
use poker_settlement::{
    preparation::SettlementPreparation,
    settlement::{AuthorizationRequest, SettlementConfig, SettlementGraph, build_origin_escrow},
};
use poker_settlement_types::{
    PokerRules, RevealOrder, Role, TimeoutSettlementPolicy, root_node_id,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::{cell::RefCell, error::Error};

mod parallel;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

#[cfg(target_arch = "wasm32")]
fn reject_randomness(_: &mut [u8]) -> std::result::Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(reject_randomness);

// This isolated diagnostic ABI imports only a clock and progress notification.
// No pointers, keys, transaction bytes, or host capabilities cross these imports.
#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "benchmark")]
unsafe extern "C" {
    fn progress(phase: u32, done: u32, total: u32, bytes: f64);
    fn now_ms() -> f64;
}
fn report(phase: u32, done: usize, total: usize, bytes: usize) {
    #[cfg(target_arch = "wasm32")]
    // SAFETY: the harness supplies the declared numeric-only callback.
    unsafe {
        progress(phase, done as u32, total as u32, bytes as f64);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (phase, done, total, bytes);
    }
}
fn clock() -> f64 {
    #[cfg(target_arch = "wasm32")]
    // SAFETY: the harness supplies a side-effect-free performance.now callback.
    unsafe {
        now_ms()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0.0
    }
}
thread_local! {
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static INVENTORY_DIGEST: RefCell<[u8; 32]> = const { RefCell::new([0; 32]) };
    static TIMINGS: RefCell<[f64; 2]> = const { RefCell::new([0.0; 2]) };
}

/// Return the last failure's UTF-8 pointer (valid until the next run).
#[unsafe(no_mangle)]
pub extern "C" fn tree_error_ptr() -> *const u8 {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}
/// Return the last failure's UTF-8 length.
#[unsafe(no_mangle)]
pub extern "C" fn tree_error_len() -> usize {
    LAST_ERROR.with(|e| e.borrow().len())
}
/// Pointer to the ordered inventory SHA-256, available after inventory derivation.
#[unsafe(no_mangle)]
pub extern "C" fn tree_inventory_digest_ptr() -> *const u8 {
    INVENTORY_DIGEST.with(|digest| digest.borrow().as_ptr())
}
/// Total signing/package creation time (0), or receiver verification time (1).
#[unsafe(no_mangle)]
pub extern "C" fn tree_timing(index: usize) -> f64 {
    TIMINGS.with(|t| t.borrow().get(index).copied().unwrap_or(0.0))
}
/// Run full reference tree (1) or short-stack smoke profile (0). Returns 1 on success.
#[unsafe(no_mangle)]
pub extern "C" fn tree_run(full: u32) -> u32 {
    LAST_ERROR.with(|e| e.borrow_mut().clear());
    TIMINGS.with(|t| *t.borrow_mut() = [0.0; 2]);
    match run(full != 0, false) {
        Ok(()) => 1,
        Err(error) => {
            LAST_ERROR.with(|e| *e.borrow_mut() = error.to_string().into_bytes());
            0
        }
    }
}

fn run(full: bool, inventory_only: bool) -> Result {
    report(1, 0, 0, 0);
    let secp = Secp256k1::new();
    let mut secrets = [[3; 32], [5; 32]];
    secrets.sort_by_key(|secret| {
        SecretKey::from_slice(secret)
            .map(|key| {
                Keypair::from_secret_key(&secp, &key)
                    .x_only_public_key()
                    .0
                    .serialize()
            })
            .ok()
    });
    let signers: Vec<_> = secrets
        .iter()
        .map(|secret| {
            SecretKey::from_slice(secret).map(|key| Keypair::from_secret_key(&secp, &key))
        })
        .collect::<std::result::Result<_, _>>()?;
    let identities = [
        signers[0].x_only_public_key().0.serialize(),
        signers[1].x_only_public_key().0.serialize(),
    ];
    let mut reveal_keys = [[[0; 32]; 9]; 2];
    let mut reveal_secrets = [[[0; 32]; 9]; 2];
    for role in 0..2 {
        for slot in 0..9 {
            let secret = [u8::try_from(40 + role * 9 + slot)?; 32];
            reveal_secrets[role][slot] = secret;
            reveal_keys[role][slot] =
                Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret)?)
                    .x_only_public_key()
                    .0
                    .serialize();
        }
    }
    let fees = ClassFeePolicy::new(500, 700, 11_000, 12_000, 500, 330)?;
    let rules = PokerRules {
        button: Role::Alice,
        unit_sat: 100,
        max_bets_per_street: 4,
        alice_starting_stack_sat: if full { 20_000 } else { 200 },
        bob_starting_stack_sat: if full { 20_000 } else { 200 },
        fee_reserve_sat: 50_000,
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
    let origin_output = TxOut {
        value: Amount::from_sat(rules.total_locked_value()? + 500),
        script_pubkey: build_origin_escrow(identities)?.script_pubkey(),
    };
    let parameters = SettlementConfig {
        network: Network::Regtest,
        network_id: bitcoin::blockdata::constants::genesis_block(Network::Regtest)
            .block_hash()
            .to_byte_array(),
        origin: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
        rules,
        fee_policy_id: fees.policy_id(),
        reveal_keys,
    };
    let config = GameConfig {
        network_genesis: parameters.network_id,
        session_anchor: parameters.session_anchor(),
        identity_a: identities[0],
        identity_b: identities[1],
        session_nonce: [3; 32],
        rules_hash: parameters.rules_hash()?,
    };
    let mut alice = LiveParticipant::new(
        config.clone(),
        dealer_protocol::Role::A,
        secrets[0],
        [0x51; 32],
    )?;
    let mut bob = LiveParticipant::new(config, dealer_protocol::Role::B, secrets[1], [0x62; 32])?;
    for _ in 0..500 {
        if alice.snapshot().accepted && bob.snapshot().accepted {
            break;
        }
        if alice.snapshot().retry_required && bob.snapshot().retry_required {
            let next = alice.snapshot().attempt + 1;
            alice.start_retry(next)?;
            bob.start_retry(next)?;
        }
        let a = alice.prepare_outgoing()?;
        let b = bob.prepare_outgoing()?;
        if let Some(bytes) = &a {
            alice.confirm_persisted_outgoing(bytes)?;
            bob.accept_peer(bytes)?;
        }
        if let Some(bytes) = &b {
            bob.confirm_persisted_outgoing(bytes)?;
            alice.accept_peer(bytes)?;
        }
    }
    if alice.certificate()? != bob.certificate()? {
        return Err("participants disagree".into());
    }
    dealer_protocol::verify_setup_certificate(alice.certificate()?)?;
    let deal = alice.accepted()?;
    report(2, 0, 0, 0);
    let id = parameters.chain_id(deal)?;
    let mut rng = ChaCha20Rng::from_seed([91; 32]);
    let (_, score_a) = generate_key(
        &mut rng,
        KeyContext::new(id, root_node_id(&id), LamportPurpose::AliceScore24Bit),
    )?;
    let (_, score_b) = generate_key(
        &mut rng,
        KeyContext::new(id, root_node_id(&id), LamportPurpose::BobScore24Bit),
    )?;
    let graph = SettlementGraph::compile(deal, parameters, &fees, [score_a, score_b])?;
    let nodes = graph.plan().nodes.len();
    if nodes != if full { 56_132 } else { 26 } {
        return Err("unexpected tree size".into());
    }
    graph.plan().verify()?;
    let total_requests: usize = graph
        .plan()
        .nodes
        .iter()
        .map(|node| {
            node.edges
                .iter()
                .map(|edge| {
                    if matches!(
                        edge.kind,
                        poker_settlement_types::EdgeKind::HoleCardReveal { .. }
                            | poker_settlement_types::EdgeKind::CommunityReveal { .. }
                    ) {
                        match node.state {
                            poker_settlement::graph::PlannedState::Reveal { pattern, .. } => {
                                pattern.slots().len()
                            }
                            _ => 0,
                        }
                    } else {
                        1
                    }
                })
                .sum::<usize>()
        })
        .sum();
    report(3, 0, total_requests, nodes);
    let activation = graph.activation(origin_output, 500)?;
    let mut preparation =
        SettlementPreparation::with_progress(&graph, activation.clone(), |count| {
            if count % 128 == 0 {
                report(3, count, total_requests, nodes);
            }
        })?;
    if preparation.requests().len() != total_requests {
        return Err("incomplete inventory".into());
    }
    let mut digest = bitcoin::hashes::sha256::Hash::engine();
    for request in preparation.requests() {
        match request {
            AuthorizationRequest::Signature {
                node_id,
                edge_index,
                signer,
                sighash,
            } => {
                digest.input(&[0]);
                digest.input(node_id);
                digest.input(&(*edge_index as u64).to_le_bytes());
                digest.input(&[signer.code()]);
                digest.input(sighash);
            }
            AuthorizationRequest::Reveal(context) => {
                digest.input(&[1]);
                digest.input(&context.deal_id);
                digest.input(&context.graph_id);
                digest.input(&context.node_id);
                digest.input(&[context.revealer, context.slot]);
                digest.input(&context.authorizer);
                digest.input(&context.sighash);
            }
        }
    }
    let digest = bitcoin::hashes::sha256::Hash::from_engine(digest).to_byte_array();
    // Canonical fixture after 1ccb951 and the retained reveal-metadata
    // simplification. Prior script fingerprints remain in the live report.
    const REFERENCE_DIGEST: [u8; 32] = [
        0x9f, 0x67, 0x58, 0xce, 0x62, 0x6d, 0x58, 0xe7, 0xae, 0x76, 0xa1, 0x66, 0xc4, 0x89, 0x47,
        0xb4, 0x9d, 0xee, 0xe9, 0xf0, 0xa8, 0xe5, 0xbd, 0x72, 0x00, 0x21, 0x9e, 0x28, 0xc6, 0xa7,
        0x17, 0xda,
    ];
    if full && digest != REFERENCE_DIGEST {
        return Err(format!(
            "authorization inventory differs from canonical script fixture: {}",
            bitcoin::hashes::sha256::Hash::from_byte_array(digest)
        )
        .into());
    }
    INVENTORY_DIGEST.with(|out| *out.borrow_mut() = digest);
    if inventory_only {
        parallel::store(preparation);
        return Ok(());
    }
    report(4, 0, total_requests, 0);
    let mut bytes_total = 0;
    let mut signatures = 0;
    let mut packages = 0;
    let mut saw_signature = false;
    let mut saw_package = false;
    for index in 0..total_requests {
        let request = preparation.requests()[index].clone();
        let start = clock();
        let (bytes, reveal) = match request {
            AuthorizationRequest::Signature {
                signer, sighash, ..
            } => {
                signatures += 1;
                (
                    sign_sighash_default(&secp, &signers[usize::from(signer.code())], sighash)
                        .to_bytes()
                        .to_vec(),
                    false,
                )
            }
            AuthorizationRequest::Reveal(context) => {
                packages += 1;
                let secret =
                    &reveal_secrets[usize::from(context.revealer)][usize::from(context.slot)];
                (
                    VerifiedRevealPackage::create(*context, secret, &[80; 32])?.to_bytes(),
                    true,
                )
            }
        };
        let created = clock();
        preparation.accept_response(index, &bytes)?;
        let verified = clock();
        TIMINGS.with(|t| {
            let mut t = t.borrow_mut();
            t[0] += created - start;
            t[1] += verified - created;
        });
        // Test an actually new inventory slot: a corrupt duplicate would only test equality.
        // Malformed fresh responses are exercised below during independent restoration.
        if reveal {
            saw_package = true;
        } else {
            saw_signature = true;
        }
        bytes_total += bytes.len();
        if index % 32 == 0 || index + 1 == total_requests {
            report(4, index + 1, total_requests, bytes_total);
        }
    }
    if preparation.missing_count() != 0 || !saw_signature || !saw_package {
        return Err("incomplete authorization classes".into());
    }
    report(5, signatures, packages, bytes_total);
    let snapshot = preparation.encode_snapshot()?;
    let snapshot_len = snapshot.len();
    let ready = preparation.into_prepared_authorizations()?;
    if ready.activation().transaction() != activation.transaction() {
        return Err("activation mismatch".into());
    }
    drop(ready);
    report(6, 0, total_requests, snapshot_len);
    let mut restored = SettlementPreparation::with_progress(&graph, activation, |count| {
        if count % 128 == 0 {
            report(6, count, total_requests, snapshot_len);
        }
    })?;
    // Reject malformed signatures and adaptor packages before accepting anything.
    for is_reveal in [false, true] {
        let index = restored
            .requests()
            .iter()
            .position(|r| matches!(r, AuthorizationRequest::Reveal(_)) == is_reveal)
            .ok_or("missing authorization class")?;
        let bad = vec![
            0;
            if is_reveal {
                dealer_bitcoin::reveal::REVEAL_PACKAGE_BYTES
            } else {
                64
            }
        ];
        if restored.accept_response(index, &bad).is_ok() {
            return Err("accepted corrupt authorization".into());
        }
    }
    if restored.missing_count() != total_requests {
        return Err("corruption partially installed".into());
    }
    report(7, 0, total_requests, snapshot_len);
    restored.restore_verified_snapshot_with_progress(&snapshot, |count| {
        if count % 32 == 0 || count == total_requests {
            report(7, count, total_requests, snapshot_len);
        }
    })?;
    if restored.missing_count() != 0 {
        return Err("recovery left missing artifacts".into());
    }
    restored.into_prepared_authorizations()?;
    report(8, signatures, packages, snapshot_len);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn full_inventory_fingerprint() -> super::Result {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                super::run(true, true).map_err(|e| e.to_string())?;
                super::INVENTORY_DIGEST.with(|d| println!("inventory digest: {:02x?}", d.borrow()));
                Ok::<_, String>(())
            })?
            .join()
            .map_err(|_| "benchmark panicked")?
            .map_err(Into::into)
    }

    #[test]
    fn short_stack_preparation_and_recovery() -> super::Result {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| super::run(false, false).map_err(|e| e.to_string()))?
            .join()
            .map_err(|_| "benchmark panicked")?
            .map_err(Into::into)
    }
}
