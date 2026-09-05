//! Full reference topology is available with authenticated dlog parameters.
#[path = "../../../../dealing-dlog/crates/dlog52-bitcoin/tests/common/mod.rs"]
mod common;
use bitcoin::hashes::Hash;
use bitcoin::{Network, OutPoint, Txid};
use bp52_chain_bitcoin::{ClassFeePolicy, FeePolicy};
use bp52_chain_compiler::dlog::{DlogGraph, DlogParameters};
use bp52_chain_types::{PokerRules, RevealOrder, Role, TimeoutSettlementPolicy, root_node_id};
use bp52_lamport::{KeyContext, LamportPurpose, generate_key};
use common::TestResult;
use rand_core::OsRng;

#[test]
fn complete_dlog_reference_topology_and_binding() -> TestResult {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| run().map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "graph test panicked")?
        .map_err(Into::into)
}
fn run() -> TestResult {
    let fees = ClassFeePolicy::new(500, 700, 11_000, 12_000, 500, 330)?;
    let parameters = DlogParameters {
        network: Network::Regtest,
        network_id: bitcoin::blockdata::constants::genesis_block(Network::Regtest)
            .block_hash()
            .to_byte_array(),
        origin: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
        rules: PokerRules {
            button: Role::Alice,
            unit_sat: 100,
            max_bets_per_street: 4,
            alice_starting_stack_sat: 20_000,
            bob_starting_stack_sat: 20_000,
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
        },
        fee_policy_id: fees.policy_id(),
        reveal_keys: common::try_array(|role| {
            common::try_array(|slot| {
                let key = k256::schnorr::SigningKey::from_bytes(
                    &[u8::try_from(40 + role * 9 + slot)?; 32],
                )?;
                Ok(key.verifying_key().to_bytes().into())
            })
        })?,
    };
    let ([a, _], _) =
        common::participants_with_context(parameters.session_anchor(), parameters.rules_hash()?)?;
    let deal = a.accepted()?;
    let id = parameters.chain_id(deal)?;
    let (_, alice) = generate_key(
        &mut OsRng,
        KeyContext::new(id, root_node_id(&id), LamportPurpose::AliceScore24Bit),
    )?;
    let (_, bob) = generate_key(
        &mut OsRng,
        KeyContext::new(id, root_node_id(&id), LamportPurpose::BobScore24Bit),
    )?;
    let graph = DlogGraph::compile(
        deal,
        parameters.clone(),
        &fees,
        [alice.clone(), bob.clone()],
    )?;
    assert_eq!(graph.plan().nodes.len(), 56_132);
    assert_eq!(graph.plan().maximum_path_length, 33);
    assert_eq!(
        graph.plan().maximum_path_fee_sat,
        fees.maximum_reference_path_fee()?
    );
    graph.plan().verify()?;
    let mut phases = std::collections::HashSet::new();
    for node in &graph.plan().nodes {
        if phases.insert(node.state.phase()) && !node.edges.is_empty() {
            graph.state(node.node_id)?;
        }
    }
    let mut wrong = parameters.clone();
    wrong.rules.unit_sat += 1;
    assert!(wrong.chain_id(deal).is_err());
    let mut wrong = parameters.clone();
    wrong.origin.vout += 1;
    assert!(wrong.chain_id(deal).is_err());
    let mut wrong = parameters.clone();
    wrong.reveal_keys[1][1] = wrong.reveal_keys[0][0];
    assert!(wrong.rules_hash().is_err());
    let mut wrong = parameters;
    wrong.network = Network::Bitcoin;
    assert!(wrong.rules_hash().is_err());
    Ok(())
}
