//! Consensus qualification for the conservative per-edge contest construction.
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut,
    opcodes::all::OP_CHECKSIG,
    script::Builder,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};
use poker_bitcoin::{
    TransactionTemplate,
    channel::{ContestOutput, RetirementLevel, retirement_commitment, retirement_secret},
    sign_sighash_default, taproot_script_sighash_default,
};
use poker_core_test_support::CoreCli;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn spend(
    output: &ContestOutput,
    parent: OutPoint,
    prevout: &TxOut,
    destination: ScriptBuf,
    delay: u16,
    signer: &Keypair,
    secret: Option<[u8; 32]>,
) -> Result<Transaction> {
    let child = TxOut {
        value: Amount::from_sat(prevout.value.to_sat() - 1_000),
        script_pubkey: destination,
    };
    let template = if delay == 0 {
        TransactionTemplate::normal(
            Network::Regtest,
            parent,
            prevout.clone(),
            vec![child],
            1_000,
        )?
    } else {
        TransactionTemplate::timeout(
            Network::Regtest,
            parent,
            prevout.clone(),
            vec![child],
            1_000,
            delay,
        )?
    };
    let script = if secret.is_some() {
        output.justice_script()
    } else {
        output.continuation_script()
    };
    let digest =
        taproot_script_sighash_default(template.transaction(), 0, &[prevout.clone()], script)?;
    let sig = sign_sighash_default(&Secp256k1::new(), signer, digest);
    let mut elements = vec![sig.to_bytes().to_vec()];
    if let Some(secret) = secret {
        elements.push(secret.to_vec());
    }
    let mut tx = template.transaction().clone();
    tx.input[0].witness = output.witness(secret.is_some(), &elements)?;
    Ok(tx)
}

#[test]
fn retirement_domains_and_scripts_are_distinct() -> Result {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32])?);
    let pubkey = key.x_only_public_key().0;
    let normal = Builder::new()
        .push_x_only_key(&pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let mut secrets = std::collections::HashSet::new();
    for level in [RetirementLevel::Hand, RetirementLevel::Branch] {
        for owner in [false, true] {
            for offender in [false, true] {
                for edge in 0..3 {
                    assert!(secrets.insert(retirement_secret(
                        &[1; 32], level, [2; 32], [3; 32], edge, owner, offender
                    )));
                }
            }
        }
    }
    assert!(ContestOutput::new(&secp, &normal, 0, [1; 32], pubkey).is_err());
    assert!(ContestOutput::new(&secp, &ScriptBuf::new(), 2, [1; 32], pubkey).is_err());
    let a = ContestOutput::new(&secp, &normal, 2, [1; 32], pubkey)?;
    let b = ContestOutput::new(&secp, &normal, 2, [2; 32], pubkey)?;
    assert_ne!(a.script_pubkey(), b.script_pubkey());
    Ok(())
}

#[test]
#[ignore = "requires managed Bitcoin Core; scripts/bitcoin-core-regtest.sh --suite channel --require"]
fn fixed_branch_contests() -> Result {
    let core = CoreCli::from_environment()?.ok_or("managed Core required")?;
    core.assert_regtest()?;
    let mining = core.new_address()?;
    core.mine(101, &mining)?;
    let secp = Secp256k1::new();
    let keys = [
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32])?),
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[4; 32])?),
    ];
    // Test both Bitcoin materializations and both edge authorizers independently.
    // This includes the case where the offender is NOT the publishing root owner.
    for owner in [false, true] {
        for offender in [false, true] {
            let actor = usize::from(offender);
            let victim = actor ^ 1;
            let secret = retirement_secret(
                &[9; 32],
                RetirementLevel::Branch,
                [1; 32],
                [2; 32],
                1,
                owner,
                offender,
            );
            let selected_secret = retirement_secret(
                &[9; 32],
                RetirementLevel::Branch,
                [1; 32],
                [2; 32],
                0,
                owner,
                offender,
            );
            let normal = Builder::new()
                .push_x_only_key(&keys[actor].x_only_public_key().0)
                .push_opcode(OP_CHECKSIG)
                .into_script();
            let make = |secret| {
                ContestOutput::new(
                    &secp,
                    &normal,
                    4,
                    retirement_commitment(secret),
                    keys[victim].x_only_public_key().0,
                )
            };
            let abandoned = make(secret)?;
            let selected = make(selected_secret)?;
            let funding = core.fund_script(
                &abandoned.script_pubkey(),
                Amount::from_sat(100_000),
                &mining,
            )?;
            let destination = core.new_script()?;
            let escape = spend(
                &abandoned,
                funding.outpoint(),
                funding.output(),
                destination.clone(),
                4,
                &keys[actor],
                None,
            )?;
            core.assert_rejected(&escape, "abandoned edge cannot escape before contest delay")?;
            let wrong = spend(
                &abandoned,
                funding.outpoint(),
                funding.output(),
                destination.clone(),
                0,
                &keys[victim],
                Some(selected_secret),
            )?;
            core.assert_rejected(&wrong, "selected-edge secret cannot revoke sibling")?;
            let self_theft = spend(
                &abandoned,
                funding.outpoint(),
                funding.output(),
                destination.clone(),
                0,
                &keys[actor],
                Some(secret),
            )?;
            core.assert_rejected(
                &self_theft,
                "offender preimage alone cannot steal justice output",
            )?;
            let justice = spend(
                &abandoned,
                funding.outpoint(),
                funding.output(),
                destination.clone(),
                0,
                &keys[victim],
                Some(secret),
            )?;
            let id = core.accept_and_broadcast(&justice, "immediate counterparty justice")?;
            core.mine_and_assert_included(id, &mining)?;
            core.assert_rejected(&escape, "offender cannot escape after justice")?;

            let funding = core.fund_script(
                &selected.script_pubkey(),
                Amount::from_sat(100_000),
                &mining,
            )?;
            let wrong = spend(
                &selected,
                funding.outpoint(),
                funding.output(),
                destination.clone(),
                0,
                &keys[victim],
                Some(secret),
            )?;
            core.assert_rejected(&wrong, "retirement preserves selected prefix")?;
            // A second protected output models a terminal branch. Delays accumulate.
            let next = make(selected_secret)?;
            let advance = spend(
                &selected,
                funding.outpoint(),
                funding.output(),
                next.script_pubkey(),
                4,
                &keys[actor],
                None,
            )?;
            core.assert_rejected(&advance, "selected prefix also observes its contest delay")?;
            core.mine(3, &mining)?;
            let id = core.accept_and_broadcast(&advance, "selected prefix remains executable")?;
            core.mine_and_assert_included(id, &mining)?;
            let terminal = spend(
                &next,
                OutPoint::new(id, 0),
                &advance.output[0],
                destination,
                4,
                &keys[actor],
                None,
            )?;
            core.assert_rejected(&terminal, "terminal has its own contest delay")?;
            core.mine(3, &mining)?;
            let id = core.accept_and_broadcast(&terminal, "terminal eventually settles")?;
            core.mine_and_assert_included(id, &mining)?;
        }
    }
    Ok(())
}
