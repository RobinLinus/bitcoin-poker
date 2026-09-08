use super::*;
use bitcoin::secp256k1::{Keypair, SecretKey};
use poker_score_ots::{generate_key, issue_alice_score_certificate};
use rand_core::OsRng;

#[test]
fn reveal_predicates_keep_context_outside_the_script() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let key = |byte| -> Result<[u8; 32], bitcoin::secp256k1::Error> {
        Ok(
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32])?)
                .x_only_public_key()
                .0
                .serialize(),
        )
    };
    let actor = key(1)?;
    let authorizer = key(2)?;
    let base = LeafProgram::Reveal(RevealProgram::new(
        [1; 32],
        [2; 32],
        actor,
        &[(0, authorizer)],
    )?);
    for (deal, node, slot) in [
        ([3; 32], [2; 32], 0),
        ([1; 32], [3; 32], 0),
        ([1; 32], [2; 32], 1),
    ] {
        let changed = LeafProgram::Reveal(RevealProgram::new(
            deal,
            node,
            actor,
            &[(slot, authorizer)],
        )?);
        assert_eq!(base.to_tapscript()?, changed.to_tapscript()?);
        assert_ne!(base.predicate_id(), changed.predicate_id());
    }
    let first = CompiledTaprootState::compile(&secp, [1; 32], std::slice::from_ref(&base))?;
    let second = CompiledTaprootState::compile(&secp, [2; 32], &[base])?;
    assert_ne!(first.script_pubkey(), second.script_pubkey());
    assert!(RevealProgram::new([0; 32], [2; 32], actor, &[(0, authorizer)]).is_err());
    assert!(RevealProgram::new([1; 32], [0; 32], actor, &[(0, authorizer)]).is_err());
    assert!(RevealProgram::new([1; 32], [2; 32], actor, &[(9, authorizer)]).is_err());
    Ok(())
}

#[test]
fn score_hashes_reject_changed_preimages_without_length_guards()
-> Result<(), Box<dyn std::error::Error>> {
    let game = [7; 32];
    let (mut secret, public) = generate_key(
        &mut OsRng,
        KeyContext::new(game, root_node_id(&game), LamportPurpose::AliceScore24Bit),
    )?;
    let score = Score24::new(poker_eval::evaluate_five_cards([0, 1, 2, 3, 4])?)?;
    let certificate = issue_alice_score_certificate(&mut secret, score)?;
    let script = append_score_certificate(Builder::new(), &public).into_script();
    let elements = alice_score_certificate_elements(&certificate);
    let (stack, _) = crate::eval5_script::tests::execute(&script, elements.clone())?;
    assert_eq!(stack, vec![encode_script_num(i64::from(score.get()))]);
    for length in [0, 31, 32, 33, 520] {
        let mut bad = elements.clone();
        bad[1].resize(length, 0);
        if length == 32 {
            bad[1][0] ^= 1;
        }
        assert!(crate::eval5_script::tests::execute(&script, bad).is_err());
    }
    Ok(())
}

#[test]
fn valid_nonstandard_preimages_remain_usable_after_alice_showdown()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::showdown_witness::ObservedAliceScoreCertificate;

    let game = [8; 32];
    let (mut secret, public) = generate_key(
        &mut OsRng,
        KeyContext::new(game, root_node_id(&game), LamportPurpose::AliceScore24Bit),
    )?;
    let score = Score24::new(poker_eval::evaluate_five_cards([0, 1, 2, 3, 4])?)?;
    let certificate = issue_alice_score_certificate(&mut secret, score)?;
    let original = alice_score_certificate_elements(&certificate);
    let bit = usize::from(LamportMessage::AliceScore(score).bits_msb_first()[0]);
    for length in [0, 31, 33, 520] {
        let mut elements = original.clone();
        elements[1] = vec![42; length];
        let mut pairs = public.public_hash_pairs().to_vec();
        pairs[0][bit] = Sha256::digest(&elements[1]).into();
        let public = LamportPublicKey::from_parts(public.context(), pairs)?;
        let script = append_score_certificate(Builder::new(), &public).into_script();
        let (stack, _) = crate::eval5_script::tests::execute(&script, elements.clone())?;
        assert_eq!(stack, vec![encode_script_num(i64::from(score.get()))]);
        let observed = ObservedAliceScoreCertificate::from_witness_elements(&elements, &public)?;
        assert_eq!(observed.to_witness_elements(), elements);
        let (reused, _) =
            crate::eval5_script::tests::execute(&script, observed.to_witness_elements())?;
        assert_eq!(reused, stack);
    }
    Ok(())
}

#[test]
fn signing_projection_matches_full_taproot_construction() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let keys = [1, 2].map(|n| Keypair::from_secret_key(&secp,
        &SecretKey::from_slice(&[n; 32]).unwrap()).x_only_public_key().0.serialize());
    let mut cache = std::collections::HashMap::new();
    for count in 1..=MAX_TAPROOT_LEAVES {
        let programs = (1..=count).map(|n| Ok(LeafProgram::Reveal(RevealProgram::new(
            [1; 32], [n as u8; 32], keys[n % 2], &[(0, keys[(n+1) % 2])],
        )?))).collect::<Result<Vec<_>, BitcoinBackendError>>()?;
        for delay in [0, 1, 144] {
            let guard = (delay > 0).then_some(crate::channel::RevocationGuard {
                contest_blocks: delay, commitment: [count as u8; 32],
                counterparty: XOnlyPublicKey::from_slice(&keys[1])?,
            });
            let full = CompiledTaprootState::compile_inner(&secp, [3; 32], &programs, guard)?;
            let (output, hashes) = CompiledTaprootState::signing_projection(
                &secp, [3; 32], &programs, guard, &mut cache)?;
            assert_eq!(output, full.script_pubkey(), "count={count}, delay={delay}");
            for (program, hash) in programs.iter().zip(hashes) {
                assert_eq!(hash, TapLeafHash::from_script(
                    full.leaf(program.predicate_id()).unwrap().script(), LeafVersion::TapScript));
            }
        }
    }
    assert!(cache.len() <= 128);
    Ok(())
}
