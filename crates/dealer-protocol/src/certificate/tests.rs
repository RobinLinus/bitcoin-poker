use super::*;
use dealer_group::{SlotPublic, create_slot};
use dealer_proofs::{RangeWitness, prove_key_pop, prove_links, prove_range52};
use dealer_uniqueness::{create_decryption, create_scale_round};
use k256::{Scalar, schnorr::SigningKey};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

fn sign_envelope(
    role: Role,
    sequence: u32,
    stage: u16,
    root: [u8; 32],
    payload: Vec<u8>,
    game_id: [u8; 32],
    signing: &SigningKey,
) -> Envelope {
    let mut envelope = Envelope {
        version: PROTOCOL_VERSION,
        params_id: protocol_parameters().params_id,
        game_id,
        attempt: 0,
        stage,
        sender_role: role,
        sender_sequence: sequence,
        previous_stage_root: root,
        payload_type: stage,
        payload,
        signature: [0; 64],
    };
    envelope.signature = signing
        .sign_prehash_with_aux_rand(
            &envelope.digest(),
            &[u8::try_from(stage).expect("bounded test stage"); 32],
        )
        .expect("envelope signature")
        .to_bytes();
    envelope
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep this complete protocol or integration sequence in its specified order."
)]
fn make_fixture() -> Vec<u8> {
    let signing_a = SigningKey::from_bytes(&[3; 32]).expect("identity A");
    let signing_b = SigningKey::from_bytes(&[5; 32]).expect("identity B");
    let mut identities = [
        (
            Into::<[u8; 32]>::into(signing_a.verifying_key().to_bytes()),
            signing_a,
        ),
        (
            Into::<[u8; 32]>::into(signing_b.verifying_key().to_bytes()),
            signing_b,
        ),
    ];
    identities.sort_by_key(|entry| entry.0);
    let config = GameConfig {
        network_genesis: [1; 32],
        session_anchor: [2; 32],
        identity_a: identities[0].0,
        identity_b: identities[1].0,
        session_nonce: [3; 32],
        rules_hash: [4; 32],
    };
    let game_id = derive_game_id(&config).expect("game id");
    let t0 = attempt_root(&game_id, 0, &[0; 32]);
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let secrets = [Scalar::from(17_u64), Scalar::from(29_u64)];
    let publics = [
        protocol_parameters().g * secrets[0],
        protocol_parameters().g * secrets[1],
    ];
    let key_bodies: [KeyOpenBody; 2] = std::array::from_fn(|index| {
        let role = if index == 0 { Role::A } else { Role::B };
        let context = proof_context(game_id, 0, 1, role, t0);
        KeyOpenBody {
            public_key: publics[index],
            proof: prove_key_pop(&context.to_bytes(), &secrets[index], &mut rng)
                .expect("key proof"),
        }
    });
    let nonces_key = [[0x10; 32], [0x11; 32]];
    let key_commits: [[u8; 32]; 2] = std::array::from_fn(|i| {
        commit(
            &proof_context(game_id, 0, 1, if i == 0 { Role::A } else { Role::B }, t0),
            2,
            &nonces_key[i],
            &body_bytes_key(&key_bodies[i]),
        )
    });
    let mut sequence = [0_u32; 2];
    let mut envelopes = Vec::new();
    for i in 0..2 {
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            1,
            t0,
            key_commits[i].to_vec(),
            game_id,
            &identities[i].1,
        ));
        sequence[i] += 1;
    }
    let t1 = stage_root(&t0, 1, &envelopes.iter().collect::<Vec<_>>());
    for i in 0..2 {
        let mut payload = nonces_key[i].to_vec();
        payload.extend_from_slice(&body_bytes_key(&key_bodies[i]));
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            2,
            t1,
            payload,
            game_id,
            &identities[i].1,
        ));
        sequence[i] += 1;
    }
    let t2 = stage_root(&t1, 2, &envelopes[2..4].iter().collect::<Vec<_>>());
    let joint = JointPublic::new(publics[0], publics[1]).expect("joint");
    let values = [
        [0_u8, 1, 7, 15, 23, 31, 39, 47, 51],
        [2_u8, 8, 14, 20, 26, 32, 38, 44, 49],
    ];
    let gammas: [[Scalar; N_SLOTS]; 2] =
        std::array::from_fn(|p| std::array::from_fn(|i| Scalar::from((100 + p * 20 + i) as u64)));
    let randomness: [[Scalar; N_SLOTS]; 2] =
        std::array::from_fn(|p| std::array::from_fn(|i| Scalar::from((300 + p * 20 + i) as u64)));
    let bundles: [PlayerBundle; 2] = std::array::from_fn(|p| {
        let role = if p == 0 { Role::A } else { Role::B };
        let context = proof_context(game_id, 0, 3, role, t2);
        let slots: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
            create_slot(values[p][i], &gammas[p][i], &randomness[p][i], &joint.y).expect("slot")
        });
        let witnesses: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
            value: values[p][i],
            gamma: gammas[p][i],
        });
        let mut statement = context.to_bytes();
        joint.encode(&mut statement);
        for slot in &slots {
            slot.encode(&mut statement);
        }
        let range_proof = prove_range52(&statement, &slots, &witnesses, &mut rng).expect("range");
        let link_proof = prove_links(
            &statement,
            &range_proof,
            &witnesses,
            &randomness[p],
            &joint.y,
            &mut rng,
        )
        .expect("links");
        PlayerBundle {
            role,
            slots,
            range_proof,
            link_proof,
        }
    });
    let bundle_nonces = [[0x20; 32], [0x21; 32]];
    for i in 0..2 {
        let c = commit(
            &proof_context(game_id, 0, 3, if i == 0 { Role::A } else { Role::B }, t2),
            4,
            &bundle_nonces[i],
            &bundles[i].to_bytes(),
        );
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            3,
            t2,
            c.to_vec(),
            game_id,
            &identities[i].1,
        ));
        sequence[i] += 1;
    }
    let t3 = stage_root(&t2, 3, &envelopes[4..6].iter().collect::<Vec<_>>());
    for i in 0..2 {
        let mut p = bundle_nonces[i].to_vec();
        p.extend_from_slice(&bundles[i].to_bytes());
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            4,
            t3,
            p,
            game_id,
            &identities[i].1,
        ));
        sequence[i] += 1;
    }
    let t4 = stage_root(&t3, 4, &envelopes[6..8].iter().collect::<Vec<_>>());
    let tests = derive_zero_tests(&bundles[0].slots, &bundles[1].slots).expect("tests");
    let first = if tagged_hash(
        "DLOG52/first-blinder/v1",
        &[game_id.as_slice(), &0_u32.to_le_bytes()].concat(),
    )[0] & 1
        == 0
    {
        Role::A
    } else {
        Role::B
    };
    let second = if first == Role::A { Role::B } else { Role::A };
    let joint_bytes = joint.to_bytes();
    let scale1 = create_scale_round(
        "DLOG52/scale-first/v1",
        &proof_context(game_id, 0, 5, first, t4).to_bytes(),
        &joint_bytes,
        &tests,
        &mut rng,
    )
    .expect("scale1");
    let fi = first as usize;
    envelopes.push(sign_envelope(
        first,
        sequence[fi],
        5,
        t4,
        scale1.to_bytes(),
        game_id,
        &identities[fi].1,
    ));
    sequence[fi] += 1;
    let t5 = stage_root(&t4, 5, &envelopes[8..9].iter().collect::<Vec<_>>());
    let scaled1 = verify_scale_round(
        "DLOG52/scale-first/v1",
        &proof_context(game_id, 0, 5, first, t4).to_bytes(),
        &joint_bytes,
        &tests,
        &scale1,
    )
    .expect("verify scale1");
    let scale2 = create_scale_round(
        "DLOG52/scale-second/v1",
        &proof_context(game_id, 0, 6, second, t5).to_bytes(),
        &joint_bytes,
        &scaled1,
        &mut rng,
    )
    .expect("scale2");
    let si = second as usize;
    envelopes.push(sign_envelope(
        second,
        sequence[si],
        6,
        t5,
        scale2.to_bytes(),
        game_id,
        &identities[si].1,
    ));
    sequence[si] += 1;
    let t6 = stage_root(&t5, 6, &envelopes[9..10].iter().collect::<Vec<_>>());
    let scaled2 = verify_scale_round(
        "DLOG52/scale-second/v1",
        &proof_context(game_id, 0, 6, second, t5).to_bytes(),
        &joint_bytes,
        &scaled1,
        &scale2,
    )
    .expect("verify scale2");
    let decrypt: [_; 2] = std::array::from_fn(|i| {
        create_decryption(
            &proof_context(game_id, 0, 7, if i == 0 { Role::A } else { Role::B }, t6).to_bytes(),
            &joint_bytes,
            &scaled2,
            &secrets[i],
            &mut rng,
        )
        .expect("decrypt")
    });
    let decrypt_nonces = [[0x30; 32], [0x31; 32]];
    for i in 0..2 {
        let c = commit(
            &proof_context(game_id, 0, 7, if i == 0 { Role::A } else { Role::B }, t6),
            8,
            &decrypt_nonces[i],
            &decrypt[i].to_bytes(),
        );
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            7,
            t6,
            c.to_vec(),
            game_id,
            &identities[i].1,
        ));
        sequence[i] += 1;
    }
    let t7 = stage_root(&t6, 7, &envelopes[10..12].iter().collect::<Vec<_>>());
    for i in 0..2 {
        let mut p = decrypt_nonces[i].to_vec();
        p.extend_from_slice(&decrypt[i].to_bytes());
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            8,
            t7,
            p,
            game_id,
            &identities[i].1,
        ));
        sequence[i] += 1;
    }
    let t8 = stage_root(&t7, 8, &envelopes[12..14].iter().collect::<Vec<_>>());
    let va = verify_player_bundle(
        &proof_context(game_id, 0, 3, Role::A, t2),
        &joint,
        &bundles[0],
    )
    .expect("va");
    let vb = verify_player_bundle(
        &proof_context(game_id, 0, 3, Role::B, t2),
        &joint,
        &bundles[1],
    )
    .expect("vb");
    let catalogue = derive_candidate_keys(
        &game_id,
        0,
        (&config.identity_a, &config.identity_b),
        &va,
        &vb,
    )
    .expect("catalogue");
    let body = AcceptedDealBody {
        version: 1,
        params_id: protocol_parameters().params_id,
        game_id,
        attempt: 0,
        commitments_a: std::array::from_fn(|i| bundles[0].slots[i].commitment),
        commitments_b: std::array::from_fn(|i| bundles[1].slots[i].commitment),
        catalogue_hash: catalogue.hash,
        verification_root: t8,
    };
    let digest = accepted_body_hash(&body);
    let signatures: [[_; 64]; 2] = std::array::from_fn(|i| {
        identities[i]
            .1
            .sign_prehash_with_aux_rand(
                &digest,
                &[0x40 + u8::try_from(i).expect("two identities"); 32],
            )
            .expect("accept")
            .to_bytes()
    });
    for i in 0..2 {
        let mut p = digest.to_vec();
        p.extend_from_slice(&signatures[i]);
        envelopes.push(sign_envelope(
            if i == 0 { Role::A } else { Role::B },
            sequence[i],
            9,
            t8,
            p,
            game_id,
            &identities[i].1,
        ));
    }
    SetupCertificate {
        certificate_version: 1,
        game_config: config,
        previous_attempt_root: [0; 32],
        envelopes,
        accepted_deal: AcceptedDeal {
            body,
            signature_a: signatures[0],
            signature_b: signatures[1],
        },
    }
    .to_bytes()
}

#[test]
fn exact_certificate_replays_and_tampering_fails() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let bytes = make_fixture();
            assert_eq!(bytes.len(), 102_070);
            assert!(verify_setup_certificate(&bytes).is_ok());
            let mut changed = bytes;
            changed[10_000] ^= 1;
            assert!(verify_setup_certificate(&changed).is_err());
        })
        .expect("spawn")
        .join()
        .expect("join");
}
