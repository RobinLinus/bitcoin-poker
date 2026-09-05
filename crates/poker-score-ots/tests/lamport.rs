//! Public score-only Lamport API and canonical-codec tests.

#![forbid(unsafe_code)]

use poker_score_ots::{
    AliceScoreCertificate, BobScoreCertificate, ExpectedLamportEntry, HASH_SIZE, KeyContext,
    LamportError, LamportMessage, LamportPublicBundle, LamportPublicKey, LamportPurpose,
    LamportRole, LamportScriptPredicate, LamportSignature, SCORE_BIT_WIDTH, Score24, generate_key,
    issue_alice_score_certificate, issue_bob_score_certificate, sign_alice_score, sign_bob_score,
    verify_alice_score, verify_bob_score,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct TestRng(u64);

impl TestRng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let bytes = self.next_u64().to_le_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

fn context(game: u8, node: u8, purpose: LamportPurpose) -> KeyContext {
    KeyContext::new([game; 32], [node; 32], purpose)
}

#[test]
fn alice_and_bob_scores_pass_rust_and_script_models() -> TestResult {
    let score = Score24::new(0x81_2345)?;
    for (purpose, seed) in [
        (LamportPurpose::AliceScore24Bit, 0x5c0a_e001),
        (LamportPurpose::BobScore24Bit, 0x5c0b_e001),
    ] {
        let key_context = context(2, purpose as u8, purpose);
        let (mut secret, public) = generate_key(&mut TestRng::new(seed), key_context)?;
        let signature = match purpose {
            LamportPurpose::AliceScore24Bit => sign_alice_score(&mut secret, score)?,
            LamportPurpose::BobScore24Bit => sign_bob_score(&mut secret, score)?,
        };
        assert_eq!(signature.preimages().len(), usize::from(SCORE_BIT_WIDTH));
        let predicate = LamportScriptPredicate::new(public.clone());
        match purpose {
            LamportPurpose::AliceScore24Bit => {
                verify_alice_score(
                    &public,
                    key_context.chain_game_id,
                    key_context.node_id,
                    score,
                    &signature,
                )?;
                predicate.verify_alice_score_witness(
                    key_context.chain_game_id,
                    key_context.node_id,
                    score,
                    signature.preimages(),
                )?;
            }
            LamportPurpose::BobScore24Bit => {
                verify_bob_score(
                    &public,
                    key_context.chain_game_id,
                    key_context.node_id,
                    score,
                    &signature,
                )?;
                predicate.verify_bob_score_witness(
                    key_context.chain_game_id,
                    key_context.node_id,
                    score,
                    signature.preimages(),
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn role_specific_score_certificates_round_trip_and_reject_cross_purpose() -> TestResult {
    let game = [2; 32];
    let alice_node = [10; 32];
    let bob_node = [11; 32];
    let score_a = Score24::new(0x71_2000)?;
    let score_b = Score24::new(0x61_3000)?;
    let (mut alice_secret, alice_public) = generate_key(
        &mut TestRng::new(0x5c0a_e002),
        KeyContext::new(game, alice_node, LamportPurpose::AliceScore24Bit),
    )?;
    let (mut bob_secret, bob_public) = generate_key(
        &mut TestRng::new(0x5c0b_e002),
        KeyContext::new(game, bob_node, LamportPurpose::BobScore24Bit),
    )?;
    let alice = issue_alice_score_certificate(&mut alice_secret, score_a)?;
    let bob = issue_bob_score_certificate(&mut bob_secret, score_b)?;
    alice.verify(&alice_public, game, alice_node)?;
    bob.verify(&bob_public, game, bob_node)?;

    let alice_encoded = alice.encode();
    let bob_encoded = bob.encode();
    assert_eq!(AliceScoreCertificate::decode(&alice_encoded)?, alice);
    assert_eq!(BobScoreCertificate::decode(&bob_encoded)?, bob);
    assert!(AliceScoreCertificate::decode(&bob_encoded).is_err());
    assert!(BobScoreCertificate::decode(&alice_encoded).is_err());
    assert_eq!(
        AliceScoreCertificate::from_parts(score_a, bob.lamport_signature().clone()),
        Err(LamportError::WrongPurpose)
    );
    assert_eq!(
        BobScoreCertificate::from_parts(score_b, alice.lamport_signature().clone()),
        Err(LamportError::WrongPurpose)
    );
    Ok(())
}

#[test]
fn score_messages_are_fixed_width_and_most_significant_first() -> TestResult {
    let score = Score24::new(0x80_0001)?;
    for message in [
        LamportMessage::AliceScore(score),
        LamportMessage::BobScore(score),
    ] {
        let bits = message.bits_msb_first();
        assert_eq!(score.to_be_bytes(), [0x80, 0x00, 0x01]);
        assert_eq!(bits.len(), 24);
        assert_eq!(bits.first(), Some(&1));
        assert!(bits[1..23].iter().all(|bit| *bit == 0));
        assert_eq!(bits.last(), Some(&1));
    }
    Ok(())
}

#[test]
fn score_mutations_context_substitution_and_cross_role_keys_fail() -> TestResult {
    let key_context = context(3, 4, LamportPurpose::AliceScore24Bit);
    let (mut secret, public) = generate_key(&mut TestRng::new(32), key_context)?;
    let score = Score24::new(0x41_2000)?;
    let signature = sign_alice_score(&mut secret, score)?;

    assert_eq!(
        verify_alice_score(
            &public,
            key_context.chain_game_id,
            key_context.node_id,
            Score24::new(score.get() ^ 1)?,
            &signature,
        ),
        Err(LamportError::InvalidSignature { bit_index: 23 })
    );
    assert_eq!(
        verify_alice_score(&public, [99; 32], key_context.node_id, score, &signature),
        Err(LamportError::WrongGame)
    );
    assert_eq!(
        verify_alice_score(
            &public,
            key_context.chain_game_id,
            [99; 32],
            score,
            &signature,
        ),
        Err(LamportError::WrongNode)
    );
    assert_eq!(
        verify_bob_score(
            &public,
            key_context.chain_game_id,
            key_context.node_id,
            score,
            &signature,
        ),
        Err(LamportError::WrongPurpose)
    );

    let mut changed = signature.clone().into_witness_elements();
    changed[5][0] ^= 1;
    let changed = LamportSignature::from_parts(LamportPurpose::AliceScore24Bit, changed)?;
    assert_eq!(
        verify_alice_score(
            &public,
            key_context.chain_game_id,
            key_context.node_id,
            score,
            &changed,
        ),
        Err(LamportError::InvalidSignature { bit_index: 5 })
    );
    Ok(())
}

#[test]
fn retired_action_purpose_and_invalid_score_widths_are_rejected() {
    assert_eq!(
        LamportPurpose::try_from(0),
        Err(LamportError::InvalidPurpose(0))
    );
    assert_eq!(Score24::new(0), Err(LamportError::InvalidScore(0)));
    assert_eq!(
        Score24::new(0x0100_0000),
        Err(LamportError::InvalidScore(0x0100_0000))
    );
    let key_context = context(6, 6, LamportPurpose::AliceScore24Bit);
    assert_eq!(
        LamportPublicKey::from_parts(key_context, vec![[[0; HASH_SIZE]; 2]; 23]),
        Err(LamportError::InvalidBitWidth {
            expected: 24,
            actual: 23,
        })
    );
    assert_eq!(
        LamportSignature::from_parts(LamportPurpose::BobScore24Bit, vec![[0; HASH_SIZE]; 23]),
        Err(LamportError::InvalidSignatureLength {
            expected: 24,
            actual: 23,
        })
    );
}

#[test]
fn secret_preflight_single_use_erasure_and_debug_are_exact() -> TestResult {
    let key_context = context(7, 7, LamportPurpose::BobScore24Bit);
    let (mut secret, public) = generate_key(&mut TestRng::new(71), key_context)?;
    let (_, unrelated_public) = generate_key(&mut TestRng::new(72), key_context)?;
    assert!(secret.matches_public_key(&public));
    assert!(!secret.matches_public_key(&unrelated_public));
    assert!(format!("{secret:?}").contains("<redacted>"));

    let score = Score24::new(1)?;
    assert_eq!(
        sign_alice_score(&mut secret, score),
        Err(LamportError::WrongPurpose)
    );
    assert!(!secret.signature_was_issued());
    sign_bob_score(&mut secret, score)?;
    assert_eq!(
        sign_bob_score(&mut secret, score),
        Err(LamportError::KeyAlreadyUsed)
    );
    assert!(!secret.matches_public_key(&public));
    secret.erase_after_branch_confirmation();
    assert!(secret.is_erased());
    assert_eq!(
        sign_bob_score(&mut secret, score),
        Err(LamportError::KeyDestroyed)
    );
    Ok(())
}

#[test]
fn public_codecs_round_trip_and_reject_trailing_or_retired_purpose() -> TestResult {
    let key_context = context(10, 1, LamportPurpose::BobScore24Bit);
    let (mut secret, public) = generate_key(&mut TestRng::new(101), key_context)?;
    let signature = sign_bob_score(&mut secret, Score24::new(42)?)?;

    let public_encoded = public.encode();
    assert_eq!(
        LamportPublicKey::decode(&public_encoded),
        Ok(public.clone())
    );
    let mut retired = public_encoded.clone();
    retired[72] = 0;
    assert_eq!(
        LamportPublicKey::decode(&retired),
        Err(LamportError::InvalidPurpose(0))
    );
    let mut public_trailing = public_encoded;
    public_trailing.push(0);
    assert!(matches!(
        LamportPublicKey::decode(&public_trailing),
        Err(LamportError::TrailingData { .. })
    ));

    let signature_encoded = signature.encode();
    assert_eq!(LamportSignature::decode(&signature_encoded), Ok(signature));
    let mut signature_trailing = signature_encoded;
    signature_trailing.push(0);
    assert!(matches!(
        LamportSignature::decode(&signature_trailing),
        Err(LamportError::TrailingData { .. })
    ));

    let predicate = LamportScriptPredicate::new(public);
    let program = predicate.encode_program();
    assert_eq!(
        LamportScriptPredicate::decode_program(&program),
        Ok(predicate)
    );
    Ok(())
}

#[test]
fn canonical_bundle_membership_signature_and_codec_are_verified() -> TestResult {
    let game = [11; 32];
    let (_, alice_public) = generate_key(
        &mut TestRng::new(111),
        KeyContext::new(game, [1; 32], LamportPurpose::AliceScore24Bit),
    )?;
    let (_, bob_public) = generate_key(
        &mut TestRng::new(112),
        KeyContext::new(game, [2; 32], LamportPurpose::BobScore24Bit),
    )?;
    let bundle = LamportPublicBundle::sign(
        game,
        LamportRole::Alice,
        &[alice_public, bob_public],
        fake_sign,
    )?;
    let expected = [
        ExpectedLamportEntry::new([1; 32], LamportPurpose::AliceScore24Bit),
        ExpectedLamportEntry::new([2; 32], LamportPurpose::BobScore24Bit),
    ];
    bundle.verify(game, LamportRole::Alice, &expected, fake_verify)?;
    assert_eq!(
        bundle.verify(game, LamportRole::Bob, &expected, fake_verify),
        Err(LamportError::WrongRole)
    );
    assert_eq!(
        bundle.verify(game, LamportRole::Alice, &expected[..1], fake_verify),
        Err(LamportError::UnexpectedEntryCount {
            expected: 1,
            actual: 2,
        })
    );
    let encoded = bundle.encode();
    assert_eq!(LamportPublicBundle::decode(&encoded), Ok(bundle));
    Ok(())
}

#[test]
fn bundle_rejects_unsorted_entries_reused_material_and_wrong_game() -> TestResult {
    let game = [12; 32];
    let (_, first) = generate_key(
        &mut TestRng::new(121),
        KeyContext::new(game, [1; 32], LamportPurpose::AliceScore24Bit),
    )?;
    let (_, second) = generate_key(
        &mut TestRng::new(122),
        KeyContext::new(game, [2; 32], LamportPurpose::BobScore24Bit),
    )?;
    assert_eq!(
        LamportPublicBundle::sign(game, LamportRole::Bob, &[second, first.clone()], fake_sign,),
        Err(LamportError::EntriesNotSorted)
    );

    let reused = LamportPublicKey::from_parts(
        KeyContext::new(game, [2; 32], LamportPurpose::AliceScore24Bit),
        first.public_hash_pairs().to_vec(),
    )?;
    assert_eq!(
        LamportPublicBundle::sign(game, LamportRole::Bob, &[first, reused], fake_sign),
        Err(LamportError::DuplicatePublicHash)
    );

    let (_, wrong_game) = generate_key(
        &mut TestRng::new(123),
        KeyContext::new([99; 32], [3; 32], LamportPurpose::BobScore24Bit),
    )?;
    assert_eq!(
        LamportPublicBundle::sign(game, LamportRole::Bob, &[wrong_game], fake_sign),
        Err(LamportError::WrongGame)
    );
    Ok(())
}

fn fake_sign(digest: [u8; 32]) -> [u8; 64] {
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&digest);
    signature[32..].copy_from_slice(&digest);
    signature
}

fn fake_verify(digest: [u8; 32], signature: &[u8; 64]) -> bool {
    fake_sign(digest) == *signature
}
