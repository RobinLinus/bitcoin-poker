#![forbid(unsafe_code)]

use std::{
    error::Error,
    hint::black_box,
    io,
    time::{Duration, Instant},
};

use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1};
use bp52_circuit::hash_length::{
    AGGREGATED_SLOTS, HASH_LENGTH_PROOF_SIZE, HashLengthParameters, MESSAGE_BUFFER_BYTES,
    prove_hash_lengths, verify_hash_lengths, witness_buffer,
};
use bp52_codec::Encode;
use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, JointPublicKey, NonZeroScalar, ProtocolGenerators,
    SecretKeyShare, commit,
};
use bp52_protocol::messages::MAX_PLAYER_BUNDLE_SIZE;
use bp52_protocol::{
    PROTOCOL_VERSION, Role,
    auth::{
        CanonicalIdentities, accepted_deal_digest, derive_game_id, sign_envelope,
        verify_accepted_deal_signatures, verify_envelope,
    },
    bundle::{
        generate_player_bundle as generate_protocol_player_bundle, verify_player_bundle_pair,
    },
    commitments::{
        bundle_commitment, decryption_commitment, key_commitment, verify_bundle_commitment,
        verify_decryption_commitment, verify_key_commitment,
    },
    messages::{AcceptedDeal, AcceptedDealBody, Envelope, PlayerBundle, UnsignedEnvelope},
    payloads::{
        BundleOpenPayload, CommitmentPayload, DecryptOpenPayload, KeyOpenPayload, ProtocolPayload,
    },
    state::{ATTEMPT_ENVELOPE_COUNT, expected_envelope, first_blinder},
    transcript::{AttemptContext, ProofCommonFrame, ProofDomain, proof_transcript},
    verify_accepted_archive,
};
use bp52_sigma::{
    N_SLOTS, ZERO_TEST_COUNT,
    encryption_link::{EncryptionLinkProof, EncryptionLinkStatement, EncryptionLinkWitness},
    schnorr::{KEY_PROOF_SIZE, KeyProof},
};
use bp52_uniqueness::{
    PARTIAL_DECRYPTION_BATCH_SIZE, SCALE_ROUND_SIZE, derive_sums_and_zero_tests,
    generate_partial_decryption_batch, generate_scale_round, verify_decryption_batches,
    verify_partial_decryption_batch, verify_scale_round,
};
use curve25519_dalek::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, Error as RandError, OsRng, RngCore};
use sha2::{Digest, Sha256};

type BenchResult<T = ()> = Result<T, Box<dyn Error>>;

const SIGNED_ENVELOPE_OVERHEAD: usize = 147;
const ACCEPTED_DEAL_CERTIFICATE_SIZE: usize = 774;

fn main() -> BenchResult {
    let Some(scenario) = std::env::args().nth(1) else {
        print_usage();
        return Ok(());
    };

    println!(
        "BP52 benchmark: {scenario} on {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    match scenario.as_str() {
        "hash-length" => benchmark_hash_length(),
        "encryption-link" => benchmark_encryption_link(),
        "uniqueness" => benchmark_uniqueness(),
        "bandwidth" => {
            report_bandwidth();
            Ok(())
        }
        "attempt" => benchmark_complete_attempt(),
        _ => {
            print_usage();
            Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown benchmark scenario").into())
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: cargo run --release --manifest-path benchmarks/Cargo.toml -- \
         <hash-length|encryption-link|uniqueness|bandwidth|attempt>"
    );
}

fn benchmark_hash_length() -> BenchResult {
    let parameters = measured("hash-length parameter setup", HashLengthParameters::new)?;
    let fixture = hash_fixture()?;

    let proof = measured("one-player nine-slot Bulletproof generation", || {
        prove_hash_lengths(
            &parameters,
            hash_transcript(parameters.circuit_id()),
            &fixture.hashes,
            &fixture.commitments,
            &fixture.values,
            &fixture.blindings,
            &fixture.buffers,
        )
    })?;
    assert_eq!(proof.len(), HASH_LENGTH_PROOF_SIZE);
    black_box(&proof);

    measured("one-player nine-slot Bulletproof verification", || {
        verify_hash_lengths(
            &parameters,
            hash_transcript(parameters.circuit_id()),
            &fixture.hashes,
            &fixture.commitments,
            &proof,
        )
    })?;
    println!("hash-length proof bytes: {}", proof.len());
    Ok(())
}

fn benchmark_encryption_link() -> BenchResult {
    let fixture = link_fixture()?;
    let proof = measured("nine-slot encryption-link generation", || {
        EncryptionLinkProof::prove(
            &mut Transcript::new(b"BP52/bench/encryption-link/v1"),
            &fixture.generators,
            &fixture.joint_key,
            &fixture.statements,
            &fixture.witnesses,
            &mut OsRng,
        )
    })?;
    black_box(&proof);
    measured("nine-slot encryption-link verification", || {
        proof.verify(
            &mut Transcript::new(b"BP52/bench/encryption-link/v1"),
            &fixture.generators,
            &fixture.joint_key,
            &fixture.statements,
        )
    })?;
    println!(
        "encryption-link proof bytes: {}",
        proof.encode_to_vec()?.len()
    );
    Ok(())
}

fn benchmark_uniqueness() -> BenchResult {
    let threshold = threshold_fixture()?;
    let inputs = uniqueness_inputs(&threshold)?;

    let first = measured("108-test first blinding generation", || {
        generate_scale_round(
            &mut Transcript::new(b"BP52/bench/scale-first/v1"),
            &threshold.generators,
            &inputs,
            &mut OsRng,
        )
    })?;
    measured("108-test first blinding verification", || {
        verify_scale_round(
            &mut Transcript::new(b"BP52/bench/scale-first/v1"),
            &threshold.generators,
            &inputs,
            &first,
        )
    })?;

    let second = measured("108-test second blinding generation", || {
        generate_scale_round(
            &mut Transcript::new(b"BP52/bench/scale-second/v1"),
            &threshold.generators,
            &first.outputs,
            &mut OsRng,
        )
    })?;
    measured("108-test second blinding verification", || {
        verify_scale_round(
            &mut Transcript::new(b"BP52/bench/scale-second/v1"),
            &threshold.generators,
            &first.outputs,
            &second,
        )
    })?;

    let partial_a = measured("Alice 108-share partial-decryption generation", || {
        generate_partial_decryption_batch(
            &mut Transcript::new(b"BP52/bench/partial-a/v1"),
            &threshold.generators,
            &threshold.public_a,
            &threshold.secret_a,
            &second.outputs,
            &mut OsRng,
        )
    })?;
    measured("Alice 108-share partial-decryption verification", || {
        verify_partial_decryption_batch(
            &mut Transcript::new(b"BP52/bench/partial-a/v1"),
            &threshold.generators,
            &threshold.public_a,
            &second.outputs,
            &partial_a,
        )
    })?;

    let partial_b = measured("Bob 108-share partial-decryption generation", || {
        generate_partial_decryption_batch(
            &mut Transcript::new(b"BP52/bench/partial-b/v1"),
            &threshold.generators,
            &threshold.public_b,
            &threshold.secret_b,
            &second.outputs,
            &mut OsRng,
        )
    })?;
    measured("Bob 108-share partial-decryption verification", || {
        verify_partial_decryption_batch(
            &mut Transcript::new(b"BP52/bench/partial-b/v1"),
            &threshold.generators,
            &threshold.public_b,
            &second.outputs,
            &partial_b,
        )
    })?;

    println!(
        "uniqueness wire bytes: two scale rounds={}, two partial batches={}",
        2 * SCALE_ROUND_SIZE,
        2 * PARTIAL_DECRYPTION_BATCH_SIZE
    );
    black_box((first, second, partial_a, partial_b));
    Ok(())
}

fn benchmark_complete_attempt() -> BenchResult {
    let total_started = Instant::now();
    let identities = measured("canonical identity setup", IdentityFixture::new)?;
    let game_id = measured("funded-game identifier derivation", || {
        let session_nonce = random_array()?;
        BenchResult::Ok(derive_game_id(
            &[0_u8; 32],
            &[1_u8; 36],
            &identities.identities,
            &session_nonce,
        ))
    })?;
    let parameters = measured(
        "fixed hash-length parameter setup",
        HashLengthParameters::new,
    )?;
    let generators = ProtocolGenerators::derive()?;
    let threshold = measured("fresh two-party threshold-key setup", || {
        random_threshold_fixture(&generators)
    })?;
    let common = ProofCommonFrame::new(
        identities.identities.alice().serialize(),
        identities.identities.bob().serialize(),
        &threshold.joint_key,
        parameters.circuit_id(),
    )?;

    let mut wire = AttemptWire::new(&identities, game_id, 0);

    let nonce_key_a = random_array()?;
    let nonce_key_b = random_array()?;
    let (key_commit_a, key_commit_b) = measured("two key commit/open digest checks", || {
        let commitment_a = key_commitment(
            &wire.context.game_id,
            wire.context.attempt,
            Role::Alice,
            &nonce_key_a,
            &threshold.public_a.to_bytes(),
        );
        let commitment_b = key_commitment(
            &wire.context.game_id,
            wire.context.attempt,
            Role::Bob,
            &nonce_key_b,
            &threshold.public_b.to_bytes(),
        );
        verify_key_commitment(
            &commitment_a,
            &wire.context.game_id,
            wire.context.attempt,
            Role::Alice,
            &nonce_key_a,
            &threshold.public_a.to_bytes(),
        )?;
        verify_key_commitment(
            &commitment_b,
            &wire.context.game_id,
            wire.context.attempt,
            Role::Bob,
            &nonce_key_b,
            &threshold.public_b.to_bytes(),
        )?;
        BenchResult::Ok((commitment_a, commitment_b))
    })?;
    wire.push(&ProtocolPayload::KeyCommit(CommitmentPayload {
        commitment: key_commit_a,
    }))?;
    wire.push(&ProtocolPayload::KeyCommit(CommitmentPayload {
        commitment: key_commit_b,
    }))?;
    wire.push(&ProtocolPayload::KeyOpen(KeyOpenPayload {
        nonce: nonce_key_a,
        public_key: threshold.public_a.clone(),
    }))?;
    wire.push(&ProtocolPayload::KeyOpen(KeyOpenPayload {
        nonce: nonce_key_b,
        public_key: threshold.public_b.clone(),
    }))?;

    let key_context = wire.context;
    let proof_key_a = measured("Alice threshold-key PoP generation", || {
        let proof = KeyProof::prove(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Alice, &common)?,
            &generators,
            &threshold.public_a,
            &threshold.public_b,
            &threshold.secret_a,
            &mut OsRng,
        )?;
        BenchResult::Ok(proof)
    })?;
    let proof_key_b = measured("Bob threshold-key PoP generation", || {
        let proof = KeyProof::prove(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Bob, &common)?,
            &generators,
            &threshold.public_a,
            &threshold.public_b,
            &threshold.secret_b,
            &mut OsRng,
        )?;
        BenchResult::Ok(proof)
    })?;
    measured("two threshold-key PoP verifications", || {
        proof_key_a.verify(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Alice, &common)?,
            &generators,
            &threshold.public_a,
            &threshold.public_b,
            true,
        )?;
        proof_key_b.verify(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Bob, &common)?,
            &generators,
            &threshold.public_a,
            &threshold.public_b,
            false,
        )?;
        BenchResult::Ok(())
    })?;
    wire.push(&ProtocolPayload::KeyProof(proof_key_a))?;
    wire.push(&ProtocolPayload::KeyProof(proof_key_b))?;

    let bundle_context = wire.context;
    let mut rng_a = FixedCardRng::new(OsRng, [0, 1, 2, 3, 4, 5, 6, 7, 8]);
    let mut rng_b = FixedCardRng::new(OsRng, [0; N_SLOTS]);
    let (bundle_a, secret_a) = measured("Alice nine-slot bundle generation", || {
        generate_protocol_player_bundle(
            &parameters,
            &bundle_context,
            &common,
            Role::Alice,
            &threshold.joint_key,
            &mut rng_a,
        )
    })?;
    let (bundle_b, secret_b) = measured("Bob nine-slot bundle generation", || {
        generate_protocol_player_bundle(
            &parameters,
            &bundle_context,
            &common,
            Role::Bob,
            &threshold.joint_key,
            &mut rng_b,
        )
    })?;
    measured("two nine-slot bundle verifications", || {
        verify_player_bundle_pair(
            &parameters,
            &bundle_context,
            &common,
            &threshold.joint_key,
            &bundle_a,
            &bundle_b,
        )
    })?;

    let nonce_bundle_a = random_array()?;
    let nonce_bundle_b = random_array()?;
    let (bundle_commit_a, bundle_commit_b) =
        measured("two bundle commit/open digest checks", || {
            let commitment_a = bundle_commitment(
                &wire.context.game_id,
                wire.context.attempt,
                Role::Alice,
                &nonce_bundle_a,
                &bundle_a,
            )?;
            let commitment_b = bundle_commitment(
                &wire.context.game_id,
                wire.context.attempt,
                Role::Bob,
                &nonce_bundle_b,
                &bundle_b,
            )?;
            verify_bundle_commitment(
                &commitment_a,
                &wire.context.game_id,
                wire.context.attempt,
                Role::Alice,
                &nonce_bundle_a,
                &bundle_a,
            )?;
            verify_bundle_commitment(
                &commitment_b,
                &wire.context.game_id,
                wire.context.attempt,
                Role::Bob,
                &nonce_bundle_b,
                &bundle_b,
            )?;
            BenchResult::Ok((commitment_a, commitment_b))
        })?;
    wire.push(&ProtocolPayload::BundleCommit(CommitmentPayload {
        commitment: bundle_commit_a,
    }))?;
    wire.push(&ProtocolPayload::BundleCommit(CommitmentPayload {
        commitment: bundle_commit_b,
    }))?;
    wire.push(&ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
        nonce: nonce_bundle_a,
        bundle: bundle_a.clone(),
    })))?;
    wire.push(&ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
        nonce: nonce_bundle_b,
        bundle: bundle_b.clone(),
    })))?;

    let derived = derive_sums_and_zero_tests(
        &decode_bundle_ciphertexts(&bundle_a)?,
        &decode_bundle_ciphertexts(&bundle_b)?,
        &generators,
    )?;
    let first_role = first_blinder(&wire.context.game_id, wire.context.attempt);
    let second_role = other_role(first_role);
    let scale_first = measured("108-test first blinding generation", || {
        let round = generate_scale_round(
            &mut proof_transcript(ProofDomain::ScaleFirst, &wire.context, first_role, &common)?,
            &generators,
            &derived.differences,
            &mut OsRng,
        )?;
        BenchResult::Ok(round)
    })?;
    measured("108-test first blinding verification", || {
        verify_scale_round(
            &mut proof_transcript(ProofDomain::ScaleFirst, &wire.context, first_role, &common)?,
            &generators,
            &derived.differences,
            &scale_first,
        )?;
        BenchResult::Ok(())
    })?;
    wire.push(&ProtocolPayload::BlindFirst(Box::new(scale_first.clone())))?;

    let scale_second = measured("108-test second blinding generation", || {
        let round = generate_scale_round(
            &mut proof_transcript(
                ProofDomain::ScaleSecond,
                &wire.context,
                second_role,
                &common,
            )?,
            &generators,
            &scale_first.outputs,
            &mut OsRng,
        )?;
        BenchResult::Ok(round)
    })?;
    measured("108-test second blinding verification", || {
        verify_scale_round(
            &mut proof_transcript(
                ProofDomain::ScaleSecond,
                &wire.context,
                second_role,
                &common,
            )?,
            &generators,
            &scale_first.outputs,
            &scale_second,
        )?;
        BenchResult::Ok(())
    })?;
    wire.push(&ProtocolPayload::BlindSecond(Box::new(
        scale_second.clone(),
    )))?;

    let partial_a = measured("Alice 108-share partial-decryption generation", || {
        let batch = generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &wire.context,
                Role::Alice,
                &common,
            )?,
            &generators,
            &threshold.public_a,
            &threshold.secret_a,
            &scale_second.outputs,
            &mut OsRng,
        )?;
        BenchResult::Ok(batch)
    })?;
    let partial_b = measured("Bob 108-share partial-decryption generation", || {
        let batch = generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptBob,
                &wire.context,
                Role::Bob,
                &common,
            )?,
            &generators,
            &threshold.public_b,
            &threshold.secret_b,
            &scale_second.outputs,
            &mut OsRng,
        )?;
        BenchResult::Ok(batch)
    })?;
    let uniqueness = measured("two partial batches and 108-result verification", || {
        let result = verify_decryption_batches(
            &mut proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &wire.context,
                Role::Alice,
                &common,
            )?,
            &mut proof_transcript(
                ProofDomain::PartialDecryptBob,
                &wire.context,
                Role::Bob,
                &common,
            )?,
            &generators,
            &threshold.public_a,
            &threshold.public_b,
            &scale_second.outputs,
            &partial_a,
            &partial_b,
        )?;
        BenchResult::Ok(result)
    })?;
    if !uniqueness.is_unique {
        return Err(io::Error::other("fixed benchmark cards were not unique").into());
    }

    let nonce_decrypt_a = random_array()?;
    let nonce_decrypt_b = random_array()?;
    let bytes_partial_a = partial_a.encode_to_vec()?;
    let bytes_partial_b = partial_b.encode_to_vec()?;
    let (decrypt_commit_a, decrypt_commit_b) =
        measured("two partial-decryption commit/open digest checks", || {
            let commitment_a = decryption_commitment(
                &wire.context.game_id,
                wire.context.attempt,
                Role::Alice,
                &nonce_decrypt_a,
                &bytes_partial_a,
            );
            let commitment_b = decryption_commitment(
                &wire.context.game_id,
                wire.context.attempt,
                Role::Bob,
                &nonce_decrypt_b,
                &bytes_partial_b,
            );
            verify_decryption_commitment(
                &commitment_a,
                &wire.context.game_id,
                wire.context.attempt,
                Role::Alice,
                &nonce_decrypt_a,
                &bytes_partial_a,
            )?;
            verify_decryption_commitment(
                &commitment_b,
                &wire.context.game_id,
                wire.context.attempt,
                Role::Bob,
                &nonce_decrypt_b,
                &bytes_partial_b,
            )?;
            BenchResult::Ok((commitment_a, commitment_b))
        })?;
    wire.push(&ProtocolPayload::DecryptCommit(CommitmentPayload {
        commitment: decrypt_commit_a,
    }))?;
    wire.push(&ProtocolPayload::DecryptCommit(CommitmentPayload {
        commitment: decrypt_commit_b,
    }))?;
    wire.push(&ProtocolPayload::DecryptOpen(Box::new(
        DecryptOpenPayload {
            nonce: nonce_decrypt_a,
            batch: partial_a,
        },
    )))?;
    wire.push(&ProtocolPayload::DecryptOpen(Box::new(
        DecryptOpenPayload {
            nonce: nonce_decrypt_b,
            batch: partial_b,
        },
    )))?;

    if wire.envelopes.len() != usize::try_from(ATTEMPT_ENVELOPE_COUNT)? {
        return Err(io::Error::other("incomplete benchmark envelope schedule").into());
    }
    let accepted_body = AcceptedDealBody {
        protocol_version: PROTOCOL_VERSION,
        game_id: wire.context.game_id,
        attempt: wire.context.attempt,
        hashes_a: std::array::from_fn(|index| bundle_a.slots[index].hash),
        hashes_b: std::array::from_fn(|index| bundle_b.slots[index].hash),
        verification_transcript_root: wire.context.prior_transcript,
    };
    let accepted_deal = measured("two accepted-deal signatures and verification", || {
        let digest = accepted_deal_digest(&accepted_body)?;
        let signature_a = sign_benchmark_digest(&identities.secp, &identities.alice, digest)?;
        let signature_b = sign_benchmark_digest(&identities.secp, &identities.bob, digest)?;
        let deal = AcceptedDeal {
            protocol_version: accepted_body.protocol_version,
            game_id: accepted_body.game_id,
            attempt: accepted_body.attempt,
            hashes_a: accepted_body.hashes_a,
            hashes_b: accepted_body.hashes_b,
            verification_transcript_root: accepted_body.verification_transcript_root,
            signature_a,
            signature_b,
        };
        verify_accepted_deal_signatures(&identities.secp, &deal, &identities.identities)?;
        BenchResult::Ok(deal)
    })?;

    let actual_envelope_bytes = wire.envelopes.iter().try_fold(0_usize, |total, envelope| {
        BenchResult::Ok(total + envelope.encode_to_vec()?.len())
    })?;
    if actual_envelope_bytes != authenticated_attempt_bytes()
        || accepted_deal.encode_to_vec()?.len() != ACCEPTED_DEAL_CERTIFICATE_SIZE
    {
        return Err(
            io::Error::other("bandwidth constants disagree with canonical encoding").into(),
        );
    }

    println!(
        "16-envelope payload encode/sign/verify/hash overhead: {:.6} s",
        wire.overhead.as_secs_f64()
    );
    let live_elapsed = total_started.elapsed();
    println!("complete accepted-attempt construction and live checks: {live_elapsed:?}");

    // The benchmark intentionally drops every per-attempt secret before
    // exercising the read-only public archive verifier.
    drop(secret_a);
    drop(secret_b);
    drop(threshold);
    let replay_started = Instant::now();
    let verified = measured("independent production semantic/archive replay", || {
        verify_accepted_archive(
            &identities.secp,
            &identities.identities,
            &parameters,
            &accepted_deal,
            &wire.envelopes,
        )
    })?;
    black_box(verified);
    println!(
        "complete attempt plus independent observer replay: {:?}",
        live_elapsed + replay_started.elapsed()
    );
    report_bandwidth();
    Ok(())
}

fn report_bandwidth() {
    let envelope_bytes = authenticated_attempt_bytes();
    println!("authenticated 16-envelope attempt bytes: {envelope_bytes}");
    println!("accepted-deal certificate bytes: {ACCEPTED_DEAL_CERTIFICATE_SIZE}");
    println!(
        "attempt plus accepted certificate bytes: {}",
        envelope_bytes + ACCEPTED_DEAL_CERTIFICATE_SIZE
    );
}

const fn authenticated_attempt_bytes() -> usize {
    let payload_bytes = (2 * 32)
        + (2 * 64)
        + (2 * KEY_PROOF_SIZE)
        + (2 * 32)
        + (2 * (32 + MAX_PLAYER_BUNDLE_SIZE))
        + (2 * SCALE_ROUND_SIZE)
        + (2 * 32)
        + (2 * (32 + PARTIAL_DECRYPTION_BATCH_SIZE));
    16 * SIGNED_ENVELOPE_OVERHEAD + payload_bytes
}

fn measured<T, E>(label: &str, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let started = Instant::now();
    let result = operation()?;
    print_duration(label, started.elapsed());
    Ok(result)
}

fn print_duration(label: &str, duration: Duration) {
    println!("{label}: {:.6} s", duration.as_secs_f64());
}

struct IdentityFixture {
    secp: Secp256k1<All>,
    identities: CanonicalIdentities,
    alice: Keypair,
    bob: Keypair,
}

impl IdentityFixture {
    fn new() -> BenchResult<Self> {
        let secp = Secp256k1::new();
        let first = benchmark_keypair(&secp, 1)?;
        let second = benchmark_keypair(&secp, 2)?;
        let (first_public, _) = first.x_only_public_key();
        let (second_public, _) = second.x_only_public_key();
        let identities = CanonicalIdentities::new(first_public, second_public)?;
        let (alice, bob) = if identities.role_for_key(&first_public)? == Role::Alice {
            (first, second)
        } else {
            (second, first)
        };
        Ok(Self {
            secp,
            identities,
            alice,
            bob,
        })
    }

    const fn key(&self, role: Role) -> &Keypair {
        match role {
            Role::Alice => &self.alice,
            Role::Bob => &self.bob,
        }
    }
}

struct AttemptWire<'a> {
    identities: &'a IdentityFixture,
    context: AttemptContext,
    envelopes: Vec<Envelope>,
    overhead: Duration,
}

impl<'a> AttemptWire<'a> {
    fn new(identities: &'a IdentityFixture, game_id: [u8; 32], attempt: u32) -> Self {
        Self {
            identities,
            context: AttemptContext::new(game_id, attempt),
            envelopes: Vec::with_capacity(16),
            overhead: Duration::ZERO,
        }
    }

    fn push(&mut self, payload: &ProtocolPayload) -> BenchResult {
        let started = Instant::now();
        let sequence = u32::try_from(self.envelopes.len())?;
        let first = first_blinder(&self.context.game_id, self.context.attempt);
        let expected = expected_envelope(sequence, first)
            .ok_or_else(|| io::Error::other("benchmark exceeded the v1 envelope schedule"))?;
        if payload.payload_type() != expected.payload_type {
            return Err(io::Error::other("benchmark payload violated the v1 schedule").into());
        }
        let unsigned = UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: self.context.game_id,
            attempt: self.context.attempt,
            round: expected.round,
            sender_role: expected.sender,
            sequence,
            previous_message_hash: self.context.prior_transcript,
            payload_type: expected.payload_type,
            payload: payload.encode_body()?,
        };
        let envelope = sign_envelope(
            &self.identities.secp,
            &unsigned,
            self.identities.key(expected.sender),
            &self.identities.identities,
            &random_array()?,
        )?;
        verify_envelope(
            &self.identities.secp,
            &envelope,
            &self.identities.identities,
        )?;
        let encoded = envelope.encode_to_vec()?;
        self.context.advance(&encoded);
        self.envelopes.push(envelope);
        self.overhead += started.elapsed();
        Ok(())
    }
}

struct FixedCardRng<R> {
    inner: R,
    cards: [u8; N_SLOTS],
    next_card: usize,
}

impl<R> FixedCardRng<R> {
    const fn new(inner: R, cards: [u8; N_SLOTS]) -> Self {
        Self {
            inner,
            cards,
            next_card: 0,
        }
    }
}

impl<R: RngCore> RngCore for FixedCardRng<R> {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        if destination.len() == 1 && self.next_card < N_SLOTS {
            destination[0] = self.cards[self.next_card];
            self.next_card += 1;
        } else {
            self.inner.fill_bytes(destination);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        if destination.len() == 1 && self.next_card < N_SLOTS {
            self.fill_bytes(destination);
            Ok(())
        } else {
            self.inner.try_fill_bytes(destination)
        }
    }
}

impl<R: CryptoRng> CryptoRng for FixedCardRng<R> {}

fn benchmark_keypair(secp: &Secp256k1<All>, number: u8) -> BenchResult<Keypair> {
    let mut secret = [0_u8; 32];
    secret[31] = number;
    Ok(Keypair::from_seckey_slice(secp, &secret)?)
}

fn random_array<const N: usize>() -> Result<[u8; N], RandError> {
    let mut bytes = [0_u8; N];
    OsRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

fn sign_benchmark_digest(
    secp: &Secp256k1<All>,
    keypair: &Keypair,
    digest: [u8; 32],
) -> Result<[u8; 64], RandError> {
    let auxiliary_randomness = random_array()?;
    Ok(secp
        .sign_schnorr_with_aux_rand(
            &Message::from_digest(digest),
            keypair,
            &auxiliary_randomness,
        )
        .serialize())
}

fn random_threshold_fixture(generators: &ProtocolGenerators) -> BenchResult<ThresholdFixture> {
    let secret_a = SecretKeyShare::random(&mut OsRng)?;
    let secret_b = SecretKeyShare::random(&mut OsRng)?;
    let public_a = secret_a.public_key(generators);
    let public_b = secret_b.public_key(generators);
    let joint_key = JointPublicKey::combine(&public_a, &public_b)?;
    Ok(ThresholdFixture {
        generators: generators.clone(),
        secret_a,
        secret_b,
        public_a,
        public_b,
        joint_key,
    })
}

fn decode_bundle_ciphertexts(bundle: &PlayerBundle) -> BenchResult<[ElGamalCiphertext; N_SLOTS]> {
    let ciphertexts = bundle
        .slots
        .iter()
        .map(|slot| CiphertextBytes::from(slot.ciphertext).decompress_contribution())
        .collect::<Result<Vec<_>, _>>()?;
    to_array(ciphertexts)
}

const fn other_role(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}

struct HashFixture {
    hashes: [[u8; 32]; AGGREGATED_SLOTS],
    commitments: [[u8; 32]; AGGREGATED_SLOTS],
    values: [u8; AGGREGATED_SLOTS],
    blindings: [Scalar; AGGREGATED_SLOTS],
    buffers: [[u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS],
}

fn hash_fixture() -> BenchResult<HashFixture> {
    let generators = ProtocolGenerators::derive()?;
    let values = [0_u8, 7, 15, 23, 31, 39, 40, 47, 51];
    let blindings = std::array::from_fn(|index| Scalar::from(index as u64 + 101));
    let mut hashes = [[0_u8; 32]; AGGREGATED_SLOTS];
    let mut commitments = [[0_u8; 32]; AGGREGATED_SLOTS];
    let mut buffers = [[0_u8; MESSAGE_BUFFER_BYTES]; AGGREGATED_SLOTS];
    for index in 0..AGGREGATED_SLOTS {
        let length = 16 + usize::from(values[index]);
        let preimage = vec![u8::try_from(index)?; length];
        hashes[index] = Sha256::digest(&preimage).into();
        let buffer = witness_buffer(&preimage)?;
        buffers[index].copy_from_slice(buffer.as_array());
        commitments[index] = commit(
            Scalar::from(u64::from(values[index])),
            blindings[index],
            &generators,
        )
        .compress()
        .to_bytes();
    }
    Ok(HashFixture {
        hashes,
        commitments,
        values,
        blindings,
        buffers,
    })
}

fn hash_transcript(circuit_id: [u8; 32]) -> Transcript {
    let mut transcript = Transcript::new(b"BP52/bench/hash-length/v1");
    transcript.append_message(b"circuit-id", &circuit_id);
    transcript
}

struct ThresholdFixture {
    generators: ProtocolGenerators,
    secret_a: SecretKeyShare,
    secret_b: SecretKeyShare,
    public_a: bp52_group::PublicKeyShare,
    public_b: bp52_group::PublicKeyShare,
    joint_key: JointPublicKey,
}

fn threshold_fixture() -> BenchResult<ThresholdFixture> {
    let generators = ProtocolGenerators::derive()?;
    let secret_a = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(13_u64))?);
    let secret_b = SecretKeyShare::from_nonzero(NonZeroScalar::new(Scalar::from(29_u64))?);
    let public_a = secret_a.public_key(&generators);
    let public_b = secret_b.public_key(&generators);
    let joint_key = JointPublicKey::combine(&public_a, &public_b)?;
    Ok(ThresholdFixture {
        generators,
        secret_a,
        secret_b,
        public_a,
        public_b,
        joint_key,
    })
}

struct LinkFixture {
    generators: ProtocolGenerators,
    joint_key: JointPublicKey,
    statements: [EncryptionLinkStatement; N_SLOTS],
    witnesses: [EncryptionLinkWitness; N_SLOTS],
}

fn link_fixture() -> BenchResult<LinkFixture> {
    let threshold = threshold_fixture()?;
    let mut statements = Vec::with_capacity(N_SLOTS);
    let mut witnesses = Vec::with_capacity(N_SLOTS);
    for index in 0..N_SLOTS {
        let value = Scalar::from(u64::try_from(index)?);
        let blinding = Scalar::from(u64::try_from(index)? + 101);
        let randomness = NonZeroScalar::new(Scalar::from(u64::try_from(index)? + 201))?;
        statements.push(EncryptionLinkStatement {
            value_commitment: commit(value, blinding, &threshold.generators),
            ciphertext: ElGamalCiphertext::encrypt(
                value,
                &randomness,
                &threshold.joint_key,
                &threshold.generators,
            ),
        });
        witnesses.push(EncryptionLinkWitness::new(value, blinding, randomness));
    }
    Ok(LinkFixture {
        generators: threshold.generators,
        joint_key: threshold.joint_key,
        statements: to_array(statements)?,
        witnesses: to_array(witnesses)?,
    })
}

fn uniqueness_inputs(
    threshold: &ThresholdFixture,
) -> BenchResult<[ElGamalCiphertext; ZERO_TEST_COUNT]> {
    let mut inputs = Vec::with_capacity(ZERO_TEST_COUNT);
    for index in 0..ZERO_TEST_COUNT {
        let value = Scalar::from(u64::try_from(index % 52 + 1)?);
        let randomness = NonZeroScalar::new(Scalar::from(u64::try_from(index)? + 301))?;
        inputs.push(ElGamalCiphertext::encrypt(
            value,
            &randomness,
            &threshold.joint_key,
            &threshold.generators,
        ));
    }
    to_array(inputs)
}

fn to_array<T, const N: usize>(values: Vec<T>) -> BenchResult<[T; N]> {
    values
        .try_into()
        .map_err(|_| io::Error::other("fixed benchmark fixture shape mismatch").into())
}
