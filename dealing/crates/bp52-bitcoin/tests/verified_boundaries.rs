//! End-to-end regression for the archive-verified Bitcoin boundary.

#![allow(clippy::panic, clippy::similar_names, clippy::too_many_lines)]

use std::error::Error;

use bitcoin::secp256k1::{Keypair, Secp256k1};
use bp52_bitcoin::{
    CardOpeningTemplate, CommunityStage, ScriptTemplateError, verify_community_reveal,
    verify_hole_card_delivery, verify_showdown_reveal,
};
use bp52_circuit::hash_length::HashLengthParameters;
use bp52_codec::Encode;
use bp52_group::{ProtocolGenerators, SecretKeyShare};
use bp52_protocol::{
    N_SLOTS, PROTOCOL_VERSION, Role,
    archive::{AcceptedArchiveError, verify_accepted_archive},
    auth::{CanonicalIdentities, derive_roles, sign_envelope},
    bundle::generate_player_bundle,
    commitments::{bundle_commitment, decryption_commitment, key_commitment},
    history::{PublicAttemptHistory, TrackedAttempt, TrackedProgress},
    messages::{Envelope, UnsignedEnvelope},
    payloads::{
        BundleOpenPayload, CommitmentPayload, DecryptOpenPayload, KeyOpenPayload, ProtocolPayload,
    },
    transcript::{ProofDomain, ProofPhase, proof_transcript},
    uniqueness::JointKeyPublic,
};
use bp52_sigma::schnorr::KeyProof;
use bp52_uniqueness::{generate_partial_decryption_batch, generate_scale_round};
use rand_core::{CryptoRng, Error as RngError, OsRng, RngCore};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct IdentityKeys {
    identities: CanonicalIdentities,
    alice: Keypair,
    bob: Keypair,
}

impl IdentityKeys {
    fn new(secp: &Secp256k1<bitcoin::secp256k1::All>) -> TestResult<Self> {
        let first = keypair(secp, 1)?;
        let second = keypair(secp, 2)?;
        let identities = derive_roles(first.x_only_public_key().0, second.x_only_public_key().0)?;
        let (alice, bob) = if identities.role_for_key(&first.x_only_public_key().0)? == Role::Alice
        {
            (first, second)
        } else {
            (second, first)
        };
        Ok(Self {
            identities,
            alice,
            bob,
        })
    }

    const fn for_role(&self, role: Role) -> &Keypair {
        match role {
            Role::Alice => &self.alice,
            Role::Bob => &self.bob,
        }
    }
}

fn keypair(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    marker: u8,
) -> Result<Keypair, bitcoin::secp256k1::Error> {
    let mut secret = [0_u8; 32];
    secret[31] = marker;
    Keypair::from_seckey_slice(secp, &secret)
}

/// Supplies prescribed contribution values while retaining OS randomness for
/// every preimage, scalar, and proof nonce.
struct ContributionRng {
    values: [u8; N_SLOTS],
    next_value: usize,
    inner: OsRng,
}

impl ContributionRng {
    const fn new(values: [u8; N_SLOTS]) -> Self {
        Self {
            values,
            next_value: 0,
            inner: OsRng,
        }
    }
}

impl RngCore for ContributionRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        if destination.len() == 1 && self.next_value < N_SLOTS {
            destination[0] = self.values[self.next_value];
            self.next_value += 1;
        } else {
            self.inner.fill_bytes(destination);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for ContributionRng {}

fn signed_next(
    attempt: &TrackedAttempt<'_, '_>,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    identities: &IdentityKeys,
    payload: ProtocolPayload,
) -> TestResult<Envelope> {
    let schedule = attempt.verifier().schedule();
    let expected = schedule.expected()?;
    if payload.payload_type() != expected.payload_type {
        return Err(std::io::Error::other("test payload does not match schedule").into());
    }
    let unsigned = UnsignedEnvelope {
        protocol_version: PROTOCOL_VERSION,
        game_id: schedule.game_id(),
        attempt: schedule.attempt(),
        round: expected.round,
        sender_role: expected.sender,
        sequence: expected.sequence,
        previous_message_hash: schedule.transcript_root(),
        payload_type: payload.payload_type(),
        payload: payload.encode_body()?,
    };
    drop(payload);
    let auxiliary_randomness = [expected.sequence.to_le_bytes()[0]; 32];
    Ok(sign_envelope(
        secp,
        &unsigned,
        identities.for_role(expected.sender),
        &identities.identities,
        &auxiliary_randomness,
    )?)
}

fn send(
    attempt: &mut TrackedAttempt<'_, '_>,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    identities: &IdentityKeys,
    payload: ProtocolPayload,
) -> TestResult<TrackedProgress> {
    let envelope = signed_next(attempt, secp, identities, payload)?;
    Ok(attempt.accept_bytes(secp, &envelope.encode_to_vec()?)?)
}

#[test]
#[ignore = "resource-intensive full accepted archive + Bitcoin boundary"]
fn verified_archive_is_the_only_safe_bitcoin_boundary() -> TestResult {
    let secp = Secp256k1::new();
    let identities = IdentityKeys::new(&secp)?;
    let parameters = HashLengthParameters::new()?;
    let generators = ProtocolGenerators::derive()?;
    let secret_a = SecretKeyShare::random(&mut OsRng)?;
    let secret_b = SecretKeyShare::random(&mut OsRng)?;
    let public = JointKeyPublic::new(
        secret_a.public_key(&generators),
        secret_b.public_key(&generators),
    )?;
    let game_id = [0x53_u8; 32];
    let mut history = PublicAttemptHistory::new(game_id, identities.identities);
    let mut attempt = history.start_attempt(&parameters, Role::Alice, secret_a)?;

    let key_nonce_a = [0x11_u8; 32];
    let key_nonce_b = [0x12_u8; 32];
    let key_commit_a = key_commitment(
        &game_id,
        0,
        Role::Alice,
        &key_nonce_a,
        &public.public_a().to_bytes(),
    );
    let key_commit_b = key_commitment(
        &game_id,
        0,
        Role::Bob,
        &key_nonce_b,
        &public.public_b().to_bytes(),
    );
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::KeyCommit(CommitmentPayload {
            commitment: key_commit_a,
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::KeyCommit(CommitmentPayload {
            commitment: key_commit_b,
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::KeyOpen(KeyOpenPayload {
            nonce: key_nonce_a,
            public_key: public.public_a().clone(),
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::KeyOpen(KeyOpenPayload {
            nonce: key_nonce_b,
            public_key: public.public_b().clone(),
        }),
    )?;

    let key_context = attempt
        .verifier()
        .phase_context(ProofPhase::KeyProof)
        .ok_or_else(|| std::io::Error::other("missing T4 key-proof context"))?;
    let common = attempt
        .verifier()
        .common_frame()
        .ok_or_else(|| std::io::Error::other("missing common proof frame"))?
        .clone();
    let proof_a = {
        let local_key = attempt
            .secrets()
            .ok_or_else(|| std::io::Error::other("missing local attempt secrets"))?
            .key_share();
        KeyProof::prove(
            &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Alice, &common)?,
            &generators,
            public.public_a(),
            public.public_b(),
            local_key,
            &mut OsRng,
        )?
    };
    let proof_b = KeyProof::prove(
        &mut proof_transcript(ProofDomain::KeyPop, &key_context, Role::Bob, &common)?,
        &generators,
        public.public_a(),
        public.public_b(),
        &secret_b,
        &mut OsRng,
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::KeyProof(proof_a),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::KeyProof(proof_b),
    )?;

    let bundle_context = attempt
        .verifier()
        .phase_context(ProofPhase::PlayerBundle)
        .ok_or_else(|| std::io::Error::other("missing T6 bundle context"))?;
    let mut rng_a = ContributionRng::new(core::array::from_fn(|index| index.to_le_bytes()[0]));
    let mut rng_b = ContributionRng::new([0_u8; N_SLOTS]);
    let (bundle_a, contribution_a) = generate_player_bundle(
        &parameters,
        &bundle_context,
        &common,
        Role::Alice,
        public.joint(),
        &mut rng_a,
    )?;
    let (bundle_b, contribution_b) = generate_player_bundle(
        &parameters,
        &bundle_context,
        &common,
        Role::Bob,
        public.joint(),
        &mut rng_b,
    )?;
    attempt.install_contribution(contribution_a)?;

    let bundle_nonce_a = [0x21_u8; 32];
    let bundle_nonce_b = [0x22_u8; 32];
    let bundle_commit_a = bundle_commitment(&game_id, 0, Role::Alice, &bundle_nonce_a, &bundle_a)?;
    let bundle_commit_b = bundle_commitment(&game_id, 0, Role::Bob, &bundle_nonce_b, &bundle_b)?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::BundleCommit(CommitmentPayload {
            commitment: bundle_commit_a,
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::BundleCommit(CommitmentPayload {
            commitment: bundle_commit_b,
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
            nonce: bundle_nonce_a,
            bundle: bundle_a,
        })),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::BundleOpen(Box::new(BundleOpenPayload {
            nonce: bundle_nonce_b,
            bundle: bundle_b,
        })),
    )?;

    let first_context = attempt
        .verifier()
        .phase_context(ProofPhase::ScaleFirst)
        .ok_or_else(|| std::io::Error::other("missing T10 scale context"))?;
    let differences = attempt
        .verifier()
        .derived_zero_tests()
        .ok_or_else(|| std::io::Error::other("missing derived zero tests"))?
        .differences
        .clone();
    let first_role = attempt.verifier().schedule().first_blinder();
    let first_round = generate_scale_round(
        &mut proof_transcript(ProofDomain::ScaleFirst, &first_context, first_role, &common)?,
        &generators,
        &differences,
        &mut OsRng,
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::BlindFirst(Box::new(first_round)),
    )?;

    let second_context = attempt
        .verifier()
        .phase_context(ProofPhase::ScaleSecond)
        .ok_or_else(|| std::io::Error::other("missing T11 scale context"))?;
    let second_role = match first_role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    };
    let first_outputs = attempt
        .verifier()
        .first_scale_round()
        .ok_or_else(|| std::io::Error::other("missing first scale round"))?
        .outputs
        .clone();
    let second_round = generate_scale_round(
        &mut proof_transcript(
            ProofDomain::ScaleSecond,
            &second_context,
            second_role,
            &common,
        )?,
        &generators,
        &first_outputs,
        &mut OsRng,
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::BlindSecond(Box::new(second_round)),
    )?;

    let decrypt_context = attempt
        .verifier()
        .phase_context(ProofPhase::PartialDecrypt)
        .ok_or_else(|| std::io::Error::other("missing T12 decrypt context"))?;
    let final_ciphertexts = attempt
        .verifier()
        .second_scale_round()
        .ok_or_else(|| std::io::Error::other("missing second scale round"))?
        .outputs
        .clone();
    let partial_a = {
        let local_key = attempt
            .secrets()
            .ok_or_else(|| std::io::Error::other("missing local attempt secrets"))?
            .key_share();
        generate_partial_decryption_batch(
            &mut proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &decrypt_context,
                Role::Alice,
                &common,
            )?,
            &generators,
            public.public_a(),
            local_key,
            &final_ciphertexts,
            &mut OsRng,
        )?
    };
    let partial_b = generate_partial_decryption_batch(
        &mut proof_transcript(
            ProofDomain::PartialDecryptBob,
            &decrypt_context,
            Role::Bob,
            &common,
        )?,
        &generators,
        public.public_b(),
        &secret_b,
        &final_ciphertexts,
        &mut OsRng,
    )?;
    let decrypt_nonce_a = [0x31_u8; 32];
    let decrypt_nonce_b = [0x32_u8; 32];
    let decrypt_commit_a = decryption_commitment(
        &game_id,
        0,
        Role::Alice,
        &decrypt_nonce_a,
        &partial_a.encode_to_vec()?,
    );
    let decrypt_commit_b = decryption_commitment(
        &game_id,
        0,
        Role::Bob,
        &decrypt_nonce_b,
        &partial_b.encode_to_vec()?,
    );
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::DecryptCommit(CommitmentPayload {
            commitment: decrypt_commit_a,
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::DecryptCommit(CommitmentPayload {
            commitment: decrypt_commit_b,
        }),
    )?;
    let _ = send(
        &mut attempt,
        &secp,
        &identities,
        ProtocolPayload::DecryptOpen(Box::new(DecryptOpenPayload {
            nonce: decrypt_nonce_a,
            batch: partial_a,
        })),
    )?;
    assert_eq!(
        send(
            &mut attempt,
            &secp,
            &identities,
            ProtocolPayload::DecryptOpen(Box::new(DecryptOpenPayload {
                nonce: decrypt_nonce_b,
                batch: partial_b,
            })),
        )?,
        TrackedProgress::ReadyToSign
    );

    let archive = attempt.verifier().authenticated_archive().to_vec();
    let mut pending = attempt.into_pending_acceptance()?;
    let _ = pending.sign(&secp, Role::Alice, &identities.alice, &[0xa1_u8; 32])?;
    let _ = pending.sign(&secp, Role::Bob, &identities.bob, &[0xb2_u8; 32])?;
    let accepted = pending.finalize(&secp)?;
    let (deal, retained_a) = accepted.into_parts();

    let verified =
        verify_accepted_archive(&secp, &identities.identities, &parameters, &deal, &archive)?;
    assert_eq!(verified.as_deal(), &deal);

    let preimage_a_0 = retained_a
        .get(0)
        .ok_or_else(|| std::io::Error::other("missing retained Alice preimage"))?;
    let preimage_b_0 = contribution_b
        .preimage(0)
        .ok_or_else(|| std::io::Error::other("missing Bob preimage"))?;
    let private_card =
        verify_hole_card_delivery(&verified, Role::Alice, 0, preimage_a_0, preimage_b_0)?;
    assert_eq!(private_card.slot(), 0);
    assert_eq!(private_card.card(), 0);

    let preimage_a_2 = retained_a
        .get(2)
        .ok_or_else(|| std::io::Error::other("missing retained Alice preimage"))?;
    let preimage_b_2 = contribution_b
        .preimage(2)
        .ok_or_else(|| std::io::Error::other("missing Bob preimage"))?;
    let showdown =
        verify_showdown_reveal(&verified, Role::Alice, 2, preimage_a_2, preimage_b_2, 2)?;
    assert_eq!(showdown.card(), 2);

    let preimage_a_4 = retained_a
        .get(4)
        .ok_or_else(|| std::io::Error::other("missing retained Alice preimage"))?;
    let preimage_b_4 = contribution_b
        .preimage(4)
        .ok_or_else(|| std::io::Error::other("missing Bob preimage"))?;
    let community = verify_community_reveal(
        &verified,
        CommunityStage::Flop,
        4,
        preimage_a_4,
        preimage_b_4,
        4,
    )?;
    assert_eq!(community.card(), 4);

    let template = CardOpeningTemplate::from_verified_deal(&secp, &verified, 4, 4)?;
    assert!(template.script_pubkey().is_p2tr());
    assert_eq!(template.satisfy(preimage_a_4, preimage_b_4)?.len(), 4);
    assert!(matches!(
        CardOpeningTemplate::from_verified_deal(&secp, &verified, 9, 0),
        Err(ScriptTemplateError::InvalidSlot { slot: 9 })
    ));

    let mut short_archive = archive.clone();
    drop(short_archive.pop());
    assert!(matches!(
        verify_accepted_archive(
            &secp,
            &identities.identities,
            &parameters,
            &deal,
            &short_archive,
        ),
        Err(AcceptedArchiveError::WrongEnvelopeCount { .. })
    ));

    let mut reordered_archive = archive.clone();
    reordered_archive.swap(0, 1);
    assert!(matches!(
        verify_accepted_archive(
            &secp,
            &identities.identities,
            &parameters,
            &deal,
            &reordered_archive,
        ),
        Err(AcceptedArchiveError::Replay { .. })
    ));

    let mut changed_hash = deal;
    changed_hash.hashes_a[0][0] ^= 1;
    assert!(matches!(
        verify_accepted_archive(
            &secp,
            &identities.identities,
            &parameters,
            &changed_hash,
            &archive,
        ),
        Err(AcceptedArchiveError::BodyMismatch { .. })
    ));

    let mut changed_root = deal;
    changed_root.verification_transcript_root[0] ^= 1;
    assert!(matches!(
        verify_accepted_archive(
            &secp,
            &identities.identities,
            &parameters,
            &changed_root,
            &archive,
        ),
        Err(AcceptedArchiveError::BodyMismatch { .. })
    ));

    let mut changed_signature_a = deal;
    changed_signature_a.signature_a[0] ^= 1;
    assert!(matches!(
        verify_accepted_archive(
            &secp,
            &identities.identities,
            &parameters,
            &changed_signature_a,
            &archive,
        ),
        Err(AcceptedArchiveError::Signatures(_))
    ));

    let mut changed_signature_b = deal;
    changed_signature_b.signature_b[0] ^= 1;
    assert!(matches!(
        verify_accepted_archive(
            &secp,
            &identities.identities,
            &parameters,
            &changed_signature_b,
            &archive,
        ),
        Err(AcceptedArchiveError::Signatures(_))
    ));

    Ok(())
}
