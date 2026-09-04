use std::error::Error;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bp52_chain_types::{
    AcceptedDeal, CHAIN_PROTOCOL_VERSION, ChainGameDescriptor, RevealOrder, Role,
    SignedChainGameDescriptor, TimeoutSettlementPolicy, VerifiedChainDescriptor,
    descriptor_signature_digest, verify_signed_chain_descriptor,
};
use bp52_protocol::{
    PROTOCOL_VERSION as DEAL_PROTOCOL_VERSION,
    auth::{CanonicalIdentities, accepted_deal_digest, derive_game_id},
};

pub(crate) fn descriptor_fixture() -> Result<ChainGameDescriptor, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let first = keypair(&secp, 1)?;
    let second = keypair(&secp, 2)?;
    let (alice, bob) =
        if first.x_only_public_key().0.serialize() < second.x_only_public_key().0.serialize() {
            (first, second)
        } else {
            (second, first)
        };
    let alice_public = alice.x_only_public_key().0;
    let bob_public = bob.x_only_public_key().0;
    let identities = CanonicalIdentities::new(alice_public, bob_public)?;
    let network_id = [0x11; 32];
    let funding_outpoint = [0x22; 36];
    let deal_session_nonce = [0x33; 32];
    let mut deal = AcceptedDeal {
        protocol_version: DEAL_PROTOCOL_VERSION,
        game_id: derive_game_id(
            &network_id,
            &funding_outpoint,
            &identities,
            &deal_session_nonce,
        ),
        attempt: 0,
        hashes_a: core::array::from_fn(|index| [index.to_le_bytes()[0].wrapping_add(1); 32]),
        hashes_b: core::array::from_fn(|index| [index.to_le_bytes()[0].wrapping_add(10); 32]),
        verification_transcript_root: [0x44; 32],
        signature_a: [0; 64],
        signature_b: [0; 64],
    };
    let message = Message::from_digest(accepted_deal_digest(&deal.body())?);
    deal.signature_a = secp.sign_schnorr_no_aux_rand(&message, &alice).serialize();
    deal.signature_b = secp.sign_schnorr_no_aux_rand(&message, &bob).serialize();
    Ok(ChainGameDescriptor {
        chain_protocol_version: CHAIN_PROTOCOL_VERSION,
        deal,
        network_id,
        funding_outpoint,
        deal_session_nonce,
        alice_xonly_pk: alice_public.serialize(),
        bob_xonly_pk: bob_public.serialize(),
        button: Role::Alice,
        unit_sat: 100,
        max_bets_per_street: bp52_chain_types::MAX_BETS_PER_STREET,
        alice_starting_stack_sat: 10_000,
        bob_starting_stack_sat: 12_000,
        fee_reserve_sat: 6_600,
        action_csv: 12,
        reveal_csv: 18,
        showdown_csv: 24,
        reveal_order: RevealOrder {
            flop_first: Role::Bob,
            turn_first: Role::Alice,
            river_first: Role::Bob,
        },
        timeout_policy: TimeoutSettlementPolicy::PotOnly,
        split_remainder_recipient: Role::Alice,
        fee_policy_id: [0x55; 32],
        compiler_id: [0x66; 32],
    })
}

pub(crate) fn verified_descriptor_fixture() -> Result<VerifiedChainDescriptor, Box<dyn Error>> {
    let descriptor = descriptor_fixture()?;
    let secp = Secp256k1::new();
    let alice = keypair_for_identity(&secp, descriptor.alice_xonly_pk)?;
    let bob = keypair_for_identity(&secp, descriptor.bob_xonly_pk)?;
    let message = Message::from_digest(descriptor_signature_digest(&descriptor)?);
    let signed = SignedChainGameDescriptor {
        descriptor,
        signature_a: secp.sign_schnorr_no_aux_rand(&message, &alice).serialize(),
        signature_b: secp.sign_schnorr_no_aux_rand(&message, &bob).serialize(),
    };
    Ok(verify_signed_chain_descriptor(&signed)?)
}

fn keypair_for_identity(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    identity: [u8; 32],
) -> Result<Keypair, Box<dyn Error>> {
    for number in [1_u8, 2] {
        let candidate = keypair(secp, number)?;
        if candidate.x_only_public_key().0.serialize() == identity {
            return Ok(candidate);
        }
    }
    Err("fixture identity key has no matching secret".into())
}

fn keypair(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    number: u8,
) -> Result<Keypair, bitcoin::secp256k1::Error> {
    let mut secret = [0_u8; 32];
    secret[31] = number;
    Keypair::from_seckey_slice(secp, &secret)
}
