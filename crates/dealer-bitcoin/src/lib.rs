#![forbid(unsafe_code)]
//! Regtest-only DLOG52 tapscript card gates.

/// Verifiable on-chain disclosure of dlog openings using adaptor preauthorizations.
pub mod reveal;

use bitcoin::hashes::Hash;
use bitcoin::{
    ScriptBuf, Transaction, TxOut, Witness, XOnlyPublicKey,
    key::Secp256k1,
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_DROP},
    script::Builder,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapNodeHash, TaprootBuilder},
};
use dealer_group::{N_SLOTS, RAW_SUM_CANDIDATES, protocol_parameters};
use dealer_protocol::{VerifiedAcceptedDeal, accepted_body_hash, point_xonly};
use k256::{
    ProjectivePoint, Secp256k1 as K256Secp256k1,
    elliptic_curve::{
        Group,
        hash2curve::{ExpandMsgXmd, GroupDigest},
    },
};
use sha2::Sha256;
use thiserror::Error;

/// Domain for unknown-log Taproot internal keys.
pub const INTERNAL_KEY_DST: &str = "DLOG52-DEAL-v1/taproot-internal/secp256k1_XMD:SHA-256_SSWU_RO_";

/// Bitcoin demonstration profile failure.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// The profile is intentionally unavailable outside regtest.
    #[error("DLOG52 card gates are restricted to regtest")]
    RealFundsDisabled,
    /// Slot/raw-sum/card metadata is inconsistent.
    #[error("invalid card-gate metadata")]
    Metadata,
    /// Internal or candidate key failed a required degeneracy check.
    #[error("degenerate or overlapping gate key")]
    Key,
    /// Canonical Taproot tree construction failed.
    #[error("canonical Taproot tree construction failed")]
    Tree,
    /// BIP341 sighash construction failed.
    #[error("failed to construct card-gate tapscript sighash")]
    Sighash,
}

/// One candidate leaf and its canonical spend proof.
#[derive(Clone, Debug)]
pub struct GateLeaf {
    /// Raw sum selected by this leaf.
    pub raw_sum: u8,
    /// Card identifier `raw_sum mod 52`.
    pub card_id: u8,
    /// Exact tapscript bytes.
    pub script: ScriptBuf,
    /// Control block for the fixed balanced tree.
    pub control_block: ControlBlock,
}

/// Complete independently reproducible gate for one deal slot.
#[derive(Clone, Debug)]
pub struct SlotGateManifest {
    /// Canonical slot number.
    pub slot: u8,
    /// Test-policy authorizer.
    pub authorizer: XOnlyPublicKey,
    /// Unknown-log internal key.
    pub internal_key: XOnlyPublicKey,
    /// Root of the canonical balanced 103-leaf tree.
    pub merkle_root: TapNodeHash,
    /// Tweaked Taproot output key.
    pub output_key: bitcoin::key::TweakedPublicKey,
    /// Tweaked P2TR output script.
    pub output_script: ScriptBuf,
    /// All 103 leaves in raw-sum order.
    pub leaves: Vec<GateLeaf>,
}

/// Nine independent regtest outputs, one for every deal slot.
#[derive(Clone, Debug)]
pub struct RegtestGateManifest {
    /// Accepted deal identifier embedded in every leaf.
    pub deal_id: [u8; 32],
    /// Fixed profile identifier.
    pub profile: &'static str,
    /// Slot manifests in canonical order.
    pub slots: [SlotGateManifest; N_SLOTS],
}

/// Build the exact leaf script for one candidate.
///
/// # Errors
///
/// Returns [`BitcoinError::Metadata`] for a slot or raw sum outside the fixed
/// protocol domain.
pub fn build_candidate_leaf(
    deal_id: [u8; 32],
    slot: u8,
    raw_sum: u8,
    candidate_key: [u8; 32],
    authorizer: [u8; 32],
) -> Result<ScriptBuf, BitcoinError> {
    if slot > 8 || raw_sum > 102 {
        return Err(BitcoinError::Metadata);
    }
    Ok(Builder::new()
        .push_slice(deal_id)
        .push_opcode(OP_DROP)
        .push_int(i64::from(slot))
        .push_opcode(OP_DROP)
        .push_int(i64::from(raw_sum))
        .push_opcode(OP_DROP)
        .push_int(i64::from(raw_sum % 52))
        .push_opcode(OP_DROP)
        .push_slice(candidate_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(authorizer)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

fn leaf_depths(first: usize, len: usize, depth: u8, out: &mut Vec<(usize, u8)>) {
    if len == 1 {
        out.push((first, depth));
        return;
    }
    let left = len / 2;
    leaf_depths(first, left, depth + 1, out);
    leaf_depths(first + left, len - left, depth + 1, out);
}

fn xonly(point: &ProjectivePoint) -> Result<[u8; 32], BitcoinError> {
    point_xonly(point).map_err(|_| BitcoinError::Key)
}

fn derive_internal_key(
    deal_id: &[u8; 32],
    slot: u8,
    authorizer: &[u8; 32],
    identities: (&[u8; 32], &[u8; 32]),
    candidates: &[ProjectivePoint; RAW_SUM_CANDIDATES],
) -> Result<XOnlyPublicKey, BitcoinError> {
    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(deal_id);
    message.push(slot);
    message.extend_from_slice(authorizer);
    let point = K256Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[&message],
        &[INTERNAL_KEY_DST.as_bytes()],
    )
    .map_err(|_| BitcoinError::Key)?;
    if bool::from(point.is_identity())
        || point == protocol_parameters().g
        || point == -protocol_parameters().g
    {
        return Err(BitcoinError::Key);
    }
    let key = xonly(&point)?;
    if key == *identities.0
        || key == *identities.1
        || key == *authorizer
        || candidates
            .iter()
            .any(|candidate| xonly(candidate).is_ok_and(|x| x == key))
    {
        return Err(BitcoinError::Key);
    }
    XOnlyPublicKey::from_slice(&key).map_err(|_| BitcoinError::Key)
}

fn build_slot_gate(
    deal_id: [u8; 32],
    slot: u8,
    authorizer_bytes: [u8; 32],
    identities: (&[u8; 32], &[u8; 32]),
    candidates: &[ProjectivePoint; RAW_SUM_CANDIDATES],
) -> Result<SlotGateManifest, BitcoinError> {
    let authorizer =
        XOnlyPublicKey::from_slice(&authorizer_bytes).map_err(|_| BitcoinError::Key)?;
    if candidates
        .iter()
        .any(|candidate| xonly(candidate).is_ok_and(|x| x == authorizer_bytes))
    {
        return Err(BitcoinError::Key);
    }
    let internal_key =
        derive_internal_key(&deal_id, slot, &authorizer_bytes, identities, candidates)?;
    let scripts: Vec<ScriptBuf> = candidates
        .iter()
        .enumerate()
        .map(|(raw_sum, candidate)| {
            build_candidate_leaf(
                deal_id,
                slot,
                u8::try_from(raw_sum).map_err(|_| BitcoinError::Metadata)?,
                xonly(candidate)?,
                authorizer_bytes,
            )
        })
        .collect::<Result<_, _>>()?;
    let mut depths = Vec::with_capacity(RAW_SUM_CANDIDATES);
    leaf_depths(0, RAW_SUM_CANDIDATES, 0, &mut depths);
    let mut builder = TaprootBuilder::new();
    for (index, depth) in depths {
        builder = builder
            .add_leaf(depth, scripts[index].clone())
            .map_err(|_| BitcoinError::Tree)?;
    }
    let secp = Secp256k1::verification_only();
    let spend = builder
        .finalize(&secp, internal_key)
        .map_err(|_| BitcoinError::Tree)?;
    let leaves = scripts
        .into_iter()
        .enumerate()
        .map(|(raw_sum, script)| {
            let control_block = spend
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .ok_or(BitcoinError::Tree)?;
            Ok(GateLeaf {
                raw_sum: u8::try_from(raw_sum).map_err(|_| BitcoinError::Metadata)?,
                card_id: u8::try_from(raw_sum % 52).map_err(|_| BitcoinError::Metadata)?,
                script,
                control_block,
            })
        })
        .collect::<Result<_, BitcoinError>>()?;
    Ok(SlotGateManifest {
        slot,
        authorizer,
        internal_key,
        merkle_root: spend.merkle_root().ok_or(BitcoinError::Tree)?,
        output_key: spend.output_key(),
        output_script: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        leaves,
    })
}

/// Assemble the exact script-path witness for one candidate leaf.
///
/// Script evaluation consumes the card signature first, so the authorizer
/// signature is lower in the initial witness stack.
#[must_use]
pub fn assemble_gate_witness(
    leaf: &GateLeaf,
    card_signature: &[u8; 64],
    authorizer_signature: &[u8; 64],
) -> Witness {
    Witness::from_slice(&[
        authorizer_signature.as_slice(),
        card_signature.as_slice(),
        leaf.script.as_bytes(),
        &leaf.control_block.serialize(),
    ])
}

/// Compute the exact BIP341 default tapscript sighash for a candidate leaf.
///
/// # Errors
///
/// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
pub fn gate_tapscript_sighash(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf: &GateLeaf,
) -> Result<[u8; 32], BitcoinError> {
    if prevouts.len() != transaction.input.len() {
        return Err(BitcoinError::Sighash);
    }
    let hash = SighashCache::new(transaction)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            bitcoin::TapLeafHash::from_script(&leaf.script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .map_err(|_| BitcoinError::Sighash)?;
    Ok(hash.to_byte_array())
}

/// Build all nine exact regtest gates from a fully verified accepted deal.
///
/// # Errors
///
/// Returns an error if an authorizer, candidate, internal key, Taproot tweak,
/// or canonical balanced tree fails validation.
pub fn build_regtest_gate(
    deal: &VerifiedAcceptedDeal,
) -> Result<RegtestGateManifest, BitcoinError> {
    let deal_id = accepted_body_hash(&deal.as_deal().body);
    let config = deal.game_config();
    let mut gates = Vec::with_capacity(N_SLOTS);
    for index in 0..N_SLOTS {
        let slot = u8::try_from(index).map_err(|_| BitcoinError::Metadata)?;
        let authorizer = if matches!(slot, 1 | 3) {
            config.identity_b
        } else {
            config.identity_a
        };
        gates.push(build_slot_gate(
            deal_id,
            slot,
            authorizer,
            (&config.identity_a, &config.identity_b),
            &deal.catalogue().keys[index],
        )?);
    }
    Ok(RegtestGateManifest {
        deal_id,
        profile: "DLOG52-regtest-single-slot-gate-v1",
        slots: gates.try_into().map_err(|_| BitcoinError::Tree)?,
    })
}

/// Enforce the hard real-funds prohibition at the public construction boundary.
///
/// # Errors
///
/// Returns [`BitcoinError::RealFundsDisabled`] for every non-regtest network.
pub fn require_regtest(network: bitcoin::Network) -> Result<(), BitcoinError> {
    if network == bitcoin::Network::Regtest {
        Ok(())
    } else {
        Err(BitcoinError::RealFundsDisabled)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use dealer_codec::Encode;
    use dealer_group::protocol_parameters;
    use dealer_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
    use dealer_protocol::{
        AcceptedDeal, AcceptedDealBody, GameConfig, JointPublic, PROTOCOL_VERSION, ProofContext,
        Role, accepted_body_hash, derive_candidate_keys, derive_game_id, finalize_verified_attempt,
        generate_player_bundle, verify_player_bundle,
    };
    use k256::{
        Scalar,
        schnorr::{Signature, SigningKey, VerifyingKey},
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    #[test]
    fn gate_metadata_and_network_are_checked() {
        assert!(build_candidate_leaf([1; 32], 8, 102, [2; 32], [3; 32]).is_ok());
        assert!(build_candidate_leaf([1; 32], 9, 0, [2; 32], [3; 32]).is_err());
        assert!(require_regtest(bitcoin::Network::Regtest).is_ok());
        assert!(require_regtest(bitcoin::Network::Bitcoin).is_err());
    }

    #[test]
    fn recursive_profile_has_103_ordered_depths() {
        let mut depths = Vec::new();
        leaf_depths(0, 103, 0, &mut depths);
        assert_eq!(depths.len(), 103);
        assert!(depths.iter().all(|(_, depth)| matches!(depth, 6 | 7)));
        assert_eq!(
            depths.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (0..103).collect::<Vec<_>>()
        );
    }

    #[test]
    fn verified_deal_compiles_all_nine_complete_gates() {
        std::thread::Builder::new()
            .name("dealer-gate-e2e".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                verified_deal_compiles_all_nine_complete_gates_inner();
            })
            .expect("spawn large-stack proof test")
            .join()
            .expect("proof test thread");
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep this complete protocol or integration sequence in its specified order."
    )]
    fn verified_deal_compiles_all_nine_complete_gates_inner() {
        let signing_a = SigningKey::from_bytes(&[3_u8; 32]).expect("valid test key");
        let signing_b = SigningKey::from_bytes(&[5_u8; 32]).expect("valid test key");
        let mut identities = [
            (signing_a.verifying_key().to_bytes().into(), signing_a),
            (signing_b.verifying_key().to_bytes().into(), signing_b),
        ];
        identities.sort_by_key(|(public, _)| *public);
        let config = GameConfig {
            network_genesis: [1; 32],
            session_anchor: [2; 32],
            identity_a: identities[0].0,
            identity_b: identities[1].0,
            session_nonce: [3; 32],
            rules_hash: [4; 32],
        };
        let game_id = derive_game_id(&config).expect("valid config");
        let joint = JointPublic::new(
            protocol_parameters().g * Scalar::from(17_u64),
            protocol_parameters().g * Scalar::from(29_u64),
        )
        .expect("valid joint key");
        let context = |role| ProofContext {
            game_id,
            attempt: 0,
            proof_stage: 3,
            prover_role: role,
            frozen_anchor: [9; 32],
        };
        let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
        let (bundle_a, secrets_a) = generate_player_bundle(&context(Role::A), &joint, &mut rng)
            .expect("A bundle generation");
        let (bundle_b, secrets_b) = generate_player_bundle(&context(Role::B), &joint, &mut rng)
            .expect("B bundle generation");
        let verified_a = verify_player_bundle(&context(Role::A), &joint, &bundle_a)
            .expect("A bundle verification");
        let verified_b = verify_player_bundle(&context(Role::B), &joint, &bundle_b)
            .expect("B bundle verification");
        let catalogue = derive_candidate_keys(
            &game_id,
            0,
            (&config.identity_a, &config.identity_b),
            &verified_a,
            &verified_b,
        )
        .expect("catalogue screening");
        let verification_root = [0x77; 32];
        let body = AcceptedDealBody {
            version: PROTOCOL_VERSION,
            params_id: protocol_parameters().params_id,
            game_id,
            attempt: 0,
            commitments_a: std::array::from_fn(|index| bundle_a.slots[index].commitment),
            commitments_b: std::array::from_fn(|index| bundle_b.slots[index].commitment),
            catalogue_hash: catalogue.hash,
            verification_root,
        };
        assert_eq!(body.to_bytes().len(), 728);
        let digest = accepted_body_hash(&body);
        let signature_a = identities[0]
            .1
            .sign_prehash_with_aux_rand(&digest, &[0x11; 32])
            .expect("A signature")
            .to_bytes();
        let signature_b = identities[1]
            .1
            .sign_prehash_with_aux_rand(&digest, &[0x22; 32])
            .expect("B signature")
            .to_bytes();
        let accepted = finalize_verified_attempt(
            &config,
            &verified_a,
            &verified_b,
            verification_root,
            AcceptedDeal {
                body,
                signature_a,
                signature_b,
            },
        )
        .expect("accepted boundary");
        let manifest = build_regtest_gate(&accepted).expect("gate compilation");
        assert_eq!(manifest.slots.len(), 9);
        assert!(manifest.slots.iter().all(|slot| slot.leaves.len() == 103));
        assert_eq!(manifest.profile, "DLOG52-regtest-single-slot-gate-v1");
        let raw_sum = secrets_a.openings[0].value() + secrets_b.openings[0].value();
        let leaf = &manifest.slots[0].leaves[usize::from(raw_sum)];
        let witness = assemble_gate_witness(leaf, &[0x11; 64], &[0x22; 64]);
        let elements = witness.iter().collect::<Vec<_>>();
        assert_eq!(elements[0], &[0x22; 64]);
        assert_eq!(elements[1], &[0x11; 64]);
        assert_eq!(elements[2], leaf.script.as_bytes());
        assert_eq!(elements[3], leaf.control_block.serialize());

        let transaction = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let prevouts = [bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: manifest.slots[0].output_script.clone(),
        }];
        let sighash = gate_tapscript_sighash(&transaction, 0, &prevouts, leaf).expect("sighash");
        let opening_a = verify_share_opening(
            &accepted,
            Role::A,
            0,
            ShareOpening {
                value: secrets_a.openings[0].value(),
                blinding: *secrets_a.openings[0].gamma(),
            },
        )
        .expect("opening A");
        let opening_b = verify_share_opening(
            &accepted,
            Role::B,
            0,
            ShareOpening {
                value: secrets_b.openings[0].value(),
                blinding: *secrets_b.openings[0].gamma(),
            },
        )
        .expect("opening B");
        let card_key =
            derive_card_signing_key(&accepted, 0, &opening_a, &opening_b).expect("card key");
        assert_eq!(card_key.raw_sum(), leaf.raw_sum);
        assert_eq!(card_key.card_id(), leaf.card_id);
        let card_signature = card_key
            .sign_tapscript_sighash(&sighash, &[0x55; 32])
            .expect("card signature")
            .to_bytes();
        let card_verifier =
            VerifyingKey::from_bytes(&card_key.public_xonly()).expect("card verifier");
        let parsed_card_signature =
            Signature::try_from(card_signature.as_slice()).expect("card signature encoding");
        assert!(
            card_verifier
                .verify_raw(&sighash, &parsed_card_signature)
                .is_ok()
        );
        let authorizer_index =
            usize::from(config.identity_a != manifest.slots[0].authorizer.serialize());
        let authorizer_signature = identities[authorizer_index]
            .1
            .sign_prehash_with_aux_rand(&sighash, &[0x66; 32])
            .expect("authorizer signature")
            .to_bytes();
        let authorizer_verifier =
            VerifyingKey::from_bytes(&manifest.slots[0].authorizer.serialize())
                .expect("authorizer verifier");
        let parsed_authorizer_signature = Signature::try_from(authorizer_signature.as_slice())
            .expect("authorizer signature encoding");
        assert!(
            authorizer_verifier
                .verify_raw(&sighash, &parsed_authorizer_signature)
                .is_ok()
        );
        let actual = assemble_gate_witness(leaf, &card_signature, &authorizer_signature);
        assert_eq!(actual.len(), 4);
        assert!(leaf.control_block.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            manifest.slots[0].output_key.to_x_only_public_key(),
            &leaf.script,
        ));
    }
}
