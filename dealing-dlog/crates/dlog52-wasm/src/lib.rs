// `no_mangle` is an unsafe attribute in Rust 2024. This boundary uses it only
// to expose one C-ABI symbol; the crate contains no unsafe block or operation.
//! Raw WebAssembly benchmark boundary. It intentionally owns no live game state.

use std::hint::black_box;

use dlog52_codec::Encode;
use dlog52_group::{N_SLOTS, SlotPublic, create_slot, protocol_parameters};
use dlog52_proofs::{RangeWitness, prove_links, prove_range52, verify_links, verify_range52};
use dlog52_uniqueness::{
    create_decryption, create_scale_round, derive_zero_tests, verify_decryption, verify_scale_round,
};
use k256::Scalar;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

#[cfg(target_arch = "wasm32")]
fn reject_ambient_randomness(_: &mut [u8]) -> Result<(), getrandom::Error> {
    // The participant ABI requires caller-supplied CSPRNG entropy and never
    // falls back to ambient randomness inside Wasm.
    Err(getrandom::Error::UNSUPPORTED)
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(reject_ambient_randomness);

#[cfg(target_arch = "wasm32")]
mod participant_abi {
    use std::{cell::RefCell, thread_local};

    use dlog52_codec::{Reader, put_u16};
    use dlog52_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
    use dlog52_protocol::{
        GameConfig, LiveParticipant, MAX_ENVELOPE_BYTES, MAX_SETUP_CERT_BYTES, Role,
        verify_setup_certificate, verify_share_reveal,
    };

    const ABI_VERSION: u32 = 1;
    const CONTROL_BYTES: usize = 193;
    const SNAPSHOT_BYTES: usize = 41;

    thread_local! {
        static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static SECRET: RefCell<Vec<u8>> = RefCell::new(vec![0; 32]);
        static ENTROPY: RefCell<Vec<u8>> = RefCell::new(vec![0; 32]);
        static PARTICIPANT: RefCell<Option<LiveParticipant>> = const { RefCell::new(None) };
    }

    fn fail(error: impl core::fmt::Display) -> u32 {
        ERROR.with(|slot| {
            let mut bytes = error.to_string().into_bytes();
            bytes.truncate(1024);
            *slot.borrow_mut() = bytes;
        });
        0
    }

    fn input() -> Vec<u8> {
        INPUT.with(|slot| slot.borrow().clone())
    }

    fn secret(slot: &'static std::thread::LocalKey<RefCell<Vec<u8>>>) -> [u8; 32] {
        slot.with(|bytes| {
            let mut out = [0; 32];
            out.copy_from_slice(&bytes.borrow());
            out
        })
    }

    fn decode_control(bytes: &[u8]) -> Result<(GameConfig, Role), &'static str> {
        if bytes.len() != CONTROL_BYTES {
            return Err("invalid DLOG52 initialization length");
        }
        let mut r = Reader::new(bytes);
        let config = GameConfig {
            network_genesis: r.array().map_err(|_| "invalid network genesis")?,
            session_anchor: r.array().map_err(|_| "invalid session anchor")?,
            identity_a: r.array().map_err(|_| "invalid identity A")?,
            identity_b: r.array().map_err(|_| "invalid identity B")?,
            session_nonce: r.array().map_err(|_| "invalid session nonce")?,
            rules_hash: r.array().map_err(|_| "invalid rules hash")?,
        };
        let role = match r.u8().map_err(|_| "missing role")? {
            0 => Role::A,
            1 => Role::B,
            _ => return Err("invalid role"),
        };
        r.finish().map_err(|_| "trailing initialization bytes")?;
        Ok((config, role))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_abi_version() -> u32 {
        ABI_VERSION
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_max_input_len() -> u32 {
        MAX_SETUP_CERT_BYTES as u32
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_begin_input(len: u32) -> u32 {
        let len = len as usize;
        if len > MAX_SETUP_CERT_BYTES {
            return fail("input exceeds DLOG52 bound");
        }
        INPUT.with(|slot| slot.borrow_mut().resize(len, 0));
        1
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_input_ptr() -> usize {
        INPUT.with(|slot| slot.borrow_mut().as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_secret_ptr() -> usize {
        SECRET.with(|slot| slot.borrow_mut().as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_entropy_ptr() -> usize {
        ENTROPY.with(|slot| slot.borrow_mut().as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_init() -> u32 {
        let (config, role) = match decode_control(&input()) {
            Ok(value) => value,
            Err(error) => return fail(error),
        };
        let participant =
            match LiveParticipant::new(config, role, secret(&SECRET), secret(&ENTROPY)) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
        SECRET.with(|slot| slot.borrow_mut().fill(0));
        ENTROPY.with(|slot| slot.borrow_mut().fill(0));
        PARTICIPANT.with(|slot| *slot.borrow_mut() = Some(participant));
        1
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_prepare_outgoing() -> u32 {
        PARTICIPANT.with(|slot| match slot.borrow_mut().as_mut() {
            Some(participant) => match participant.prepare_outgoing() {
                Ok(Some(bytes)) => {
                    OUTPUT.with(|out| *out.borrow_mut() = bytes.to_vec());
                    1
                }
                Ok(None) => {
                    OUTPUT.with(|out| out.borrow_mut().clear());
                    2
                }
                Err(error) => fail(error),
            },
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_confirm_outgoing() -> u32 {
        let bytes = input();
        PARTICIPANT.with(|slot| match slot.borrow_mut().as_mut() {
            Some(participant) => participant
                .confirm_persisted_outgoing(&bytes)
                .map_or_else(fail, |_| 1),
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_accept_peer() -> u32 {
        let bytes = input();
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return fail("envelope exceeds DLOG52 bound");
        }
        PARTICIPANT.with(|slot| match slot.borrow_mut().as_mut() {
            Some(participant) => participant.accept_peer(&bytes).map_or_else(fail, |_| 1),
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_snapshot() -> u32 {
        PARTICIPANT.with(|slot| match slot.borrow().as_ref() {
            Some(participant) => {
                let state = participant.snapshot();
                let mut bytes = Vec::with_capacity(SNAPSHOT_BYTES);
                bytes.extend_from_slice(&state.attempt.to_le_bytes());
                bytes.extend_from_slice(&state.stage.to_le_bytes());
                bytes.extend_from_slice(&state.stage_root);
                bytes.push(u8::from(state.has_pending_outgoing));
                bytes.push(u8::from(state.accepted));
                bytes.push(u8::from(state.retry_required));
                OUTPUT.with(|out| *out.borrow_mut() = bytes);
                1
            }
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_export_certificate() -> u32 {
        PARTICIPANT.with(
            |slot| match slot.borrow().as_ref().and_then(|p| p.certificate().ok()) {
                Some(bytes) => {
                    OUTPUT.with(|out| *out.borrow_mut() = bytes.to_vec());
                    1
                }
                None => fail("DLOG52 certificate is not available"),
            },
        )
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_start_retry(next_attempt: u32) -> u32 {
        PARTICIPANT.with(|slot| match slot.borrow_mut().as_mut() {
            Some(participant) => participant
                .start_retry(next_attempt)
                .map_or_else(fail, |_| 1),
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_verify_certificate() -> u32 {
        match verify_setup_certificate(&input()) {
            Ok(_) => 1,
            Err(error) => fail(error),
        }
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_export_share(slot_index: u32) -> u32 {
        let Ok(slot_index) = u8::try_from(slot_index) else {
            return fail("invalid share slot");
        };
        let request = input();
        if request.len() != 34 {
            return fail(
                "share authorization must contain recipient, stage, and auxiliary randomness",
            );
        }
        PARTICIPANT.with(|slot| {
            match slot.borrow().as_ref().and_then(|p| {
                let mut auxiliary = [0_u8; 32];
                auxiliary.copy_from_slice(&request[2..]);
                p.authorized_share_reveal(slot_index, request[0], request[1], &auxiliary)
                    .ok()
            }) {
                Some(bytes) => {
                    OUTPUT.with(|out| *out.borrow_mut() = bytes.to_vec());
                    1
                }
                None => fail("DLOG52 share is not available"),
            }
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_sign_card(slot_index: u32) -> u32 {
        let Ok(slot_index) = u8::try_from(slot_index) else {
            return fail("invalid card slot");
        };
        let request = input();
        if request.len() != 263 {
            return fail(
                "card signing request must contain a signed reveal, sighash, and auxiliary randomness",
            );
        }
        PARTICIPANT.with(|participant_slot| {
            let binding = participant_slot.borrow();
            let Some(participant) = binding.as_ref() else {
                return fail("DLOG52 participant is not initialized");
            };
            let accepted = match participant.accepted() {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let peer_reveal = match verify_share_reveal(accepted, &request[..199]) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            if peer_reveal.sender() == participant.role()
                || (peer_reveal.recipient() != 255
                    && peer_reveal.recipient() != participant.role().as_u8())
                || peer_reveal.slot() != slot_index
            {
                return fail("share reveal is not authorized for this participant");
            }
            let local_secret = match participant.setup_secrets().and_then(|secrets| {
                secrets
                    .openings
                    .get(usize::from(slot_index))
                    .ok_or(dlog52_protocol::ProtocolError::Stage)
            }) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let local = ShareOpening {
                value: local_secret.value(),
                blinding: *local_secret.gamma(),
            };
            let peer = ShareOpening {
                value: peer_reveal.value(),
                blinding: *peer_reveal.blinding(),
            };
            let (opening_a, opening_b) = if participant.role() == Role::A {
                (
                    verify_share_opening(accepted, Role::A, slot_index, local),
                    verify_share_opening(accepted, Role::B, slot_index, peer),
                )
            } else {
                (
                    verify_share_opening(accepted, Role::A, slot_index, peer),
                    verify_share_opening(accepted, Role::B, slot_index, local),
                )
            };
            let opening_a = match opening_a {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let opening_b = match opening_b {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let key = match derive_card_signing_key(accepted, slot_index, &opening_a, &opening_b) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let mut sighash = [0; 32];
            sighash.copy_from_slice(&request[199..231]);
            let mut auxiliary = [0; 32];
            auxiliary.copy_from_slice(&request[231..263]);
            let signature = match key.sign_tapscript_sighash(&sighash, &auxiliary) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let mut output = Vec::with_capacity(98);
            output.push(key.raw_sum());
            output.push(key.card_id());
            output.extend_from_slice(&key.public_xonly());
            output.extend_from_slice(&signature.to_bytes());
            OUTPUT.with(|out| *out.borrow_mut() = output);
            1
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_sign_offchain_commitment() -> u32 {
        let request = input();
        if request.len() != 64 {
            return fail("off-chain signing requires a commitment hash and auxiliary randomness");
        }
        let mut commitment_hash = [0_u8; 32];
        commitment_hash.copy_from_slice(&request[..32]);
        let mut auxiliary = [0_u8; 32];
        auxiliary.copy_from_slice(&request[32..]);
        PARTICIPANT.with(|slot| match slot.borrow().as_ref() {
            Some(participant) => {
                match participant.sign_offchain_commitment(commitment_hash, &auxiliary) {
                    Ok(signature) => {
                        OUTPUT.with(|out| *out.borrow_mut() = signature.to_vec());
                        1
                    }
                    Err(error) => fail(error),
                }
            }
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_verify_offchain_commitment() -> u32 {
        let request = input();
        if request.len() != 97 {
            return fail("off-chain verification requires role, commitment hash, and signature");
        }
        let signer = match request[0] {
            0 => Role::A,
            1 => Role::B,
            _ => return fail("invalid off-chain commitment signer"),
        };
        let mut commitment_hash = [0_u8; 32];
        commitment_hash.copy_from_slice(&request[1..33]);
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(&request[33..]);
        PARTICIPANT.with(|slot| match slot.borrow().as_ref() {
            Some(participant) => participant
                .verify_offchain_commitment(signer, commitment_hash, signature)
                .map_or_else(fail, |_| 1),
            None => fail("DLOG52 participant is not initialized"),
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_evaluate_seven() -> u32 {
        let cards = input();
        if cards.len() != 7 {
            return fail("seven-card evaluation requires 7 bytes");
        }
        let mut seven = [0; 7];
        seven.copy_from_slice(&cards);
        let mut best: Option<(u32, u8)> = None;
        for (subset_id, indices) in bp52_poker::SUBSETS_5_OF_7.iter().enumerate() {
            let selected = std::array::from_fn(|position| seven[usize::from(indices[position])]);
            let score = match bp52_poker::evaluate_five_cards(selected) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            if best.is_none_or(|(current, _)| score > current) {
                best = Some((score, subset_id as u8));
            }
        }
        let Some((score, subset)) = best else {
            return fail("no poker subsets");
        };
        let mut output = score.to_le_bytes().to_vec();
        output.push(subset);
        OUTPUT.with(|out| *out.borrow_mut() = output);
        1
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_gate_leaf(slot_index: u32, raw_sum: u32) -> u32 {
        let (Ok(slot_index), Ok(raw_sum)) = (u8::try_from(slot_index), u8::try_from(raw_sum))
        else {
            return fail("invalid DLOG52 gate selector");
        };
        PARTICIPANT.with(|participant_slot| {
            let binding = participant_slot.borrow();
            let Some(participant) = binding.as_ref() else {
                return fail("DLOG52 participant is not initialized");
            };
            let accepted = match participant.accepted() {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let manifest = match dlog52_bitcoin::build_regtest_gate(accepted) {
                Ok(value) => value,
                Err(error) => return fail(error),
            };
            let Some(slot) = manifest.slots.get(usize::from(slot_index)) else {
                return fail("invalid DLOG52 gate slot");
            };
            let Some(leaf) = slot.leaves.get(usize::from(raw_sum)) else {
                return fail("invalid DLOG52 raw sum");
            };
            let script = leaf.script.as_bytes();
            let control = leaf.control_block.serialize();
            let (Ok(script_len), Ok(control_len)) =
                (u16::try_from(script.len()), u16::try_from(control.len()))
            else {
                return fail("DLOG52 gate artifact too large");
            };
            let mut output = Vec::new();
            output.extend_from_slice(&manifest.deal_id);
            output.extend_from_slice(&[slot.slot, leaf.raw_sum, leaf.card_id]);
            output.extend_from_slice(&slot.authorizer.serialize());
            output.extend_from_slice(&slot.internal_key.serialize());
            use bitcoin::hashes::Hash;
            output.extend_from_slice(&slot.merkle_root.to_byte_array());
            output.extend_from_slice(slot.output_script.as_bytes());
            put_u16(&mut output, script_len);
            output.extend_from_slice(script);
            put_u16(&mut output, control_len);
            output.extend_from_slice(&control);
            OUTPUT.with(|out| *out.borrow_mut() = output);
            1
        })
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_output_ptr() -> usize {
        OUTPUT.with(|slot| slot.borrow_mut().as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_output_len() -> u32 {
        OUTPUT.with(|slot| slot.borrow().len() as u32)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_error_ptr() -> usize {
        ERROR.with(|slot| slot.borrow_mut().as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_error_len() -> u32 {
        ERROR.with(|slot| slot.borrow().len() as u32)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn dlog52_deal_clear() {
        PARTICIPANT.with(|slot| *slot.borrow_mut() = None);
        INPUT.with(|slot| slot.borrow_mut().fill(0));
        OUTPUT.with(|slot| slot.borrow_mut().fill(0));
        SECRET.with(|slot| slot.borrow_mut().fill(0));
        ENTROPY.with(|slot| slot.borrow_mut().fill(0));
    }
}

/// Execute `iterations` of one benchmark operation and return a nonzero checksum.
///
/// Operation codes: 0 range prove, 1 range verify, 2 link prove, 3 link verify,
/// 4 scale prove, 5 scale verify, 6 decryption prove, 7 decryption verify.
#[unsafe(no_mangle)]
pub extern "C" fn dlog52_benchmark(operation: u32, iterations: u32) -> u32 {
    if operation > 7 || iterations == 0 || iterations > 10_000 {
        return 0;
    }
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let sk_a = Scalar::from(17_u64);
    let sk_b = Scalar::from(29_u64);
    let pk_a = protocol_parameters().g * sk_a;
    let pk_b = protocol_parameters().g * sk_b;
    let joint = pk_a + pk_b;
    let values_a = [0_u8, 1, 7, 15, 23, 31, 39, 47, 51];
    let values_b = [2_u8, 8, 14, 20, 26, 32, 38, 44, 50];
    let gammas_a: [Scalar; N_SLOTS] = std::array::from_fn(|i| Scalar::from((100 + i) as u64));
    let gammas_b: [Scalar; N_SLOTS] = std::array::from_fn(|i| Scalar::from((200 + i) as u64));
    let randomness_a: [Scalar; N_SLOTS] =
        std::array::from_fn(|i| Scalar::from((300 + i * 3) as u64));
    let randomness_b: [Scalar; N_SLOTS] =
        std::array::from_fn(|i| Scalar::from((400 + i * 5) as u64));
    let slots_a: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
        create_slot(values_a[i], &gammas_a[i], &randomness_a[i], &joint)
            .unwrap_or_else(|error| panic!("invalid benchmark fixture A: {error}"))
    });
    let slots_b: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
        create_slot(values_b[i], &gammas_b[i], &randomness_b[i], &joint)
            .unwrap_or_else(|error| panic!("invalid benchmark fixture B: {error}"))
    });
    let witnesses: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
        value: values_a[i],
        gamma: gammas_a[i],
    });
    let statement = b"DLOG52 wasm benchmark frozen bundle statement";
    let range = prove_range52(statement, &slots_a, &witnesses, &mut rng)
        .unwrap_or_else(|error| panic!("range fixture failed: {error}"));
    let links = prove_links(
        statement,
        &range,
        &witnesses,
        &randomness_a,
        &joint,
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("link fixture failed: {error}"));
    let tests = derive_zero_tests(&slots_a, &slots_b)
        .unwrap_or_else(|error| panic!("uniqueness fixture failed: {error}"));
    let mut joint_public = Vec::new();
    dlog52_group::encode_point(&pk_a, &mut joint_public);
    dlog52_group::encode_point(&pk_b, &mut joint_public);
    dlog52_group::encode_point(&joint, &mut joint_public);
    let scale = create_scale_round(
        "DLOG52/scale-first/v1",
        b"scale context",
        &joint_public,
        &tests,
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("scale fixture failed: {error}"));
    let scaled = verify_scale_round(
        "DLOG52/scale-first/v1",
        b"scale context",
        &joint_public,
        &tests,
        &scale,
    )
    .unwrap_or_else(|error| panic!("scale verification fixture failed: {error}"));
    let decrypt = create_decryption(b"decrypt context", &joint_public, &scaled, &sk_a, &mut rng)
        .unwrap_or_else(|error| panic!("decryption fixture failed: {error}"));

    let mut checksum = 1_u32;
    for _ in 0..iterations {
        let ok = match operation {
            0 => prove_range52(statement, &slots_a, &witnesses, &mut rng)
                .map(|proof| proof.to_bytes().len() == 13_964)
                .unwrap_or(false),
            1 => verify_range52(statement, &slots_a, black_box(&range)).is_ok(),
            2 => prove_links(
                statement,
                &range,
                &witnesses,
                &randomness_a,
                &joint,
                &mut rng,
            )
            .is_ok(),
            3 => verify_links(statement, &range, &slots_a, &joint, black_box(&links)).is_ok(),
            4 => create_scale_round(
                "DLOG52/scale-first/v1",
                b"scale context",
                &joint_public,
                &tests,
                &mut rng,
            )
            .is_ok(),
            5 => verify_scale_round(
                "DLOG52/scale-first/v1",
                b"scale context",
                &joint_public,
                &tests,
                black_box(&scale),
            )
            .is_ok(),
            6 => create_decryption(b"decrypt context", &joint_public, &scaled, &sk_a, &mut rng)
                .is_ok(),
            7 => verify_decryption(
                b"decrypt context",
                &joint_public,
                &scaled,
                &pk_a,
                black_box(&decrypt),
            )
            .is_ok(),
            _ => false,
        };
        checksum = checksum.wrapping_mul(16_777_619) ^ u32::from(ok);
    }
    black_box(checksum)
}
