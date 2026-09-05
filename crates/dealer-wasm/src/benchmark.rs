//! Cryptographic benchmark export.
use std::hint::black_box;

use dealer_codec::Encode;
use dealer_group::{N_SLOTS, SlotPublic, create_slot, protocol_parameters};
use dealer_proofs::{RangeWitness, prove_links, prove_range52, verify_links, verify_range52};
use dealer_uniqueness::{
    create_decryption, create_scale_round, derive_zero_tests, verify_decryption, verify_scale_round,
};
use k256::Scalar;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

/// Execute `iterations` of one benchmark operation and return a nonzero checksum.
///
/// Operation codes: 0 range prove, 1 range verify, 2 link prove, 3 link verify,
/// 4 scale prove, 5 scale verify, 6 decryption prove, 7 decryption verify.
#[unsafe(no_mangle)]
pub extern "C" fn dealer_benchmark(operation: u32, iterations: u32) -> u32 {
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
    dealer_group::encode_point(&pk_a, &mut joint_public);
    dealer_group::encode_point(&pk_b, &mut joint_public);
    dealer_group::encode_point(&joint, &mut joint_public);
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
