#![forbid(unsafe_code)]
// A failed benchmark fixture must abort the diagnostic run, not report timings.
#![allow(clippy::panic)]
//! Small dependency-free benchmark harness for the cryptographic primitives.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use dealer_codec::Encode;
use dealer_group::{N_SLOTS, SlotPublic, create_slot, protocol_parameters};
use dealer_proofs::{RangeWitness, prove_links, prove_range52, verify_links, verify_range52};
use dealer_uniqueness::{
    create_decryption, create_scale_round, derive_zero_tests, verify_decryption, verify_scale_round,
};
use k256::Scalar;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

fn measure(mut operation: impl FnMut(), samples: usize) -> (Duration, Duration) {
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        operation();
        times.push(start.elapsed());
    }
    times.sort_unstable();
    (
        times[samples / 2],
        times[(samples * 95 / 100).min(samples - 1)],
    )
}

fn show(name: &str, samples: usize, result: (Duration, Duration)) {
    println!(
        "{name:24} n={samples:4} median={:9.3} ms p95={:9.3} ms",
        result.0.as_secs_f64() * 1_000.0,
        result.1.as_secs_f64() * 1_000.0
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep this complete protocol or integration sequence in its specified order."
)]
fn main() {
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
            .unwrap_or_else(|error| panic!("fixture A: {error}"))
    });
    let slots_b: [SlotPublic; N_SLOTS] = std::array::from_fn(|i| {
        create_slot(values_b[i], &gammas_b[i], &randomness_b[i], &joint)
            .unwrap_or_else(|error| panic!("fixture B: {error}"))
    });
    let witnesses_a: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
        value: values_a[i],
        gamma: gammas_a[i],
    });
    let statement = b"DLOG52 benchmark frozen bundle statement";

    let range = prove_range52(statement, &slots_a, &witnesses_a, &mut rng)
        .unwrap_or_else(|error| panic!("range setup: {error}"));
    let links = prove_links(
        statement,
        &range,
        &witnesses_a,
        &randomness_a,
        &joint,
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("link setup: {error}"));
    let tests =
        derive_zero_tests(&slots_a, &slots_b).unwrap_or_else(|error| panic!("tests: {error}"));
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
    .unwrap_or_else(|error| panic!("scale setup: {error}"));
    let scaled = verify_scale_round(
        "DLOG52/scale-first/v1",
        b"scale context",
        &joint_public,
        &tests,
        &scale,
    )
    .unwrap_or_else(|error| panic!("scale verify setup: {error}"));
    let decrypt = create_decryption(b"decrypt context", &joint_public, &scaled, &sk_a, &mut rng)
        .unwrap_or_else(|error| panic!("decrypt setup: {error}"));

    for _ in 0..2 {
        black_box(
            prove_range52(statement, &slots_a, &witnesses_a, &mut rng)
                .unwrap_or_else(|error| panic!("warmup: {error}")),
        );
    }
    show(
        "range prove",
        20,
        measure(
            || {
                black_box(
                    prove_range52(statement, &slots_a, &witnesses_a, &mut rng)
                        .unwrap_or_else(|error| panic!("range: {error}")),
                );
            },
            20,
        ),
    );
    show(
        "range verify",
        100,
        measure(
            || {
                black_box(verify_range52(statement, &slots_a, &range))
                    .unwrap_or_else(|error| panic!("range verify: {error}"));
            },
            100,
        ),
    );
    show(
        "link prove",
        50,
        measure(
            || {
                black_box(
                    prove_links(
                        statement,
                        &range,
                        &witnesses_a,
                        &randomness_a,
                        &joint,
                        &mut rng,
                    )
                    .unwrap_or_else(|error| panic!("links: {error}")),
                );
            },
            50,
        ),
    );
    show(
        "link verify",
        100,
        measure(
            || {
                black_box(verify_links(statement, &range, &slots_a, &joint, &links))
                    .unwrap_or_else(|error| panic!("links verify: {error}"));
            },
            100,
        ),
    );
    show(
        "scale prove (108)",
        20,
        measure(
            || {
                black_box(
                    create_scale_round(
                        "DLOG52/scale-first/v1",
                        b"scale context",
                        &joint_public,
                        &tests,
                        &mut rng,
                    )
                    .unwrap_or_else(|error| panic!("scale: {error}")),
                );
            },
            20,
        ),
    );
    show(
        "scale verify (108)",
        50,
        measure(
            || {
                black_box(verify_scale_round(
                    "DLOG52/scale-first/v1",
                    b"scale context",
                    &joint_public,
                    &tests,
                    &scale,
                ))
                .unwrap_or_else(|error| panic!("scale verify: {error}"));
            },
            50,
        ),
    );
    show(
        "decrypt prove (108)",
        50,
        measure(
            || {
                black_box(
                    create_decryption(b"decrypt context", &joint_public, &scaled, &sk_a, &mut rng)
                        .unwrap_or_else(|error| panic!("decrypt: {error}")),
                );
            },
            50,
        ),
    );
    show(
        "decrypt verify (108)",
        50,
        measure(
            || {
                black_box(verify_decryption(
                    b"decrypt context",
                    &joint_public,
                    &scaled,
                    &pk_a,
                    &decrypt,
                ))
                .unwrap_or_else(|error| panic!("decrypt verify: {error}"));
            },
            50,
        ),
    );
    println!("range proof bytes        {}", range.to_bytes().len());
    println!(
        "link proof bytes         {}",
        links
            .iter()
            .map(|item| item.to_bytes().len())
            .sum::<usize>()
    );
    println!("scale payload bytes      24840");
    println!("decryption body bytes    7193");
}
