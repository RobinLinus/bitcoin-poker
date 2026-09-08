# Full settlement tree in the browser

The benchmark runs the production Rust settlement compiler and preparation APIs
inside browser Web Workers. It signs every required transaction authorization
in the full 56,132-node reference tree, then reconstructs and re-verifies the
complete preparation snapshot. See the [harness instructions](../../tools/settlement-benchmark/README.md)
for reproduction and measurement boundaries.

## Qualified parallel setup — 2026-09-05

All three isolated trials passed the complete setup target using four crypto
workers, with every existing cryptographic check retained.

| Trial | Initial setup, including persistence | Local preparation reload | Fully verified import |
| --- | ---: | ---: | ---: |
| 1 | 26.39 s | 70.7 ms | 17.40 s |
| 2 | 26.93 s | 71.8 ms | 17.52 s |
| 3 | 27.26 s | 73.9 ms | 17.60 s |

Initial setup includes load/compile, authenticated dealing, full construction,
signing, receiver verification, checkpoint assembly and IndexedDB persistence.
Each trial used a fresh coordinator and crypto workers; browser/compiler caches
may be warm. No native build/test workload ran alongside the measurements.

The pool pipelines bounded role-owned batches and prioritizes incoming verification.
The owner authenticates worker receipts instead of repeating their public-key
checks. Reload authenticates a persisted preparation checkpoint in a fresh Wasm
instance. Untrusted import reconstructs the graph and verifies every artifact.
All trials also rejected five checkpoint/key/binding/ciphertext failure cases.

The original full inventory fingerprint and 8,416,186-byte snapshot are unchanged.
The sealed checkpoint is 12,512,289 bytes. Setup allocates 374,079,488 bytes of
Wasm linear memory (356.75 MiB); the full diagnostic including its extra reload
instance peaks at 474,480,640 bytes (452.5 MiB). This is not total browser RAM.

These are local diagnostic measurements with public fixture keys, not a two-device
network benchmark or funded gameplay integration. Local persistence is included;
relay latency is excluded. The checkpoint caches preparation, not full game secret,
score-key usage or chain-journal state. See the [raw records](browser-settlement-parallel-2026-09-05.json)
and [implementation scope](../plans/setup-and-recovery-performance.md).

## Qualified optimized construction — 2026-09-05

Three sequential isolated full runs, each in a fresh browser worker, all passed
complete preparation and snapshot recovery. No native build/test workload ran
alongside these three qualification measurements.

| Trial | Construction | Co-signing and verification | Recovery inventory | Recovery verification |
| --- | ---: | ---: | ---: | ---: |
| 1 | 9.32 s | 57.28 s | 9.46 s | 22.69 s |
| 2 | 9.51 s | 57.61 s | 9.76 s | 22.61 s |
| 3 | 9.73 s | 57.80 s | 9.81 s | 22.77 s |

The median construction time is **9.51 seconds**, about **64.7x faster** than the
614.72-second baseline. Every trial is below the 30-second construction target.
The snapshot remains 8,416,186 bytes; observed peak Wasm allocation is 118,751,232
bytes (113.25 MiB), including the fixed 32 MiB stack. No worker pool was used in these serial reference trials.

All 56,161 ordered authorization requests match the original materializer's
SHA-256 fingerprint, captured before optimization:
`47139bb56b6d3c638d98fea1aaa15adf1215a4c39d7b8503865214afbf3e4fad`.
It commits to node IDs, edge indices/roles, exact transaction sighashes, and reveal
context bindings. The full benchmark checks this fingerprint before signing.
Native tests, strict Clippy, and all managed Bitcoin Core suites passed as well.

The unchanged inventory contains 54,855 ordinary signatures and 1,306 reveal
packages (67,912 adaptor signatures). See the
[three raw qualification records](browser-settlement-optimized-2026-09-05.json).
The [cache-only intermediate run](browser-settlement-cache-only.json) reduced
construction to 59.59 seconds before adding the two-pass materializer; that
intermediate run was intentionally stopped after construction and is not a
complete recovery qualification.

This serial reference took roughly 69 seconds for initial setup.
The additional ~32 seconds of recovery in this harness are a separate simulated
reload, not a mandatory second setup pass. The
[setup performance plan](../plans/setup-and-recovery-performance.md) addresses both.

## Measured baseline — 2026-09-05

One run in the local in-app Chromium 152 browser, one Wasm worker, 32 MiB stack.
The exact artifact SHA-256 and browser metadata are in the
[raw record](browser-settlement-2026-09-05.json).

| Stage | Measured time / size |
| --- | ---: |
| Authenticated two-party dealing | 1.240 s |
| Full logical graph compilation and verification | 0.204 s |
| All 56,161 exact transaction authorization contexts | 614.725 s |
| All authorizations created and receiver-verified | 58.104 s |
| Snapshot encoding and first inventory teardown | 0.009 s |
| Complete encoded snapshot | 8,416,186 bytes |
| Observed peak Wasm allocation before stop | 99,876,864 bytes (95.25 MiB) |

**The full run was stopped during recovery inventory reconstruction**, at 9,088
of 56,161 requests. Full-tree construction, co-signing, and snapshot encoding
completed successfully; full-tree snapshot recovery has not yet completed. Do not
interpret the cancelled overall result as a full recovery pass. The separate
26-node browser smoke test completed preparation and recovery in 2.232 s.

These are single-run observations, not medians or isolated CPU profiles. Source
inspection identifies repeated work, but does not establish the percentage of
time attributable to each function. The 30-second construction target requires
roughly a 20.5x speedup over this baseline.

## Interpretation

Logical topology construction and exact Bitcoin transaction construction are
separate workloads. `SettlementGraph::compile` creates the logical plan, whereas
`SettlementPreparation` derives the complete inventory of BIP341 sighashes and
reveal contexts by materializing scripts and transaction outputs for every branch.
A fast logical graph test does not establish fast preactivation preparation.

The original materialization repeated expensive work: `visit_authorizations` constructs
a parent Taproot state, `transition` constructs it again via `outputs`, and child
outputs construct their states too. Showdown programs repeatedly convert the same
accepted candidate points to x-only encodings and rebuild large scripts. The optimized implementation caches candidates and scripts and materializes
compact node records once; these baseline observations motivated those changes.

The reported co-signing time includes both simulated signers and receiver
verification, including all 52 adaptor candidates per reveal package. Recovery
independently derives the inventory again and verifies every encoded artifact.
The benchmark checks malformed signature/package rejection and requires zero
missing authorizations before and after snapshot recovery.

The run uses public deterministic test keys and a synthetic regtest outpoint.
It does not broadcast, execute every branch in Bitcoin Core, measure relay latency, or implement funded browser gameplay. The existing Core campaign
executes a prepared 26-node short-stack tree through a complete confirmed hand.
