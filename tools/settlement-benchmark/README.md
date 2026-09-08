# Browser settlement benchmark

This developer tool runs the production settlement compiler, signature/adaptor
creation, receiver verification, and preparation recovery in a real browser Web
Worker. The full profile has 56,132 nodes, 20,000 sats per player, 100-sat units,
and four bets per street. A 26-node short-stack profile checks the harness quickly.

```sh
# Prepare the pinned builder once using scripts/build-browser-wasm.sh if needed.
scripts/build-settlement-benchmark.sh
node tools/settlement-benchmark/serve.mjs
# Open http://127.0.0.1:3101 and click the desired profile.
```

The serial **Run 3 qualification trials** button runs three sequential full trials, each
in a fresh worker, and requires construction under 30 seconds. The benchmark
checks the ordered authorization SHA-256 against the qualified script revision before
co-signing, covering all 56,161 requests.

Results are automatically saved under `target/settlement-benchmark/`:
`smoke.json`, `full.json`, `progress.json`, and timestamped result history. The result includes the exact Wasm
SHA-256, browser user agent, profile, phase timings, authorization counts, encoded
response/snapshot sizes, and sampled peak Wasm linear memory. The full run may
be expensive; Stop terminates the worker and saves partial progress. No partial
run is reported as a successful full-tree benchmark.

The harness establishes an actual authenticated two-party deal, builds the full
logical tree, derives every exact transaction preauthorization, signs all required
identity sighashes, creates all 52-candidate reveal adaptor packages, and verifies
every response. It encodes the complete snapshot, discards the first inventory,
reconstructs the inventory from the graph, rejects malformed signature/package
responses, restores every artifact, and requires complete preparation again.

Both parties use deterministic public test secrets in this local harness. The serial reference uses one worker. This
measures combined cryptographic work, not two-device wall-clock latency. The serial reference
excludes relay traffic, disk persistence, funding, and Bitcoin execution. The
origin is a synthetic regtest outpoint; no transactions are broadcast. Bitcoin
Core execution is covered separately by `scripts/bitcoin-core-regtest.sh`.

The diagnostic artifact is separate from production Wasm and uses a 32 MiB stack,
matching the native full-tree fixture. Memory reports are allocated Wasm linear
memory sampled at progress boundaries, not live Rust heap or total browser RAM.
Load/compile is reported separately from the overall run. Signing time includes
the package creator's internal checks; receiver verification is measured separately.

## Parallel setup and authenticated reload

Use **3 parallel trials** for the complete <=30-second setup qualification. Each
trial uses a fresh coordinator and four crypto workers (two assigned to each
participant). Workers share a compiled Wasm module and process bounded binary
batches. Receiver verification takes priority over further signing. All existing
Schnorr/adaptor checks, including sender self-verification, remain enabled.

The coordinator installs batches only after checking a local HMAC verification
receipt bound to its independently derived inventory. This delegation key is a
local trust capability and must never be sent to a peer. The Rust APIs live in
`poker-settlement::preparation`; reusable worker and storage modules live under
`apps/web/src`. The diagnostic Wasm bridge supplies public fixture keys.

`initialSetupMs` includes module load, authenticated dealing, graph construction,
all signing and receiver verification, assembly, and durable IndexedDB storage.
`localResumeMs` measures a fresh Wasm instance loading and authenticating that
checkpoint. `importRecoveryMs` measures fresh graph derivation and full parallel
verification of an untrusted public snapshot. These are separate operations.

IndexedDB stores a nonextractable AES-GCM key separately from encrypted checkpoint
bytes. The encrypted payload contains the local receipt key and HMAC-sealed
inventory/artifacts. Browser checks reject wrong keys/bindings, altered checkpoints,
altered ciphertext, and missing keys. Local checkpoints cache verified preparation;
they do not contain the complete game secret/score-key journal or reconcile chain
freshness. Funded application integration remains separate work.

Parallel measurements include local persistence, but exclude relay/network
latency and actual two-device coordination. `setupWasmBytes` sums allocated linear
memory for the owner and crypto workers; `peakWasmBytes` additionally includes the
fresh reload instance. Neither measures total browser RAM. Timestamped parallel
records are saved as `parallel-*.json` in the result directory.

## Script fingerprint migration

The original materializer parity fingerprint was
`47139bb56b6d3c638d98fea1aaa15adf1215a4c39d7b8503865214afbf3e4fad`.
Commit `1ccb951` intentionally removes redundant signature guards and card metadata,
changing transaction IDs. Its qualified reference fingerprint is
`bd1b971f06c87c284b595741f4e35729c71e838d5384f698458ce15d4840577e`.
Earlier benchmark results retain their original artifact hashes and fingerprint;
rebuild the diagnostic Wasm when measuring the new scripts. The funded browser
integration lives separately at `/tools/onchain-e2e`; see
`docs/benchmarks/mutinynet-browser-2026-09-05.json`.

The subsequent retained reveal-metadata simplification also moves context into
`RevealProgram`'s binding encoding instead of executable push/drop operations.
Its current full reference fingerprint is
`9f6758ce626d58e7ae76a166c48947b49deee9f0a8e5bd7200219e28c6a717da`.
This is a further intentional script change, not materializer parity with either
earlier script revision.
