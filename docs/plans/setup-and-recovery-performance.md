# Complete setup under 30 seconds, fast reloads

## Implementation status — 2026-09-05

Implemented the four-worker approach first: bounded role-owned signing queues,
prioritized receiver verification, reusable verifier contexts, authenticated batch
receipts, encrypted IndexedDB preparation checkpoints, fresh-instance local reload,
and fully verified public snapshot import. The complete graph and original
inventory fingerprint are preserved. See [browser results](../benchmarks/browser-settlement.md).

The implementation retains sender self-verification and the existing crypto
backend. Additional point caches, backend changes, and further construction
parallelism are deferred because the measured local setup meets the target.
The benchmark simulates both roles locally; real two-device transport, funded UI,
and durable game secrets/score-key usage/chain reconciliation remain integration
work. The checkpoint is a preparation cache, not complete game recovery.

The following sections retain the broader design and acceptance criteria; they
are not a claim that every proposed experiment or application integration is done.

## What was measured before parallelization

The optimized construction run measured approximately:

| Work | Time |
| --- | ---: |
| Authenticated dealing | 1.26 s |
| Logical graph and shared script context | 0.21 s |
| Full transaction authorization inventory | 9.74 s |
| Both parties' combined signing and receiver verification | 58.07 s |
| Snapshot encoding | 0.009 s |
| Rebuild inventory for the recovery test | 9.78 s |
| Re-verify saved authorizations | 22.85 s |

Initial cryptographic setup is about **69.3 seconds**. The benchmark then performs
a simulated recovery, bringing the total test duration to about **101.9 seconds**.
Recovery is not a second mandatory stage of initial setup. The browser application
does not yet implement this funded-game setup/recovery flow; these measurements
come from the production Rust APIs exercised by a dedicated browser harness.

There are 54,855 ordinary signatures and 1,306 reveal packages, containing 67,912
adaptor signatures. Encoded responses total 7.97 MB and the snapshot is 8.42 MB.
On reveal edges the adaptors already ARE the counterparty's presignatures; there
is no extra ordinary counterparty signature to eliminate for those edges.

## Acceptance targets

- **Initial setup:** both actual participant workers have complete, verified,
  durable preparation in <=30 seconds on the reference machine/defined fast
  connection. Measure wall time, including transfer and persistence. Exclude
  waiting for an opponent to join and Bitcoin confirmations; report module load
  separately and also include it in a cold end-to-end result.
- **Normal local reload:** restore preparation in <=2 seconds, plus separately
  reported chain reconciliation/network latency.
- **Untrusted/imported recovery:** independently verify everything in <=30 seconds
  on the reference machine. No trust is granted to a peer-supplied ready flag.
- Preserve all 56,132 nodes and 56,161 authorizations, exact context bindings,
  receiver verification, timeout paths, and the complete on-chain settlement graph.

These are targets to verify, not predicted speedups or guarantees for every device
and connection. At 10 Mbit/s, 8 MB alone represents roughly 6.4 seconds of aggregate
payload transmission before overhead; the transport assumptions must be explicit.

## 1. Fix the benchmark boundaries and identify crypto costs

Report `initialSetupMs`, `localResumeMs`, and `importRecoveryMs` separately. Keep
individual phase times and aggregate CPU time available. Add measurements by role
and operation: ordinary signing, ordinary verification, adaptor generation,
generator self-verification, and receiver adaptor verification. Include outgoing
bytes per role, rather than assuming the two participants' work is balanced.

Add a genuine two-worker scenario, one participant per worker. Each independently
verifies the agreed game context and derives its own inventory. Compare inventory
fingerprints before exchanging batched artifacts. Neither participant receives
the other's private keys. The current one-worker sum is a useful CPU baseline,
but dividing it by two is not an adequate latency measurement.

## 2. Remove redundant work in adaptor generation

Create a game-scoped reveal cache keyed by accepted deal, role, slot and candidate:

- Precompute the 18 × 52 public encryption points C - vM, their canonical bytes,
  parsed authorizer keys, and accepted commitment encodings.
- Reuse those points during nonce derivation, generation, and verification.
  Derive fresh nonces for each exact transaction context with unchanged framing.
- Parse each authorizer secret/public-key relation once per signer context.

Currently `VerifiedRevealPackage::create` verifies every signature immediately
after producing it; the receiver then verifies all of them again. Introduce a
separate generated/outgoing package type and remove that unconditional sender
self-verification from the release hot path. Keep construction self-checks in
qualification tests and keep full verification of incoming artifacts before a
participant can become ready. A generated package must not be installable as a
verified peer authorization merely by changing its type.

Maintain deterministic vector tests for every candidate and cross-verify generated
packages using the existing verifier. Never share a completed signature or nonce
across different sighashes as an optimization.

## 3. Reuse cryptographic contexts and measure a faster backend

`SettlementPreparation::accept_response` currently constructs a secp verification
context and parses the identity key for each ordinary signature. Retain those
contexts/keys for a preparation session and its verified restore operation.

Compare the current musig2 k256 backend with its libsecp256k1 backend using the
same pinned Wasm build. The project already builds C secp256k1 for Bitcoin signing,
but the adaptor backend is a separate dependency and needs independent build and
interoperability qualification. Compare canonical encodings, signer/verifier
cross-compatibility, completed signatures, and extracted openings. Adopt a backend
only if it is faster in the browser and preserves those contracts.

Do not start with a new batch-verification algorithm or a new proof protocol.
The repeated point calculations, duplicate checks, and context setup are simpler
first targets with clearer correctness tests.

## 4. Pipeline the two participants' actual work

Generate outgoing artifacts and verify incoming artifacts concurrently in bounded
batches. Use compact binary batches (initially 64–256 KiB) with canonical request
indices, game/inventory binding, and idempotent retry behavior. Avoid one relay
round trip and JSON/base64 envelope per signature. Persist accepted batches as
part of the pipeline and apply backpressure so the receiver cannot accumulate an
unbounded queue.

Start with one owner worker per participant, plus public/verification workers only
if measurements justify them. Any signing helpers stay within their participant's
key ownership. Measure role imbalance, startup cost, memory, and real wall time.
Shared compiled Wasm modules can avoid repeated compilation overhead.

This remains cooperative SETUP of a fully on-chain game tree, not cooperative
in-game progression. Every on-chain authorization is ready before activation.

## 5. Reduce the remaining construction cost if the setup budget needs it

The current ~10-second inventory already meets the earlier construction goal.
For complete setup, aim for 3–5 seconds to leave room for cryptography and transfer.
Cache the game-wide executable showdown leaf hashes, and construct output-only
Taproot roots from hashes during preparation. Preserve exact Huffman weights and
ties, node commitment leaves, and output keys. Full scripts/control blocks remain
available through the witness materializer for actual spends.

Stream predicate encodings into the hasher using shared constant encodings to
avoid allocating/copying large buffers per node. If necessary, parallelize the
independent node-output pass in small batches; retain ordered parent-txid propagation.
Use the original full authorization fingerprint and exact script/control-block
comparisons to qualify all such changes.

## 6. Give local reload a dedicated path

The current public snapshot contains artifacts, not the independently derived
request inventory. Recovery therefore reconstructs the inventory (~10 s) and
checks every artifact again (~23 s). This is appropriate for an untrusted import,
but should not be the normal browser refresh path.

Persist a versioned local checkpoint after successful verification, including:

- Agreed setup certificate, configuration, activation binding, inventory digest,
  compact derived inventory and verified artifacts.
- Durable secret/replay state, one-time score-key usage, observed openings,
  pending transaction journal and the last confirmed chain cursor needed to resume.
- Integrity authentication under a local key held independently of the checkpoint
  bytes, covering all bindings and the verification/encoding version.

Write checkpoint and associated usage/journal updates atomically. On local resume,
authenticate the checkpoint, validate its version/game bindings and canonical
structure, then restore the already-verified inventory. This avoids both complete
reconstruction and repeated public-key verification. An unkeyed checksum or a
boolean ready flag is insufficient for this fast path.

Authentication proves local provenance/integrity, not chain freshness or protection
against a previously valid stale checkpoint. Reconcile confirmed/pending spends
and one-time-key usage before enabling new actions. Do not replay an old key-use
state merely because its checkpoint authenticates.

If the local authentication key is unavailable, the checkpoint is incompatible,
or bytes come from another source, take the full import path: verify the deal,
reconstruct or validate the inventory, and verify all authorizations using the
optimized contexts/backend. Bind all parsed requests to the locally derived game.

## 7. Measure to completion

Suggested latency budget (wall time, accounting for overlap): dealing/context 2 s,
construction 5 s, crypto exchange/verification 18 s, and persistence/load overhead
5 s. These allocations are adjustable; the decisive check is measured readiness
on BOTH participants within 30 seconds.

Qualification must cover:

- Full inventory fingerprint parity and complete authorizations on both peers.
- Corrupt/misbound batches, conflicting replay, interrupted setup, refresh, and
  failed atomic writes; incomplete state never enables activation.
- Valid local reload, altered checkpoint, missing key, stale checkpoint, version
  change, and untrusted import, each using the correct recovery path.
- Complete full-tree import recovery and managed Bitcoin Core execution tests.
- At least three isolated cold/warm trials with browser/build/worker metadata,
  explicit network conditions and actual durable persistence. Report the slowest
  run, per-role time, bytes, and memory, not only the best result.

Implement crypto instrumentation/cache/type separation first, then backend/context
improvements and two-peer batching. Implement local checkpoint recovery separately.
Only add further construction parallelism if the measured total still needs it.
