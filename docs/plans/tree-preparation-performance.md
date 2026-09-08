# Full-tree preparation under 30 seconds

## Implementation status

The game-scoped candidate/script cache and two-pass compact materializer are
implemented. The ordered full-tree authorization fingerprint matches the original
materializer. Browser construction is now approximately 9–10 seconds on one worker;
full preparation and recovery pass. No worker pool or cryptographic-backend change
was needed to meet the construction target. See the
[measured results](../benchmarks/browser-settlement.md).

The stricter objective of complete readiness under 30 seconds now has a separate
[setup and recovery plan](setup-and-recovery-performance.md). Co-signing remains
approximately 58 seconds of combined work in the current single-worker harness.

## Target and baseline

Primary acceptance target: construct every exact transaction authorization in the
unchanged 56,132-node reference tree in **at most 30 seconds** in the same browser
and Wasm build configuration. Keep co-signing and recovery as separately reported
stages. Complete preactivation readiness under 30 seconds is a second, stricter
objective: signing alone currently takes 58.1 seconds in the single-worker harness.

[Baseline and raw browser record](../benchmarks/browser-settlement.md): 0.204 s
logical graph compilation, 614.725 s exact transaction inventory, 58.104 s combined
signing and receiver verification, 8.42 MB encoded snapshot. Recovery was stopped
partway through inventory reconstruction; its full duration is not measured.

The primary target needs about 20.5x acceleration. This is plausible because the
current path recomputes invariant data extensively, but no speedup is promised
until the browser benchmark demonstrates it. Preserve the full tree, poker rules,
transaction encodings, authorization checks, and on-chain-only settlement paths.

## Why construction is slow

- `SettlementGraph::visit_authorizations` compiles the parent's Taproot state.
  For each outgoing edge, `transition` calls `outputs(parent)`, recompiling the
  same parent, and `outputs(child)`, compiling the child. That child is later
  rebuilt when visited. Another `program` call rebuilds a program just to look
  up its predicate identifier.
- Each `ShowdownOpenings::from_deal` converts 7 × 103 = 721 projective curve
  points to x-only encodings. `point_xonly` calls `to_affine`, which requires
  field normalization. The entire deal has only 9 × 103 = 927 distinct points.
  Those immutable bytes are repeatedly regenerated for many showdown programs.
- `accepted_body_hash` serializes and hashes the accepted deal body again during
  program construction. It is invariant for the entire tree.
- Large showdown scripts, candidate selector fragments, and program encodings
  are repeatedly allocated and copied. `CompiledTaprootState::compile` also
  recomputes script leaf hashes inside a sorting comparator, then construction
  and sighash calculation hash scripts again.
- The preparation path eagerly builds full witness-oriented Taproot objects,
  including scripts and control blocks, even when it only needs an output key
  and leaf hash to derive a signature request.

This is evidence of redundant work, not a measured CPU-percentage breakdown.
Transaction serialization itself has not been shown to account for the delay.

## 1. Capture costs and equivalence before changing the path

Add optional counters/timers for point normalization, body hashing, program/script
construction, Taproot finalization, transaction serialization/txid calculation,
and sighash calculation. Sample representative betting, reveal, Alice-showdown,
and Bob-payout nodes first; avoid rerunning a ten-minute full trace for each edit.

Keep the current materializer as a temporary test oracle during migration.
Compare exact script bytes, predicate identifiers, Tapleaf hashes, output keys,
control blocks, transaction bytes/txids, sighashes, and authorization order. Build
an ordered digest of all 56,161 requests for the fixed complete fixture. Remove
any temporary alternate production path after parity is established.

Deliverable: measured hotspots and stable, complete reference expectations.

## 2. Cache all accepted-deal invariants once

Introduce a game-scoped prepared script context holding:

- The accepted-body hash and all 927 validated x-only candidates (29,664 bytes).
- Shared Alice/Bob candidate-selector fragments and score/evaluator fragments.
- Parsed identity/reveal public keys and reusable curve verification contexts.

Construct it from `VerifiedAcceptedDeal`; its cache identity must include the
actual deal, score keys, and configuration that determine each fragment. Render
node-specific commitments explicitly. Keep cache lifetime tied to one game.

Measure this change alone. It removes the clearest repeated expensive arithmetic
without changing the tree traversal. Only investigate batch point normalization
if the remaining one-time conversion is material after this change.

## 3. Compile compact node records once; build transactions in a second pass

Pass A compiles every nonterminal node once. Store compact records containing
its output scriptPubKey, amounts, and each edge's predicate ID and Tapleaf hash.
Compute script leaf hashes once and sort their stored values. Preserve the exact
existing Huffman weights, tie-breaking rules, commitment leaf, and output key.
Keep large script fragments shared or transient; do not cache gigabytes of full
per-node scripts/control blocks.

Pass B walks canonical preorder. With every child output already available, build
each transaction once, propagate its txid to its child, and compute the exact
sighash using the stored Tapleaf hash. Add a hash-taking sighash helper backed by
the existing Bitcoin library. Preserve the script-taking API for callers that
already have a script.

Regenerate full scripts and control blocks for the selected spend, checking them
against the compact record. Preactivation preparation still covers every branch.

Deliverable: one node compilation per nonterminal node and one transaction build
per edge, with full byte-for-byte equivalence to the reference path. Re-run the
full browser construction benchmark at this point; this is the first candidate
for meeting the 30-second target.

## 4. Parallelize remaining public construction only if needed

Pass A is independent across nodes once the logical plan and verified public game
context exist. If the single-worker result still exceeds 30 seconds, use a small
bounded worker pool for batches of public node compilation. Share/clone the
compiled Wasm module and initialize public context once per worker. Return compact
binary records in deterministic index order; avoid per-node JSON round trips.

Start with two and four workers, measure actual wall time and memory, and retain
one-worker fallback. Keep parent-txid propagation in Pass B ordered. Set a measured
memory budget before enabling more workers; a 32 MiB stack per worker adds up.

## 5. Reduce co-signing cost for the stricter readiness target

The 58.1-second baseline combines both simulated parties' work in one worker.
Measure ordinary Schnorr creation/verification separately from reveal package
creation/verification and split results by actual signing role.

Cache the reveal encryption points and serialized encodings per (deal, role,
slot, candidate). There are at most 18 × 52 such public points. Current package
creation recalculates them across contexts and again for nonce derivation.
Continue deriving nonces and authorizations for each exact transaction context.
Reuse parsed keys and curve contexts during verification.

Compare the available libsecp256k1-backed adaptor implementation against the
current k256 backend in the same Wasm harness. Require cross-verification and
encoding compatibility before any switch. Use real two-participant concurrent
measurements rather than assuming half the combined CPU time is actual latency.
All receiver checks remain required.

A provisional budget for complete readiness is: dealing 2 s, transaction inventory
10 s, exchange/co-signing/verification 15 s, and snapshot work 3 s. These are
engineering budgets, not predictions or measured results; actual relay/persistence
latency must be added and tested when that browser integration exists.

## 6. Qualification and completion gates

- Every original node and authorization remains present; no cooperative-play
  shortcut, reduced profile, skipped verification, or sampling passes as full prep.
- Exact differential parity across the full reference tree; corrupted signatures,
  adaptor packages, and snapshots remain rejected transactionally.
- Complete the browser full-tree recovery test, which was interrupted in the
  baseline. Reconstruction should use the optimized deterministic materializer.
- Re-run the managed Bitcoin Core suite, including the complete short-stack hand,
  payouts, and CSV paths, after the construction changes.
- Run at least three isolated full browser measurements, report cold module load
  separately, and require construction to stay at or below 30 s in all three on
  the baseline machine. Record browser, Wasm hash, worker count, memory and phases.
  Broader device guarantees require separate device measurements.
- Keep actual co-signing, snapshot bytes, recovery time and memory visible even
  when the construction target passes. Declare complete readiness under 30 s only
  after that distinct end-to-end measurement passes.

Implement in order: counters/parity, invariant cache, compact two-pass compiler,
then measured parallelism and signing work. Stop adding complexity once the
relevant measured target is met.
