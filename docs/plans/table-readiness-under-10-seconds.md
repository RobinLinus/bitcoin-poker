# Table preparation and consecutive hands under 10 seconds

Status: partial implementation complete; ten local trials recorded. The adaptor backend
now uses libsecp256k1; construction, bounded worker scheduling, durable batching,
and foreground protocol exchanges have been optimized. Full owner inventories
remain byte-for-byte equivalent. The strict end-to-end target is not yet met:
short hands can still wait for several shuffle attempts. See
[the implementation report](../benchmarks/table-readiness-libsecp256k1.md).

## Target and measurement boundaries

Make both “Getting the table ready…” and “Preparing next hand…” finish in
**less than 10,000 ms on both players**, with a 9-second engineering budget.
Preserve the complete fallback trees, legal poker actions, receiver verification,
durable recovery, and safe retirement of the previous hand.

Measure these separately so a shorter label does not hide an unchanged wait:

1. **Initial preparation:** from entry into `Preparing the full game` to both
   players having complete, durable preparation and enforceable recovery roots,
   ready to release funding. Include the peer-ready exchange and root setup,
   not just the worker's `prepare()` duration. Also record every visible interval
   using the “Getting the table ready…” title, including funding-return setup.
2. **Between hands:** from the agreed terminal state of the previous hand to
   both browsers displaying the successor's hole cards and betting state, with
   legal actions enabled for the acting player. Include residual shuffle time,
   final-term binding, preparation, monitoring, retirement, promotion and dealing.
   Record the “Preparing next hand…” interval inside that complete gap.
3. **Full first-hand startup:** join/funding action to playable cards, reporting
   Wasm load, shuffle/retries, opponent delay and initial funding confirmation
   separately. A sub-10-second preparation result does not promise a Bitcoin
   confirmation or complete first startup within 10 seconds.

Initial qualification environment: the reference development machine/browser,
visible tabs, no competing build workload, and a controlled connection of
50 Mbit/s symmetric bandwidth and 50 ms RTT. Record the actual hardware/browser
and CPU/memory budgets. Test both two local seats and independent devices; the
slower participant determines readiness. Cold loads, a slower device, background
tabs and a 10 Mbit/s connection are separate reported cases. Do not generalize
the result to those cases unless they also pass.

## Existing evidence

| Recorded measurement | Time |
| --- | ---: |
| Initial channel preparation, slower player | 31.96 s |
| Each owner inventory, built concurrently | approximately 15.2 s |
| Initial readiness including shuffle | 42.40 s |
| Initial startup including funding confirmation | 57.19 s |
| Successor preparation, slower player | 30.76 s |
| Recorded hand-to-hand transition | 34.59 s |
| Later cashout campaign's hand-to-hand transition | 31.63 s |

Sources: [initial setup](../benchmarks/browser-channel-setup-2026-09-05.json),
[redeal](../benchmarks/browser-channel-redeal-2026-09-05.json), and
[later campaign](../benchmarks/browser-channel-cashout-2026-09-05.json).
These are historical runs with different recorded Wasm hashes, not a new
baseline for the current checkout. The redeal harness currently stops its timer
at successor `channelReady`; the stronger playable-cards endpoint above still
needs measurement.

Each player prepares two owner variants, each with 56,161 authorization requests
in the recorded full fixture. This needs roughly a 3.2–3.5x improvement in observed
latency. The older single-tree benchmark is not the current channel workload.

Already implemented and included in those results:

- Concurrent construction of the two owner inventories; four crypto workers
  per player, incoming verification priority, and local signing receipts.
- Two-pass inventory construction, output-only Taproot projection, bounded
  script-hash caching, and cached public adaptor encryption points.
- Separate immutable preparation storage and mutable journals.
- A separate successor worker that completes authenticated dealing during play.

The next-hand worker stops at the accepted deal. Final balances must be bound
before score keys, retirement commitments or settlement signatures are created.
The current preparation then finishes each owner's crypto/exchange sequentially.

## Implementation order

### 1. Establish a reproducible, complete baseline

Instrument `channel-worker.js`, `construction-worker.js`, `channel-redeal.js`,
`TableSession.advanceChannel`, and the actual rendering boundary. Extend
`channel-e2e.js` with a preparation-only synthetic-origin scenario that uses the
actual channel workers, relay and encrypted persistence without publishing funds.
The old on-chain setup benchmark is useful diagnostically but does not replace
this two-owner channel benchmark.

Record per owner and player:

- Module/worker startup, dealer attempts, final binding and commitment exchange.
- Snapshot replay, graph/context creation, node output materialization (Pass A),
  ordered transaction/sighash construction (Pass B), inventory transfer/import.
- Ordinary signing and verification; adaptor generation, sender self-check and
  receiver verification; pool idle/queue time and owner scheduling overlap.
- Actual transmitted bytes, POST/GET counts and latency, base64/JSON costs,
  persistence time/bytes, and time until both players have recovery roots.
- Successor monitor registration, retirement acknowledgments, promotion and
  first actionable cards; background preparation completion versus hand end.

Use wall-clock spans and a timeline: parallel phase durations must not be added
as though they were sequential. Capture current per-owner inventory fingerprints
before optimizing; old benchmark fingerprints belong to earlier script revisions.

Deliverable: three baseline runs and a ranked critical path. No new timers or
protocol details need to appear in the normal player UI.

### 2. Cut full inventory construction to a 2.5-second budget

This is the first major gate: the current approximately 15-second construction
floor already exceeds the entire target.

- Replace `signing_projection`'s script-byte-keyed cache with prepared executable
  leaf descriptors/hashes keyed by every script-determining input. It currently
  clones each script, prepends the contest delay, then hashes/compares the large
  bytes merely to look up a cached Tapleaf hash. Cache the guarded executable
  leaves once per applicable context. Keep node commitments, justice leaves,
  Merkle roots and output-key tweaks specific to their exact owner and node.
- Share the immutable accepted-deal/candidate context and eligible base script
  data across both local owner variants. Avoid repeated private transcript replay
  and rebuilding the same base graph during commitment exchange and construction
  where a locally authenticated, precisely bound representation is sufficient.
  Keep each participant's independent derivation and each owner's final inventory.
- Expose bounded ranges of Pass A as independent jobs. Measure 2- and 4-worker
  execution across both variants using one total CPU budget, returning compact
  records in canonical index order. Retain Pass B's deterministic parent-txid
  dependency order. Prioritize whichever pass the profile actually identifies.
- Keep large scripts transient/shared; measure total browser memory as well as
  Wasm linear memory. Do not multiply complete graphs and private checkpoints
  into an unbounded pool.

Deliverable: identical full ordered inventories, output keys, transaction bytes,
sighashes and selected-path witnesses, with both owner inventories available
within the construction budget. This budget is a goal, not a projected speedup.

### 3. Cut crypto, exchange and verification to a 4-second budget

- Refactor mutable globals (`owner`, `pool`, `manifest`, `role`) into explicit
  owner contexts. Use one bounded pool per player, able to schedule both owners
  and prioritize incoming verification. Preserve independent inventory bindings,
  completion barriers, cursor handling, deferred messages and crash replay.
  Simply wrapping the existing `prepareOwner()` calls in `Promise.all` is unsafe.
- Reuse compiled modules and worker instances, and initialize per-hand/per-owner
  contexts once. Start work as soon as its final inventory is available. Only
  claim gains from measured reduction in idle time; both owners still require
  all their cryptographic work.
- Reuse signer/key contexts and serialized public encryption points within their
  correct lifetime. Public point caching and local installation receipts already
  exist; profile the remaining work before expanding caches.
- Benchmark removing the remaining adaptor generator self-verification using a
  distinct generated/outgoing type. Preserve full peer verification and the
  authenticated local generation receipt. A generated package must not enter an
  API that treats unverified peer data as verified. Keep independent construction
  checks in qualification tests, and adopt only after measuring the gain.
- Benchmark the pinned adaptor library's alternative secp256k1 backend in the
  same Wasm build against the current k256 backend if adaptor arithmetic still
  dominates. Require cross-verification, completed-signature and extracted-opening
  parity, deterministic/context-bound nonce tests and browser build qualification.
- Tune batches by measured bytes and CPU cost under the existing size limits.
  Pipeline bounded outgoing publication and incoming verification. If relay or
  serialization time is material, add binary batch transport with durable,
  idempotent acknowledgment and backpressure; do not remove the durable-before-send
  boundary. Count actual per-role bytes before setting network expectations.

Deliverable: both owners' complete authorizations signed, exchanged and checked
within the measured crypto/transport budget. Owner overlap alone does not promise
that reduction. No signature/nonce reuse across transaction contexts and no
reduction of the complete settlement graph is part of this plan.

### 4. Extend next-hand background work within the final-binding boundary

Reuse `startPredeal` / `tickPredeal`; there is already a separate successor worker.
After accepting its deck, keep it alive to prepare validated candidate encodings,
candidate-selector and evaluator fragments, public encryption-point data, and
warm worker/module resources where these depend only on the accepted deal and
static rules. Retain those caches through final configuration and promotion.

Prove the dependencies of each cache explicitly. Final stack-dependent topology,
chain/game/node bindings, score keys, revocation commitments, outputs, txids,
sighashes and signatures remain after final settlement and `bind_predeal`.
Do not pre-sign several guessed outcomes or generate final settlement keys early.
Construction jobs must consume the retained data, rather than discard it by
replaying a complete snapshot in a new worker.

Use a small background CPU budget and prioritize current-hand input, signing and
monitoring. Expand work only after settlement. Cover a first-action fold, so an
unfinished background shuffle cannot be hidden by testing only long hands.
If short hands exceed 10 seconds, the general next-hand target is not met.

Deliverable: the same safe final-term binding and hidden future cards, with
measurably less foreground work and no regression in action responsiveness.

### 5. Finish the transition and qualify the actual UI

Reduce polling gaps or serial small exchanges only where the trace shows idle
time. Preserve the order: complete durable successor roots and monitor package,
local certificate, old-root revocation, verified peer retirement and durable
monitor acknowledgment, then successor adoption and card delivery.

Provisional foreground budget, including overlap:

| Critical-path contribution | Budget |
| --- | ---: |
| Final context/commitment exchange and dispatch | 0.5 s |
| Both inventories | 2.5 s |
| Crypto, transport and verification | 4.0 s |
| Final durable preparation writes | 0.5 s |
| Ready/root exchanges; next-hand monitoring, retirement and dealing | 1.5 s |
| Total target | 9.0 s |

The remaining 1 second is headroom, including residual next-deck work. These are
engineering allocations, not measurements. If a stage misses its budget,
re-profile that stage; a faster progress bar or earlier ready flag does not pass.

Acceptance:

- At least ten isolated trials for initial preparation and ten hand transitions;
  include immediate folds and longer hands, cold/warm caches and asymmetric
  supported stacks. Every trial in the declared qualification environment must
  be strictly below 10,000 ms on the slower player. Report median, p95 and maximum.
- Full inventories for both owners match the current reference, with every
  required authorization installed before activation. Verify exact selected-path
  scripts/control blocks and all existing fold, showdown, timeout and penalty
  behaviors. Keep broader device/network results separate and explicit.
- Corrupted/misbound batches and receipts, interrupted preparation, failed writes,
  reload, sit-out/cashout races and interrupted retirement fail safely and resume
  through the correct durable boundary. Future cards remain hidden.
- Run the relevant native settlement/session/channel tests, browser contracts
  and managed Bitcoin Core scenarios for affected paths. Complete actual two-seat
  browser play across multiple hands with unchanged funding and no redeal
  broadcasts. Record exact build hashes, hardware, network and memory results.
- After implementation, rebuild session/browser Wasm when its Rust changes;
  rebuild embedded assets with `cargo build -p poker-relay --offline`, restart the
  existing local relay with its database/configuration, and verify served assets
  before reporting the optimization live.

## Main code locations

- UI boundaries: `apps/web/src/onchain/table-controller.js` and `table-feedback.js`.
- Orchestration: `apps/web/src/onchain/table-session.js`, `channel-worker.js`,
  `channel-redeal.js`, `construction-worker.js`, and `crypto-pool.js`.
- Materialization: `crates/poker-settlement/src/settlement.rs` and
  `crates/poker-bitcoin/src/taproot/mod.rs`.
- Cryptography: `crates/poker-session/src/crypto.rs`,
  `crates/poker-settlement/src/preparation/batches.rs`, and
  `crates/dealer-bitcoin/src/reveal.rs`.
- Binding/retirement: `crates/poker-session/src/lib.rs`, `channel_hand.rs`,
  and `channel/redeal.rs`.

Implementation sequence: baseline, construction reduction, crypto/transport
reduction, retained background precomputation, complete transition qualification.
The first two optimization tracks can proceed independently after the baseline.
If they cannot meet the budget, report the measured remaining floor and make any
protocol redesign a separate proposal rather than weakening preparation checks.
