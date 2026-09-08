# Continuously prepare future channel hands

Implemented behavior and measured limitations are recorded in [the qualification report](../benchmarks/background-hand-buffer.md).

## Intended behavior

Maintain a rolling buffer of future hands while the current hand is being played. Prepare the complete setup for those hands in the background: dealer 2PC, both owner trees, ordinary preauthorizations, adaptor packages, launch signatures, full peer verification, and durable browser storage. Withhold the funding-root signature that makes a particular tree spendable.

After a hand settles, select the next buffered hand with the exact resulting balances, exchange its remaining funding-root authorizations, complete the existing hand retirement handshake, and start play. Replenish the buffer continuously. The normal transition should do no bulk tree construction or signature verification.

There are two owner roots, so “the first signature” is an activation barrier for each owner variant: neither player gets the counterparty signature needed to spend the permanent channel funding before selection. Live move choices, card-opening shares, and score certificates remain gated by play; precomputation must not disclose future cards.

## Baseline before implementation

- `TableSession.startPredeal()` already starts one successor dealer session. `tickPredeal()` stops once the shuffle is accepted. `continueChannelHand()` waits for terminal settlement before constructing and signing the successor.
- The latest local libsecp256k1 benchmark records roughly 8–10 seconds of next-hand preparation and 8.5–13.7 seconds from terminal state to playable successor. Older 31-second results predate those optimizations. These are historical local measurements, not a new qualification of the changed transient relay.
- The funding outpoint remains fixed, but starting balances are committed by the settlement chain ID, scripts, transaction outputs and descendant transaction IDs. A prepared tree cannot be patched to new balances while keeping its signatures.
- Exact native betting-state traversal found 50 cooperative balance pairs from the current deep-stack full-game rules, using only 288 deduplicated betting states. Once betting is complete, at most three showdown payouts remain. Prepare a bounded portfolio of exact balance variants; do not multiply every future hand by every possible history.
- The existing next-hand nonce depends on the preceding hand's settlement chain ID. That prevents straightforward preparation several hands ahead and must change.
- The relay remains transient and opaque. All buffer contents, protocol transcripts, activation decisions, and recovery records live in browsers.

## Implementation sequence

### 1. Separate a future hand slot from a balance-specific tree

Add an immutable `HandSlot` with a channel ID, monotonic hand index, agreed fresh slot entropy, alternating button, static rules, and dealer context. Derive the channel ID from the initial funding/participant context and an opening nonce. Derive future slot contexts from that channel ID and hand index, independently of the preceding hand's eventual balance variant.

Store the slot context in native terms and checkpoints, not just the UI hand counter. Derive the button from the opening button and hand-index parity.

Players agree a fixed slot order before revealing cards. They consume slots in that order; they cannot choose between future decks after inspecting openings. Authenticate slot negotiation and dealer attempts to the channel, index and static rules. A relay room is a transport capability, not the authority for the hand's position in the channel.

Each slot has one accepted dealer transcript and multiple immutable `HandCandidate` values. A candidate binds the slot, exact balances, funding/value, fee policy, full rules, both owners, and engine version. Different paths leading to identical terms share the same candidate.

Replace the current previous-hand-derived nonce check in native `channel/redeal.rs` with channel/slot continuity checks. The actual preceding terminal state remains mandatory at activation, rather than being required to name a future slot.

### 2. Make preparation and activation separate native states

Introduce explicit lifecycle states: `preparing`, `prepared`, `selected`, `entered`, `active`, `retired` or `discarded`. A candidate can reach `prepared` without an enforceable funding root.

The private worker can generate, exchange and verify all setup material below the funding root, including launch signatures. Split the current `entry_frame()` so those launch signatures can be prepared ahead without releasing funding authorization. Do not call today's automatic entry path from a background candidate.

Add a channel-wide durable activation record containing the active index and selected candidate, protected by a channel-wide lock. Current room-scoped locks alone cannot prevent two stale workers from activating conflicting candidates. Only the next unused index can be selected; never recycle activated indices.

The parent hand issues a local, authenticated selection capability only after verifying its terminal settlement. Bind that capability to channel, parent terminal digest, next slot, candidate ID and complete exact terms. Persist exactly one selection before a child can release its funding-root signature. Enforce the barrier inside Rust/Wasm, for both sending and accepting entry; JavaScript flags are not sufficient.

Keep the current hand enforceable until the selected successor has its complete recovery roots and durable local recovery data. Then perform the existing old-hand revocation exchange. Future hole-card openings and live actions become available only after that handoff completes.

### 3. Reuse accepted dealer work without reusing candidate keys

Extract an immutable accepted-deal handle shared by the slot's candidate sessions and both owner variants. Keep local openings and seeds inside private workers. Do not replay rejected and accepted dealer attempts once per candidate, as ordinary checkpoint restoration currently does.

On browser recovery, validate the slot's saved transcript once, then reconstruct its candidates through authenticated local state. Never treat a peer's “already verified” assertion as verification.

Separate key domains: dealer entropy belongs to the slot; score-key entropy must additionally bind the candidate's exact settlement chain ID. Today `score_public()` derives its Lamport secrets from seed and nonce alone, which would reuse secrets across candidates sharing a slot. Preserve existing exact hand/node/owner retirement domains and transaction-bound adaptor nonces. Do not mutate terms on a prepared candidate.

Cache only proven shared work: accepted-deal data, public candidate-point tables, static rule/topology data where equal, and compiled Wasm. Keep transaction inventories, signatures and commitments bound to their exact candidate.

### 4. Add a continuously replenished, bounded buffer

Replace the single `nextSession` with a `HandBuffer` coordinator. Start with three future slots and a bounded ready-candidate cache; an initial eight candidate-pair limit is a tuning starting point, subject to a measured byte budget. Do not retain eight full worker pools.

Use one shared execution budget for speculative construction/signing. Keep current moves, incoming verification and browser recovery ahead of speculative batches. Start with one candidate being constructed/signed at a time, using its existing parallel owner paths and a small background worker allowance. Reuse workers and evict inactive candidate state to encrypted IndexedDB.

For the nearest slot, enumerate reachable exact balances from the native public betting state. Prioritize immediate fold outcomes and outcomes of finishing with checks/calls; deduplicate them and then expand coverage. Prune unreachable variants after each accepted move. Exclude timeout exits and balances unable to start another hand.

For later slots, keep bounded projected balance variants, merging equal balances reached by different histories. Allocate most work to the nearest slot; use remaining capacity to prepare deeper slots. On promotion, reprioritize existing candidates against the now-known current balances without discarding a future slot's accepted deck.

Keep message batches bound to slot, candidate, owner and inventory digest. Add backpressure so background preparation cannot saturate relay queues or delay active move messages. Preparation does not imply any server persistence.

### 5. Make handover and cancellation deterministic

For a ready candidate, handover consists of:

1. Validate the current terminal and exact candidate; durably select it.
2. Exchange the missing funding-root authorizations and verify those few signatures.
3. Persist the selected successor's enforceable roots and browser recovery data.
4. Exchange/acknowledge the old hand's revocation, activate the selected slot, and reveal its holes.
5. Shift the buffer forward and replenish it.

A cache miss promotes the exact required candidate to foreground priority, reusing its slot's accepted deal and any partial preparation. It must never select a wrong balance merely because that tree is ready.

Sit-out and cashout take priority before selection. Unfunded candidates can be paused or discarded without revocation. Once activation authorization has escaped, freeze conflicting cashout/reselection and recover the same handoff after reload. Never delete the active recovery state when evicting speculative work. Because relay messages are transient, browsers retain the transcripts and outboxes needed to resume their own prepared candidates.

### 6. Qualify behavior, resource costs and the transition target

- Native: prepared candidates cannot release funding-root signatures, accept premature entry, disclose cards, issue scores, or become active; wrong balances/slot/parent, duplicate selection and cross-candidate signatures are rejected. Test key-domain separation and full checkpoint recovery around every activation/revocation cut.
- Buffer: test FIFO slots, bounded memory/workers, deterministic prioritization, pruning, repeated chip balances across different hands, missed candidates, very short hands, low balances, sitting out, cashout, reload and transient-relay reconnects.
- Browser: run multiple consecutive hands with a visibly replenishing diagnostic buffer, using the actual table. Assert zero gameplay/redeal broadcasts; test cooperative cashout and selected/unselected root behavior in Bitcoin Core regtest.
- Measure background throughput, ready coverage, cache hits/misses, memory, storage, bandwidth, live-move latency and complete terminal-to-playable time. Separate warm-buffer and cold/immediate-fold results.
- Target a warm-hit transition p95 below two seconds on the qualified local test profile. Treat this as a target until measured; network and retirement handshake latency remain. Sustained preparation must outpace consumption for the buffer to stay full. Short hands or unprepared balance outcomes can still miss.
- Rebuild browser Wasm and the relay, restart with its existing configuration, and verify served assets before declaring the implementation live.

## Main code boundaries

- `crates/poker-session/src/channel.rs`, `channel/redeal.rs`, `channel_hand.rs`: lifecycle, native selection/entry guard, retirement and recovery.
- `crates/poker-session/src/lib.rs`, `construction.rs`: shared accepted-deal state, candidate creation and score-key domains.
- `crates/poker-settlement/src/config.rs`: stable slot/deal context versus exact balance-bound settlement context.
- `crates/poker-session-wasm/src/lib.rs`: explicit prepare/select/enter commands.
- `apps/web/src/onchain/hand-buffer.js` (new), `table-session.js`, `channel-redeal.js`: rolling buffer, scheduling, promotion and cancellation.
- `apps/web/src/onchain/channel-worker.js`, `crypto-pool.js`, `construction-worker.js`: private candidate work, bounded queues and shared caches.
- `AGENTS.md`: refine the preparation rule to require immutable exact terms for every candidate and verified final balances before activation. No backward-compatibility path is needed.
