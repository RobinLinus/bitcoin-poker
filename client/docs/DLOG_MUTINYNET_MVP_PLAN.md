# Dlog MutinyNet MVP plan

Revised September 4, 2026. The first playable milestone is the **full dlog poker settlement graph, played entirely on-chain**. Off-chain gameplay and cooperative closing are a later optimization milestone. This supersedes the earlier cooperative-first recommendations.

Implementation is in progress. The native dlog graph, reusable on-chain reveals,
showdown/payout scripts, and verified preparation snapshots now exist and have
managed Bitcoin Core coverage. Browser integration and MutinyNet deployment are
not complete. See [implementation status](DLOG_ONCHAIN_IMPLEMENTATION.md).

**Required outcome**

Two people play a complete heads-up fixed-limit hand using dlog dealing and real MutinyNet coins. Activation, each betting move, each graph reveal step, showdown, and payout are broadcast and confirmed on-chain. The full transaction graph enforces legal actions and outcomes; when a participant stops, the other can execute the prescribed mature timeout without fresh cooperation from the absent opponent.

Dlog proofs and private hole-card delivery still use peer communication. The poker state advances through confirmed graph transactions. There is no off-chain betting ratchet or cooperative-close shortcut in this first milestone.

The MVP can omit production hardening. It cannot omit the mechanism it is intended to demonstrate. An isolated card-gate spend and a mutually signed payout are intermediate tests, not the release outcome.

**Existing implementation and reusable work**

| Area | Actual state | Plan |
| --- | --- | --- |
| Dlog dealing | Authenticated setup, collision retries, public certificate verification, selective openings, and candidate card keys exist. | Keep this protocol; do not return to legacy proofs. |
| Dlog table | The default page supports remote practice play, betting, showdown, and rematches. | Reuse its presentation and interaction work. |
| Dlog Bitcoin bridge | Nine independent regtest card gates exist; they are not the poker settlement graph. | Prove the card-to-settlement integration, then implement it. |
| Existing chain workspace | Contains the finite betting graph, compiler, runtime, poker evaluator, score handoff, authorization machinery, and timeout concepts. Its accepted-deal and reveal interfaces are tied to legacy dealing. | Port/adapt reusable machinery to a dlog-specific profile. Do not rebuild unrelated components. |
| Funded browser | The funded route selects the legacy application, with wallet/origin/Esplora and recovery infrastructure. | Connect reusable funding and chain capabilities to dlog. |
| Dlog recovery | Only the move ratchet is persisted; full deal/session restoration is incomplete. | Persist the secrets, transcript, graph authorization, and selected path needed to resume and settle. |

Evidence: [entry-point selection](../crates/bp52-relay-server/web/bootstrap.js), [dlog table](../crates/bp52-relay-server/web/dlog52-game.js), [card-gate bridge](../../chain/crates/bp52-chain-bitcoin/src/dlog52.rs), [legacy graph descriptor](../../chain/crates/bp52-chain-types/src/descriptor.rs), [recent funded handoff](LIVE_RELEASE_STATE.md).

During planning, the dlog workspace's 13 tests and the move-ratchet's seven tests passed. The published dlog Wasm completed a same-process scripted two-party harness in 1.93 seconds, attempt 0, with a 102,070-byte certificate. This does not measure networked gameplay or graph preparation. The existing card-gate test checks a signature and Taproot commitment separately, but does not execute the assembled witness in Core and unconditionally chooses the raw-sum-zero leaf.

**MVP boundaries**

Use one configured heads-up fixed-limit game. Start from the existing 20,000-sat stacks, 100/200 blinds, and four-bet cap. Recalculate required deposits and reserves from the final dlog graph; the existing 27,000-sat contribution is a starting assumption, not a verified dlog fee budget.

Support one funded hand at a time. Rematch stays in the same room but uses a fresh deal and graph, settling and reusing payout funds through the supported funding flow. Carrying balances inside a single long-lived funded multi-hand channel is deferred. Make the confirmation wait clear and automate the preparation possible during it.

Every ordinary action follows the on-chain path. Show pending transactions immediately, but advance the authoritative game state only after the configured confirmation requirement. Disable actions that depend on an unconfirmed parent. Accept block latency for this foundational milestone and make the waiting experience clear.

**Milestone 1: complete on-chain dlog poker on MutinyNet**

The following six work packages all belong to this first milestone. A card-gate prototype alone does not complete it.

**1. Prove the dlog reveal-to-settlement construction — timebox initial prototype to 2–3 days**

This is the critical design gate. The existing graph's preimage witnesses cannot simply be replaced with ordinary card signatures.

- Execute a correct dlog candidate-gate spend in Bitcoin Core, and reject the wrong candidate, wrong signature, and wrong context.
- Specify how the verified accepted dlog certificate and candidate catalogue bind the graph, identities, rules, network, funding outpoint, and hand.
- Write a phase-by-phase table identifying who knows each opening, who can derive each card key, which later transaction hashes require that key, and what remains available after either player stops.
- Prototype a board card through first reveal, second reveal, and repeated authentication at later showdown. Exercise both orders of revealer refusal. Progress or the prescribed timeout must be possible without requesting new data from an absent peer.
- Establish bounded authentication of all seven showdown cards, tied to their slots and accepted deal, feeding the poker evaluator and score handoff. Avoid an exponential enumeration of all card combinations.
- Execute a complete reveal-to-showdown-to-payout prototype, including score propagation and payout comparison. Measure script and witness sizes, stack/signature limits, relay policy, fees, and signing cost.

An ordinary BIP340 signature does not release a reusable scalar. A child transaction cannot inspect its parent's witness. Any construction must explicitly handle these constraints; adding adaptor signatures or changing disclosure rules would be a protocol change requiring a concrete design and tests.

Done when actual node execution demonstrates the core construction and its refusal cases. If the prototype exposes a missing mechanism, resolve that design before promising graph completion. A missed timebox revises the estimate; it does not remove enforcement from scope.

**2. Implement the complete dlog poker graph**

Reuse the finite game-state topology, compiler/runtime structure, and evaluator wherever they fit the proven construction. Add explicit dlog descriptors and witnesses rather than coercing dlog objects into legacy accepted-deal types.

Required coverage:

- Origin funding, setup-abort refund, and activation.
- Legal betting transitions on every street: check, bet, call, raise, and fold, with the configured cap and effective-stack rules.
- Hole-card delivery and community reveal phases, including refusal by either obligated participant.
- All-in board runout and exact unmatched-chip handling.
- Both players' showdown authentication, ranking, score handoff, and win/loss/split payout branches.
- Timeout branches for each required betting, reveal, and showdown action, with exact beneficiaries and CSV maturity.
- Conservation of stacks, pot, remaining reserve, fees, and final outputs along every transition.

Implement transaction construction, script trees, control blocks, sighashes, witnesses, compiler commitments, streamed graph preparation, and browser signing together. Bind authorizations to the exact allowed transitions and preserve every authorization needed for the promised unilateral exits.

Choose and verify the on-chain signing schedule explicitly. Before activation, persist the counterparty preauthorizations and timeout artifacts required to choose legal moves and recover without an absent opponent. Competing legal branches spend the same state output; its confirmed spend selects the next state. Do not import assumptions from the optional off-chain ratchet into this baseline. A later off-chain optimization will need its own analysis of stale and conflicting authorizations.

Done when deterministic graph checks cover every reachable node/edge class and Core executes representative complete fold, win, loss, split, all-in, and timeout paths with correct outputs. Wrong card, illegal move, altered score, wrong payout, and unavailable authorization must fail.

**3. Connect the funded dlog browser path**

- Route the public application exclusively through dlog. Remove the legacy funded entry point from the MVP UI. Shared utility dependencies can remain; optimizing or deleting the legacy proof workspace is out of scope.
- Adapt wallet, staging deposits, origin/refund construction, and Esplora observation to the dlog descriptor and canonical participant ordering.
- Automate deal acceptance, graph preparation, signature exchange, and readiness. Do not expose playable funded actions before the required recovery artifacts are available and durable.
- When a player chooses an action, have the chain runtime construct and validate the actual authorized child transaction and predicate witness, persist it, and broadcast it. Confirmed chain observations determine when the next action becomes available.
- Broadcast activation and automatic reveal/showdown transitions through the same pipeline. Observe confirmations and execute the appropriate terminal payout or mature timeout. On-chain execution is the default; there is no “Go on-chain” switch in this milestone.
- Restore and reconcile the current confirmed outpoint before sending anything after refresh. Handle lost broadcast responses by looking up and resubmitting the same transaction. Handle unexpected spends and reorganizations explicitly rather than guessing from relay messages.
- Settle fold, win/loss/split, and timeout through their real graph transactions. Do not wire cooperative close or off-chain action commits into this release path.
- Return unused fees/reserve under one explicit tested policy. Recalculate the worst-case full on-chain path budget from actual dlog transactions.

Done when two browsers play a whole funded hand by broadcasting and confirming its graph transitions, and interruption does not require recreating signatures from an offline opponent.

**4. Make multiplayer sessions recoverable — parallel with graph work**

- Replace publicly hardcoded identities with generated, persisted keys. Bind actual network/rules/session data and correctly map host/guest to sorted protocol roles.
- Provide authenticated encrypted delivery of private opening material. Keep participant secrets in the Worker; use conventional cryptography rather than inventing a transport protocol.
- Persist participant state or deterministic reconstruction inputs, setup/retry transcript, accepted certificate, funding context, graph commitments and authorizations, confirmed outpoint/block references, pending transaction bytes, current path, table state, relay cursor, and pending sends.
- Persist exact outbound bytes and message IDs before sending. Retry identical messages after lost responses; never generate a conflicting move while one awaits acknowledgement.
- Restore host and guest seats on refresh and verify/replay saved state before resuming. Duplicate historical messages should be idempotent.
- Test refresh during setup, authorization, betting, reveal, and settlement. Test relay restart, lost peer/broadcast responses, an opponent leaving, and reconciliation of pending or replaced chain observations.

Done when either browser resumes the same hand and has the artifacts required for its supported unilateral recovery. Cosmetic reconnect messages are not sufficient.

**5. Finish the enjoyable play loop — parallel with integration**

- Use the authoritative graph/runtime to drive legal buttons, turn ownership, stacks, pot, and game completion; avoid a second divergent set of browser rules.
- Support short stacks and all-ins without enabled actions that throw. Add clear bust-out and rematch behavior.
- Show the current turn, last action, winning hand name, and highlighted best five cards. Add short card/chip animations.
- Explain shuffle retries, graph preparation, opponent waits, reconnecting, and confirmations with concise progress states.
- Reuse the invite/table, alternate the button for rematches through the next hand's agreed descriptor, and automate reuse of settled funds where supported.
- Cache Wasm in-session and prepare public/static work early. Measure graph generation and authorization independently from dlog dealing; fast proofs alone do not make setup fast.

Measure warm desktop deal latency, graph preparation/authorization time, broadcast response time, confirmations per hand, and time to the next playable hand. Make local button feedback immediate, show the pending action and explorer link, and distinguish opponent waits from block waits. Do not promise one-second completed moves when every move confirms on-chain. Set a concrete graph-setup release budget after work package 1 establishes cost. Do not optimize the legacy proof path.

Done when two testers can play several consecutive funded hands, including fold and showdown, without manual resets or hidden state divergence.

**6. Qualify on MutinyNet and deploy**

- Add an explicit MutinyNet dlog profile alongside regtest, using the existing exact custom-Signet challenge/checkpoint validation. Verify actual script and transaction acceptance; do not loosen a regtest guard into arbitrary Signet permission.
- Run full dlog graph paths on a local node before spending public test coins. Use deterministic fixtures for rare split/all-in/timeout cases.
- Add dedicated dlog workspace, graph-integration, browser-session, and real Wasm checks to CI. Existing legacy UI tests are not dlog coverage.
- Package the relay with matching embedded web/Wasm assets. Use one HTTPS server with persistent SQLite, restart policy, basic health reporting, and proxy rate limits.
- Verify public-origin invites, Worker loading, CSP, content types, and cache behavior. Keep capabilities/private material out of logs; retain the prior binary and database for rollback.
- Perform a real two-device funded run from different networks against the public URL, with refresh/reconnect and rematch.
- Demonstrate a hand with every played graph transition confirmed, followed by graph-based showdown/payout. Separately demonstrate fold settlement, an absent-player timeout, and setup refund. No cooperative closing transaction may substitute for a graph branch in these runs.
- Record release commit, Wasm hashes, observed timings, and public transaction IDs.

The official [MutinyNet faucet](https://faucet.mutinynet.com/) publishes the configured custom-Signet challenge and 30-second target block time. Its linked [faucet CLI](https://github.com/benthecarman/mutinynet-cli) requires GitHub login. These were checked during the initial planning pass; live Esplora health/checkpoint responses remain deployment preflight checks. Pre-fund facilitator wallets so faucet authentication does not interrupt demonstrations.

**Milestone 1 acceptance and sequencing**

The critical path is: prove the dlog card/reveal/settlement construction → implement the full graph and on-chain authorization policy → integrate the confirmation-driven browser → play complete on-chain hands on MutinyNet, including settlement and timeout paths.

Session recovery and UI polish can proceed alongside the protocol/graph work. Preserve existing uncommitted fixes in shared compiler/runtime/browser components; assess them for reuse rather than discarding them or completing the legacy release as a prerequisite.

Release requires a real funded dlog hand whose played graph transitions confirm on-chain, usable unilateral exits, correct payouts, durable recovery, and a credible repeat-play experience. A standalone gate demonstration, scripted local showdown, or cooperative cashout does not pass.

**Milestone 2: optimize the proven backbone with cooperative play**

Start only after milestone 1 passes. Keep its on-chain execution path as the reference implementation and regression suite.

- Retain fully authorized graph transactions and their required witnesses while exchanging moves off-chain. An identity signature over a move hash is not Bitcoin spending authority.
- Design the off-chain authorization/update policy explicitly, including stale/conflicting states and availability of each unilateral exit. Do not assume the baseline's legal-branch preauthorizations automatically provide safe off-chain updates.
- Add durable action acknowledgements and publication of the retained graph path when cooperation ends. Verify recovery with the peer offline.
- Add cooperative terminal closing only after both clients validate its exact payouts against the enforceable game outcome. Reuse the existing closing builder where it fits.
- Measure the reduction in block waits, fees, and setup/play latency. Preserve the ability to run the complete hand on-chain.

Off-chain gameplay, the off-chain ratchet, and cooperative close are excluded from milestone 1 implementation and acceptance. They are optimizations of the completed settlement system.

Defer external audit, extensive fuzz campaigns, independent cryptographic implementations, production fee bumping, watchtowers, mainnet, multi-hand channel enforcement, matchmaking, tournaments, native-client parity, and legacy performance work.

The earlier 8–14 day estimate applied to the rejected cooperative-only scope and is withdrawn. Expect a multi-week on-chain integration, with substantial uncertainty concentrated in the dlog-to-settlement construction and graph preparation cost. Re-estimate milestone 1 after its initial 2–3 day prototype; estimate the cooperative optimization milestone separately.
