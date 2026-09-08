# Channel plan: current-code audit

Reviewed 2026-09-05 against HEAD `1ccb951` plus the current modified and untracked
working tree. This compares current capabilities with the planning assumptions;
it is not a claim that every working-tree diff occurred during planning.
No application or protocol code was changed by this audit.

The [refreshed design](offchain-channel.md) also incorporates the user's subsequent
clarification: prepare a fresh complete tree once per hand, with bounded updates
inside that fixed tree. The preceding document still prescribed per-move root
replacement; that architecture is no longer the baseline.

## Relevant implemented changes

| Evidence | What is implemented | Consequence for the plan |
| --- | --- | --- |
| [SettlementConfig](../../crates/poker-settlement/src/config.rs): predeal_anchor, session_anchor, dealing_rules_hash | Dealer setup can use a fresh hand anchor before final funding, stacks and reserve are known. The dealer hash normalizes the mutable financial context; final rules_hash/chain_id still bind the real terms. | Reuse the existing split between early dealing and final settlement. Do not propose it as entirely new work. |
| [Session](../../crates/poker-session/src/lib.rs): bind_predeal | Final terms can be installed only with matching anchor, nonce, identities and static dealer context, before score keys, preparation, pending transaction or chain activity. | Keep this one-way readiness boundary; extend it to final channel/hand terms. |
| [Wasm ABI](../../crates/poker-session-wasm/src/lib.rs), operation 29; [player worker](../../apps/web/src/onchain/player-worker.js): configurePredeal/configure | The worker defers score exchange during predealing, binds final terms and then enables normal preparation. | Reuse the existing ABI/worker lifecycle rather than a parallel prefetch subsystem. |
| [TableSession](../../apps/web/src/onchain/table-session.js): startPredeal, prepareNextDeck, tickPredeal, continueHand | A separate fresh worker and relay room complete accepted next-hand 2PC. Warm promotion keeps that accepted transcript; cards stay hidden. | Background work is real authenticated dealing, but not full settlement signing. |
| [TableSession](../../apps/web/src/onchain/table-session.js): setSitOutNext/continueHand; [controller](../../apps/web/src/onchain/table-controller.js) | Automatic readiness after a short result pause, persisted sit-out choice, carried balances and physical-seat dealer rotation. | Preserve the current player flow when settlement moves off-chain. |
| [TableSession](../../apps/web/src/onchain/table-session.js): restoreFundingKey/rememberFundingKey | The test wallet is encrypted locally and scoped to the table's hand lineage. Render data exposes availability, not the key. | Keep this for opening/closing and fee rescue; remove normal channel hand top-ups. |
| [Player worker](../../apps/web/src/onchain/player-worker.js), [storage](../../apps/web/src/storage/preparation-checkpoint-store.js) | Serialized commands, exclusive seat ownership, durable outgoing frames, encrypted state and engine pinning. | Reuse these foundations. Integrity and engine consistency do not establish state freshness. |
| [Preparation](../../crates/poker-settlement/src/preparation.rs), [batches](../../crates/poker-settlement/src/preparation/batches.rs), [crypto worker](../../crates/poker-session/src/crypto.rs) | Complete public inventories, role-constrained signing, parallel verification receipts and authenticated local restoration. | Preserve the once-per-hand artifact pipeline; these optimizations already contribute to the older benchmark. |

Current hand identities are fresh and sorted into canonical roles. A persistent
channel needs stable channel parties/funding keys plus an explicit mapping to
those hand roles. Do not equate a physical seat with canonical Alice/Bob forever.

## Remaining implementation gaps

1. **No channel/move revocation was found in the inspected settlement/session
   modules.** Existing signed dealer messages do not invalidate Bitcoin branches.
   The fixed-tree move-enforcement prototype remains necessary.
2. **Automatic next hands still fund on-chain.** TableSession builds and publishes
   rollover funding, then calls originFact with minConfirmations: 1 before marking
   it funded. The [rollover module](../../crates/poker-session/src/rollover.rs)
   consumes both prior confirmed payouts and a sponsor input. The newest AGENTS
   requirement for continuation without funding confirmation is not yet met by
   this source snapshot. Suppressing the wallet prompt is a separate UX change.
3. **Dealer context separation is incomplete for owner variants.** score_public
   still derives its Lamport context from origin-bound chain_id. One semantic hand
   and one issuance guard across owner materializations still need explicit design.
4. **The runtime still advances from confirmed chain records.** action requires
   activation; observe verifies locally expected templates while relying partly
   on chain validation for ordinary signatures. Add verified cooperative input,
   not fabricated confirmation records.
5. **Current refunds are not revocable channel exits.** A permanently signed
   preactivation return can survive off-chain progress. It must not be reused as
   the fallback for a hand whose cards are already being disclosed.
6. **Future 2PC does not prepare the signed tree.** The worker deliberately stops
   before score creation and SettlementPreparation. Background dealing therefore
   does not eliminate full hand preparation or prove a new readiness time.

## Newly relevant performance work

- Session::graph reconstructs the logical plan, indices and prepared showdown
  material. It is called by view, action and observe. Retain owned immutable hand
  data with cheap borrowed views rather than storing a self-referential graph.
- PreparedAuthorizations::signature and reveal scan the request/artifact arrays.
  Build node/edge and node/slot indices after authenticated preparation.
- Reveal package access lazily verifies all 52 adaptor candidates when first
  decoded after restoration. Prewarm upcoming exact packages and retain verified
  results before an information barrier; do not skip untrusted verification.
- Session::checkpoint appends the complete sealed preparation. player-worker
  persist exports that session when terms exist. Separate the immutable prepared
  artifact from the small journal so each cooperative move does not rewrite it.
- Current AmountState/state-commitment scripts include hypothetical path fees.
  Keep off-chain poker balances and actual fee reserve distinct from an unrolled
  path's costs; never charge unpublished transactions during cooperative play.

These are source-level cost observations, not a new CPU profile. The plan adds
measurements of graph rebuilds, lookup work, first-access crypto and bytes written
per move before claiming a speedup.

## Verification performed for this refresh

The following current tests were run successfully:

```sh
node --test apps/web/src/onchain/table-session.test.mjs \
  apps/web/src/onchain/table-feedback.test.mjs \
  apps/web/src/onchain/display-view.test.mjs
cargo +stable test -p poker-session --test hand \
  predealt_players_bind_final_funding_and_complete --offline
```

- JavaScript: 42 tests passed, no failures or skips. These are contract/unit tests
  with simulated dependencies, not live two-browser MutinyNet qualification.
- Rust: the selected predeal test passed. It completes dealing with provisional
  terms, rejects changes to nonce/anchor/CSV/button, adopts final funding and
  asymmetric stacks, restores and completes the hand. This unoptimized test took
  122.88 seconds; that is not a production preparation benchmark.
- No managed Core, browser E2E, new live funding or new performance campaign was
  run for this planning refresh. No server restart or asset rebuild was needed.

## Documentation and benchmark boundaries

The [consecutive-hand report](../benchmarks/consecutive-hands.md) records an older
manual Next hand flow and non-retained test key. Its historical test counts and
Wasm hash must not be read as qualification of the latest automatic/predeal/wallet
combination. [The on-chain README](../../apps/web/src/onchain/README.md) describes
the newer source behavior more accurately. Parts of docs/status.md and
docs/architecture.md also still describe the earlier lifecycle.

The [26–27 second benchmark](../benchmarks/browser-settlement.md) remains useful
historical single-root evidence, with its stated boundaries. It does not measure
the latest hand transition or proposed revocation scripts. Source improvements,
present tests, and live qualification are kept separate in the updated plan.
