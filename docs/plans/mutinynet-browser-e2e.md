# MutinyNet browser end-to-end integration

Status: implemented, with live qualification recorded in
[`../benchmarks/mutinynet-browser-2026-09-05.json`](../benchmarks/mutinynet-browser-2026-09-05.json).
The dedicated runner, player API, funding/return, relay preparation, encrypted
recovery and confirmed game progression are implemented. Retained script changes
from `1ccb951` are qualified separately from the earlier compiled build.
Never copy the supplied disposable private key into fixtures, commands or reports.

Implementation choices: two independently keyed player workers in one operator
tab; four crypto workers per player for the full graph; worker entries colocated
under `apps/web/src/onchain/`; binary inventory transfer and private checkpoint
framing; game-specific Wasm pinning. An additional unfunded setup scenario allows
repeat timing trials without spending test coins. Native Core tests cover all
four terminal scenarios. Public deployment and a two-device table remain outside
this integration runner's scope.

The original implementation plan follows. Acceptance claims are limited to the
measurements and recovery boundaries explicitly recorded in the results.

## Objective and scope

Run two independent browser player sessions through a real, confirmed dlog poker
hand on MutinyNet: funding, authenticated dealing, complete graph preparation,
activation, hole delivery, betting, board reveals, showdown and payout. All game
progression is on chain. Cooperative setup/signature exchange is necessary;
cooperative in-game play is outside this milestone.

Start with a dedicated `/tools/onchain-e2e` browser page backed by reusable
production settlement modules. Avoid requiring a table redesign or wallet product
before the first live test. Keep the practice app available separately. The test
page should show each player, the current confirmed state, legal actions, preparation
progress, transaction links, timeouts and final balances, and offer a scripted run.

## Existing building blocks

- `crates/poker-settlement/tests/settlement_core_regtest.rs` confirms a complete
  26-node hand in Core, including actual reveal extraction, showdown witnesses,
  payout and authenticated preparation reload. Port the sequence, not its public
  fixture keys, mining calls or direct access to both players' secrets.
- `poker-settlement` builds the exact graph and authorization inventory;
  `poker-bitcoin` builds actual scripts, witnesses and transactions.
- Four-worker preparation and authenticated preparation checkpoints are qualified
  locally for the full 56,132-node / 56,161-request reference profile.
- The Esplora browser adapter supports network checks, transaction publication and
  chain observations. The relay already transports opaque bounded messages.
- Existing `poker-funding` handles a P2WSH diagnostic escrow. The dlog graph expects
  the Taproot output from `build_origin_escrow`; these cannot simply be connected
  by changing a configuration flag.

## 1. Add a real per-player settlement API

Create `crates/poker-session` to own the live player, graph, authorizations,
confirmed node and transaction journal. Add a thin `crates/poker-session-wasm`
binary ABI. Keep Bitcoin codecs and signing in Rust.

Expose operations to initialize/resume one player, exchange authenticated setup
messages, export public reveal/score keys, compile and bind the graph, prepare and
verify batches, report legal actions, construct a signed transition, ingest a
confirmed transaction, and export/import encrypted recovery state. Expose public
status and opaque bytes to JavaScript; do not expose an arbitrary signing oracle
or a method that can inject a ready flag.

Each participant owns its identity, dealing entropy, nine authorizer secrets for
the other participant's reveal slots, and its own game-bound score key. Canonical
Alice/Bob ordering must be explicit and independent of transport seat or button.
Persist generated secrets and authenticated setup replay state. Reconstruct the
accepted dealing session from durable secrets plus the exact transcript if that
is simpler than introducing a new secret-state codec.

Port live witness assembly and on-chain opening extraction from the Core test.
Derive counterparty card openings only from confirmed reveal witnesses; do not
reuse the practice app's off-chain opening exchange. Preserve one-time score-key
usage and the exact issued certificate across reloads and retries.

Acceptance: native tests drive two isolated sessions through the Core complete-hand
campaign using only the new API, including refund and timeout paths.

## 2. Fund the correct origin on MutinyNet

Add a small test-funding adapter that consumes selected confirmed UTXOs controlled
by the supplied key and pays `build_origin_escrow(identities)` plus change. Inspect
the faucet generator's address derivation first, then verify candidate funding
outputs against raw transactions; do not assume a private-key encoding determines
the script type. The supplied key funds the campaign only, never either player's
game identity or reveal keys.

Load the key into a dedicated local funding worker through a transient input. Do
not send it to the relay or include it in requests, URLs, logs or tracked files.
Persist player recovery separately under the existing nonextractable local
WebCrypto encryption key. Use a small explicit campaign budget, initially proposed
at 250,000 sats for test escrows and fees; leave other UTXOs/change available. Check
actual costs before construction rather than treating that estimate as verified.

Validate the configured Signet genesis, MutinyNet challenge binding and checkpoint
against the selected backend. Read current UTXOs, tip and fees during execution.
Compute the fee reserve from the full graph's maximum path and transaction classes,
including the large showdown witnesses. Freeze funding inputs, outputs and fees
before binding setup to the origin outpoint: replacement changes the binding and
requires a new setup.

The origin is a two-party escrow without a unilateral preactivation refund leaf.
For this same-operator test, both sessions must sign and durably store an exact
return transaction spending that origin before its funding transaction is published.
Use a stable SegWit funding txid, or wait for confirmation before constructing any
dependent transaction if the actual funding input type cannot guarantee stability.
In the latter case, funding before a refund is available is an explicit limitation
to resolve rather than silently accepting it. Confirm the origin before activation.

This simple pre-signed return is adequate for disposable same-operator test funds;
trustless two-depositor staging/refund economics is separate product work. Do not
introduce a cooperative gameplay branch to solve funding.

Acceptance: a tiny origin-fund/return transaction pair confirms on MutinyNet and
its amounts and fees reconcile. The primary hand then uses a fresh origin.

## 3. Connect two independent browser sessions

Add focused modules under `apps/web/src/onchain/` for the settlement client,
player session, preparation exchange, recovery and test-page controller, with
explicit worker entries under `apps/web/src/workers/`. Extend the relay asset
routes and Wasm build/package manifest for the new bridge.

Use two independently keyed seats with separate worker instances and storage namespaces. Enforce
one writer per player session with Web Locks or a storage lease. For
this E2E, same-origin tabs may share an operator but must never pass private game
keys between player sessions. Change `VerificationPool` to accept an explicit
local role: start with two crypto workers per participant, four across the test.
Each signs only its local role and verifies the opposite role. Receipt keys stay
inside the participant's local worker pool and never travel through the relay.

Each player independently verifies the game parameters, derives the full inventory,
and compares its binding with the peer. Exchange bounded indexed binary batches
through the relay with acknowledgments, deduplication and bounded pending bytes.
Base64 is acceptable at the existing relay envelope boundary; keep binary inside
workers. Reuse compiled Wasm modules within a browser and cached crypto contexts.
Both players must have complete verified inventories and durable local state before
releasing activation signatures.

Introduce an explicit deployment schema/mode for on-chain testing, including game
rules, fee policy and MutinyNet network configuration. Do not just remove the
practice-mode broadcast guard. Keep mainnet rejected and route all publication
through the existing profile-checked Esplora adapter.

Acceptance: two real browser seats complete authenticated dealing and preparation
through the relay, with matching inventory bindings and no shared signing keys.
Record readiness independently for both seats.

## 4. Drive confirmed transactions and survive reload

The state machine is: origin pending → dealing → preparing → ready → activation
pending → confirmed game node → transition pending → next confirmed node → terminal.
The selected transition must be an edge of the locally derived graph, spend the
expected outpoint and match the expected scripts, amounts and transaction ID.
Relay notifications are hints to query the chain, never evidence of confirmation.

Before broadcast, atomically persist the exact signed transaction, current node,
secret/replay state changes, and any issued one-time score certificate. Retry by
rebroadcasting the same bytes. After confirmation, verify the spend/witness, extract
and verify disclosed openings, update the canonical cursor, and enable the next
legal action. Reconcile pending transactions on startup and stop advancement if
the previously confirmed branch becomes uncertain.

Extend the preparation cache with game-state recovery, keyed by game and player:
identity/deal/reveal/score secrets, transcript, peer bindings, observed openings,
score-key usage, pending transaction journal and confirmed block cursor. Use one
atomic game-state record or a transaction spanning the associated stores. Loading
a preparation checkpoint alone must not enable signing. On reload, authenticate
local state and reconcile its pending/confirmed chain position first.

Expose unilateral timeout claims at the actual parent confirmation height plus
CSV delay. Exercise refusal on a separate game: an ordinary hand and its conflicting
timeout cannot both be confirmed from the same output.

Acceptance: refresh during preparation, after broadcast but before confirmation,
and after a reveal/score certificate; the hand continues without duplicate key
usage or a conflicting replacement transaction.

## 5. Run the browser integration campaign

1. Repeat the native Core full-hand suite through the new session API. Keep
   malformed/wrong-context batch rejection and original full inventory parity.
2. Run the dedicated page with two seats and the 26-node short-stack graph on
   MutinyNet, ending in confirmed payout. This checks the plumbing cheaply.
3. Prepare the complete 56,132-node reference graph on both players, then play one
   confirmed hand through its real betting/reveal/showdown branches. Preparing every
   branch does not mean broadcasting mutually exclusive branches.
4. Use fresh small games for fold, opponent-refusal timeout and preactivation refund.
5. Repeat the main test with a player reload at the recovery boundaries above.

Use a browser-visible scripted runner and native browser automation to operate
it. It must stop with a useful phase/error on timeout, preserve recovery state,
and never label an unconfirmed or partially completed hand as a pass. No fixed
sleep should stand in for observing confirmation.

Write a public JSON/Markdown report containing network/profile, browser and Wasm
build identifiers, inventory binding, counts, per-player preparation times,
relay bytes/timing, confirmation waits, transaction IDs/explorer links, fees,
final payout values and recovery/timeout assertions. Exclude secrets and relay
credentials. Store transient artifacts under the ignored target directory and
copy only the public report to `docs/benchmarks/`.

## Completion criteria and boundaries

- A complete confirmed hand on the full reference graph, observed independently by
  both browser sessions, with payout and fee accounting matching the graph.
- All 56,161 authorizations prepared and verified before activation; a successful
  small-graph run alone does not satisfy the full-profile requirement.
- Confirmed fold, refund and unilateral refusal timeout in separate small games.
- Durable reload at the tested boundaries, without score-key reuse or trusting
  stale preparation as current chain state.
- Report setup latency separately from funding/Bitcoin confirmation waits. Target
  <=30 seconds from both peers having the agreed funded context to durable verified
  readiness, including relay transfer. Report cold module startup as well. The
  existing 26–27-second local benchmark does not establish this two-peer target:
  both peers now derive inventories independently, so remeasure before claiming it.
- No cooperative in-game progression, legacy hash proofs, table redesign, general
  wallet feature work, public deployment or sweep of the supplied wallet is needed.

Implement in this order. Funding-format checks and the browser shell can proceed
alongside the session API. Live funding follows native qualification and durable
refund/recovery support; the full browser campaign is the final integration gate.
