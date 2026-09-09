# Heads-up no-limit Hold’em

Status: implementation plan, based on the working tree inspected on 2026-09-08.
No production code changed or performance qualification performed for this plan.

Follow-up: the user's fixed-sequence proposal now has a concrete
[protocol construction and qualification specification](linear-no-limit-protocol.md).
Its next milestone is a small Bitcoin transaction prototype with local fraud
proofs and exact contestable payouts. The exponential lower bound below applies
to the original history-expanded tree, not to this proposed fixed sequence.

## Recommendation

Implement the exact no-limit rules model and prototype the fixed-sequence
construction first. Use the counting tool to validate depth and payout-range
bounds rather than trying to allocate the old history-expanded no-limit tree.
Treat scalable unilateral settlement as the critical design gate before
integrating funded play. A 200BB effective-stack bound makes the game finite,
but does not make the current fully presigned transaction tree small.

Preserve the existing once-per-hand preparation goal from
[the channel plan](offchain-channel.md). Do not silently replace it with rebuilding
the remaining tree after each move, a restricted bet menu, or a requirement that
the opponent cooperate to complete the hand.

## Scope and stack bound

- Heads-up Hold’em with arbitrary legal integer-base-unit wager amounts, standard
  minimum bets/raises, no fixed raise-count cap, and all-ins.
- Start with 200BB buy-ins per player and fixed blinds. With 400BB total poker
  funds and no additions, the effective stack is always at most 200BB, even if
  one individual balance grows above 200BB. Validate actual effective stacks;
  do not clip a winner's balance. Any later top-up policy must preserve or revise
  this bound explicitly.
- Keep fee reserves separate from poker stacks, exact payouts, private dealing,
  automatic consecutive hands, browser-owned recovery, and the opaque relay.
- Adopt the relevant digital betting semantics from the
  [Poker TDA rules](https://www.pokertda.com/view-poker-tda-rules/), particularly
  minimum raises and reopening. Physical-chip and verbal-declaration rules are
  outside this interface's scope.

## Why 200BB is insufficient for full enumeration

Consider only whole-BB wager sizes, equal 200BB stacks, and this narrow family:

1. The button raises preflop to `1 + x₁` BB; the big blind calls.
2. On each of flop, turn, river, the first player bets `x₂`, `x₃`, `x₄` BB
   respectively, and the other calls.
3. Every `xᵢ` is a positive integer and `x₁ + x₂ + x₃ + x₄ ≤ 199`.

Every sequence is legal: the initial raise adds at least 1BB, subsequent streets
open for at least 1BB, and each player invests at most 200BB. Positive later bets
ensure no earlier street exhausts the stack.

The count is `C(199, 4) = 63,391,251` distinct betting histories. This is a lower
bound excluding re-raises, alternative action orders, checks, folds, timeouts,
reveal stages, and sub-BB wager sizes. It counts histories, not distinct balances
or card outcomes. The accepted deal already fixes the cards; enumerating all
possible decks is not the issue here.

For scale, one distinct 64-byte authorization per such history alone is about
4.06 GB decimal, before transaction inventories, additional signatures, recovery
records, or the second owner variant. The existing reference tree has 56,132
nodes; its historical timings are not a current no-limit benchmark.

Memoization can make logical counting and rule evaluation inexpensive relative
to history enumeration. It does not automatically merge Bitcoin authorizations:
different parent transactions produce different spent outpoints. Taproot
signatures commit to spent outpoints, including with ANYONECANPAY; see
[BIP 341](https://bips.dev/341/). Any proposed merging construction must show
actual transaction/signature reuse, not just equal poker-state hashes.

## 1. Implement a pure no-limit rules model

Primary files: `crates/poker-settlement-types/src/rules.rs`, `state/mod.rs`,
`state/` accounting helpers, and `codec.rs`.

- Replace fixed street increments and `max_bets_per_street` with explicit blinds
  and no-limit validation. Separate wager granularity from blind size: the
  default wager quantum is one integer base unit, not one BB.
- Represent aggression as `BetTo(amount)` / `RaiseTo(amount)`, with amount meaning
  the player's total contribution on this street. Keep Fold, Check and Call;
  an all-in is an exact amount, not an ambiguous extra action encoding.
- Replace `bets_used` with the last full raise increment and sufficient
  acted/reopening state. Preserve actor order, street contributions, the big
  blind's option after a limp, and checked arithmetic.
- Return a compact legal-action description: passive actions, call amount,
  full-wager min/max range, and any legal short all-in amount. Validate a selected
  amount directly; never allocate a vector containing every base-unit size just
  to render or validate an action.
- Handle short blinds, short calls, short all-in bets/raises, and uncalled excess.
  In heads-up play, refund unmatched excess and run out the board when no further
  betting is possible; do not introduce a multiplayer side-pot subsystem.
- Define how effective-stack normalization treats a covering player's shove and
  commit one canonical amount representation. UI, rules, signatures and payout
  accounting must agree on matched value and any returned excess.

Tests: table-driven betting examples plus property tests for conservation,
legal-action completeness, min-raise/reopening boundaries, no overflow, correct
actor/street progression, all-in runouts, ties and odd-unit payouts. Include
unequal stacks and balances below either blind. Use a small independent reference
model for differential checks; avoid testing only a duplicate implementation.

Deliverable: exact rules and a simulator, without changing the funded app yet.
The final migration replaces obsolete fixed-limit paths directly.

## 2. Count the real state space without constructing it

Add a counting mode to `tools/settlement-benchmark`, using memoized semantic
states and arbitrary-precision or explicitly saturating counts. Track suffix
counts separately from multiplicities of paths reaching equivalent states.

- Compare 10, 20, 50, 100 and 200BB effective stacks, including unequal balances.
- Parameterize the number of base units per BB. Whole-BB and coarser menus are
  comparison profiles, never evidence that arbitrary-size no-limit fits.
- Report unique semantic states, history/edge counts, maximum legal path length,
  terminal/reveal/timeout multiplicities, and both owner materializations.
- Reproduce the analytic lower bound above. Cross-check exhaustive tiny-stack
  cases against the rules simulator.
- Measure representative real script, transaction, signing and verification
  costs. Clearly label projections versus measured end-to-end results.
- Bound the counter itself by time and memory; emit a proven lower bound on
  exhaustion. Do not attempt to allocate the full 200BB tree.

Deliverable: a feasibility report with counts, memory/signature-volume lower
bounds, recovery and chain-depth costs. Distinguish computational preparation
limits from transaction fee and contest-delay limits on an actual unroll.

## 3. Resolve settlement architecture before funded integration

The current expansion in `crates/poker-settlement/src/betting.rs` recursively
creates every action path. `node.rs` also assumes at most five children and
four-byte action-derived path codes. `poker-session/src/channel.rs` ratchets
through two fixed owner materializations. Merely adding amount-bearing actions
to this architecture is not an adequate implementation strategy.

Evaluate a concrete compact enforcement construction that covers arbitrary legal
amounts without enumerating every future history. Require a small executable
prototype demonstrating actual Bitcoin transactions and unilateral recovery.
Do not assume a Merkle commitment, shared logical DAG, or smaller action encoding
by itself enforces amounts or makes signatures reusable.

If considering cooperative incremental signing, identify the exact change in
guarantees. At every message boundary, demonstrate what happens if either player
withholds signatures or disappears after seeing a wager or new cards. Returning
to an earlier state can create selective aborts; keeping funds safe alone does
not establish correct poker settlement. Rebuilding a full suffix per move also
leaves the initial combinatorial problem unresolved.

Acceptance gates for a candidate construction:

- Both owner exits cover every legal action, reveal, showdown and eligible
  timeout, without needing fresh signatures from an absent opponent.
- Exact wager amount, rules, channel, hand, owner and path/state are bound into
  authorizations. Distinct sizes cannot alias in commitments or revocation keys.
- Interrupted updates have an enforceable recovery state; stale alternatives
  cannot defeat accepted moves or exploit newly disclosed cards.
- Quantify preparation, per-move work, recovery storage, maximum unroll depth,
  contest windows and transaction-sized fee reserve.
- Qualify scripts and adversarial paths against the actual target Bitcoin Core
  configuration. Any dependency on unavailable consensus features is an explicit
  separate research/deployment dependency, not an implementation assumption.

If no construction passes, record full no-limit as blocked on protocol design.
Present restricted sizing as a separately named product option with measured
costs, or seek an explicit change to the once-per-hand/unilateral-play guarantees.
Do not ship a restricted menu under the claim of arbitrary-size no-limit.

## 4. Implement the qualified protocol and migrate its encodings

Only after the architecture gate:

- Update `poker-settlement-types` action/state codecs, `EdgeKind` identity and
  child limits; canonical encodings must include the full amount.
- Update `poker-settlement`, `poker-bitcoin`, session authorization/verification,
  revocation commitments, checkpoints, and both owner variants together.
- Remove assumptions that action kind alone identifies a unique outgoing edge.
  Audit path depth, indices, bounded work batches and serialized size limits.
- Keep funds and fee reserve conserved through folds, calls, all-ins, timeouts,
  showdowns, cashout and recovery. Derive fees from actual transaction sizes at
  0.1 ₿/vB, rounding only final fees up to integer base units.
- Replace obsolete schemas and fixed-limit production paths; no saved-session
  compatibility layer is required for this unpublished software.

## 5. Redesign future-hand preparation for exact all-in boundaries

`SettlementParameters::balance_independent()` currently relies on a fixed-limit
maximum wager that both stacks can exceed. That proof does not extend to
no-limit: all-ins and legal maximum sizes depend on exact effective balances.

Preserve balance-independent dealer work and any internal preparation that the
qualified construction proves reusable. Keep unique hand/path contexts and
future cards hidden. Bind exact settled balances into all payouts, including
folds and timeouts, before releasing funding-root signatures.

Rework `poker-session/src/payout_binding.rs` and browser `hand-buffer.js` around
the new reuse boundary. Do not enumerate every possible next-hand balance, patch
signed amounts, or assume deep stacks share the same topology. Prepare exact
balance-dependent material where required, with bounded workers/storage and
measured transition latency. Qualify the entire sequence across unequal and
short-stack hands, not only the opening 200BB/200BB hand.

## 6. Expose arbitrary legal sizes in the browser

- Export compact legal ranges and exact selected amounts through
  `poker-session-wasm`, the worker ABI and the table session.
- Add integer amount entry and a slider, with optional min/half-pot/pot/all-in
  shortcuts. Shortcuts select a size; they do not constrain the legal action set.
  Define pot-relative calculations after accounting for a call, and disable or
  normalize illegal shortcuts visibly before submission.
- Display the exact total in `Bet ₿…` / `Raise to ₿…`, using `bitcoin-amount.js`.
  Keep all actions equally styled and only show legal actions on the local turn.
- Give immediate submission feedback, block duplicates, clear failures, keep
  stable action-area dimensions and preserve the card/chip layout rules in
  `docs/ui-design.md`.

Rebuild changed Wasm and the client, run `cargo build -p poker-relay --offline`,
restart the local relay with its existing configuration, and verify served assets
before claiming the implementation is live.

## 7. Qualification and release gates

- Native rule/property tests, codec tampering tests, cross-size authorization
  rejection, and deterministic replay through both owner variants.
- Managed Bitcoin Core tests for legal recovery and attempted cheating: short
  all-ins, uncalled excess, every timeout phase, stale branches, interrupted
  signing/revocation, showdown, and fee-reserve exhaustion prevention.
- Browser two-seat tests for arbitrary sizes, reconnect/reload at protocol
  boundaries, automatic timeouts, consecutive hands, sit out and cashout.
- Adversarial disconnect after each outbound protocol message, including before
  and after card disclosure. Verify both money and poker outcomes.
- Report cold preparation, peak memory, transferred/stored bytes, move latency,
  handover latency and recovery costs on representative desktop and mobile
  hardware. Preserve the existing 30-second preparation and 500ms p95 move goals
  at 50ms relay RTT as targets, not predictions; record misses explicitly.

First implementation milestone: exact rules and a small fixed-sequence
settlement prototype, accompanied by depth/payout counts. Qualify its
state-linking, payout and interrupted-update behavior before scaling its
inventory. Remaining integration work depends on that result.
