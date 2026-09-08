# Poker channel: one prepared tree per hand

Status: refreshed against the current working tree on 2026-09-05, including
uncommitted code. This incorporates the user's latest clarification: a fresh
tree per hand is acceptable; regenerating the remaining tree after every move
is not the target. See the [code audit](offchain-channel-code-audit.md) for source
locations, verification results and limitations.

## Decision and scope

- Keep one channel funding output across hands.
- Deal, construct and presign the complete fallback once per hand. One logical
  tree may need two owner-specific Bitcoin materializations for unilateral exit.
- Keep those transaction templates, outpoints and preparation artifacts fixed
  during that hand. A move exchanges bounded signing/revocation material and a
  small durable state update.
- Use hand-level revocation to retire the previous hand and move-level revocation
  to retire conflicting alternatives within the active tree.
- Preserve the selected prefix for an honest on-chain unroll.
- All cooperative play, settlement accounting and next hands remain off-chain.
  Failed cooperation freezes the channel, unrolls an enforceable path and closes.
- Target total hand readiness within 30 seconds and accepted moves below 500 ms
  p95 at 50 ms relay RTT, with immediate click feedback. Measure both targets.

The previous per-move root/checkpoint replacement design is no longer the
baseline. Its changing outpoints would require new descendant signatures.
Neither a second revocation namespace nor a stable ancestor removes that cost.

The fixed-tree move ratchet is not implemented by the new code. Its script and
interrupted-message qualification remains the first protocol milestone.

## 1. Reuse the new code instead of rebuilding its foundations

| Current capability | Plan change |
| --- | --- |
| Separate background next-hand worker completes authenticated 2PC | Reuse startPredeal / prepareNextDeck / tickPredeal. Do not add a second prefetch subsystem. |
| predeal_anchor and dealing_rules_hash separate dealing from final financial terms | Extend this existing boundary to channel/hand identity. The old claim that all dealer setup requires the final origin is obsolete. |
| bind_predeal rejects late or incompatible rebinding | Keep final-term adoption before score keys, preparation, pending actions or chain activity. |
| Worker defers score exchange while predealing, then promotes the warm session | Preserve the accepted transcript and hidden cards through promotion. |
| Automatic next hands, Sit out next hand and physical-seat dealer rotation | Preserve these behaviors when rollover becomes an off-chain balance update. |
| Encrypted lineage-scoped test wallet and pinned Wasm recovery | Reuse local key ownership and engine pinning. The wallet remains useful for opening/closing, not per-hand top-ups. |
| Parallel preparation, authenticated worker receipts and sealed inventory | Keep these as the once-per-hand preparation pipeline. They already underlie the historical benchmark. |
| Pending transaction restoration and one-time score guard | Extend these into cooperative pending moves; do not invent another score-issuance mechanism. |

Automatic continuation currently still constructs payout-rollover funding,
broadcasts it and waits for one confirmation. Hiding the wallet prompt does not
make it a channel. The latest AGENTS requirement for continuation without funding
confirmation remains a gap in this source snapshot.

Background work currently prepares the deal only, not the full signed settlement
tree. It improves inter-hand dealing latency; no new end-to-end timing has yet
qualified the automatic/background/wallet combination.

## 2. Two revocation levels, one fixed hand tree

### Hand-level state

Maintain owner-specific hand commitments against the same channel funding output.
Each owner retains its missing funding signature; the peer must not receive a
complete copy that it could publish after revocation to frame the owner.

Before entering a hand, both players obtain complete response coverage under
either owner variant, persist recovery and establish monitoring. An owner may
publish its root and disappear at the other player's turn; that other player
must still have every required legal action, reveal and timeout authorization.

Install an enforceable replacement balance/next-hand state before releasing the
old hand's revocation secrets. Never reuse a permanently valid refund or a
cooperative closing transaction as an ordinary state receipt. A mutual close is
signed only after both state machines freeze in Closing.

A revocable root with a constrained CSV-delayed launch remains a candidate for
hand retirement. It protects an old hand at its entry. It does not, by itself,
punish stale decisions made inside an otherwise current hand.

This follows Lightning's replacement-before-revocation principle, with custom
game enforcement still to qualify:
[BOLT 2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#completing-the-transition-to-the-updated-state-revoke_and_ack).

### Move-level state

The semantic graph is a tree. At a node, committing a selected move must:

1. Make its exact recovery transaction usable under each hand variant.
2. Retire the actor's unchosen authorized alternatives.
3. Retire the other player's obsolete timeout, or retain a protected pending
   defense until that retirement completes.
4. Persist the transition, outgoing frames, revocations and monitoring receipts
   before the next dependent choice or information release.

Retirement must target abandoned edges, not the whole earlier node: the selected
prefix still has to be publishable during unroll. A move retirement can be a
small bundle of secrets for its unused branches, rather than a single key that
also invalidates the chosen path.

Bind every branch secret to hand, logical node, outgoing edge, authorizer and
materialization policy. The normal actor or timeout beneficiary is the offender
for that edge; it need not be the hand-root publisher. Keep hand retirement and
branch retirement as separate domains. Do not release a derivation seed that
also opens justice paths on the current selected prefix.

Each justice condition needs the counterparty's signature as well as the accused
player's disclosed secret. A bare key already known to the accused player would
let that player bypass the game.

### Enforcement choice to qualify first

Current ordinary transitions have no revocation window, and current terminal
outputs are immediately spendable. Exchanging secrets without changing these
scripts does not enforce retirement.

Start with a tiny, explicit fixed-tree construction. The conservative reference
is an immediate penalty at an abandoned edge's output, with a contest delay
before any ordinary spend can escape that output. Terminal value must also remain
protected for the window. Timeouts must leave the intended action opportunity;
their existing CSV values cannot simply be copied.

This keeps preparation fixed and monitoring local to known retired outputs, but
can add a contest wait at every unpublished edge during honest unroll. Report
that exit cost; do not retain the previous design's promise of one total contest
window.

An alternative carries revocation through descendants and delays only final
release. It can shorten unroll but adds script/value-coverage and monitoring
complexity. Select it only after a small prototype establishes the invariants
and measured exit/fee requirements justify it. It is not an assumed optimization
already provided by the current code.

Both constructions must prove:

- selected-prefix publication cannot punish an honest player;
- an abandoned branch cannot race forward or split value to escape justice;
- the correct edge authorizer bears the penalty;
- either player can finish under either published root;
- no key path, refund, fee/anchor output or terminal exit defeats protection.

## 3. Keep one accepted deal and one score context per hand

The new predeal implementation already provides most of the setup lifecycle:

1. Start a fresh background dealer worker and relay context while the current
   hand is active. Keep future cards hidden.
2. Complete authenticated dealing against its fresh anchor/nonce and static terms.
3. After settlement, map final balances and dealer to the fresh hand's roles.
4. Adopt final hand/channel terms before generating score keys or signatures.
5. Prepare both required fixed hand materializations, persist recovery, complete
   the entry/revocation barrier and promote the worker into play.

The existing dealing_rules_hash deliberately normalizes origin, final stacks,
reserve and fee-policy identity while keeping static context consistent. Reuse
its validation, rather than casually weakening the hash or changing its sentinel
values to accommodate the channel.

More work remains: chain_id and score_public still bind the final origin.
Introduce a semantic hand identity distinct from exact owner/materialization
identities. One accepted deal and one score key per canonical role must cover the
mutually exclusive hand variants, with one durable issuance guard. Reuse an
already issued certificate; never issue another score under the same one-time key.

Channel parties and funding keys persist across hands. Hand identities can remain
fresh, as today, but canonical Alice/Bob ordering may change. Keep an explicit
mapping to physical seats when carrying balances and rotating the dealer.

## 4. Make each move independent of full-tree size

The audit found concrete runtime work to remove from the cooperative path:

| Current operation | Required change |
| --- | --- |
| Session::graph recompiles plan, indices and showdown material during views/actions/observations | Retain owned immutable hand data and cheap borrowed graph views. Avoid a self-referential Session; separate owned cache from the borrowed dealer reference. |
| PreparedAuthorizations::signature scans all requests | Build a node/edge index once after authenticated preparation. |
| PreparedAuthorizations::reveal scans requests and lazily verifies 52 adaptors on first access | Index node/slot packages; prewarm the next required verified packages before the disclosure barrier. Reuse verified cache entries. |
| Session::checkpoint appends the full sealed inventory; player-worker persist exports the session | Store the immutable prepared artifact once and append only small move/revocation/score-use changes. |
| TableSession/view rebuilds derived display state through the graph | Read the current node and public display from cached validated state. |

Avoid replacing one CPU problem with unbounded retained scripts: retain topology,
indices and reusable candidate data, with bounded caches for materialized nodes
and active-path witnesses. Reuse the existing four-worker preparation pipeline,
binary inventories and authenticated local receipts.

Within a hand, signatures remain valid because the exact tree stays fixed.
No speculative successor-root forest or background re-signing of remaining
subtrees belongs in the normal move path.

A cooperative entry point must validate live signatures, amounts, allowed edges,
openings and score evidence itself. Today's observe() relies partly on the
confirmed-chain boundary for ordinary signature validity. Do not call it with
fabricated heights. Share semantic validation while retaining separate verified
cooperative and confirmed-chain entry points.

Do not debit fallback fees while advancing the off-chain ledger. Current graph
AmountState and Taproot state commitments include decreasing hypothetical fee
reserve. Keep actual channel reserve/poker accounting separate from path-specific
on-chain execution costs, while binding exact transaction values in preparation.
At hand end, only real broadcast fees reduce the channel reserve.

## 5. Crash-safe moves and protected disclosure

Use one pending cooperative decision, one selected successor and exact outbound
frame replay. Persist before signatures or secrets leave the worker. Once a
complete selected authorization is exposed, a missing acknowledgment does not
permit a conflicting retry.

Maintain a durable selected prefix, retired alternatives, timeout retirement
status, score-use record and service receipts. A monotonic move counter identifies
the log; it does not by itself invalidate Bitcoin transactions.

For card delivery:

- complete the required retirement of earlier choices before exposing information;
- keep the actual reveal obligation enforceable until the recipient verifies it;
- before disclosure, durably install the exact pending reveal defense under all
  relevant hand variants with the persistent service;
- if the recipient learns the card and withholds timeout retirement, publish the
  valid pending move before that old timeout can win.

This has an explicit availability/fee assumption: the participant or service must
confirm the defense within the applicable game timeout. A fresh chain view is
required at information barriers. Once on-chain closing has started, freeze
cooperative updates and handle the actual published path.

Batch deterministic proof/reveal messages only where no intervening poker choice
can be rewound. Acknowledgments and adaptor candidates do not each need a new
logical game tree.

Preserve encrypted local storage, engine pinning, exclusive seat locks and the
existing durable outbox. Their integrity guarantees are useful, but encrypted
snapshots are not proof of freshness. A restored state of uncertain freshness
must not blindly publish an old root.

Keep active on-chain hands pinned to their existing engine and protocol. Create
new channels with an explicit new script/storage version; do not reinterpret an
already funded tree or its saved signatures as a revocable channel.

## 6. Reuse the table, replace its settlement driver

The actual integration point is TableSession and table-controller.js.
controller.js remains the separate on-chain qualification campaign.

- Route legal actions through the cooperative reducer and existing worker
  ownership model; render pending feedback immediately and accepted state after
  durable validation.
- Keep automatic next hands, the result pause, Sit out next hand, equal legal
  action emphasis and stable action-area layout.
- Sitting out blocks the next hand's entry barrier; it does not forfeit the
  active hand or silently close the channel.
- Retain the foreground worker plus one background dealer worker. Promote the
  warm worker only after final balances and the channel entry barrier are durable.
- Replace the successor's payout-spend/rollover/top-up path with installation of
  the next hand against the same channel funding output.
- Keep the encrypted lineage wallet for opening, closing and exceptional fee
  rescue. Healthy hand transitions need neither wallet prompts nor funding
  broadcasts or confirmations.
- Move current automatic on-chain reveals, showdown and timeout submissions into
  the Closing runner. Healthy cooperative play must not reach publish().
- Preserve independent confirmed-chain observation for closing and reorg handling;
  do not make routine polling blink or disable action buttons.

Follow current AGENTS.md for UI behavior and embedded-asset rebuilds when code is
implemented. This refresh changes planning documents, not the running server.

## 7. Monitoring and fees depend on the chosen move scripts

Use the existing relay/process infrastructure with narrowly scoped capabilities:
root/branch justice, pending-delivery defense and explicit close execution.

Prefer fixed-destination signed justice packages for known punishable outputs.
The conservative per-edge construction may install a bounded package per newly
retired alternative, under each owner variant. Inherited descendant revocation
would require broader coverage; do not assume its watchtower cost is constant.

Keep participant recovery independent of the service. A passive watcher receives
no complete owner root, wallet key, deck seed or general signing authority.
An explicit Closing transition may provide a chosen complete root and exact
allowed actions/timeouts so the runner can finish after the tab closes.

Budget and qualify fees, anchors, package ancestry, pinning, reorgs and actual
reveal/showdown sizes. Hand-entry, move-contest and game-action timeouts are
different parameters. If conservative move protection creates repeated waits,
show that honestly in the exit estimate.

After funding is spent, unroll the actually published root and path. Apply
penalties only to enforceably retired alternatives; an ordinary unavailable
player still receives the existing pot-only timeout economics. Never resume the
channel after unilateral publication begins.

## 8. Performance evidence and acceptance

The historical single-root reference is 56,132 nodes, 54,855 ordinary signatures
and 1,306 reveal packages. Four-worker local preparation took 26.39–27.26 seconds,
including persistence but excluding relay latency.
See [the benchmark](../benchmarks/browser-settlement.md).

Those figures predate the latest predeal/table changes and do not qualify either
the new channel scripts or a two-owner fixed-hand preparation. Existing caching
and parallelism are already counted; do not claim them again as new speedups.

Measure:

- cold hand readiness and background-predealt hand readiness separately;
- the complete required owner variants, verification, transfer, persistence and
  monitor registration within the 30-second target;
- repeated views/actions at early and late nodes, with cold/warm package caches;
- accepted move p95 below 500 ms at 50 ms relay RTT, with immediate pending feedback;
- signing count, graph-compilation count, inventory lookup work and bytes written
  per move: none may grow with the unvisited tree;
- reload freshness, interrupted moves, pending disclosure, rapid clicks and
  service outages; no assumption of human think time;
- zero broadcast calls during normal multi-hand cooperation.

The earlier all-checkpoint forest estimate of 2,682,258 node instances belongs
only to the abandoned per-move re-root alternative. It is not work required by
this fixed-hand-tree plan.

## 9. Implementation milestones

See [implementation progress](offchain-channel-implementation.md) for landed
components, verification and remaining gates. The table remains on-chain.

| Milestone | Deliverable | Acceptance gate |
| --- | --- | --- |
| 1. Qualify the fixed-tree ratchet | Tiny hand with two owner roots, a choice, reveal, timeout and terminal; exact retirement messages and chosen contest scripts | Selected prefix is safe, stale alternatives cannot escape, both players can recover, all message cuts/disclosure failures have defined handling. Quantify exit waits. |
| 2. Establish the owned hand runtime | Cache shared hand data; index prepared authorizations; separate immutable artifact from journal; preserve current predeal/final-bind flow | No full graph rebuild, inventory scan or full snapshot write per move. Existing dealing, recovery and on-chain fixtures remain valid. |
| 3. Prepare the full hand once | Add qualified hand/branch protection to complete owner materializations; reuse current worker pipeline | Complete coverage before hand entry; measure full setup, bytes, memory, fee reserve and monitor work against target. No re-rooting during moves. |
| 4. Wire cooperative play | Verified cooperative reducer, durable move/retirement exchange and pending-delivery defense in the actual table | Full two-browser hand with zero broadcasts; crashes/reconnects cannot change a chosen move or reveal prematurely. |
| 5. Carry hands inside the channel | Promote predealt workers using final channel balances; retire prior hand roots; preserve automatic redeal/sit-out | Funding remains unspent across hands; fresh private deals, correct seat/role mapping, no rollover/top-up fees. |
| 6. Qualify forced exit on MutinyNet | Narrow persistent monitoring, exact unroll runner, fee rescue and browser recovery | Offline exit, stale branch/hand, pending reveal, reorg/service restart and confirmed payouts; report normal-flow and exit latency separately. |

Do not substitute per-move tree regeneration if the fixed-tree protocol gate is
difficult. It is a different architecture with a different performance contract.
If the prototype fails, identify the counterexample and revise the move
enforcement before implementing the rest.

## 10. Work that remains after the code refresh

Recent changes have implemented background dealing, controlled late binding,
warm-worker promotion, automatic hands and wallet continuity. They have not
implemented hand or move revocation, verified cooperative state acceptance,
fixed-tree penalty scripts, a channel journal or a persistent channel monitor.

The first protocol gate remains real. In particular, a single hand-entry contest
window cannot protect all later in-hand decisions, and a revealed hand seed must
not accidentally revoke the currently selected prefix. Exact transaction binding
also remains unchanged:
[BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message).

Keep the current on-chain integration as the regression oracle. The new channel
is a separate qualified use of that backbone, with the latest implemented
preparation and table infrastructure reused directly.
