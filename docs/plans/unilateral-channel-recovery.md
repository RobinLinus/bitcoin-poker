# Unilateral channel recovery

Implement a complete browser-owned path from an unresponsive opponent to a
confirmed wallet payout. No relay cooperation, server recovery storage, or new
game-tree preparation is required. Preserve cooperative play performance.

## 1. Native recovery selection and durable close intent

Build a native recovery planner using the authenticated channel checkpoints,
activation frontier, pending move authorizations, and parent/successor proofs.
Do not select a hand by timestamp, highest hand number, or the current UI route.

- During ordinary play, select the enforceable local root and the latest safe
  authorized continuation, including partially acknowledged moves.
- An unactivated speculative candidate is never a recovery source.
- Once a parent retirement secret may have been released, use the attested,
  enforceable successor. Do not relax `begin_close`'s rejection of a parent
  with a handoff. Handle this across parent and child records, including the
  interval before local offchain play authorization.
- Prefer an already completed signed cooperative cashout when applicable.
  If funding is already spent, follow the observed spend rather than broadcast
  a conflicting root. Classify current roots, revoked roots, cooperative cashout,
  and unknown spends against authenticated saved history.

Expose typed Wasm operations for recovery preview, starting recovery, accepting
chain observations, and obtaining the next eligible transaction.

Persist a channel-wide close intent and selected recovery source before releasing
the root transaction. Serialize against move and retirement release across all
workers/tabs for that channel. Stop automatic redeals and cooperative signing;
recovery must remain accessible when the ordinary table poll is paused.

## 2. Separate onchain replay and settlement

Implement `RecoverySession` alongside `ChannelHand`. Reuse native transaction,
witness, signature, and timeout validation, but keep cooperative virtual progress
separate from confirmed chain state. `Session::observe` already rejects feeding
chain confirmations directly into a session advanced through cooperative play.

Starting with the actual funding spend, reconstruct the confirmed game frontier:

1. Broadcast the chosen root when funding is still unspent.
2. Replay the available signed path in dependency order, observing the actual
   spent outputs and validating the transaction witnesses.
3. Continue the game onchain. Complete required protocol disclosures, but wait
   for the player's choice at every local betting decision. Never automatically
   check, call, bet, raise, or fold. Do not invent future opponent signatures.
   This is the user's explicit recovery policy: an unresponsive opponent will
   typically lose through the applicable timeout rather than a local auto-fold.
4. Automatically claim eligible opponent timeouts. Derive maturity from each
   actual parent confirmation and transaction sequence, including contest delays.
   Recheck pending/confirmed competing spends immediately before publication.
5. If a revoked opponent state appears, prioritize its applicable justice path.
6. Sweep spendable local settlement/justice outputs to the existing wallet.
   Account for fees and distinguish outputs controlled by channel identity keys
   from outputs already paying the wallet. Report completion only after the
   wallet payment is confirmed.

Qualify which existing preauthorizations remain usable in recovery and which
native operations must construct local timeout/disclosure witnesses. A saved
`WatchPackage.paths` list alone is not a complete settlement engine.

## 3. One browser recovery executor

Extend the existing defense worker to drive the native recovery planner and
executor under one browser lock per funded channel. Keep old-hand justice data
available, but avoid multiple monitors independently broadcasting competing
continuations for the same funding output.

Persist transaction intent before publication; reconcile uncertain responses
using the exact txid and outpoints. Resume from IndexedDB after reload, network
failure, or worker termination. Revalidate after reorgs and handle simultaneous
closes and peer activity during recovery. Unknown spends require an explicit
diagnostic rather than a false “Funds returned”.

Batch chain observations and cache only facts whose validity is rechecked when
needed. Keep recovery independent of relay sockets. Run while the app is open;
do not introduce server monitoring. Respect the transactions' actual fee budget
and report fee-related blockage; do not promise arbitrary replacement of
pre-signed transactions.

## 4. Player-facing Close onchain flow

Expose “Close onchain” in table controls once funds are locked, including paused
play, pending moves, handover, and an unresponsive cooperative cashout. Make it
easy to find after prolonged peer silence, but do not automatically force close
because a socket briefly disconnects. Clicking gives immediate visible feedback
and prevents duplicate submissions.

Keep the playable table visible after switching onchain. At the local player's
turn, show the exact legal poker actions and wait for a choice. Submit the chosen
action onchain and show its confirmation progress. When the opponent acts onchain,
validate and follow that spend; when an eligible opponent timeout expires, claim
it automatically. Do not return to cooperative offchain play or redeal afterward.

Use the centered table popup and shared progress indicator for brief phases:
“Closing onchain”, “Waiting for timelock”, “Recovering funds”, “Funds returned”.
Show exact remaining block requirements, transaction links in collapsed details,
and the final wallet amount using the existing Bitcoin-amount formatter. Do not
show “Claim win”; eligible timeouts run automatically. Explain that closing
ends offchain cooperation; the current game continues onchain until settlement.
The app must remain open for browser recovery, and the player must respond to
their own turns within the applicable onchain deadlines.

## 5. Qualification and deployment

First make the planner/executor work from funded entry through confirmed wallet
payout in Bitcoin Core regtest; then wire it to the table. Test crash cuts and
disconnects at entry, every move release/acknowledgement, disclosure, showdown,
each retirement exchange, and cooperative cashout. Cover both owners, short
stacks, local betting choices without automatic actions, opponents who resume
acting onchain, and automatic claims against opponents who remain unresponsive.
Also cover
observed current/revoked roots, competing spends, reorgs, duplicate
delivery, and storage failures. In particular, prove a revoked local parent
root is never selected during handover.

Browser E2E uses independent storage profiles. Fund both players, disconnect one
completely, initiate close from the other, reload the recovering browser midway,
and assert the correct confirmed wallet payout with no peer or relay assistance.
Repeat for disconnects during a move and during handover. Verify normal
cooperative play still performs no onchain moves and does not regress setup or
redeal timings.

Rebuild and qualify Wasm, rebuild/restart the local relay, and verify served
assets. Deploy only reviewed recovery changes according to the EC2 runbook.
The implementation is complete only when end-to-end recovery reaches the wallet;
a root broadcast or a button wired to Wasm operation 72 is not sufficient.
