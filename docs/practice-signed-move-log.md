# Off-chain move ratchet

The browser table advances betting moves with a two-phase, identity-signed
ratchet instead of treating relay messages as authoritative game state.

1. The acting player creates a canonical move containing the game id, hand,
   sequence, previous commitment hash, actor, street, action, and (when the
   chain client is active) the exact fully authorized graph transaction.
2. The actor signs the commitment with the same BIP340 identity bound into the
   accepted DLOG52 deal and sends a proposal.
3. The peer verifies the signature, rejects stale/skipped/cross-session moves,
   runs the poker legality check, countersigns, and durably stores the record.
4. The peer returns the countersignature. The actor verifies and durably stores
   the identical record. Only then do both reducers apply the move.

Replays are idempotent. A different commitment at an occupied sequence is an
equivocation and fails closed. The durable record includes both signatures, so
recovery re-verifies the complete hash chain rather than trusting storage.

`SignedMoveLog.disputePackage()` returns the dual-signed history, signed
activation, and selected transaction path. `escalateDispute()` durably submits
activation first, then descendants in bounded batches, waits for the latest
state to confirm, waits for its exact CSV maturity, and asks the authenticated
chain runtime to construct the timeout. Interrupted recovery resumes from its
last durable checkpoint. It refuses to run unless every move has a contiguous
authorized transaction descending from activation.

For cooperative terminal states, `OriginPackage::cooperative_close` constructs
one exact two-signature transaction that spends the untouched origin directly
to the two participant payout scripts. `broadcastCooperativeClose()` accepts it
only when a chain-runtime validator binds it to the latest ratchet head. Thus a
normal game publishes neither activation nor the intermediate transaction
graph.

The practice UI uses real identity-signed off-chain moves but does not attach a
funded origin or graph transactions. Its escalation method therefore fails
closed and it cannot be mistaken for an enforceable real-money channel.

This construction is a forward descendant ratchet over the existing graph. It
does not claim to be an eltoo channel or a production Lightning implementation.
The chain setup must issue signatures only for the selected edge at runtime;
pre-signing conflicting sibling edges defeats the ratchet's safety. Timeout
edges remain the unilateral escape hatch, and the latest retained descendant
path is published before exercising the appropriate CSV timeout.
