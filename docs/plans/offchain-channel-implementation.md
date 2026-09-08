# Channel implementation progress

Implementation started on 2026-09-05 against the refreshed fixed-tree plan.
The playable table now uses the paired cooperative channel driver. Browser
full-hand tests on MutinyNet complete with zero in-game broadcast attempts and
unspent permanent funding; initial channel funding still requires confirmation.

## Implemented

- `poker_bitcoin::channel::ContestOutput`: script-only Taproot output with an
  immediate preimage-plus-counterparty-signature justice path and a delayed
  ordinary continuation. Terminal branches can use the same protection.
- Domain-separated HMAC retirement secrets for hand/branch, hand identifier,
  node, edge, materialization owner and accountable authorizer.
- `poker_session::retirement`: an exact retirement-set barrier. Both owner
  materializations must be represented; secrets must be distinct; the selected
  edge cannot be retired. Frames bind the exact decision and transaction pair.
  Incomplete, conflicting, duplicate-secret and cross-hand inputs fail closed.
  Valid retransmissions are idempotent; closing freezes the barrier.
- An owned settlement graph, cached once per live session after score agreement.
  Changed terms after compilation fail closed. Restoring creates a new cache.
- Indexed node, signature and reveal lookups. No full graph/inventory scan is
  needed to find an active node's authorization.
- Split encrypted recovery storage: immutable authenticated preparation is saved
  before the journal references its SHA-256 digest. Moves export and write only
  the journal. Restore verifies and rejoins the original checkpoint format.
  Old pinned Wasm engines retain their original monolithic export behavior.
- Wasm capability export `session_checkpoint_parts_version`, with operations 50
  (journal) and 51 (artifact). Existing crypto operations 30–34 remain unchanged.

## Verification

- Managed Bitcoin Core: `scripts/bitcoin-core-regtest.sh --docker --suite channel
  --require` passed. Tests execute immediate justice, reject premature ordinary
  spends, wrong preimages and offender-signed justice, preserve the selected
  output, and enforce another contest delay at the terminal output. Both owner
  and authorizer combinations are exercised at the **output-script level**.
- Three retirement-barrier tests passed, including both arrival orders and every
  cut of that two-frame exchange, replay, close, conflicting selections, missing
  owner coverage and reused commitments.
- Complete settlement reference topology/binding regression passed.
- Complete predeal/final-bind/hand/reload regression passed, including exact
  equality between joined checkpoint parts and the previous checkpoint export.
- All 50 on-chain browser-module tests passed, including compiled Wasm ABI and
  artifact storage failures/integrity checks.
- Clippy completed with one existing missing-errors-documentation warning in
  `SettlementConfig::dealing_rules_hash`.
- Rebuilt session Wasm and relay; verified the running server at port 3102 serves
  the matching Wasm and checkpoint worker modules.

## Cooperative move format

Both players prepare the same fixed unsigned transaction for each edge of each
owner materialization. A live `Move` contains the selected edge, the new witness
elements, and the retirement frame. Ordinary betting moves contain just one new
64-byte actor signature per owner variant. Transaction bodies, witness scripts,
control blocks, and previously verified counterpart signatures stay local.

The receiver reconstructs the recovery transaction from its prepared edge and
checks the new signature against that edge's sighash. The known counterpart
signature is compared with its prepared value, not cryptographically verified
again. Reveal moves also authenticate adaptor openings; showdown moves also
authenticate score certificates and card proofs. A valid identity signature alone
would not establish those claims. Retirement preimages must match exactly the
abandoned branches in both owner variants, never the selected prefix.

Both variants are validated before either changes state. The pending in-memory
proof is retained across the monitor acknowledgment, avoiding repeated move
verification at commit. Restore revalidates the journal and recreates that proof;
it never persists a trusted boolean in place of verification.

## Native channel progress

- Full protected owner roots spend one permanent funding output. Only each owner
  completes its own root; passive monitor packages contain root IDs, selected
  paths, and fixed-destination justice transactions, never complete local roots.
- All ordinary branch continuations and terminal payouts retain contest delays
  and immediate justice. Timeouts use contest delay plus action timeout.
- Paired `ChannelHand` stages moves and acknowledgments behind an exact watch
  digest, retains a durable pending choice, and handles exact retransmissions.
- Cooperative state updates have a separate entry point from chain observations;
  no block heights are fabricated. Both variants share poker accounting and the
  full fee reserve remains available across cooperative play.
- Stable identity keys coexist with nonce-separated dealer and score entropy.
- Split channel checkpoint parts retain both owner preparations and verify the
  recovered local root, selected paths, and retirement evidence.
- Wasm operations 60–73 expose paired setup, entry, move, acknowledgment, watch
  packages, checkpoint parts, and closing. Existing session operations keep their
  ABI; setup operations 52–53 exchange public revocation commitments.

## Additional verification

- Managed Bitcoin Core's channel suite passed both full protected owner-hand
  materializations, including withholding the owner's root signature, immediate
  root justice, delayed launch, reveal/adaptor transactions, timeouts, both
  showdowns, and protected terminal outputs.
- Native cooperative complete-hand integration passed with both owners and zero
  chain observations. Normal betting frames assert exactly one 64-byte signature
  per owner. Corrupt new witness material is rejected before advancing.
- The same test passed with checkpoint reloads at entry, all four pending message
  boundaries for the first reveal and betting move, and terminal settlement.
  Restored views and watch digests match exactly. Debug run: 191.98 seconds,
  including setup and repeated full checkpoint verification; this is not a
  browser setup or live-move benchmark.

## Remaining gates

The cooperative browser transport, encrypted durable outbox, and persistent
monitor are connected to the paired native driver. Hand-to-hand root retirement and automatic redealing are now connected and
covered by native recovery tests and a two-hand browser run. Full forced-exit
orchestration remains to be completed and qualified.

The 30-second total startup target and MutinyNet channel forced-exit behavior
remain unqualified. The actual channel table has now completed two consecutive
cooperative hands with unchanged funding and zero in-game broadcasts.


## Browser setup optimization

- Both owner inventories are built concurrently in separate local workers. Each
  worker replays the private snapshot, builds the full deterministic inventory,
  and returns a MAC bound to that snapshot. Installation rejects changed bytes,
  another owner/hand, and duplicate imports; peer inventory claims cannot use it.
- Preparation computes Taproot output keys and signing leaf hashes without
  constructing discarded control blocks. A bounded script-hash cache avoids
  repeated hashing of identical showdown/reveal scripts. The selected runtime
  path still uses the full compiler; equivalence tests cover Huffman ties and
  contest delays.
- Locally generated signatures carry authenticated installation receipts. Peer
  signatures still undergo full verification, queued across the bounded worker
  pool. Public adaptor encryption points are computed once per commitment and
  cached for at most eighteen commitments per worker.
- Immutable preparation blobs and mutable recovery journals are stored
  separately; signature batches do not rewrite the full native journal.
- `/tools/channel-e2e` exercises the actual TableSession and reports preparation
  separately from initial funding confirmation. It rejects any broadcast attempt
  after funding and checks that both players finish at the same terminal node
  with the permanent funding output unspent.

Final browser measurement: 31.96 seconds for preparation, 42.40 seconds including
shuffle, and 57.19 seconds including initial funding confirmation. The full hand
passed with zero in-game broadcast attempts and matching terminal balances. One
transient fetch failure recovered. The earlier baseline startup was 96.83
seconds; network confirmation and dealer retries vary. This is an improvement,
not a qualification of total startup below 30 seconds. See
`../benchmarks/browser-channel-setup-2026-09-05.json` for timings and limitations.


## Automatic cooperative redealing

The next room and deck are created in a separate local worker as soon as the
current hand is active. The next nonce binds the predecessor hand and new room.
The same private player identity is reused locally because permanent channel
funding retains its original keys. Dealer and score entropy remain hand-specific.
Background preparation stops at accepted dealing: no future cards are displayed
and no score keys, settlement inventory, or signatures are generated until final
balances are known.

After terminal agreement, both players automatically consent, bind the next
balances and alternating button, and run the parallel settlement preparation.
There is no artificial result timer, wallet spend, or funding confirmation.
The old result stays visible while this work completes.

Both successor roots and their initial monitoring package must be durably saved
before the successor worker issues its local MAC certificate. The predecessor
worker checks the certificate, unchanged funding/rules/identities, exact settled
balances, flipped button, and fresh nonce before releasing its hand revocation.
Peer revocations are checked against the old root commitment; the exact root
justice transaction is registered before acknowledging retirement. Only then
is the prepared successor promoted into the existing TableSession.

Retired monitoring records drop their old move paths and branch penalties in
favor of one root justice transaction. Their records remain active independently
of relay-room expiry. Native recovery revalidates the handoff certificate and
received secret. A retired root cannot be selected by the local close API.

“Sit out next hand” pauses automatic readiness, and a player below the minimum
prevents another hand. Once readiness commits the transition, the checkbox is
disabled until the next hand. Full forced-exit UI and on-chain penalty execution
are separate qualifications; the redealing test does not claim them.

Two browser runs passed on MutinyNet: automatic handoff took 31.24 and 34.59
seconds, with the latter using 30.76 seconds for successor settlement preparation.
Both kept funding unspent, transferred balances exactly, alternated the button,
and completed the second hand without broadcasts. Sitting out blocked a third
hand. The final successor also restored successfully in the actual table UI.
See `../benchmarks/browser-channel-redeal-2026-09-05.json`.

### Cooperative wallet cashout

A player sitting out after settlement can choose **Leave table & cash out**. The peer automatically accepts a request tied to the same hand and terminal node, and stops redealing. Merely checking the sit-out box does not close the channel.

The private channel workers sign one direct spend of the permanent funding output. Each canonical role receives its verified `nextStacks` balance plus half the unused reserve (an odd remainder goes to Alice), less the shared closing fee. Both destinations must be Taproot wallets. The fee is `ceil(signed_vsize / 10)` base units. No game-tree transaction is published.

Signing freezes the exact destination pair and prevents a successor handoff. The encrypted journal records this freeze before the durable signature outbox is sent. Recovery rechecks the close context and peer signature; retries reuse the same transaction. Once confirmed, both seats are marked left and their wallets refresh. This is a cooperative close: an absent peer still requires the separate force-exit flow.
