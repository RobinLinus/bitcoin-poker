# Browser on-chain integration test

Run the on-chain player build and a local relay:

```sh
scripts/build-session-wasm.sh
cargo run -p poker-relay -- 127.0.0.1:3102 deployments/mutinynet/onchain-test.json
```

Open `http://127.0.0.1:3102/tools/onchain-e2e`. Enter a disposable MutinyNet faucet
key, select a graph/scenario and run. The source wallet format is the faucet
generator's raw x-only Taproot output key, not a BIP86 internal key. The funding
worker validates the selected transaction/output, preserves change, and bounds
the escrow and fee. It never sends or persists the sponsor key.

This page is a same-operator integration runner with two independently keyed
player workers. Both players derive the graph and use authenticated relay
mailboxes. Each separately observes confirmed chain spends. It is not yet a
normal table or a general wallet. The `/` page now hosts the playable table described below.

`poker-session` owns the local dealer, preparation, live witnesses, observed dlogs,
score-key usage and pending transaction. `poker-session-wasm` exposes the bounded
ABI. Four crypto workers per player are used for full preparation; two per player
for short-stack tests. Verification gets priority. Existing generator and receiver
checks are retained, including verification of locally generated batches.

Player seeds, transcripts, exact outgoing frames, preparation and pending game
transactions are AES-GCM encrypted in IndexedDB. A local lock enforces one writer
per game/seat. The session checkpoint uses binary preparation framing to avoid
large JSON byte arrays. It is private and must never be exported as a public
snapshot. A fresh Wasm instance restores it and checks confirmed block identities
before continuing. Deep reorgs stop the test for reconciliation rather than
silently replaying one-time score keys on a new branch.

The exact preactivation return transaction is saved before funding publication.
Use **Return unactivated escrow** if setup cannot finish. Once activation may have
been published, use **Resume saved test** and follow the game or its timeout.
Same-operator pre-signed return is deliberately not a trustless two-depositor
funding protocol. Every actual game transition uses the on-chain graph.

Pause stops at the next durable boundary. Resume works without re-entering the
sponsor key. The URL's game ID identifies an archived encrypted campaign; `latest`
is a fallback. Independent campaigns can run in separate tabs, but avoid selecting
the same funding output concurrently. The public report has no credentials or
private checkpoints. It records transaction IDs, block heights, outputs, fees,
per-player preparation timings and the preparation-reload check. Bitcoin
confirmation waits are separate from preparation time.

Native qualification:

```sh
cargo test -p poker-session
scripts/bitcoin-core-regtest.sh --docker --suite session --require
node scripts/test-browser.mjs
```

The Core suite covers complete hands, fold, refund and unilateral timeout using
the same runtime, including pending-transaction restoration. The live browser
runner exercises chain indexing races with bounded retries for known temporary
inconsistencies; invalid chain identities, transaction bytes or witnesses stop.

Select **Setup benchmark · no funding** to measure full preparation repeatedly
without a key or any broadcast. It uses fresh player keys, an unfunded origin and
the same relay/inventory/verification/persistence path. Reports separate player
startup, inventory construction and crypto initialization from total setup.
The funded scenarios independently demonstrate the resulting on-chain behavior.

Games pin verified Wasm bytes by SHA-256. Resuming after a script upgrade restores
the original engine, and a missing or corrupted pinned engine stops recovery.
Both page resume and worker reload check saved block identities before signing.
The 1×/2×/3× fee controls freeze a test schedule into the graph; the estimate-based
option refuses values above the runner's bound. Fees cannot be changed after setup.

Use **List saved tests** to select an archived campaign after closing its tab.
Only public summaries are displayed; its credentials and private recovery state
remain encrypted locally. See `docs/benchmarks/mutinynet-browser.md` for the
completed live qualification and measurement boundaries.

## Playable table

With the same on-chain configuration, `/` now serves the playable table. Create a
table and share its invite with the guest. Each browser owns only its local player
worker and four local-role crypto workers. Each player funds their own ₿20,000 buy-in and share of the required fee reserve
from a generated wallet key stored in localStorage, with no backup. Wallet change
stays outside the game. Both wallet signatures commit to the exact inputs and outputs. Both seats save the
exact origin return before funding is published.

Fold, Check, Call, Bet and Raise choose actual graph edges. Required card delivery,
board reveals and showdown publish automatically on the local turn; betting is
manual. Cards, stacks and pot follow confirmed transactions. Community cards are
withheld until both required reveals confirm. The local seat receives only its
own private hole cards. Opponent cards appear only after verifying their confirmed
showdown candidate signatures and hand claim. Timeout claims use the confirmed
parent height plus 12 blocks.

The `/table/<game>/<seat>` fragment contains no relay credential. Reload restores
that seat's encrypted controller state and pinned player engine, reconciles its
confirmed journal, and retries the exact pending transaction. Keep the tab URL to
resume. The host may return funding before activation signatures are released;
after settlement, **New table** starts a fresh-key game with a new invitation.
The wallet panel shows a receiving address and balance; there is no funding popup.

### Consecutive hands

After settlement, the next hand starts automatically after a short result pause.
The left-side **Sit out next hand** checkbox returns both players’ settled funds to their wallets and ends the table. The table
carries forward poker balances, rotates the button, and uses fresh identities,
reveal keys, score keys and a fresh shuffle for every hand.

As soon as a hand is active, a separate player worker runs the next hand's 2PC
in a fresh relay room. Its unique anchor and nonce bind the deck to that hand;
private cards remain hidden. Final balances and the funding outpoint are bound
only after settlement, before score keys or settlement signatures are created.
The final settlement chain still commits to the actual funding and all rules.
The prepared worker is promoted directly, avoiding transcript replay between hands.
Reload restores the encrypted preparation; old URLs follow the durable successor.

The funding transaction spends both confirmed payout outputs and a sponsor
fee-top-up output. Each old player signs only its own payout input. The host's local wallet covers the necessary top-up and receives change.
New hands use the configured 0.1 ₿/vB floor, integer-rounded transaction fees,
and a reserve quoted from the maximum reachable settlement path.
The private wallet key stays in localStorage and is never sent to the relay.
Before either payout signature is released, both seats save a return transaction
that restores the old payout amounts to their original owners and returns the
remaining top-up to the sponsor. Consent and all funding bytes survive reload.
A stack below the protocol's ₿200 minimum requires a new table/rebuy.

The relay keeps only transient delivery queues in memory. Both browsers save received pages to IndexedDB before acknowledging delivery; acknowledged payloads are discarded. Recovery packages stay encrypted in IndexedDB and are executed by a browser worker while the app is open, including in the lobby. There is no server recovery service. Restarting the relay removes its rooms. Browsers recreate them using their saved invitations and capabilities, replay their outgoing messages, and deduplicate delivery using message IDs. Browser cursors remain stable across relay epochs.


## Console diagnostics

The app writes timestamped `[poker ...]` events for table state, background preparation, worker operations, relay status, errors and storage delays. Unfinished operations report waiting every 15 seconds. Repeated states are coalesced and the most recent 2,000 lines are retained in page memory. Background worker events are forwarded to the page log.

Reload before reproducing a problem, then run `copy(pokerLog())` in Chrome DevTools Console and share the copied text. In a console without `copy`, run `pokerLog()` and copy its result. Reloading clears the in-memory log. The logger records only selected public metadata, never message payloads, keys or unrevealed cards.
