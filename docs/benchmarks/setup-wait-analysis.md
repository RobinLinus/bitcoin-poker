# Setup waits and funding overlap

## User logs, 2026-09-08

Both browsers agreed the opening dealer phase ran approximately 02:15:26–02:16:29 (62–63 seconds), then tree preparation ran until 02:17:25 (55–56 seconds). Construction workers took approximately 16 seconds each. Hundreds of repeated HTTP 429 errors followed funding submission until roughly 02:18:06. The “Waiting for your opponent’s buy-in” poll duration included the later dealer and tree work; its stale starting label did not mean the whole two-minute operation was waiting for the buy-in.

## Changes

- Accept unspent mempool wallet funding outputs for setup, prefer confirmed coins when available, and gate the funding signature exchange on parent confirmations. Run the initial dealer in parallel with waiting for wallet funds. Use an opening hand anchor; bind the exact final funding into a fresh opening channel slot before score keys and settlement preparation. Reject changed nonce/anchor contexts.
- Generate and verify the dealer transcript once, then share the immutable accepted result across both private recovery roots. Both owners retain their own settlement signatures. Persist the shared transcript so reload still reconstructs both sessions.
- Increase bounded bulk relay pages and upload batches from 128 to 512 KiB; increase the preparation queue from eight to 32 chunks. Message-count bounds and foreground socket priority remain enforced.
- Check wallet funds, channel funding confirmation, and cashout confirmation at most once per three seconds. Failed table polls back off exponentially up to 30 seconds.
- Apply provider-wide cooldown within each Esplora adapter after HTTP 429; honor Retry-After. Recovery and profile checks using that adapter also respect cooldown. This is not a global IP-wide limiter across unrelated browsers.

## Qualification

- Unfunded two-player lobby: both dealers accepted in 3.122 seconds. After binding a synthetic final funding outpoint, both players produced the same preparation binding in a further 7.451 seconds. No broadcast or funded wallet was needed. This specifically qualifies early dealing and the funding-context transition.
- Three MutinyNet hands with a TCP proxy adding 100 ms in each direction: PASS, 24 off-chain betting moves, automatic redealing, sit out and confirmed cashout, no 429 failures. The proxy adds latency but does not throttle bandwidth or CPU.
- Tree preparation under that latency: 14.142 / 14.165 seconds for the two players. Handovers: 14.557 / 15.031 seconds. Initial playable setup including chain confirmation: 48.630 seconds. Three buffered future trees were ready at 123.152 seconds from test start.
- WebSocket frames sent: 1,156 versus 3,050 in the earlier local three-hand run; payload volume remains about 93.3 MB including background replenishment. Different conditions and random hands prevent interpreting this as a controlled wall-clock speedup.
- Four native channel tests passed, covering shared dealer preparation, deferred payouts, opening funding-context binding and future hand contexts. Browser contract tests passed, including cooldown, poll backoff and single initial-dealer-loop tests.

These measurements do not establish sub-10-second total setup over the hosted connection. Chain confirmation remains separate from computation. The next optimization targets are repeated transcript restoration in construction workers, private inventory replication, and remaining serialized protocol exchanges.

Selected funding inputs remain bound to their exact transaction IDs. Replacement of an unconfirmed parent requires a new setup; the app does not silently substitute a different input under existing signatures. Mempool acceptance and the final confirmation gate have dedicated tests.

## Follow-up: setup pipeline optimization

The later two-browser logs supplied on September 8 show preparation from
03:18:58.77 to approximately 03:19:31.6: **32.8 seconds**. Construction took
9.58/8.50 seconds on Alice and 3.51/3.76 seconds on Bob. Funding confirmation
then added roughly 32 seconds. This was not solely a network wait, and a
preparation-only timing must not be presented as time to a funded, playable table.

Implemented changes:

- Compile and verify the public Wasm module once per page and share that module
  with private worker instances. Preload the channel worker in the lobby and the
  bounded construction/signing pools during dealing. Reuse the stateless lobby
  funding worker rather than loading another worker for every seat/future hand.
- Delegate an authenticated local construction job containing the already
  verified public dealer result. Construction workers no longer replay the
  dealer transcript. The parent authenticates the inventory against its exact
  checkpoint context. Peer dealer proofs and signatures are still verified.
  Commitments and the accepted dealer catalogue use binary local framing.
- Cache the unprotected graph within a session. Exchange both owners' retirement
  commitments in one flight and start each construction as its commitments
  arrive. Commitment chunks and signing batches are 128 KiB; relay batches/pages
  have a bounded 2 MiB budget.
- Batch the initial seat announcement and derive the fixed opening fee/nonce
  plan identically on both seats. First subscriptions can upload immediately;
  subscriptions with a known stale epoch must still resynchronize first.
- Acknowledge durable incoming pages without awaiting an empty server response.
  Incoming pushes no longer trigger redundant resynchronization. Uploads have
  their own lock, so waiting for an upload response does not block a worker from
  consuming peer data. The dealer also consumes peer stages while its outgoing
  upload acknowledgement is in flight.
- Save regenerable preparation frames in the durable relay log instead of also
  copying them into the channel checkpoint on every chunk. Completed recovery
  artifacts and entry/move/revocation barriers still persist before release.

### Reproduction and scope

`tools/setup-benchmark.mjs` runs two isolated Chrome contexts, warms the lobby
wallets, creates the host seat, then times guest join, dealer completion, score
exchange and full preparation for both owners on both players. It checks equal
preparation bindings. It binds a synthetic unfunded outpoint and never funds or
broadcasts. Lobby warmup is reported separately. Dealer retries are recorded;
never discard retry trials when reporting the wait distribution.

```sh
PLAYWRIGHT_MODULE=/path/to/playwright node tools/setup-benchmark.mjs \
  --origin=http://127.0.0.1:3114 --trials=3 --output=target/setup-latency.json
PLAYWRIGHT_MODULE=/path/to/playwright node tools/setup-benchmark.mjs \
  --origin=http://127.0.0.1:3114 --trials=1 --reload-during-preparation \
  --output=target/setup-reload.json
```

Port 3114 in these measurements is a local TCP proxy to the release relay with
100 ms added in each direction (200 ms round-trip), without bandwidth or CPU
throttling. Both browsers run on one machine. These are not hosted production
measurements and do not model a slow device or restricted upload bandwidth.

The final build produced these consecutive trials (no retries excluded):

| Added RTT | Dealer retries | Join + dealer | Remaining preparation | Total |
| --- | ---: | ---: | ---: | ---: |
| 200 ms | 0 | 4.534 s | 6.563 s | 11.097 s |
| 200 ms | 2 | 10.431 s | 6.751 s | 17.182 s |
| 200 ms | 0 | 4.594 s | 6.632 s | 11.225 s |
| None | 0 | 1.285 s | 6.044 s | 7.328 s |
| None | 0 | 1.528 s | 6.486 s | 8.013 s |
| None | 4 | 5.643 s | 6.426 s | 12.069 s |

Lobby warmup was approximately 4.5 seconds with added RTT and 1.0 second
without it; that happens before this benchmark's Join timer. Initial chain
confirmation is excluded. Full setup is below 10 seconds in the local no-retry
trials, but not yet in the 200 ms RTT trials, nor consistently across retries.

Construction was 2.40–2.46 seconds per owner, worker initialization approximately
instant for construction and tens of milliseconds for crypto, and preparation
checkpoint persistence approximately 0.3–0.4 seconds per player. An earlier no-retry
trial still uploaded 19.67 MB across both players. Binary batching cuts round
trips and repeated metadata; it does not compress cryptographic signatures.

### Interruption and correctness qualification

- Browser reload after signing had begun: both seats completed with identical
  preparation bindings. Recovery regenerates incomplete preparation from the
  saved context and durable transcript; the interrupted run took 28.995 seconds
  including two dealer retries and the reload.
- Actual isolated relay restart: all 100 queued binary messages replayed without
  duplicate local delivery, and a new message was delivered afterward. Idle
  polling made no exchanges. Forged acknowledgements with an unseen cursor or
  wrong epoch closed the connection.
- Two full cooperative browser hands, automatic redealing and sit out passed.
  Only the chain adapter was mocked to treat the synthetic origin as confirmed
  and unspent; recovery digest validation, local persistence, crypto and relay
  transport were real. No transaction was broadcast. This deliberately fast
  automated game outran the future-hand buffer: its handover gap was 35.193
  seconds, even though final payout preparation took 3.6 seconds. The setup
  improvement does not establish a universal sub-10-second redeal guarantee.
  The final local build also passed two complete hands after wallet-worker reuse;
  its initial preparation was 5.7 seconds and final payout preparation 1.1 seconds,
  but its unbuffered handover gap was still 21.750 seconds.
- Four native full-channel tests passed, including local construction parity
  against the original fully restored session, deferred payout reuse, recovery,
  handoff and cashout. Local construction capabilities reject wrong keys,
  tampering and truncation.
- 117 browser contract tests and 25 relay unit/API tests passed.

The 10-second total target is not guaranteed: dealer retries add approximately
three seconds each at this latency, bandwidth still matters, and funding
confirmation is external. Predealing while funding is pending and the bounded
future-hand buffer hide work when there is time to do so; they do not eliminate
that work from cold setup.


The final client and pinned Wasm were rebuilt. The main local relay was restarted
with its existing `deployments/mutinynet/onchain-test.json` configuration, and its
served JavaScript, Wasm and manifest bytes matched the source artifacts. This
follow-up was deployed to the hosted server on 2026-09-08 (UTC).


### Hosted deployment qualification, 2026-09-08

The deployment includes the shared-wallet funding fix: the guest excludes the
host's selected outpoint and requests a separate payment when no second output
is available. All 121 browser contract tests passed before deployment.

The installed Linux executable matches the server build:
`53345d24efeba7fe93a737afea48d7cd3ca0e456e677ea8b1fd14b24cd514826`.
All 13 changed browser runtime assets, including Wasm and its manifest, matched
the deployment checksums over public HTTPS. An isolated browser delivered 100
binary relay messages in four upload exchanges, with zero idle exchanges and
no page errors.

A full hosted setup with two isolated empty wallets and a synthetic unfunded
origin passed with identical preparation bindings: 4.851 seconds join/dealer,
14.396 seconds remaining preparation, 19.247 seconds total, no dealer retries.
Lobby warmup was another 10.466 seconds. No funding or transaction broadcast
occurred. The actual hosted result is slower than the local latency-only proxy;
the proxy does not model production bandwidth or server performance. This
result does not establish a hosted 10-second setup.

Close all app tabs and reopen the site after this release so the previous
SharedWorker exits; create a new table for the changed engine/protocol. Do not
clear wallet storage.

## Hosted browser investigation: relay races, caching and handovers

The later two-wallet qualification uses the actual hosted origin, real funding,
independent Chrome storage contexts, full cooperative hands, automatic redealing,
sit out and confirmed cashout. `tools/playable-e2e.mjs --funded --hands=3` runs
this test only with explicit funded-test authorization. It never prints wallet
keys. Do not publish its browser storage files. `tools/relay-priority-regression.mjs`
qualifies payout priority and durable replay against an isolated local relay.

Changes made during this investigation:

- Give incompatible SharedWorker protocols separate identities. A retained old
  worker was reproduced withholding the new durable acknowledgements after reload.
- Do not return pushed bytes again in an upload response. Persist earlier pushes
  before acknowledging a response which skips them. A delivered cursor is not a
  durable ACK. A stale `joined: false` response can no longer undo an already
  received peer join within the same relay epoch.
- Send the two independent owner inventories over separate binary WebSockets.
  Merge their durable inboxes into a stable rewindable local cursor. Keep control
  and gameplay separate; payouts have their own streams. Preserve queue bounds,
  authentication, acknowledgement checks and conservative cache cleanup.
- Content-version public assets and cache them immutably, including worker modules
  and authenticated Wasm. HTML and API responses remain uncached. Enable compressed
  Wasm delivery while still verifying the decoded artifact's exact size and hash.
- Begin the future-hand buffer after signed funding exists, while its confirmation
  is pending. Preserve the confirmation gate for initial play. Keep the shared
  wallet alive when adopting a prepared successor.
- Cache binary terminal transaction templates inside authenticated local
  construction receipts. Rebinding verifies their original sighashes and recipient
  layout, sets exact terminal amounts, and recalculates affected digests. It covers
  folds, timeouts and showdowns. Unchanged internal authorizations remain intact;
  changed payouts are still signed and verified before entry. Cold recovery can
  reconstruct the cache. Release hot payout caches after binding.
- Bound upload batches to 512 KiB. Pause future-tree bulk uploads during payout
  binding, drain the candidate's existing frames before taking priority, and resume
  afterward. Never cancel durable messages to give an operation priority.

Qualification so far:

- 130 browser contract tests and 27 relay unit/API tests passed. The real browser
  priority test held a future upload while payouts progressed, resumed it, then
  restarted its relay and verified exact replay without duplicate local delivery.
- All four native full-channel tests passed. The hot delegated payout path and a
  cold full reconstruction produced byte-identical complete inventories, including
  every terminal branch. Native payout rebinding fell from 2.817 s to 0.633 s in
  that comparison; this excludes signing and network transfer.
- The rebuilt Wasm completed a two-browser setup with a reload during signing in
  12.455 s locally, with matching preparation bindings and no browser errors.
- On the hosted connection, removing duplicate responses reduced received setup
  data from approximately 34.95 MB to 19.7 MB, close to the 19.67 MB sent. The
  signature payload itself remains substantial; compression does not shrink it.
- Before traffic pacing, funded three-hand runs passed correctness and confirmed
  cashout but exposed handover gaps of 13–33 s. Separate connections alone did not
  establish faster handovers. During a slow interval, even 735 KiB payout uploads
  took 19 s while future trees uploaded concurrently; the server had ample free
  memory, no active swapping and very low CPU utilization when sampled.

The 10-second hosted total is not established. Initial block confirmation, dealer
retries, upload bandwidth and whether the next tree is already buffered must be
reported separately from local construction timings.

## September 8: bounded upload windows and hand-entry priority

The first isolated setup run on `https://poker.bitvm.org` took 25.48 s:
12.01 s for dealing (attempt 2), then 13.47 s for preparation. This test uses
real dealing and signature verification with an unfunded synthetic origin;
it does not measure funding confirmations.

Changes qualified against the real browser transport:

- Authenticated bulk streams can keep four 512 KiB uploads in flight. Initial
  subscriptions and reconnects remain serial; the control connection stays
  separate. Bytes are saved before upload and responses applied in order.
- Peer data carried by upload replies now enters the same bounded queue as
  pushed data. Later delivery cursors cannot acknowledge an earlier reply whose
  payload the browser has not saved. Lost replies, replay, ordering and failed
  storage are covered by the transport tests.
- A future deck does not start construction/signing pools that it will never
  use. The candidate worker forks the saved deck and owns those pools. With three
  deck slots, this avoids up to 30 idle worker instances per player.
- Payout preparation keeps priority through entry, retirement of the old hand
  and hole-card exchange, until the next hand can act. Merely finishing payout
  signatures released bandwidth too early. Future preparation can use up to
  two crypto workers per owner, retaining the existing CPU budget on small devices.

The first three-hand run after upload pipelining passed with no page errors,
correct balance carryover and confirmed cashout. Its handovers were 18.925 s
and 8.613 s **from both players reaching the terminal state to their first
shared actionable node**. These include entry and card disclosure, rather than
stopping the timer at signature readiness. Payout preparation took 9.274 s and
3.642 s. The later hand-entry priority change follows directly from this trace:
future uploads restarted while the current entry exchange was still pending.

The funded driver is `tools/playable-e2e.mjs`. Use a new private output directory
for each run and `--funded --hands=3`; keys are read from the ignored
`test-accounts.keys`. Each seat now uses its own persistent Chrome profile.
Playwright's JSON `storageState` does **not** preserve non-extractable IndexedDB
CryptoKeys and must not be treated as a recovery backup. `--resume --hands=1`
with the same output directory resumes a saved test hand for completion/cashout.
A test interrupted by a separate relay restart was resumed this way and its
cashout confirmed; that interrupted run is not a performance result.

A subsequent transport timeout exposed a separate recovery bug: the table
kept polling a worker that preparation had already halted. Transport failures
now reopen that worker from its durable checkpoint after backoff. Protocol and
signature-validation failures do not trigger this automatic replacement.
The contract suite covers both cases (135 tests passing).

For an isolated comparison, an immutable relay executable served both variants
behind local WebSocket proxies adding 125 ms in each direction. The previous
four client modules were served for the baseline; the new modules were served
for the other run. Both ran real dealing/cryptography with empty wallets and
unfunded synthetic origins, sequentially on the same machine:

| Measurement | Before | After |
| --- | ---: | ---: |
| Dealer protocol, attempt 0 | 4.882 s | 4.900 s |
| Full preparation | 9.411 s | 7.379 s |
| Combined setup | 14.293 s | 12.279 s |

This single controlled pair shows approximately 22% less preparation time.
It isolates round-trip latency; it is not a bandwidth simulation or a claim
that all hosted setups finish in ten seconds. Concurrent deployments of another
UI task interrupted stable-version hosted qualification, so later tests use a
separate fixed executable and ports instead of the shared local/hosted relay.

The final fixed-version funded browser run used the same proxy latency, two
persistent independent Chrome profiles, real MutinyNet funding and confirmed
cashout. Three complete hands passed, including maximum supported bets/raises
in the first hand and automatic balance carryover thereafter. No page errors
or gameplay broadcasts occurred. Handovers to the first actionable node were
**8.194 s and 9.219 s**; their payout preparation took **2.148 s and 2.705 s**.
The third hand's dealer had retried four times in the background, before it was
needed. Initial table readiness still took 45.173 s including funding gates;
the full preparation portion was 7.431 s. The total run, including confirmed
cashout, took 135.042 s. These are controlled test results, not a guarantee for
public-server bandwidth or initial funding confirmation times.

The later aborted hosted setup was inspected from its persistent profile:
no completed preparation, no signed funding, no funded table and no recorded
transactions. It was not a second paid game requiring cashout. Its profiles
remain available, and no wallet/recovery data was cleared.
