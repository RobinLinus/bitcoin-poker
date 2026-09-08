# Table readiness with libsecp256k1

The libsecp256k1 optimization is implemented. The strict target of every initial
preparation and every terminal-to-playable transition taking less than 10 seconds
is **not yet qualified**. Short hands can finish before the background shuffle;
rejected shuffle attempts also cost time when construction workers restore the
private checkpoint. These waits remain visible and are not hidden by an earlier
ready flag.

## Implementation

- Enable musig2's supported libsecp256k1 backend for adaptor signing and
  verification. Keep k256 conversions for the existing dealer point types.
  Bitcoin Schnorr signing already used libsecp256k1; the dealer's general proof
  arithmetic still uses k256.
- Force libsecp256k1's supported `USE_FORCE_WIDEMUL_INT64` implementation in every
  Wasm build path. Clang's default int128 products otherwise lower to expensive
  `__multi3` emulation. No custom curve arithmetic or unchecked peer verification
  replaces the library.
- Cache immutable showdown leaf hashes, validated identity pairs, and verification
  contexts. Calculate signing outputs without constructing unused witness/control
  blocks. For the fixed NUMS point, compute the standard BIP341 `P + tG` using
  libsecp256k1's generator tables and point addition; reject invalid scalars and
  infinity. All node, funding, owner and revocation bindings remain exact.
- Generate outgoing adaptor packages through a separate type with no peer decoder.
  Trusted local signing workers issue authenticated installation receipts. Every
  received package still undergoes all 52 candidate verifications.
- Construct both owner inventories concurrently, then sign and verify both through
  owner-specific queues. The bounded budget is one to four workers per owner,
  depending on reported CPU concurrency. Messages contain at most 2,048 ordinary
  signatures or 32 full reveal packages, below the existing 256 KiB batch limit.
- Reuse IndexedDB connections, while retaining encrypted checkpoints and durable
  outboxes. Preserve final-term binding, both recovery roots, monitor receipts and
  retirement barriers before successor adoption.
- Reuse the parent's chain adapter for the same channel, accelerate active protocol
  exchanges, and advance unfinished shuffle rounds promptly after settlement.
- Handle relay pages that contain the end of one failed shuffle attempt and the
  first frame of the next: persist the retry state before processing the next
  frame. The authenticated dealer still validates every incoming frame.

The graph still requires 56,161 authorizations for **each** of its two owners.
There is no reduced tree, skipped receiver verification, guessed settlement
balance, early signature, or early card disclosure.

## Measurement scope

Apple M5 Pro, 24 GiB RAM, Chrome 152 reporting 15 cores, two synthetic browser
seats on one machine. No competing benchmark/build workloads during qualification.
Initial preparation includes both durable inventories and enforceable recovery
roots. The hand gap starts at the first observed terminal state and ends when
both seats have matching successor hands, hole cards and a playable betting state.

The harness uses the served app's real TableSession, channel workers, relay
messages, Wasm and IndexedDB. It supplies synthetic funding and mocks only the
chain-backed monitor endpoint. Wallet publication is disabled in the harness.
These are local relay measurements, not a two-device, WAN, visible-tab, memory,
or funded-chain latency qualification. The requested 50 Mbit/s / 50 ms profile
and the funding-return UI interval have not been qualified.

The recorded baseline used the debug relay and the previous Wasm. Final timing
uses a release relay as well as the optimized client. Do not attribute the whole
end-to-end difference solely to changing elliptic-curve libraries.

## Final local timing results

Ten fresh browser contexts completed two hands each: five check/call hands with
₿20,000 per seat and five immediate-fold hands starting at ₿19,800 / ₿20,200.
Every initial preparation and named next-hand preparation interval was below
10 seconds in these trials. The stricter full transition target passed only
2 of 10 trials. Percentiles use nearest rank, so p95 equals the maximum at n=10.

| Interval (slower seat) | Minimum | Median | p95 / maximum |
| --- | ---: | ---: | ---: |
| Initial durable preparation + recovery roots | 7.629 s | 7.826 s | 9.894 s |
| “Preparing next hand…” interval | 8.032 s | 8.666 s | 9.543 s |
| Complete terminal-to-playable gap | 8.476 s | 10.691 s | 13.712 s |

Longer-hand gaps ranged from 8.476 to 13.712 seconds;
immediate-fold gaps ranged from 10.397 to 12.767 seconds.
The earlier three-trial baseline had 28.152–29.848-second initial preparation
and 30.431–35.199-second gaps. A prequalification immediate-fold trial reached
18.288 seconds; it is not hidden by the final sample’s smaller maximum.

Attempt counters in the final reports confirm that rejected shuffles can add
both foreground dealing time and checkpoint replay time. Even an accepted first
attempt has limited timing headroom, so these results are not a general guarantee.

The raw [measurement report](table-readiness-libsecp256k1.json) includes per-owner
construction phases, attempt counts, stage boundaries and the baseline.

## Validation

- Both complete 4,096,055-byte owner inventories match the original Wasm byte for
  byte. Their fixture SHA-256 hashes remain
  `5240cfcb61a8635e63b99582022732a6cbbfcc1ba1c52ea925f34bc0ddf713e6` and
  `964a22dbfda77545ef88b9196d90e32b35ca444208c6a9c67584519c269f3763`.
- Sampled ordinary and adaptor batches for both roles and owners match byte for
  byte, cross-verify between the two backends, and reject modified signatures.
  Native tests exercise completion/extraction for every one of the 52 candidates,
  including zero and nonzero blinding cases.
- 35 dealer-bitcoin/poker-bitcoin unit tests pass. The native channel test passes
  complete play, checkpoint cuts, handoff and cashout.
- Managed Bitcoin Core regtest passes fixed branch contests and both full channel
  owner paths through activation, hole delivery, board reveals, showdowns and
  payouts. The Core fixtures use smaller stacks.
- 83 browser contract tests pass. The real browser corruption test stops before
  activation, then resumes both seats from durable checkpoints against the
  original unmodified relay messages.
- `tools/channel-retry-regression.mjs` reproduces the authenticated-stage rejection
  with real deterministic Wasm frames, then accepts the queued retry frame only
  after the production retry helper advances and persists both owner states.
- Strict Clippy passes for dealer-bitcoin and poker-bitcoin. The broader
  session/Wasm/relay check still reports existing missing documentation and style warnings
  in surrounding session/settlement code. This is not recorded as a passing check.

## Build and reproduction

The full browser build, debug relay build, release relay build and artifact
manifest check were run. The local relay is restarted with the same database and
configuration; all 22 transitive JavaScript dependencies of the table/channel worker and four
Wasm assets are compared against workspace files. New tables use the new engine;
existing development checkpoints retain their pinned engine hash.

Session Wasm: `bab20cb5aeaea5bbe495934f93b0a12258d1aaaa04307fd58973a64defc35c52`
(5,259,104 bytes). The artifact budget is 6 MiB to accommodate the additional
libsecp256k1 backend. Existing rust-bitcoin and musig2 use different pinned
secp256k1 crate versions, so both C libraries remain in the build.

```sh
scripts/build-browser-wasm.sh --docker
cargo build -p poker-relay --offline
cargo build -p poker-relay --release --offline
# In another terminal, use a fresh isolated database:
# target/release/poker-relay /tmp/readiness.sqlite 127.0.0.1:3104 deployments/mutinynet/onchain-test.json
node tools/session-inventory-parity.mjs target/readiness-original.wasm apps/web/public/wasm/session.wasm
node tools/channel-retry-regression.mjs
node tools/channel-readiness.mjs --origin=http://127.0.0.1:3104 --trials=5 --hands=2
node tools/channel-readiness.mjs --origin=http://127.0.0.1:3104 --trials=5 --hands=2 --fold
node tools/channel-readiness.mjs --origin=http://127.0.0.1:3104 --trials=1 --hands=1 --fold --corrupt-batch
```

Use an isolated benchmark relay database and an installed Playwright module
(`PLAYWRIGHT_MODULE` may point to it). Raw reports contain public fixture IDs,
not wallet keys or relay capabilities. Protocol completion and timing-target
success are reported separately.

## Remaining work

The main remaining work is reducing accepted-deal restoration and residual
shuffle retries, while preserving transcript verification and private openings.
Retaining authenticated, verified deal data across background-worker promotion
is not implemented. A general under-10-second claim requires the planned
multi-device/network qualification and short-hand cases to pass; changing the
status copy or excluding shuffle retries does not meet that goal.
