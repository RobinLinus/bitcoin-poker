# Browser chain adapter

This directory is the only browser component that speaks to a chain backend.
It implements a small backend-neutral chain port over an injected Esplora
deployment. Poker rules, graph selection, wallet keys, and relay exchange do
not live here.

```js
import { loadRuntimeConfig } from "./config/runtime-config.js";
import { createEsploraChainAdapter } from "./chain-adapter/esplora.js";

const deployment = await loadRuntimeConfig();
const chain = createEsploraChainAdapter(deployment, {
  timeoutMs: deployment.relay.requestTimeoutMs,
});
await chain.verifyProfile();
const tipEvent = await chain.tipFact();
```

The Rust-validated `/api/v1/config` response is the sole source for the
endpoint, chain identity, checkpoint, address HRP, and broadcast policy. The
factory accepts only that config plus a Fetch implementation (for tests) and a
bounded timeout. Profile verification checks the configured genesis and
optional checkpoint plus three mutually consistent tip observations. A
profile mismatch permanently poisons that adapter instance. `publish` repeats
the complete profile check immediately before its POST, validates the
submitted transaction locally, requires broadcasting to be enabled, and
requires the returned txid to match.

## Port surface

- `verifyProfile()` authenticates the pinned endpoint observations.
- `tip()` and `tipFact()` return a best-chain observation or the exact
  `tip-observed` game-runtime event.
- `blockHash(height)` returns display-order bytes or `null` for a 404.
- `rawTransaction(displayTxid)` sends bounded opaque bytes through the
  `bp52-browser-transaction-wasm` boundary, where `rust-bitcoin` canonically
  deserializes/reserializes the transaction, computes its txid, and projects
  the checked inputs and outputs.
- `transactionStatus(displayTxid)` returns `unknown`, `mempool`, `confirmed`, or
  `reorged`. Because some Esplora deployments return `{confirmed:false}` even
  for an unknown txid, that response is `mempool` only when `/raw` exists and
  the Rust/Wasm inspector validates both the transaction and requested txid.
  A confirmed report is checked against `/block-height/:height`.
- `outpointStatus({displayTxid, vout})` (also `outspend`) returns `unknown`,
  `unspent`, or `spent`; a spent observation includes
  `spendingDisplayTxid`, `inputIndex`, and `spendingStatus`.
- `originFact({outpoint, valueSat, scriptPubkey, minConfirmations})` locally
  verifies the exact creating transaction/output and returns an
  `origin-confirmed` event. It returns `null` while absent, mempool-only,
  reorged, insufficiently deep, or observed across a changing tip.
- `spendFact({spentOutpoint, expectedSpendingDisplayTxid?,
  expectedInputIndex?, minConfirmations?})` cross-checks outspend and tx-status
  endpoints, then verifies that the reported raw input spends the exact
  outpoint. It returns a `spend-confirmed` event or `null` under the same
  conservative transient conditions.
- `publish(rawTransaction, {expectedProfileId?})` broadcasts only after all
  local and configured profile checks pass.
- `feeEstimates()` returns the bounded Esplora target/rate map.
  `relayFeeFloorCompatibility(1)` always returns `unknown` plus advisory fields,
  including `estimateAboveGraphRate`. Confirmation-target estimates are not
  relay-policy evidence: standard Esplora exposes no authenticated
  `mempoolminfee` or equivalent relay-floor endpoint, so it can prove neither
  acceptance nor rejection of the immutable graph rate. A future adapter to a
  trusted Bitcoin Core JSON-RPC endpoint could use `getmempoolinfo`'s
  `mempoolminfee` and `minrelaytxfee`; those fields cannot be inferred from
  Esplora fee estimates.

All transaction ids and block hashes in browser control/view DTOs use
lowercase explorer/display-order hex. Rust owns the single conversion to
Bitcoin consensus order. Raw transactions and scripts remain opaque consensus
bytes. Fact `profileId` is the exact configured chain-profile id, not a display
hash.

Every response is streamed under a fixed byte bound and the complete fetch plus
body read is covered by the timeout. JavaScript performs HTTP/status
orchestration and converts the bounded, strict Serde JSON view emitted by Rust;
it does not implement a binary metadata codec, Bitcoin transaction parsing,
serialization, or hashing. Input, output, and diagnostic bounds come directly
from Wasm exports rather than duplicated JavaScript constants. Redirects, malformed
consensus encodings, trailing transaction data, inconsistent status/outspend
data, wrong expected outputs/inputs, and txid mismatches fail closed.

Build the raw inspector from `client/` with the same pinned clang-capable Wasm
toolchain used by the game worker:

```sh
./scripts/build-browser-wasm.sh
```

The relay serves it at `/wasm/transaction.wasm` with the digest and byte length
bound by `/wasm/manifest.json`.

Run the dependency-free mocked suite from `client/`:

```sh
node browser/chain-adapter/transaction-runtime.test.mjs
node browser/chain-adapter/esplora.test.mjs
```
