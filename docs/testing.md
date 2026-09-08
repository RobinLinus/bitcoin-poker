# Testing

## Native and browser

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --no-deps --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
node scripts/test-browser.mjs
node apps/web/tests/deal-e2e.mjs
```

The native suite includes protocol acceptance, canonical encodings, complete
reference topology/accounting, funding/refund signatures, and backend contracts.
The browser suite covers modules, workers, Wasm loading, and practice move logs.
The real Wasm scenario runs two dealer participants through setup and showdown.
Relay integration tests check asset imports, schema-3 practice config, opaque
message behavior, and the removal of legacy assets.

## Qualified Wasm artifacts

```sh
scripts/build-browser-wasm.sh --docker
scripts/build-browser-wasm.sh --check
```

The pinned Docker toolchain builds each binding independently. Dealer Wasm keeps
its 8 MiB stack setting. Avoid workspace-wide Wasm builds: host/network features
must not leak into secret-owning browser modules. `--validate-only` checks built
artifacts without publishing. Export, import, size, and hash contracts are defined
in `toolchains/browser-wasm-artifacts.json`.

## Bitcoin Core

For actual browser co-signing and recovery of the full 56,132-node tree, use the
[settlement benchmark](../tools/settlement-benchmark/README.md). It reports complete
transaction preparation separately from logical graph compilation.

```sh
scripts/bitcoin-core-regtest.sh --docker --suite all --require
```

The runner uses a cached pinned Core image and an isolated standard-policy regtest
node, then cleans it up. `--native` uses locally installed Core. The complete suite
covers card gates, reusable reveals, score/payout branches, prepared short-stack
settlement, recovery, and CSV timeouts. `--suite dlog-graph` runs only the complete
hand campaign; `dlog` is an algorithm label, not a package prefix.

## Source archives

`scripts/check-workspace.sh` checks the locked dependency graph. Run
`scripts/check-source-archive.sh` after committing to verify that HEAD contains a
complete source distribution. These checks do not substitute for compilation.

## Parallel preparation

`verification-pool.test.mjs` covers role assignment, verification priority,
cancellation and unexpected worker responses. Native benchmark tests cover corrupt
batches, wrong/misbound receipts, idempotent replay, incomplete checkpoints and
checkpoint authentication. The managed Core complete-hand test also reloads an
authenticated checkpoint before spending, exercising lazy reveal validation.
The diagnostic browser's **3 parallel trials** checks the full original inventory,
complete setup, encrypted IndexedDB reload, five checkpoint failure cases, and
full untrusted import. See `tools/settlement-benchmark/README.md` for boundaries.

## Browser on-chain session

Build with `scripts/build-session-wasm.sh`, then run the relay using
`deployments/mutinynet/onchain-test.json` and open `/tools/onchain-e2e`.
See `apps/web/src/onchain/README.md` for the live runner and recovery controls.
`cargo test -p poker-session` exercises the reusable player API;
`scripts/bitcoin-core-regtest.sh --docker --suite session --require` validates full
hand, fold, refund and CSV timeout against an isolated Bitcoin Core node.
`node scripts/test-browser.mjs` includes bounded chain-index retry and fee
conservation tests. Live public evidence lives in `docs/benchmarks/`.

The setup-only scenario uses real independent players and relay exchange with an
unfunded synthetic origin; it never broadcasts. Use it for repeated performance
qualification. It is not a substitute for a confirmed funded hand. Script changes
must update the reference fingerprint explicitly and retain earlier build results.

## Playable table qualification

The root page selects the on-chain controller under schema 4. Use two independent
browser seats joined by an invite, then fund from the host. Exercise Raise/Call,
Bet/Call and Check/Check through actual buttons, refresh during a pending move,
and verify matching board/pot values and different private hole cards. Required
reveals and showdown must progress automatically, with payout links only after
confirmation. `poker-session` tests assert that hole cards are unavailable before
the corresponding delivery and community cards stay hidden until both reveals.
Browser contract tests cover invitation validation, deferred pre-join outbox
publication, pinned-engine agreement and wrong-escrow rejection.

Consecutive-hand tests cover payout rollover, fresh dealing with asymmetric
stacks and the opposite dealer, second-hand settlement, and cancellation returns
to both original payout owners. The current browser checkpoint and the distinction
between Core and live-network coverage are in
[consecutive hands](benchmarks/consecutive-hands.md).
