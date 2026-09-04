# Testing

Use the cheapest layer that can reproduce a bug. A browser or live-chain failure
must gain a deterministic unit or contract regression before its fix is merged.

The test pyramid is:

1. pure Rust policy, codec, Serde, graph-streaming, receipt, and security tests;
2. dependency-injected JavaScript unit and Worker-contract tests;
3. DOM/source contracts for the minimal table, BIP-177 amounts, automatic
   setup, and absence of protocol/debug copy;
4. real Wasm proof and exhaustive graph qualification suites; and
5. one final funded two-browser game played through settlement.

Layers 1–3 are the ordinary regression loop. Layers 4–5 are qualification
checks, not substitutes for unit coverage.

## Fast checks

Run every dependency-injected browser test plus the real wallet/origin Wasm
contract from any directory with:

```sh
node client/scripts/test-browser.mjs
```

From `client/`, use `node scripts/test-browser.mjs`. The script discovers every
`browser/**/*.test.mjs` and relay-web `*.test.mjs` file, so new tests enter CI
without another hand-edited list. These tests use fake relay, chain, clock,
storage, and Worker ports; they do not generate DEAL proofs or contact a public
chain.

`browser/flow/chain-game-client.test.mjs` is the fast whole-hand contract. It
drives the exact 100-BB deployment through automatic setup, a 21-transition
multi-street hand, settlement, fold, and timeout branches while checking every
stack/pot conservation step and every publish/confirmation boundary. Keep
protocol-only transitions automatic and add gameplay regressions there before
reaching for a funded browser run.

For focused Rust policy work, select the owning module or crate first:

```sh
cargo test --locked -p bp52-game-session policy::tests
cargo test --locked -p bp52-relay-server
node scripts/package-browser-wasm.mjs --check
```

The relay API suite includes a recursive `/app.js` module-graph check. It fetches
each same-origin static import through the in-process Axum router, catching a
missing production asset route without starting a browser or HTTP server.
The UI contracts assert that both stacks, pot, centered status/funding, and
₿100/₿200 blinds exist while setup controls, recovery prompts, raw exceptions,
and internal protocol vocabulary remain absent from player-facing surfaces.

## Fixtures

Keep cross-language fixtures versioned under `browser/fixtures/`. Rust should
produce canonical signed, hashed, or Bitcoin bytes; JavaScript consumes those
bytes as hex or base64 rather than duplicating layouts. Use Serde for Rust-owned
JSON metadata. Test-only keys and entropy must be deterministic, explicitly
labelled, and kept outside served web assets. Ordinary fixtures should use
non-production names and sentinel values (including confirmation depths above
one) so they cannot accidentally pass by sharing production defaults.

## Broader gates

Run the full client workspace before merge:

```sh
cargo test --workspace --all-targets --locked
```

The real two-participant DEAL Worker run and ignored proof/archive tests require
minutes and several GiB of memory. Keep them for nightly or release qualification:

```sh
node browser/deal/run-two-party-e2e.mjs
```

Bitcoin Core regtest belongs in scheduled or release validation. A final funded
two-browser public-Signet smoke is the last release check, after all deterministic
layers pass; it is not an ordinary regression test.
