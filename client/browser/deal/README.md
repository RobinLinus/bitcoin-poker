# Browser BP52 DEAL worker

This directory runs the real `BP52-DEAL-v1` protocol in a dedicated Web
Worker. It is not a browser substitute: every peer message is a canonical
`bp52-codec` envelope and each attempt follows the fixed 16-envelope
`bp52-protocol` state machine, including the real Bulletproof,
shuffle/uniqueness, partial-decryption, retry, and BIP340 checks.

## Build and static routes

From `client/`, build the raw Worker artifact with the other isolated browser
security boundaries using the pinned rustc/LLVM and clang toolchain:

```sh
./scripts/build-browser-wasm.sh
./scripts/build-browser-wasm.sh --check
```

The relay serves:

| URL | Source |
| --- | --- |
| `/wasm/deal.wasm` | `crates/bp52-relay-server/web/wasm/deal.wasm` |
| `/browser/deal/deal-worker.js` | `browser/deal/deal-worker.js` |
| `/browser/deal/deal-runtime.js` | `browser/deal/deal-runtime.js` |

The Wasm response uses `application/wasm`, and `/wasm/manifest.json` binds its
byte length and SHA-256 digest. The artifact has no imports and is
single-threaded inside its disposable Worker; it needs neither
`SharedArrayBuffer` nor cross-origin isolation. See
[`../../docs/browser-wasm-build.md`](../../docs/browser-wasm-build.md).

Only this artifact enables the explicit pure-Rust BIP340 protocol feature.
Other browser modules retain `rust-secp256k1` and Bitcoin public-key types, so
the build keeps DEAL isolated rather than linking every boundary together.

## Worker interface

Worker requests and responses use the usual `{id, type, ...}` RPC envelope.
The Wasm bridge itself accepts one strict Rust Serde control object for public
initialization fields and uses separate Rust-sized memory regions for the
local identity secret and fresh entropy. The runtime sorts the two identities
by x-only encoding, derives the canonical role, validates every exact length,
and erases staged secrets after initialization.

The JavaScript runtime queries the Wasm module for authoritative input, output,
error, secret, and entropy bounds. It uses named operations for:

- fresh initialization and public snapshot projection;
- concurrent private bundle preparation;
- local envelope generation and peer-envelope acceptance;
- reducer-approved retry start;
- verification-attestation, accepted-body, signature, and accepted-certificate
  export or acceptance;
- one-time sealing of the nine retained local preimages;
- authorized local-preimage reveal to CHAIN; and
- explicit clearing and Worker termination.

Statuses and roles are named Serde values. Authenticated envelopes, accepted
bodies/certificates, identity signatures, verification attestations, and
sealed preimages remain opaque canonical artifacts. JavaScript has no init
magic, fixed record layout, selector table, numeric status table, signature
length rule, or preimage-slot rule.

Inputs are bounded in Rust before decoding and trailing data is rejected.
Re-delivery of the exact envelope at an occupied sequence is idempotent; a
different replay fails. Once both key-proof envelopes establish the required
transcript state, both browsers begin private bundle preparation concurrently.

## GAME integration

The public reducer is the durable coordinator and DEAL is the secret
cryptographic participant:

1. GAME supplies the exact shared configuration, session nonce, game id, and
   canonical identities; WebCrypto supplies a fresh local secret seed.
2. Every generated or received canonical envelope is journaled through GAME.
   The DEAL Worker independently authenticates and verifies peer envelopes.
3. At an accepted or verifier-proven retry terminal, DEAL returns a compact
   identity-signed attestation bound to the exact configuration, session,
   game, attempt, transcript result, and role.
4. GAME verifies that attestation without replaying the heavyweight archive.
   For acceptance, both runtimes also require the same canonical accepted body
   before either identity signature is used.
5. GAME journals both accepted-deal signatures. A retry begins only after the
   reducer has verified both approvals and selected the exact next attempt.

The public journal already contains the authenticated envelopes. No second
proof archive is persisted or passed to GAME, and plaintext preimages never
enter GAME or the relay.

## Sealed handoff and automatic resume

The accepted DEAL Worker keeps a non-cloneable zeroizing owner for all nine
local preimages. It seals them in the protocol's authenticated
XChaCha20-Poly1305 envelope bound to the accepted deal, attempt, role, and body
digest. The application durably stores the accepted certificate, attestation,
and sealed preimages, reads them back, and byte-compares them before clearing
the memory-heavy Worker.

CHAIN receives those three opaque artifacts and the transient unsealing
material directly. It verifies the attestation, both accepted-deal signatures,
encrypted context, and all nine hash locks before activation. It never loads
or replays the proof archive.

Reloading the same current-schema seat route performs this handoff or restore
automatically. There is no player-facing recovery step, recovery-code UI, old
snapshot reader, or migration path. Previous room and artifact schemas are
rejected.

The current prototype keeps both ciphertext and the material needed to recover
it within the same browser origin. This is not protection from same-origin
script execution, profile theft, storage rollback, or site-data loss. A
platform-bound external key and independent rollback anchor remain required
for production custody.

## Measured two-party run

`run-two-party-e2e.mjs` drives two independent Node Worker threads through the
same raw Wasm/Worker interface. The verified run completes a real attempt with
matching accepted certificates and independent signed attestations.

On the development machine, fixed-parameter initialization took about 12.1
seconds per participant. Bundle proof generation took 236–238 seconds and
verification 11–12 seconds. Each Worker's Wasm linear-memory high-water mark
was about 1,389 MiB. The Worker boundary keeps the table responsive, but the
latency and memory cost remain release blockers.

Run the qualification harness after building the artifact:

```sh
node browser/deal/run-two-party-e2e.mjs
```

Ordinary application regressions belong in the fast dependency-injected suite;
this expensive real-proof run is a nightly or release gate.
