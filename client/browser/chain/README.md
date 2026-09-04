# Browser BP52 CHAIN worker

This directory is the secret-owning browser boundary for the exact heads-up
100-BB graph profile. Bitcoin transaction decoding, template construction,
sighash calculation, signature verification, streaming graph audit, runtime
witness construction, confirmed-spend monitoring, and Lamport-key erasure all
run in Rust/Wasm. JavaScript performs bounded DTO copies, routes opaque relay
artifacts, and enforces the durable-checkpoint barrier.

The configured profile locks ₿27,000 from each player. Activation creates a
₿53,000 gameplay root containing two ₿20,000 stacks and a ₿13,000 fee reserve.
The blinds are ₿100/₿200, exactly 100 BB deep, and every street permits four
wagers.

## Secret ownership

The Worker owns the local identity/signing capability, all nine accepted local
DEAL openings, deterministic local Lamport derivation state, peer Lamport
public material, the peer's packed transaction-preauthorization vector, the
active graph window, and an encrypted private checkpoint. None of these
plaintext values belongs in a relay payload or GAME snapshot.

The logical graph contains 56,132 nodes and 56,131 possible transactions, but
CHAIN does not retain a fully materialized copy. Setup stream-compiles and
audits one parent/child pair at a time, with at most two compiled Taproot states
live together. Logical/hash/request rows required for setup may be cached
transiently and are dropped afterward. Runtime pages re-derive the path and
active children required for the current decision.

Each possible transaction is authorized by one fixed 64-byte signature.
Across both roles the vectors contain 3,592,384 bytes. A participant keeps only
the opponent's non-derivable vector: 1,469,632 bytes for 22,963 signatures or
2,122,752 bytes for 33,168 signatures in the configured button orientation.
It stores neither its own signature vector nor all transaction/request bytes;
the selected local signature, request, and template are re-derived when used.
The 5,103 local one-time keys use a two-bit state each, a 1,276-byte bitmap,
rather than a second expanded key-state structure.

The encrypted checkpoint and its wrapping material still reside in the same
browser origin and have no external monotonic rollback anchor. Encryption
therefore provides lifecycle separation and corruption detection, not
confidentiality against same-origin script execution, browser-profile theft,
or rollback. Production custody requires an external user-bound key store and
independent rollback protection.

## Initialization and graph preparation

CHAIN initialization uses a strict Rust Serde control DTO, dedicated regions
for secret bytes, and opaque accepted-DEAL, verification-attestation, and
sealed-preimage artifacts. Rust validates configuration and deployment
bindings, canonical identities, the origin, both accepted-deal signatures, the
local DEAL attestation, its encrypted context, and all nine local hash locks.
It never receives or replays the DEAL proof archive.

The graph setup pass deterministically:

1. generates and verifies the local 5,103-key Lamport sequence;
2. audits all 56,132 logical states and 56,131 templates as a bounded stream;
3. commits to and authenticates the common graph root;
4. generates local preauthorization signatures from transient request rows
   without retaining either completed vector after exchange;
5. verifies and stores only the peer's packed vector; and
6. emits a compact identity-signed graph-prepared receipt for GAME.

Both browsers exchange only canonical opaque artifacts. The private Worker
owns the CHAIN exchange codec, graph/context checks, activation-signature
collection, and relay-message identifier. JavaScript never decodes a package
kind, role byte, graph binding, signature, or frame layout.

## Runtime API

The Worker API uses strict named Serde commands and named public views. Its
operations cover:

- accepting an authenticated session event;
- graph-root and peer-preauthorization setup;
- activation signing and confirmed activation;
- tip observation and confirmed child transactions;
- legal betting actions, community-card reveals, showdown, payout, and mature
  timeout construction;
- public card and runtime-status projections;
- encrypted checkpoint restore and verification; and
- explicit zeroization and Worker termination.

Canonical session events, relay payloads, transactions, witnesses, receipts,
and checkpoints remain opaque bytes. CHAIN returns relay work as
`{kind, messageId, payload}`; Rust derives the message identifier from the
immutable context. Public values are descriptive strings and checked fields,
not numeric JavaScript variant tables.

For one selected transition, CHAIN reconstructs the exact active window,
loads the required peer signature, creates the local live signature, validates
the witness and balance transition, and persists the updated one-time-key state
before returning anything usable. The result is a compact signed
runtime-authorization receipt. After the chain confirms the exact transaction,
CHAIN crosses the erasure checkpoint barrier and emits a compact signed
confirmed-state receipt. GAME verifies both receipts and their relationship to
its prior public state.

## Durability barrier

Every secret-bearing mutation completes an IndexedDB write, readback, byte
comparison, and Rust AEAD verification before its Promise resolves. An
OTS-bearing witness, activation signature, or erasure attestation cannot leave
the Worker before the corresponding used/erased state and cached result are
durable. Exact idempotent replays return the cached result; conflicting replays
fail closed.

Reloading the same current-schema seat route restores the private checkpoint
and independently replays the GAME journal. There is no manual recovery screen,
old checkpoint reader, or schema migration. An old room or artifact is rejected
instead of being interpreted by the current runtime.

## Build and checks

Build all browser artifacts together from `client/` using the pinned
rustc/LLVM and clang toolchain:

```sh
./scripts/build-browser-wasm.sh
./scripts/build-browser-wasm.sh --check
```

The relay serves `/wasm/chain.wasm`; `/wasm/manifest.json` binds its byte
length and SHA-256 digest. Validation rejects Wasm imports and missing
boundary-specific exports. See
[`../../docs/browser-wasm-build.md`](../../docs/browser-wasm-build.md).

Run the fast deterministic suite before an expensive funded game:

```sh
node scripts/test-browser.mjs
```

Rust unit tests cover graph streaming, profile counts, signature ownership,
receipt binding, transition rules, checkpoint authentication, and erasure.
Dependency-injected browser contracts cover Worker DTOs, automatic intent
draining, retry identity, persistence failures, and full-hand orchestration.
