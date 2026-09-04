# Browser BP52 GAME worker

This directory exposes the backend-neutral `bp52-game-session` reducer in a
dedicated Web Worker. It is the durable public coordinator: every accepted
event is checked against the current protocol state, and snapshots contain the
immutable configuration binding plus a bounded hash-chained journal and
compact public receipts. The module performs no HTTP, Esplora, relay, wallet,
storage, clock, or random-number I/O.

GAME is not the secret CHAIN runtime. Identity and Bitcoin signing keys,
Lamport secrets, retained DEAL preimages, peer signature vectors, and witness
construction belong in separate secret-bearing Workers. GAME never receives a
DEAL proof archive or a compiled 56,132-node graph.

## Serde boundary

Browser commands and public projections are strict Rust Serde DTOs. Fixed
identifiers use lowercase hex, opaque canonical artifacts use padded base64,
and `u64` values use decimal strings. Rust rejects unknown fields and converts
display-order transaction identifiers at the single owning boundary.

The JavaScript runtime queries Wasm for its input, output, and diagnostic
bounds, copies one complete DTO, invokes a named operation, and copies the
result immediately. It contains no protocol magic, binary reader/writer,
numeric phase table, event tag table, transaction limit, or signature rule.
Pointers are invalidated by the next ABI call.

The command surface covers:

- initialization from one Rust-validated deployment and exact origin;
- replay from that configuration plus an opaque snapshot;
- application of a named local event from its explicit trusted source;
- authenticated peer exchange using an opaque canonical `SessionEvent`;
- application of compact identity-signed CHAIN receipts;
- current public projection; and
- opaque snapshot export and explicit state clearing.

Peer DEAL envelopes and signatures remain opaque in dispatch results.
Projections use descriptive Serde phase, intent, edge, and authorization names
and include the authoritative Alice/Bob stacks, pot, current actor, board, and
only the public identifiers needed to coordinate Workers.

## Trust boundaries

The generic local-event entry point distinguishes chain observations, wallet
results, and local secret-runtime attestations. A relay event cannot be
presented as any of those sources. Authenticated peer events enter through a
separate operation that binds the canonical sender before applying the reducer.

The disposable DEAL Worker verifies the heavyweight protocol once and emits a
compact identity-signed attestation bound to the exact configuration, session,
game, attempt, and result. GAME validates the attestation and ordinary identity
signatures; it does not allocate Bulletproof generators or replay the archive.

CHAIN similarly reports only compact signed facts:

- a graph-prepared receipt binds the descriptor, graph root, exact profile
  counts, and local role after the streaming audit;
- a runtime-authorization receipt binds one selected parent/child transition,
  transaction, witness policy, and public balance change; and
- a confirmed-state receipt binds the observed transaction and new active
  state.

GAME verifies each receipt and its state-transition relationship before it can
emit a broadcast or next-step intent. It never trusts a derived graph cache
embedded in a snapshot.

## Automatic orchestration

GAME exposes protocol intents, not player setup controls. The application
drains setup-only intents automatically after both ₿27,000 deposits confirm:
DEAL, graph preparation, peer authorization exchange, and activation. A player
action is requested only at a real poker decision. The current deployment
starts each player at ₿20,000 with ₿100/₿200 blinds, exactly 100 BB.

GAME relay outbox identifiers are random 32-byte values generated once and
persisted with the opaque payload before transmission. Retries reuse the same
identifier and bytes; identifiers are not JavaScript transcript hashes.

## Build and checks

Build all isolated browser modules with the pinned rustc/LLVM and clang
toolchain from `client/`:

```sh
./scripts/build-browser-wasm.sh
./scripts/build-browser-wasm.sh --check
```

The relay serves `/wasm/game.wasm` with its byte length and SHA-256 digest
bound by `/wasm/manifest.json`. The artifact must have no Wasm imports. See
[`../../docs/browser-wasm-build.md`](../../docs/browser-wasm-build.md).

Run the dependency-injected browser suite from `client/`:

```sh
node scripts/test-browser.mjs
```

The fast tests cover DTO failures, source provenance, transactional rejection,
snapshot replay, automatic setup, stack/pot conservation, and a complete
21-transition 100-BB hand without generating proofs or contacting a chain.
