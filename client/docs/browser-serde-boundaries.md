# Browser Serde boundary

This is the browser boundary contract. It is a clean break: the current client
has one schema and one decoding path, with no old ABI readers, room migrations,
artifact adapters, or version-negotiation shims.

## Rules

- Every browser-facing command and public-view DTO is a Rust Serde struct or
  enum using camel-case names and unknown-field rejection.
- Signed, hashed, relayed, journaled, checkpoint, DEAL, and Bitcoin artifacts
  retain their canonical Rust codec or consensus encoding. JavaScript carries
  them only as bounded opaque bytes or canonical padded base64.
- Each Wasm module exports its authoritative maximum input, output, and
  diagnostic lengths. JavaScript does not duplicate artifact-size constants.
- JavaScript performs generic bounded memory copies, UTF-8/JSON parsing,
  exact public-view conversion, Worker RPC, persistence ordering, and HTTP
  transport. It contains no protocol magic, numeric variant table, fixed
  record layout, txid byte-order conversion, sighash rule, or signature rule.
- Fixed public identifiers use canonical lowercase hex. Variable opaque
  artifacts use canonical padded base64. Rust validates and decodes both.
- Public `u64` values are serialized as decimal strings and converted to
  JavaScript `BigInt`, avoiding precision loss.
- DEAL and CHAIN remain separate secret-bearing Workers. GAME is a public
  reducer Worker and never receives secret material.
- Commands use named Wasm operations rather than selector integers.

The raw Wasm transport uses the same pattern in each module: query the ABI and
Rust-owned bounds, reserve one input region, invoke one named operation, copy
the bounded output or diagnostic, then invalidate the pointers on the next
call. Secret initialization fields use dedicated Rust-sized regions where they
must be erased independently of public Serde control data.

## Origin, wallet, and transaction inspection

Rust/Serde owns staging observations, origin package construction, exact
signature authorization, transaction assembly, and public chain-fact
projections. Origin package and signature artifacts are opaque to JavaScript.
The wallet module signs only a Rust-authorized digest and never exposes its
private key to the origin module.

The transaction inspector consumes bounded raw consensus bytes and returns a
strict Serde view. rust-bitcoin performs deserialization, canonical
reserialization, txid calculation, input/output projection, and bound checks.
The Esplora adapter queries the Wasm exports for the raw-transaction and output
limits; it does not maintain a JavaScript binary reader or a second limit.

## GAME

GAME receives a strict configuration DTO and builds the canonical session
configuration in Rust. Initialization validates roles, network/profile
bindings, identity ordering, display-order txids, confirmation depths, game
policy, and the opaque origin witness script.

Commands cover fresh initialization, snapshot replay, trusted-source local
events, authenticated peer exchange, compact CHAIN receipts, projection, and
snapshot export. Peer envelopes and signatures stay opaque. Projection phases,
append dispositions, intents, edge kinds, and authorization policies are named
Serde values rather than numeric JavaScript tables.

GAME stores only the immutable configuration binding, its bounded hash-chained
event journal, and compact identity-signed graph, runtime-authorization, and
confirmed-state receipts. It does not own a compiled graph, DEAL proof archive,
Lamport material, transaction-signature vector, or live signing key.

## CHAIN

CHAIN initialization receives strict public configuration plus dedicated
secret regions and opaque accepted-DEAL, attestation, and sealed-preimage
artifacts. Rust validates their exact lengths and cross-context bindings and
erases staged secrets after use.

Named commands cover session-event acceptance, graph setup, activation,
confirmed transactions, poker actions, reveals, showdown, payout, timeout,
card/status projections, and checkpoint restore/verification. Transaction and
checkpoint bytes remain opaque. CHAIN owns the exchange codec, activation
signature collection, and relay-message derivation; JavaScript never parses a
package discriminator, cryptographic role, graph binding, DER signature, or
frame magic.

CHAIN returns relay DTOs containing `{kind, messageId, payload}`. Rust derives
CHAIN message identifiers from the immutable context. The private Worker owns
only peer preauthorization signatures, peer Lamport public material, sealed
DEAL openings, its compact local one-time-key state, and the active graph
window. It regenerates local transaction signatures and deterministic requests
when needed.

## DEAL

DEAL uses strict Serde public initialization plus separate fixed-size regions
for the local identity secret and fresh entropy. Rust owns identity ordering,
all secret/artifact lengths, named status values, retry approval, acceptance
signature validation, and preimage-slot validation.

Authenticated envelopes, accepted bodies/certificates, verification
attestations, signatures, and sealed preimages remain opaque canonical
artifacts. Separate named exports return each artifact; JavaScript has no init
magic, record layout, output selector, numeric status table, or duplicated
signature-length check.

## Relay identifiers

GAME outbox identifiers are random 32-byte values generated once, persisted
beside the opaque payload before sending, and reused for that logical retry.
They are not transcript hashes. CHAIN identifiers come from its Rust-owned
relay DTO. The relay enforces uniqueness and byte binding while treating every
identifier and payload as caller-opaque.

## Required gates

- Rust DTO tests reject unknown fields, wrong enum names, noncanonical
  hex/base64, unsafe values, cross-context artifacts, and operation-shape
  confusion.
- Dependency-injected fake-Wasm tests reject bad exported bounds, invalid
  UTF-8/JSON, unknown fields, unsafe integers, malformed view data, invalid
  memory regions, and failed operation codes.
- Reducer and Worker contracts assert projections and opaque artifact identity
  without a browser or public chain.
- A static source gate rejects protocol magic literals, handwritten binary
  readers/writers, JavaScript transcript hashes, and duplicated transaction
  bounds in production browser runtimes.

All source-level gates pass before the six pinned LLVM Wasm artifacts are built
and published together.
