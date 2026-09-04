# Browser application boundary

The BP52 browser is a local protocol participant, not a view onto a trusted
game server. Each browser creates its own keys and dealing secrets, verifies
peer artifacts, authorizes only the selected transaction branch, and submits
already validated Bitcoin transactions. The relay stores ordered opaque bytes
and has no poker, wallet, dealing, or signing authority.

```text
player-facing table
  |
  +-- public GAME Worker -------- deterministic session reducer
  +-- disposable DEAL Worker ---- private proofs and card-share secrets
  +-- private CHAIN Worker ------ graph, signatures, monitor, key erasure
  +-- origin/wallet Wasm -------- funding, refund, activation signing
  +-- transaction Wasm ---------- rust-bitcoin parsing and txid checks
  +-- relay adapter ------------- same-origin opaque room transport
  +-- chain adapter ------------- configured Esplora observation/broadcast
```

Rust owns protocol interpretation at every boundary. Strict Serde objects carry
browser commands and public projections. Signed, hashed, relayed, journaled,
sealed, and Bitcoin artifacts keep their canonical Rust encodings and cross
JavaScript only as bounded opaque bytes. JavaScript handles Worker RPC, HTTP,
durability ordering, and presentation; it does not reproduce binary layouts,
variant tags, transaction parsing, sighash rules, or signature validation.

Card-share preimages, private scalars, local Lamport secret keys, wallet keys,
and plaintext CHAIN checkpoints never enter relay messages or the public GAME
snapshot.

## Player experience

The lobby has two decisions: create a table or join an invite. At the table,
the center status is the primary state indicator. It shows funding progress,
then the current poker turn or result. The table also shows both stacks, the
pot, and the ₿100 small blind / ₿200 big blind. Protocol phase names,
preauthorization counts, recovery terminology, retry internals, raw errors,
and debug logs are not player-facing copy; detailed diagnostics go to the
developer console.

The configured game is fixed and requires no stake selection:

| Item | Amount |
| --- | ---: |
| Deposit per player | ₿27,000 |
| Starting stack per player | ₿20,000 |
| Small blind | ₿100 |
| Big blind | ₿200 |
| Starting depth | 100 BB |
| Shared gameplay fee reserve | ₿13,000 |

Once both exact deposits confirm, every setup-only transition runs
automatically in the background: origin/refund authorization, the private
deal, graph audit, peer signature exchange, and activation. The application
does not ask the player to mark a seat ready, start setup, approve a recovery
phase, or click through protocol milestones. Visible action buttons appear only
when the player has a real poker decision. A terminal or safely refundable
game may expose a single contextual return-funds action.

## Room and resume model

A room invite carries only the information needed to claim the second seat.
The player capability is never placed in the URL. Each tab has an independent
random resume handle, and a live route has the form
`#/game/<game-id>/resume/<resume-handle>`. That handle selects one exact
deployment- and schema-bound local record; the client never scans storage or
guesses which seat to restore.

Reloading the same route resumes saved progress automatically and retries an
unfinished idempotent send with the same durable message identifier. There is
no recovery-code import/export UI and no format migration. Records, snapshots,
rooms, or artifacts from any previous schema are rejected rather than adapted.
This clean break keeps one validation path and prevents an old room from being
interpreted under current protocol rules.

A same-origin Web Lock permits one tab to drive a given player capability.
Another tab may observe but cannot concurrently produce setup or gameplay
messages. The relay's joined flag means only that the second capability was
claimed; it is not an online-presence signal.

## Automatic two-input origin

After nonce agreement, each browser creates a single-use secp256k1 staging key
inside the wallet Wasm boundary and displays its native-SegWit funding address.
The UI asks for exactly ₿27,000 and the configured adapter waits for an exact,
confirmed UTXO. Rust validates the outpoint, value, witness script, and
scriptPubKey and emits one opaque staging artifact. JavaScript relays that
artifact without decoding it.

The two staging inputs fund a ₿53,500 shared P2WSH origin after a fixed ₿500
funding fee. Before either browser releases its funding signature, both
independently construct, sign, assemble, persist, read back, and revalidate a
144-block CSV abort refund. That refund returns ₿26,500 to each staging script
after its fixed ₿500 fee. The origin activation pays a further ₿500 and creates
the ₿53,000 gameplay root: two ₿20,000 stacks plus the ₿13,000 fee reserve.

Origin setup is fail-closed and automatic:

1. Both staging artifacts are rechecked against fresh configured-chain facts.
2. Rust reconstructs the same origin package in each browser and verifies the
   peer's opaque package artifact.
3. Each browser releases its refund signature, then durably validates the fully
   signed abort refund.
4. Only then does each browser release its exact funding-input signature.
5. The fully signed origin is persisted, revalidated, and broadcast; Esplora
   observations, not relay hints, determine mempool and confirmation status.
6. A confirmed origin starts DEAL without user interaction.

Every outbox entry is persisted before its relay request and is byte-identical
on retry. Rust/Serde owns the staging, package, signature, assembly, and
chain-fact schemas. JavaScript never signs arbitrary digests or parses these
artifacts.

## DEAL handoff

The isolated DEAL Worker executes the real fixed 16-envelope protocol,
including the Bulletproof, shuffle/uniqueness, partial-decryption, retry, and
BIP340 checks. Both expensive private proof computations are started
concurrently when their prerequisites are present.

At a terminal attempt, DEAL emits a compact identity-signed verification
attestation bound to the exact configuration, session, game, attempt, and
result. GAME verifies that attestation and ordinary identity signatures; it
does not replay the heavyweight proof archive. The accepted certificate,
attestation, and nine sealed local preimages are durably read back before the
memory-heavy DEAL Worker is cleared. CHAIN verifies those opaque artifacts and
all nine hash locks before activation.

The authenticated DEAL envelope journal remains sufficient for public replay.
No duplicate proof archive and no plaintext preimage crosses into GAME,
JavaScript application state, or the relay.

## Streaming graph and compact authorization

The exact 100-BB profile contains 56,132 logical nodes and 56,131 possible
gameplay transactions. CHAIN audits and compiles this graph as a stream. During
the full setup pass at most two compiled Taproot states coexist; logical rows,
record hashes, and sorted request rows needed for that audit are transient and
dropped afterward. The live runtime materializes only the active window needed
to validate or build the next transition. GAME holds compact signed graph,
authorization, and confirmed-state receipts rather than a second graph.

Each possible transaction needs one fixed 64-byte preauthorization signature.
Across both roles that is 3,592,384 bytes. A browser persists only its
opponent's non-derivable packed vector: either 1,469,632 or 2,122,752 bytes for
the configured button assignment. It does not store its own vector or a second
copy of every request or transaction; those are deterministically re-derived
before the selected branch executes. Local Lamport use is represented by a
two-bit state per each of 5,103 keys, a 1,276-byte bitmap. Peer Lamport public
material remains available for verification.

For every action, the private CHAIN Worker validates the active node, obtains
the exact peer preauthorization, generates the local live signature, builds the
witness, and crosses a durable checkpoint barrier before releasing a public
authorization receipt. GAME independently verifies the receipt's identity,
graph, prior-state, next-state, balance, and transaction bindings before it can
emit a broadcast intent.

## Persistence and security limits

DEAL retained preimages and CHAIN checkpoints are authenticated and encrypted
at rest, and every secret-bearing mutation requires IndexedDB write, readback,
byte comparison, and Rust verification before its witness can escape the
Worker. This protects lifecycle separation and detects corruption.

It is not production custody. The staging/identity key and the material needed
to unwrap local recovery state are still held by the same browser origin. The
checkpoint database has no independent monotonic rollback anchor, so a
same-origin compromise, browser-profile theft, or rollback can defeat the local
storage boundary. Clearing site data can also destroy the only usable local
state. Do not use mainnet or real funds.

The configured Esplora genesis and checkpoint are trusted inputs. Raw
transactions and txids are checked by rust-bitcoin Wasm, but the client does
not validate headers or Merkle proofs and cannot safely recover every
same-or-higher-height reorganization after one-time-key erasure. Fixed graph
fees have no fee-bump path. A public relay still needs TLS termination and
IP-aware edge rate limiting.

The DEAL circuit is also expensive. The measured single-thread browser-shaped
run used roughly 1.4 GiB of Wasm linear memory at its high-water point, while
each participant's bundle generation took several minutes on the development
machine. Running it in a disposable Worker preserves UI responsiveness but
does not solve latency or memory use. Independent cryptographic review,
cross-implementation vectors, Bitcoin Core coverage, reorg/race analysis,
external rollback protection, and representative-browser performance work all
remain release gates.

## Test strategy

Most regressions belong below the live browser layer. Pure Rust tests cover
poker policy, graph streaming, receipts, signature ownership, Serde shape
validation, and snapshot replay. Dependency-injected JavaScript tests cover
automatic orchestration, persistence barriers, relay retries, DOM contracts,
and Worker DTO handling with fake chain, relay, clock, storage, and Wasm ports.
The fast whole-hand contract drives the exact 100-BB profile through a
21-transition multi-street game plus settlement, fold, and timeout branches.

Real proof generation, exhaustive graph qualification, Bitcoin Core paths, and
a funded two-browser public-Signet game are deliberately separate expensive
gates. A live browser run is the final smoke check after deterministic tests,
not the primary way to catch application bugs. See [`../TESTING.md`](../TESTING.md).
