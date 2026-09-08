# Architecture

The on-chain settlement graph is the backbone. A participant prepares all required
counterparty authorizations before activation, follows confirmed transactions,
and can use the stored authorizations for unilateral completion or timed exits.
Cooperative play is an application optimization, not a prerequisite.

## Ownership

| Layer | Packages and responsibilities |
| --- | --- |
| Dealing | `dealer-group`, `dealer-transcript`, `dealer-proofs`, `dealer-uniqueness`, `dealer-protocol`, `dealer-openings`: cryptographic primitives, authenticated setup, replay verification, and selective openings |
| Card authorization | `dealer-bitcoin`: candidate gates and reusable reveal adaptors |
| Poker | `poker-eval`: cards and hand evaluation; `poker-score-ots`: Lamport score certificates |
| Settlement model | `poker-settlement-types`: rules, accounting, roles, and canonical logical records |
| Bitcoin construction | `poker-bitcoin`: scripts, Taproot outputs, witnesses, transactions, and fees |
| Graph | `poker-settlement`: topology planning/verification, configuration binding, materialization, and preparation |
| Player runtime | `poker-session`: one player’s dealer, preparation, live witnesses, observed openings, score usage and recovery journal; `poker-session-wasm`: bounded browser ABI |
| Funding utility | `poker-funding`: parameterized P2WSH deposits, escrow, refund, and activation; its diagnostic Wasm bridge is not integrated with the native Taproot settlement origin |
| Client contracts | `poker-client-ports`: network observation, publication, wallet, transport, and storage contracts |
| Adapters | `poker-esplora`, `poker-store-sqlite`, `poker-transport-libp2p`, `poker-chain-monitor` |
| Bindings | `dealer-wasm`, `poker-wallet-wasm`, `poker-funding-wasm`, `poker-transaction-wasm` |
| Applications | `apps/relay` owns routing/authentication/transient delivery/assets; `apps/web` owns persistence and browser interaction |

Core libraries perform no network I/O. Shared settlement records live below both
Bitcoin construction and graph compilation, preventing dependency cycles.
The relay carries opaque bytes; it does not decide poker or transaction validity.
It uses an in-memory queue, with no game database or recovery service on disk.
Browsers save each received page in encrypted IndexedDB before acknowledging it.
After both seats acknowledge a page, the relay discards its payloads, retaining
only small digests for idempotent retries until the room expires. Preparation
replay reads the browser inbox. Recovery packages are also stored locally before
a move is authorized; a browser worker observes the chain and publishes eligible
defenses while the app remains open. Players are responsible for staying online.

## State and names

`SettlementPreparation` verifies responses against locally derived requests.
`PreparedAuthorizations` means the public inventory is complete, not that a game
is funded or its secrets are durably stored. Snapshot restoration re-verifies
artifacts. `VerifiedAcceptedDeal` and verified opening types preserve their
construction guarantees.

Browser `practice/` owns the current demo's identities, signed move log, and table.
`dealing/`, `funding/`, `bitcoin/`, `workers/`, and `wasm/` provide focused reusable
modules. Funding and Esplora have explicit worker entry points. The seat session
store saves relay credentials; it is not full game recovery.

## Compatibility

Source packages use `dealer-*` and `poker-*`. Cryptographic domain tags, binary
magic, canonical ordering, serialized discriminants, and transaction encodings
retain their specified bytes, including historical `DLOG52` and `BP52` identifiers.
The public dealer Wasm artifact and exports are now `dealer.wasm` and `dealer_*`;
its loader, workers, and artifact manifest were migrated together.

Relay deployment schema 3 is explicitly practice-only and omits funded-game
terms. Existing schema-2 funding examples are diagnostic fixtures under the
client-ports crate, not production deployment configurations. Practice storage
keys and cryptographic/relay message identifiers remain unchanged.

## Deliberate boundaries

The two codecs have different contracts: dealer `Encode` appends to a byte vector;
poker `Encode` uses a checked writer and different length/error semantics. They
remain separate rather than adding a compatibility facade or changing protocol
encoding during repository cleanup. Similarly, `Broadcaster` and
`TransactionPublisher` retain their distinct transaction and identity contracts.
The native libp2p adapter is optional application infrastructure, not a dependency
of the default browser application. Cooperative funding helpers live in an
explicit module and are not used by the on-chain settlement graph.

## Dedicated on-chain browser runner

`apps/web/src/onchain/` owns the integration page, per-player worker, local-role
crypto pool and transient funding worker. Each player derives its own inventory
and exchanges bounded authenticated frames through the relay. Receipt keys and
signing material stay inside that player's local workers. Binary inventory loading
avoids per-worker hex/JSON copies. Game state is encrypted in IndexedDB and the
verified Wasm bytes are cached by hash so script upgrades cannot alter saved games.

The page uses schema 4 `onchainTest` configuration; schema 3 still runs practice.
All game actions follow confirmed graph edges. Each player queries the chain
adapter independently. A changed saved confirmation stops restoration. The chain
adapter is the observation trust boundary; the runtime does not embed Core's
script interpreter. Managed Core tests validate consensus/policy behavior.

## Playable table control

`onchain/table-session.js` coordinates one player per browser seat. A separate
`table.*` relay stream carries public keys, frozen funding terms, return signatures,
readiness bindings and activation signatures. The dealer/preparation worker reads
only `onchain.*` frames; both consumers retain independent durable cursors. The
table never accepts relay hints as a confirmed move: it discovers the spending
transaction through Esplora and asks its player worker to verify the spend again.
`table-controller.js` renders confirmed card IDs, accounting and legal actions
from the session's public view. It never receives the peer's private game keys.

Confirmed showdown witnesses supply public candidate indices. The player runtime
verifies all seven candidate signatures and the claimed hand before exposing the
opponent's two hole cards. Recovery reconstructs this public display by replaying
the confirmed journal. An older pinned engine can retain all signing operations
while a newer engine enriches only its settled display: the newer engine must
successfully replay the exact checkpoint and agree on terminal tip and local role.
A differing script revision cannot silently replace the signing engine.

Consecutive playable hands use a durable successor link between hand-specific
relay rooms. Both players consent to the same confirmed settlement before a
successor is created. Poker stacks come from terminal accounting before fee
reserve disposition; canonical role changes preserve ownership, and the button
alternates between the physical seats. Fresh player workers generate new keys
and a new full-tree preparation for each hand.

`poker-session::rollover` constructs a three-input funding transaction from both
previous payout outputs and a sponsor top-up, verifies the three key-spend
signatures, and derives a multi-recipient cancellation return. Old payout keys
stay inside the previous player worker. Pinned engines still own old game-tree
signing; the current wallet runtime independently restores the settled journal
for the separate payout-spending operation.
