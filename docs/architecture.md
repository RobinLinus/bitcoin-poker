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
| Funding utility | `poker-funding`: parameterized P2WSH deposits, escrow, refund, and activation; its diagnostic Wasm bridge is not integrated with the native Taproot settlement origin |
| Client contracts | `poker-client-ports`: network observation, publication, wallet, transport, and storage contracts |
| Adapters | `poker-esplora`, `poker-store-sqlite`, `poker-transport-libp2p`, `poker-chain-monitor` |
| Bindings | `dealer-wasm`, `poker-wallet-wasm`, `poker-funding-wasm`, `poker-transaction-wasm` |
| Applications | `apps/relay` owns routing/authentication/storage/assets; `apps/web` owns browser interaction |

Core libraries perform no network I/O. Shared settlement records live below both
Bitcoin construction and graph compilation, preventing dependency cycles.
The relay carries opaque bytes; it does not decide poker or transaction validity.

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
