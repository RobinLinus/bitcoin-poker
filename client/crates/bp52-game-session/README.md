# BP52 game session

`bp52-game-session` is the deterministic orchestration layer between an
application and the existing BP52 DEAL and CHAIN crates. It performs no HTTP,
Esplora, Bitcoin Core, wallet, clock, randomness, or UI work.

The application feeds authenticated `SessionEvent` values and their explicit
trust boundary into `GameSession::apply_from`. The reducer rejects a relay
event presented as a chain observation, wallet action, or local secret-runtime
attestation; then it verifies the event against the exact current protocol
state and returns `SessionIntent` values describing the only safe next work.
The lifecycle covers:

1. confirmed shared origin;
2. the canonical 16-envelope DEAL attempt (including mutually authorized
   verifier-directed retries);
3. compact DEAL verification attestations plus accepted-deal and descriptor
   signatures;
4. identity-signed graph-prepared receipts and verified peer
   preauthorization receipts from the streaming private runtime;
5. fully signed and confirmed activation;
6. signed runtime-authorization and confirmed-state receipts for action,
   reveal, fold, implicit all-in/showdown, payout, and timeout transitions; and
7. terminal settlement.

Snapshots contain the immutable configuration binding, a bounded hash-chained
canonical event journal, and compact public receipts. Loading a snapshot
replays and re-verifies every event through the current DEAL/CHAIN APIs;
derived graph pages and monitor caches are never trusted as serialized GAME
state. Current tags are contiguous and deliberately incompatible with old
room and snapshot formats; there is no migration reader.

Still-private card preimages, Lamport secret keys, and live Bitcoin signing keys
remain in a separate secret runtime. That runtime stream-audits the same
authenticated graph, retains only its peer authorization material and active
window, keeps its own journal-synchronized `ChainMonitor`, and uses the real
CHAIN witness builders. It returns only compact identity-signed public receipts
and verified card identifiers. The public coordinator validates every receipt,
including the prior/next state and balance transition, before broadcasting.

The reducer has no proof-generator cache, DEAL archive, compiled graph,
Lamport bundle, or preauthorization vector. That separation keeps most
orchestration and replay failures reproducible in fast deterministic unit tests
without running the expensive proof or browser integration campaigns.
