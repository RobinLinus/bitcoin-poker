# Dlog on-chain implementation status

Milestone 1 is **not yet complete or deployed**. The native on-chain backbone is
implemented and tested. The browser still runs its existing practice/funded
flows; it does not yet call the new dlog graph.

## Implemented

- `PokerRules` separates finite poker economics from legacy dealing. The shared
  planner retains the complete reference topology, capped raises, short-stack
  calls, forced all-in runouts, folds, and pot-only timeout accounting.
- `DlogParameters` binds the origin outpoint, exact network domain, rules,
  fee policy, and 18 distinct reveal authorization keys into the dlog setup's
  authenticated rules hash. The session anchor binds the known origin escrow.
  Mainnet is rejected. Signet requires a challenge-bound network identifier.
- `DlogGraph` builds the complete logical tree and materializes exact Bitcoin
  scripts and transactions on demand. It uses only replay-verified dlog card
  candidates. It contains no cooperative-close or witness-free advance leaf.
- Reveal spends complete per-slot Schnorr adaptors. Confirmed signatures disclose
  reusable openings, which the recipient verifies against accepted commitments
  before deriving later card keys. A plain card signature would not provide this
  disclosure. The contract extension is specified in
  `dealing-dlog/docs/ONCHAIN_REVEAL_EXTENSION.md`.
- Showdown authenticates seven card candidates at the exact transaction sighash,
  then uses the existing card-distinctness checks, five-card evaluator, Lamport
  score certificates, and payout comparison. Both score keys have distinct
  hashes and the exact game-root context.
- `DlogPreparation` independently derives and verifies every fixed opponent
  signature and reveal package before becoming `ReadyDlogGame`. Snapshots are
  public artifacts, bound to the activation transaction; restoration re-verifies
  every artifact transactionally. Partial inventories cannot become ready.

## Native integration sequence

1. Generate and persist actual identity, reveal-authorizer, and dealing entropy
   secrets. Establish both canonical identities and their reveal public keys.
2. Establish the origin escrow outpoint. Construct `DlogParameters`, then put its
   `session_anchor()` and `rules_hash()` into the dlog `GameConfig`.
3. Run authenticated dlog setup and certificate verification. Derive `chain_id()`
   and generate the two game-root-bound score keys. Exchange their public keys.
4. Call `DlogGraph::compile`, construct the exact activation template, and create
   `DlogPreparation`. Stream and verify each requested response. Reveal keys are
   controlled by the opponent of the indexed revealer; do not send ordinary
   signatures under these keys.
5. Persist the complete preparation plus all local secret recovery state before
   signing or broadcasting activation. `ready()` covers the public authorization
   inventory; it does not certify application-level secret durability.
6. Derive every outgoing template locally. Add only the acting player's live
   authorization (or complete their reveal adaptors), broadcast, and wait for
   confirmation before advancing. Extract reusable openings from confirmed
   reveal witnesses. A relay message is not a confirmation.
7. On refusal, use the stored opponent signature plus the beneficiary's live
   signature after the exact CSV deadline. At showdown persist the one-time score
   certificate before broadcasting, including the fact that its key was used.

The managed Core graph test is an executable example of this sequence, including
preparation snapshot restoration and using only observed counterparty openings
for later card signatures.

## Qualification performed

- Native reference topology: 56,132 nodes and maximum 33 gameplay transitions;
  exact fee bound; representative states compiled; wrong parameter bindings
  rejected. This does not benchmark preparation of every reference transaction.
- Real Core confirms all nine candidate card gates and rejects wrong candidates.
- Real Core confirms both three-slot reusable reveals and a later card spend;
  duplicate slot signatures fail; both reveal-refusal timeout scenarios settle.
- Real Core confirms Alice-win, Bob-win, and split showdown/payout spends.
- Real Core confirms a complete funded short-stack hand through activation,
  both hole deliveries, an all-in call, all board reveals, both showdowns, and
  payout. Its 26-node graph is fully prepared before activation. Every encountered
  timeout is rejected before CSV and accepted by Core policy after maturity.
- Corrupted public preparation snapshots fail without partially installing
  artifacts; complete restored inventories can finish the same hand.

Run from the repository root:

```sh
chain/scripts/bitcoin-core-regtest.sh --docker --suite dlog --require
cargo +stable test --manifest-path dealing-dlog/Cargo.toml -p dlog52-bitcoin --lib
cargo +stable test --manifest-path chain/Cargo.toml -p bp52-chain-compiler --test dlog_graph
cargo +stable test --manifest-path chain/Cargo.toml -p bp52-chain-bitcoin -p bp52-chain-types -p bp52-chain-compiler --lib
```

Use `--suite dlog-graph` for just the complete-hand preparation/recovery campaign.
The harness uses an isolated, standard-policy regtest node and cleans it up.

Measured showdown transactions are approximately 9,176 vbytes for Alice and
9,977 vbytes for Bob in the leaf-class fixture. The test fee schedule uses
500/700/11,000/12,000/500 sats for betting/reveal/Alice/Bob/timeout. This yields a
40,100-sat maximum reference gameplay reserve, excluding activation. These are
regtest qualification values, not a current MutinyNet fee recommendation.

## Remaining work before the milestone can be called complete

1. Expose the native graph and preparation in the browser worker/WASM API; sign
   actual graph sighashes using random, durable keys instead of practice inputs.
2. Wire the funding, relay, confirmation monitor, and table controls to that
   API. Every button must select an actual graph edge and every displayed state
   must follow a confirmed transaction. Add visible timeout claims and payout.
3. Persist and recover local secrets, setup replay state, preparation artifacts,
   score-key usage, observed openings, pending broadcasts, and the active chain
   cursor. Public preparation snapshots alone do not solve game recovery.
4. Complete preactivation abort/refund handling and qualify refresh, disconnect,
   and opponent-refusal behavior from real browser sessions.
5. Benchmark full-profile graph preparation and verify browser memory limits;
   52 adaptors per reveal can be expensive across the full tree. Measure the
   deployed fee/reserve and run complete MutinyNet hands before publishing.

No independent cryptographic audit is claimed for the adaptor extension. Legacy
application changes already present in the working tree were preserved.
