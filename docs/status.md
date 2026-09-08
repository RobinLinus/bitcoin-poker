# Dlog on-chain implementation status

The on-chain backbone, playable browser table and dedicated integration runner
are implemented. With the schema-4 MutinyNet configuration, `/` is the playable
table: invite another seat, fund the full graph, choose betting actions and follow
confirmed reveals through payout. Each browser owns one independently keyed player.
`/tools/onchain-e2e` remains the scripted diagnostic runner. Schema-3 deployments
retain practice play; public deployment remains separate work.
The legacy funded application and hash-based proof stack have been removed.

## Implemented

- `PokerRules` separates finite poker economics from legacy dealing. The shared
  planner retains the complete reference topology, capped raises, short-stack
  calls, forced all-in runouts, folds, and pot-only timeout accounting.
- `SettlementConfig` binds the origin outpoint, exact network domain, rules,
  fee policy, and 18 distinct reveal authorization keys into the dlog setup's
  authenticated rules hash. The session anchor binds the known origin escrow.
  Mainnet is rejected. Signet requires a challenge-bound network identifier.
- `SettlementGraph` builds the complete logical tree and materializes exact Bitcoin
  scripts and transactions on demand. It uses only replay-verified dlog card
  candidates. It contains no cooperative-close or witness-free advance leaf.
- Reveal spends complete per-slot Schnorr adaptors. Confirmed signatures disclose
  reusable openings, which the recipient verifies against accepted commitments
  before deriving later card keys. A plain card signature would not provide this
  disclosure. The contract extension is specified in
  `docs/protocols/onchain-reveal-extension.md`.
- Showdown authenticates seven card candidates at the exact transaction sighash,
  then uses the existing card-distinctness checks, five-card evaluator, Lamport
  score certificates, and payout comparison. Both score keys have distinct
  hashes and the exact game-root context.
- `SettlementPreparation` independently derives and verifies every fixed opponent
  signature and reveal package before becoming `PreparedAuthorizations`. Snapshots are
  public artifacts, bound to the activation transaction; restoration re-verifies
  every artifact transactionally. Partial inventories cannot become ready.

## Native integration sequence

1. Generate and persist actual identity, reveal-authorizer, and dealing entropy
   secrets. Establish both canonical identities and their reveal public keys.
2. Establish the origin escrow outpoint. Construct `SettlementConfig`, then put its
   `session_anchor()` and `rules_hash()` into the dlog `GameConfig`.
3. Run authenticated dlog setup and certificate verification. Derive `chain_id()`
   and generate the two game-root-bound score keys. Exchange their public keys.
4. Call `SettlementGraph::compile`, construct the exact activation template, and create
   `SettlementPreparation`. Stream and verify each requested response. Reveal keys are
   controlled by the opponent of the indexed revealer; do not send ordinary
   signatures under these keys.
5. Persist the complete preparation plus all local secret recovery state before
   signing or broadcasting activation. `into_prepared_authorizations()` covers the public authorization
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
  rejected. The [browser benchmark](benchmarks/browser-settlement.md) now covers
  every reference transaction authorization: construction fell from 614.7 seconds
  to roughly 9–10 seconds, with the exact original authorization fingerprint.
  Four crypto workers now parallelize signing and receiver verification. The
  diagnostic harness measures complete setup including IndexedDB persistence,
  authenticated local preparation reload, and fully verified untrusted import
  separately. See the [implementation status](plans/setup-and-recovery-performance.md);
  the dedicated funded integration now adds private game-state recovery and
  independently observed confirmations. See the live
  [campaign report](benchmarks/mutinynet-browser.md).
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
scripts/bitcoin-core-regtest.sh --docker --suite dlog --require
cargo +stable test -p dealer-bitcoin --lib
cargo +stable test -p poker-settlement --test settlement_graph
cargo +stable test -p poker-bitcoin -p poker-settlement-types -p poker-settlement --lib
```

Use `--suite dlog-graph` for just the complete-hand preparation/recovery campaign.
The harness uses an isolated, standard-policy regtest node and cleans it up.

Measured showdown transactions are approximately 9,176 vbytes for Alice and
9,977 vbytes for Bob in the leaf-class fixture. The test fee schedule uses
500/700/11,000/12,000/500 sats for betting/reveal/Alice/Bob/timeout. This yields a
40,100-sat maximum reference gameplay reserve, excluding activation. These are
regtest qualification values, not a current MutinyNet fee recommendation.

## Browser integration and remaining product work

`poker-session` and `poker-session-wasm` own each player's real identities, dealer,
preparation, observed openings, one-time score certificates and exact pending
transactions. The browser persists encrypted recovery state, pins each game's
Wasm engine and checks saved confirmations on restore. The schema-4 MutinyNet
configuration permits the dedicated runner to fund the Taproot origin only after
a signed return is durable. Mainnet stays rejected.

Full-tree browser hands have confirmed through payout. The live report separates
setup from confirmation waits and identifies each script build. The session Core
suite covers full hand, fold, refund and unilateral CSV timeout, including exact
pending-transaction restoration. Preparing the full graph does not broadcast its
mutually exclusive branches.

The playable table uses host-sponsored test funding for both 20,000-sat stacks.
It supports invitations, full preparation, manual betting, automatic required
reveals/showdown, confirmed balances, timeout claims and reload recovery.
Remaining product work: general wallet/cash-out UX, trustless multi-depositor
funding, automatic reorg reconciliation and public deployment. Its pre-signed
origin return is not a unilateral two-depositor refund protocol.

No independent cryptographic audit is claimed for the adaptor extension. Uncommitted legacy application changes were backed up outside the repository
before removal.

## Repository cleanup

The root workspace, dealer/poker package names, unified browser tree, explicit
worker entries, schema-3 practice deployment, and parameterized native funding
utilities are implemented. The older funding Wasm bridge retains its diagnostic
profile. The on-chain session uses its own Taproot origin funding adapter.

The playable table supports consecutive hands with carried poker balances, an
alternating dealer, fresh keys and payout rollover plus a host fee top-up. Both
players confirm Next hand, and saved URLs follow the successor hand. See
[consecutive-hand qualification](benchmarks/consecutive-hands.md) for completed
Core tests and the live MutinyNet funding checkpoint.
