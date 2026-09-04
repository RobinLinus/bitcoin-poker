# Bitcoin Core regtest qualification

The opt-in harness in this workspace submits BP52 script-path spends to a real
Bitcoin Core regtest node. Bitcoin Core's `testmempoolaccept`,
`sendrawtransaction`, and block-generation RPCs are the authority for the
consensus and policy result. The crate's in-process Script evaluator is not
called by this test and is not a substitute for Bitcoin Core validation.

The workspace-private `bp52-core-test-support` crate provides the managed RPC
client and a sequential `PathExecutor` to every integration-test crate. The
executor pins each transition to the currently confirmed outpoint, checks
one-input graph shape and value conservation, obtains Core's policy verdict,
broadcasts and mines the transaction, and verifies the selected child output in
the active UTXO set before advancing. The executor also checks that the fresh
best block actually contains the broadcast txid. It retains an ordered
transcript of confirmed labels, txids, spent outpoints, next outputs, block
hashes, and heights for path and runtime-monitor assertions. A caller can
checkpoint the active tip for diagnostics. Independent sibling scenarios use
distinct funded roots: Core re-adds transactions after `invalidateblock` and
does not provide a `clearmempool` RPC, so in-process rollback is not treated as
a clean test reset. Terminal execution additionally requires every payout
output to appear unspent in Core's active UTXO set.

The harness has two layers: a focused leaf-class smoke test and a release-mode
materialized-graph path campaign. Passing both substantially exercises section
37, but does not by itself clear the remaining funding, persistence, adversarial
mempool, reorg, or signet production-readiness gates.

## Running it

From the `chain` workspace:

```sh
scripts/bitcoin-core-regtest.sh
```

The default `all` suite runs the two explicit ignored Core campaigns. Suites
can be selected individually:

```sh
scripts/bitcoin-core-regtest.sh --suite leaf
scripts/bitcoin-core-regtest.sh --suite paths
scripts/bitcoin-core-regtest.sh --suite mutinynet
scripts/bitcoin-core-regtest.sh --suite all
```

`leaf` invokes only `bitcoin_core_regtest_leaf_classes`; `paths` invokes the
exact `bitcoin_core_regtest_graph_paths` campaign in release mode. The path
campaign materializes eight complete 56,132-node 100-big-blind graphs plus
three smaller descriptor-pruned all-in graphs. The same filter also runs seven
small-value smoke-profile paths using their exact class fees. The full-profile campaign
is intentionally not run as a debug test. Keeping the names stable is part of
the private launcher/test contract.

`mutinynet` runs only the seven-path small-value campaign, which is useful for
quickly rechecking its exact fee floor without materializing the full
graphs.

The launcher prefers a native `bitcoind` plus `bitcoin-cli`. If they are not on
`PATH`, it uses the already-cached Bitcoin Core 31.1 image pinned as
`bitcoin/bitcoin@sha256:da25cedc66b1daefff9f412ee196c901a899c3fa68a33b20849c3e08b5c40d63`
when available. It never pulls an image or downloads a binary. If neither
backend is present, the default mode prints `SKIP` and exits successfully. CI
and release qualification should require execution instead:

```sh
scripts/bitcoin-core-regtest.sh --require
```

Choose one backend explicitly with `--native` or `--docker`. An explicit
backend request fails if that backend is unavailable. The native mode starts a
daemon with a fresh temporary datadir and the Docker mode starts an ephemeral
container; both are stopped on exit. `--keep-datadir` retains a native
datadir for diagnosis.

The image can be replaced with another already-cached reference, preferably a
digest-pinned one:

```sh
BP52_CORE_IMAGE='bitcoin/bitcoin@sha256:<digest>' \
  scripts/bitcoin-core-regtest.sh --docker
```

`BP52_BITCOIND`, `BP52_BITCOIN_CLI`, `BP52_DOCKER`, and `BP52_CARGO` may point
to specific executables. The other `BP52_CORE_*` variables form a private
contract between the launcher and the ignored Rust integration test; normal
users should not set them manually.

The underlying Rust tests are marked `#[ignore]`, so ordinary `cargo test`
runs cannot accidentally report Core qualification. Invoking an ignored test
directly without a managed node prints a clear `SKIP`. With
`BP52_REQUIRE_BITCOIND=1`, that situation is an error.

## Covered today

Each valid spend is first accepted by `testmempoolaccept`, then broadcast and
mined. The launcher explicitly sets `acceptnonstdtxn=0` (regtest normally
permits non-standard transactions) and does not lower the minimum relay fee.
The synthetic state output pays a ₿10,000 transition fee so the large
showdown witnesses clear the normal fee floor.

| Leaf class | Accepted and confirmed | Rejected mutations |
| --- | --- | --- |
| Betting action | Opponent preauthorization plus the actor's live signature on the selected transaction | Wrong opponent or actor signature |
| Share reveal | Two signatures plus the committed shares | Wrong Bitcoin signature; wrong share preimage |
| Timeout | Defaulting player’s fixed preauthorization plus beneficiary’s 64-byte `SIGHASH_DEFAULT` signature after relative maturity | Early spend; wrong or missing signature; beneficiary-signed altered-output transaction with no matching opponent preauthorization |
| Alice showdown | Card openings, Eval5 witness, score certificate, signatures | Wrong card opening; wrong Lamport score certificate |
| Bob payout | Card openings, two authenticated score certificates, comparison, live signature | Wrong card opening; wrong Bob score certificate; wrong live signature |

The test also verifies that the RPC endpoint identifies itself as `regtest`.
All funding outputs are created and confirmed by the isolated node's wallet.

The full-path suite additionally executes exact transactions from a distinct
confirmed origin escrow through activation and the materialized graph. It
checks every parent linkage and value transition with Core, confirms terminal
payout outputs as live UTXOs, and covers:

- the section-37 mixed Bob-win route;
- maximal 33-gameplay-transaction Bob-win and split routes;
- an immediate preflop fold;
- a deep river action timeout;
- a second river-reveal timeout;
- an Alice-showdown timeout;
- a Bob-payout timeout;
- an unequal-stack short raise followed by a fold, including both stack
  refunds;
- an unequal-stack short raise and call followed by the forced board runout
  and Bob-win showdown; and
- a reveal timeout during that forced runout.

The Mutinynet-profile extension repeats Bob-win, split, fold, action-timeout,
river-reveal-timeout, Alice-showdown-timeout, and Bob-payout-timeout paths with
only a small synthetic origin. It uses class-specific
₿224/₿264/₿2,203/₿3,089/₿232 class fees and checks `fee >= vsize` before
asking Core to accept each spend. This qualifies the ₿1/vB assumption under
the launcher's standard-only node policy rather than relying on the separate
high-fee fixture.

Activation is deliberately outside the 33 gameplay transitions. Each scenario
uses a fresh origin so sibling branches do not inherit mempool state from a
previous scenario. The fixtures install the complete authenticated opponent
preauthorization sets, including the defaulting player’s output-binding timeout
signature; the beneficiary supplies the second signature only after CSV. Every
terminal case checks that uncommitted stack remainders are refunded and that
only the pot and unused fee reserve are distributed according to the signed
policy. At the
maximal Bob terminal, Core first accepts both the Bob-win and split siblings
while their parent is unspent, then rejects the split sibling after Bob-win is
confirmed.

## Not yet covered

The path campaign deliberately does **not** qualify:

- production origin funding authorization (the test wallet creates a
  test-only `P2WSH(OP_TRUE)` origin before the real activation/root graph);
- every node of the 56,132-node full profile graph, every node of each
  descriptor-pruned graph, or every possible betting history;
- broader sibling race coverage beyond the terminal Bob-win/split check,
  stable child txids across alternate valid witnesses, or descendant validity
  after parent witness insertion;
- package relay, pinning, replacement, restart, or reorg behavior;
- crash-safe monitor recovery and full public audit-archive replay; or
- signet behavior.

Those remain explicit work items and production-readiness gates. Mainnet stays
disabled independently of this harness.
