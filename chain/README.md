# BP52-CHAIN-v1 reference implementation

This Rust workspace implements the finite two-player Bitcoin poker
transaction-tree prototype described in
[`BP52-CHAIN-v1-agent-implementation-spec.md`](BP52-CHAIN-v1-agent-implementation-spec.md).
It consumes the sibling [`BP52-DEAL-v1`](../dealing/) implementation.
The two directories therefore form one source distribution even though Cargo
commands are run from their separate workspace roots.

Implemented components include the exhaustive five-card evaluator, canonical
descriptor/state codecs, one-time Lamport score certificates, the complete
descriptor-derived 56,132-node 100-big-blind logical graph, executable
Taproot/Tapscript predicates, deterministic top-down descendant transactions,
authenticated graph/signature exchanges, and a confirmation-bound runtime.
The production path audits the graph as a stream and retains only a bounded
active window; the exhaustive campaign is available as an ignored long-running
test.

At a betting node, only the opponent's signature for each candidate child is
exchanged. The actor selects one action by adding their live Bitcoin signature
to that exact transaction; betting actions use no Lamport witness. Separate
24-bit Lamport certificates authenticate Alice's and Bob's dynamic showdown
scores. Each nonterminal P2TR output also contains a hidden, unspendable state
commitment tapleaf, so its output key and txid commit to the complete logical
stack/pot/reserve state without publishing a separate data output.

Fixed-limit all-ins are implicit and graph-derived. A `Bet` or `Raise` target is
capped by both players' effective stacks, so unmatchable excess remains in the
larger player's refundable remainder. The responder retains `Fold` and `Call`;
after a matching call, the existing two-party reveal transactions run out every
remaining community card without creating further betting states. There is no
separate all-in action code, amount witness, or two-player side pot.

The funding-readiness API is role-local and capability based. CHAIN audits the
complete graph as a stream, verifies the peer's exact packed
preauthorizations, and checks the fresh score-key sequence plus all nine
accepted local share preimages. GAME receives compact identity-signed receipts,
not graph material or secret inventories. CHAIN retains only the peer's
non-derivable signature vector, peer Lamport public material, and a two-bit
state per local Lamport key. Setup request rows are transient and dropped;
local transaction signatures, Lamport keys, and active requests are re-derived
when selected.

Unused Lamport keys can be persisted only through the authenticated-ciphertext
API: `LamportSecretKey::seal_at_rest` verifies the corresponding compiled
public key, creates a versioned XChaCha20-Poly1305 envelope, and erases the live
owner only after encryption succeeds. `LamportStorageKey` is deliberately
non-cloneable and non-exportable. Supplying, backing up, and protecting its
32-byte key through an OS keyring or HSM remains an application responsibility.

> This is research software. Mainnet and real-funds use are disabled pending
> every production-readiness gate in the specification.

The compiler uses a noncircular two-stage model: the descriptor names a
pre-existing origin escrow, preparation exposes the exact gameplay-root
output, and a canonical activation transaction links the two. Origin creation
is intentionally outside CHAIN; the browser client supplies the two-input
contribution package and a fully signed CSV abort refund before funding can be
broadcast. See
[`ADR-0001`](docs/ADR-0001-reference-encoding-and-compiler-profile.md).

The reference v1 settlement profile is pot-only. Every fold, timeout, and
showdown returns both players' uncommitted remaining stacks, distributes only
the pot according to the outcome, and assigns unused fee reserve under the
committed fee policy. The reserved `SlashRemainingStack` descriptor value is
rejected before compilation.

`HEADS_UP_FIXED_LIMIT_V1_PROFILE` defines the executable profile with ₿27,000
from each player. After the ₿500 funding and activation fees, its ₿53,000
gameplay root contains two ₿20,000 (100-big-blind) stacks and a ₿13,000 shared
fee reserve. Blinds are ₿100/₿200, each street
permits the full four wagers, and timeout delays are 144 blocks. The complete
graph has 56,132 nodes, 56,131 possible gameplay transactions, and a
33-transaction maximum gameplay path whose ₿12,556 fee leaves ₿444 of reserve
slack. See the ADR for the full economics and relay-floor
assumption.

Deployments select their chain identity and backend separately; the profile is
not tied to Mutinynet or Esplora. Applications need not copy its values. The profile's `descriptor` constructor
accepts only session-specific fields, `fee_policy` returns the committed fee
schedule, and `origin_output`, `gameplay_root_output`, and `activation_template`
produce or expose the exact outputs and canonical activation transaction. The
profile also exposes role-indexed inventory accessors. This graph requires
5,103 Lamport score keys and all nine local deal-share preimages from each
player. For an Alice-button hand, Alice and Bob respectively contribute
33,168 and 22,963 fixed preauthorizations; for a Bob-button hand the counts are
33,169 and 22,962. Exactly one 64-byte signature authorizes each possible
gameplay transaction, for 3,592,384 bytes across both roles. In the checked-in
Alice-button deployment, Alice stores Bob's 1,469,632-byte peer vector and Bob
stores Alice's 2,122,752-byte peer vector. Reversing the button changes those
sizes by one signature to 1,469,568 and 2,122,816 bytes. The local vector is
never retained because its selected signature can be re-derived on demand.
`inventory(button)` returns the exact values, and the streaming profile check
validates them before activation.

Every timeout uses two transaction signatures over the same fixed template:
the defaulting player exchanges a preauthorization before activation, while
the beneficiary keeps the second signature private until CSV maturity. This
lets the beneficiary settle unilaterally without allowing either party to
replace the committed refund outputs.

Network binding is exact. Mainnet, testnet3, and regtest retain their
consensus-order genesis identifiers. Because every BIP325 signet shares the
same genesis block, a raw signet genesis is rejected. Mutinynet descriptors
instead commit to that genesis and the complete canonical Mutinynet challenge
script under a dedicated tagged hash. Runtime broadcast compares this exact
descriptor identifier with the connected backend, so a default-signet node
cannot impersonate Mutinynet.

Run the normal development gates from this directory:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --no-deps --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

Run the complete 56,132-node fixed-limit streaming campaign separately. It is
ignored by the normal suite because it is an exhaustive qualification check:

```sh
cargo test -p bp52-chain-compiler \
  full_reference_oracle_has_bounded_compiled_and_retained_state \
  -- --ignored --nocapture
```

Opt-in leaf and full materialized-graph path campaigns can be run against a
real, isolated Bitcoin Core node:

```sh
scripts/bitcoin-core-regtest.sh --require
scripts/bitcoin-core-regtest.sh --suite paths --require
```

The path suite covers exact 33-transaction Bob-win and split games, unequal-stack
all-in runout and refund accounting, early fold, and action/reveal/showdown
timeout branches, plus exact-fee routes for the ₿27,000-per-player
deployment profile,
with full-stack remainder refunds checked at every terminal output.
Package/race behavior, production origin
funding, persistence/recovery, signet, and other listed cases remain
production-readiness gates. See
[`bitcoin-core-regtest.md`](docs/bitcoin-core-regtest.md) for exact coverage and
the native/cached-Docker launch modes. The in-process Script interpreter is not
a substitute for Bitcoin Core validation.

The reference profile and the two specification errata used by this workspace
are recorded in
[`ADR-0001`](docs/ADR-0001-reference-encoding-and-compiler-profile.md).
