# Bitcoin Poker

This repository is the home of the Bitcoin Poker project.

For an architectural explanation of how a private poker hand is represented
and settled with Bitcoin transactions, see the
[`high-level protocol specification`](HIGH_LEVEL_SPEC.md).

The project currently contains four Rust workspaces in one source distribution:

- [`dealing/`](dealing/) implements the hidden-card dealing protocol.
- [`chain/`](chain/) implements the finite Bitcoin transaction tree and poker
  runtime that consumes an accepted deal.
- [`client/`](client/) implements the web client, its application relay, and
  shared backend-neutral game, origin, and chain ports.
- [`client-cli/`](client-cli/) implements the standalone two-human terminal
  client, native wallet and durable state, and relay-assisted hole punching.

The workspaces are independently invocable, but `chain/` deliberately uses
path dependencies from `dealing/`, while both clients use shared protocol
crates. Copy or archive all four together.

To work on the dealing implementation:

```sh
cd dealing
cargo test --workspace --all-targets --locked
```

Use the same commands from `chain/`, `client/`, and `client-cli/` for those
implementations.

Before creating a source archive, run:

```sh
scripts/check-source-integrity.sh --archive-smoke
```

This verifies that the locally hardened proof backend is present as ordinary
source files and that all four locked workspaces survive `git archive`.

Both the browser and two-process native CLI coordinate the complete configured research flow: two
₿27,000 deposits, a jointly authorized origin and abort refund, the private
deal, streamed transaction-graph preparation, activation, poker actions, and
terminal payout. Its table uses ₿20,000 stacks with ₿100/₿200 blinds, exactly
100 big blinds per player. Setup advances automatically once both deposits
confirm; the visible controls are reserved for actual poker decisions.

This remains research software and is not ready for real funds. Read the
repository [security policy](SECURITY.md) before integrating it.
