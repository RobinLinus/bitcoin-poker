# BP52 command-line client

This is the standalone native, two-human Bitcoin Poker application. It does
not start or use the web client or its application server. Players connect
through a generic libp2p Circuit Relay v2, with DCUtR attempting a direct
hole-punched connection when their networks permit it.

The CLI owns all native-only concerns in this workspace: key and wallet
creation, Esplora access, SQLite persistence, the private CHAIN engine, peer
transport, and both executable binaries. It imports shared protocol and
backend-neutral reducer crates from `dealing/`, `chain/`, and `client/`.

## Play

Build once, then run the client with no arguments:

```sh
cd client-cli
cargo build --release --locked
target/release/bp52-client-cli
```

The wizard asks whether to host, join, or resume. It creates the selected
player's keys on first use, shows the Mutinynet funding address, and walks both
players through the game. For two terminals on one computer, the host can press
Enter at the relay prompt to launch the bundled local relay automatically. A
remote host can instead paste a publicly reachable generic relay multiaddress;
the guest only pastes the host's private invite.

Runtime identity, wallet, refund, checkpoint, and journal files are stored
under `client-cli/.bp52/` when the program is launched from this directory.
Host and guest files are role-scoped so both clients can be tested from one
checkout. Existing runtime files under `client/.bp52/` are not imported.

Native proof generation and verification use all available CPU cores. At the
T6 card-proof boundary both players prepare their independent proofs at the
same time instead of serializing them through the message exchange. A
collision-free attempt should complete its expensive card-proof phase in the
low tens of seconds on a recent multi-core machine. Two clients on one computer
share the same cores and will be slower, and a verified neutral card collision
requires a fresh attempt.

Advanced diagnostic and automation commands remain available through
`target/release/bp52-client-cli --help`. The bundled generic relay can also be
started directly:

```sh
target/release/bp52-p2p-relay /ip4/127.0.0.1/tcp/4001
```

## Develop

Run this workspace's checks independently of the web client:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
```

This is research software for Mutinynet. It is not ready for mainnet or real
funds.
