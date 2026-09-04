# BP52 native peer transport

This crate replaces the application-specific HTTP room/message relay for a
native client. It carries opaque BP52 artifacts between exactly two players
using libp2p:

- Noise authenticates each peer's durable Ed25519 transport identity;
- a private invite capability HMAC-authenticates every ordered message;
- Circuit Relay v2 introduces peers behind NAT and remains a fallback path;
- DCUtR attempts to upgrade that path to a direct TCP or QUIC connection;
- request/response acknowledgements prevent the sender from advancing before
  the receiver has accepted a message.

The relay is not trusted with poker or Bitcoin state. It sees encrypted libp2p
traffic and needs no game database, room API, player token, or durable message
queue. Both players must be online for setup and play. Canonical GAME journals
and secret-bearing CHAIN snapshots remain local responsibilities.

## Development relay

Any compatible public Circuit Relay v2 node can be used. A minimal generic
relay is included for local development:

```sh
cargo run --locked --bin bp52-p2p-relay -- \
  /ip4/127.0.0.1/tcp/4001
```

It prints a multiaddress ending in `/p2p/<relay-peer-id>`. This generic process
does not host the BP52 web application and stores no player messages.

## CLI transport harness

The host creates a durable transport identity and prints a private invitation:

```sh
cargo run --locked -p bp52-client-cli -- \
  peer-host <relay-multiaddr>
```

The other player joins with that invitation:

```sh
cargo run --locked -p bp52-client-cli -- \
  peer-join <invite>
```

No key setup is required. The commands create their durable identities on
first use and reuse them afterward:

- host: `.bp52/host-peer.key`
- guest: `.bp52/guest-peer.key`
- development relay: `.bp52/relay-peer.key`

The transport is also used by the interactive funded-game wizard. Run
`cargo run --locked` from the `client-cli/` directory to start it without
arguments.
