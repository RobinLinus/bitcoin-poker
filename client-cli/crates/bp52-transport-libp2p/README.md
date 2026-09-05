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
queue. Both players must be online for setup and play. Game journals and secret recovery state remain local responsibilities.

## Development relay

Any compatible public Circuit Relay v2 node can be used. A minimal generic
relay is included for local development:

```sh
cargo run --locked --bin bp52-p2p-relay -- \
  /ip4/127.0.0.1/tcp/4001
```

It prints a multiaddress ending in `/p2p/<relay-peer-id>`. This generic process
does not host the BP52 web application and stores no player messages.

The legacy CLI transport commands and funded-game wizard have been removed.
Use the library API to integrate a new native client.
