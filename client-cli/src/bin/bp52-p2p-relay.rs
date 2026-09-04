//! Minimal generic Circuit Relay v2 node for development and self-hosting.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use bp52_transport_libp2p::load_or_create_identity;
use futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, identify, noise, ping, relay, tcp, yamux};

const USAGE: &str = "usage: bp52-p2p-relay [listen-multiaddr]";
const DEFAULT_IDENTITY_PATH: &str = ".bp52/relay-peer.key";
const BP52_MAX_CIRCUIT_BYTES: u64 = 64 * 1024 * 1024;
const BP52_MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let listen = arguments
        .next()
        .map(|value| value.into_string().map_err(|_| USAGE))
        .transpose()?
        .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/4001".to_owned())
        .parse::<Multiaddr>()?;
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }

    let identity = load_or_create_identity(Path::new(DEFAULT_IDENTITY_PATH))?;
    let peer_id = identity.public().to_peer_id();
    let mut relay_config = relay::Config::default();
    relay_config.max_circuit_bytes = BP52_MAX_CIRCUIT_BYTES;
    relay_config.max_circuit_duration = BP52_MAX_CIRCUIT_DURATION;
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| Behaviour {
            relay: relay::Behaviour::new(peer_id, relay_config),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/bp52/generic-relay/1".to_owned(),
                key.public(),
            )),
        })?
        .with_swarm_config(|configuration| {
            configuration.with_idle_connection_timeout(Duration::from_secs(60 * 60))
        })
        .build();
    swarm.listen_on(listen)?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("relay: {address}/p2p/{peer_id}");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                info,
                ..
            })) => swarm.add_external_address(info.observed_addr),
            _ => {}
        }
    }
}
