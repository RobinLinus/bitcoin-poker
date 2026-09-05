//! Native two-player BP52 transport using authenticated libp2p streams.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{PeerId, StreamProtocol, dcutr, identify, noise, ping, relay, tcp, yamux};
use poker_client_ports::{MAX_PEER_MESSAGE_BYTES, PeerMessage};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

const PROTOCOL: StreamProtocol = StreamProtocol::new("/bp52/peer-message/1");
const IDENTIFY_PROTOCOL: &str = "/bp52/native-client/1";
const INVITE_PREFIX: &str = "bp52p2p1:";
const AUTH_TAG: &[u8] = b"BP52/p2p-message-auth/v1";
const HELLO_KIND: &str = "hello";
const CHANNEL_CAPACITY: usize = 64;

/// A private invitation sufficient to locate and authenticate the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invite {
    relay_address: Multiaddr,
    host_peer_id: PeerId,
    capability: [u8; 32],
}

impl Invite {
    /// Create an invite after validating that the relay address ends in a peer id.
    ///
    /// # Errors
    ///
    /// Rejects an address without a relay peer id or an all-zero capability.
    pub fn new(
        relay_address: Multiaddr,
        host_peer_id: PeerId,
        capability: [u8; 32],
    ) -> Result<Self, TransportError> {
        validate_relay_address(&relay_address)?;
        if capability == [0; 32] {
            return Err(TransportError::InvalidInvite);
        }
        Ok(Self {
            relay_address,
            host_peer_id,
            capability,
        })
    }

    /// Encode the invitation as a pasteable, URL-safe string.
    #[must_use]
    pub fn encode(&self) -> String {
        let wire = InviteWire {
            relay: self.relay_address.to_string(),
            host: self.host_peer_id.to_string(),
            capability: URL_SAFE_NO_PAD.encode(self.capability),
        };
        let json = serde_json::to_vec(&wire).unwrap_or_default();
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    /// Decode and strictly validate a pasteable invite.
    ///
    /// # Errors
    ///
    /// Rejects the wrong prefix, malformed Base64/JSON, or invalid embedded values.
    pub fn decode(encoded: &str) -> Result<Self, TransportError> {
        let payload = encoded
            .strip_prefix(INVITE_PREFIX)
            .ok_or(TransportError::InvalidInvite)?;
        let json = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TransportError::InvalidInvite)?;
        let wire: InviteWire =
            serde_json::from_slice(&json).map_err(|_| TransportError::InvalidInvite)?;
        let relay_address =
            Multiaddr::from_str(&wire.relay).map_err(|_| TransportError::InvalidInvite)?;
        let host_peer_id =
            PeerId::from_str(&wire.host).map_err(|_| TransportError::InvalidInvite)?;
        let capability_bytes = URL_SAFE_NO_PAD
            .decode(wire.capability)
            .map_err(|_| TransportError::InvalidInvite)?;
        let capability = capability_bytes
            .try_into()
            .map_err(|_| TransportError::InvalidInvite)?;
        Self::new(relay_address, host_peer_id, capability)
    }

    /// Public host identity authenticated by libp2p Noise.
    #[must_use]
    pub const fn host_peer_id(&self) -> PeerId {
        self.host_peer_id
    }

    /// Public circuit-relay address used for introduction and fallback.
    #[must_use]
    pub fn relay_address(&self) -> &Multiaddr {
        &self.relay_address
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteWire {
    relay: String,
    host: String,
    capability: String,
}

/// Whether the active path is direct or still circuit-relayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPath {
    /// A direct TCP or QUIC connection between the players.
    Direct,
    /// A Circuit Relay v2 fallback path.
    Relayed,
}

/// Events emitted by the peer networking task.
#[derive(Debug)]
pub enum PeerEvent {
    /// The host's circuit reservation is active and its invite may be shared.
    RelayReady,
    /// The authenticated opponent is reachable.
    Connected {
        /// Noise-authenticated libp2p identity.
        peer_id: PeerId,
        /// Best currently observed path.
        path: ConnectionPath,
    },
    /// A direct connection replaced or supplemented the relayed path.
    PathChanged(ConnectionPath),
    /// A direct upgrade failed; the authenticated relay connection remains usable.
    HolePunchFailed,
    /// One new authenticated application message arrived.
    Message(PeerMessage),
    /// The opponent no longer has any live connection.
    Disconnected,
}

/// Cloneable command handle for a running two-player network session.
#[derive(Clone)]
pub struct PeerHandle {
    commands: mpsc::Sender<Command>,
}

impl PeerHandle {
    /// Send one opaque artifact and wait for the peer's acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, disconnection, rejection, or transport failure.
    pub async fn send(
        &self,
        kind: String,
        payload: Vec<u8>,
    ) -> Result<PeerMessage, TransportError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Send {
                kind,
                payload,
                reply,
            })
            .await
            .map_err(|_| TransportError::Closed)?;
        response.await.map_err(|_| TransportError::Closed)?
    }
}

/// Receiving half of a running peer session.
pub struct PeerEvents {
    events: mpsc::Receiver<PeerEvent>,
}

impl PeerEvents {
    /// Wait for the next connection or application event.
    pub async fn next(&mut self) -> Option<PeerEvent> {
        self.events.recv().await
    }
}

/// Start a host which reserves a relay circuit and accepts the first invite-authenticated guest.
///
/// # Errors
///
/// Returns an error when the invite or native network stack cannot be initialized.
pub fn host(
    keypair: Keypair,
    relay_address: Multiaddr,
    capability: [u8; 32],
) -> Result<(Invite, PeerHandle, PeerEvents), TransportError> {
    let peer_id = keypair.public().to_peer_id();
    let invite = Invite::new(relay_address.clone(), peer_id, capability)?;
    let (handle, events, runner) = build(keypair, relay_address, capability, None, true, None)?;
    tokio::spawn(runner.run());
    Ok((invite, handle, events))
}

/// Start a guest and dial the host through its advertised relay circuit.
///
/// # Errors
///
/// Returns an error when the invite or native network stack cannot be initialized.
pub fn join(keypair: Keypair, invite: Invite) -> Result<(PeerHandle, PeerEvents), TransportError> {
    let mut host_address = invite.relay_address.clone();
    host_address.push(Protocol::P2pCircuit);
    host_address.push(Protocol::P2p(invite.host_peer_id));
    let (handle, events, runner) = build(
        keypair,
        invite.relay_address,
        invite.capability,
        Some(invite.host_peer_id),
        false,
        Some(host_address),
    )?;
    tokio::spawn(runner.run());
    Ok((handle, events))
}

/// Generate a fresh native libp2p identity.
#[must_use]
pub fn generate_identity() -> Keypair {
    Keypair::generate_ed25519()
}

/// Load a durable identity, creating it atomically when absent.
///
/// # Errors
///
/// Returns an error when the key cannot be decoded, created, written, or synced.
pub fn load_or_create_identity(path: &Path) -> Result<Keypair, TransportError> {
    match std::fs::read(path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes).map_err(|_| TransportError::Identity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let identity = generate_identity();
            let bytes = identity
                .to_protobuf_encoding()
                .map_err(|_| TransportError::Identity)?;
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).map_err(|_| TransportError::Identity)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(&bytes)
                        .and_then(|()| file.sync_all())
                        .map_err(|_| TransportError::Identity)?;
                    Ok(identity)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let bytes = std::fs::read(path).map_err(|_| TransportError::Identity)?;
                    Keypair::from_protobuf_encoding(&bytes).map_err(|_| TransportError::Identity)
                }
                Err(_) => Err(TransportError::Identity),
            }
        }
        Err(_) => Err(TransportError::Identity),
    }
}

/// Generate a fresh invitation capability using operating-system entropy.
///
/// # Errors
///
/// Returns an error when secure operating-system entropy is unavailable.
pub fn generate_capability() -> Result<[u8; 32], TransportError> {
    let mut value = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut value)
        .map_err(|_| TransportError::Entropy)?;
    Ok(value)
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay_client: relay::client::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour,
    messages: request_response::cbor::Behaviour<WireRequest, WireResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireRequest {
    sequence: u64,
    message_id: [u8; 32],
    kind: String,
    #[serde(with = "byte_vec")]
    payload: Vec<u8>,
    authentication: [u8; 32],
}

mod byte_vec {
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteVecVisitor;

        impl<'de> Visitor<'de> for ByteVecVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte string or byte sequence")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(value)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
                while let Some(byte) = sequence.next_element()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_byte_buf(ByteVecVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireResponse {
    accepted: bool,
    next_sequence: u64,
}

enum Command {
    Send {
        kind: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<PeerMessage, TransportError>>,
    },
}

struct Runner {
    swarm: libp2p::Swarm<Behaviour>,
    local_peer_id: PeerId,
    relay_address: Multiaddr,
    relay_peer_id: PeerId,
    mode: Mode,
    peer_dial_address: Option<Multiaddr>,
    learned_relay_address: bool,
    informed_relay_address: bool,
    capability: [u8; 32],
    expected_peer: Option<PeerId>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<PeerEvent>,
    next_outgoing_sequence: u64,
    next_incoming_sequence: u64,
    pending: HashMap<request_response::OutboundRequestId, Pending>,
    hello_pending: Option<request_response::OutboundRequestId>,
    authenticated_connected: bool,
    connected_path: Option<ConnectionPath>,
}

#[derive(Clone, Copy)]
enum Mode {
    Host { relay_listening: bool },
    Guest { peer_dial_started: bool },
}

struct Pending {
    message: PeerMessage,
    reply: oneshot::Sender<Result<PeerMessage, TransportError>>,
}

fn build(
    keypair: Keypair,
    relay_address: Multiaddr,
    capability: [u8; 32],
    expected_peer: Option<PeerId>,
    is_host: bool,
    peer_dial_address: Option<Multiaddr>,
) -> Result<(PeerHandle, PeerEvents, Runner), TransportError> {
    validate_relay_address(&relay_address)?;
    let Some(Protocol::P2p(relay_peer_id)) = relay_address.iter().last() else {
        return Err(TransportError::InvalidInvite);
    };
    let peer_id = keypair.public().to_peer_id();
    let config = request_response::Config::default().with_request_timeout(Duration::from_secs(120));
    let codec = request_response::cbor::codec::Codec::<WireRequest, WireResponse>::default()
        .set_request_size_maximum((MAX_PEER_MESSAGE_BYTES + 4_096) as u64)
        .set_response_size_maximum(4_096);
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|_| TransportError::Network)?
        .with_quic()
        .with_dns()
        .map_err(|_| TransportError::Network)?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|_| TransportError::Network)?
        .with_behaviour(|identity, relay_client| Behaviour {
            relay_client,
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_owned(),
                identity.public(),
            )),
            dcutr: dcutr::Behaviour::new(peer_id),
            messages: request_response::cbor::Behaviour::with_codec(
                codec,
                [(PROTOCOL, ProtocolSupport::Full)],
                config,
            ),
        })
        .map_err(|_| TransportError::Network)?
        .with_swarm_config(|configuration| {
            configuration.with_idle_connection_timeout(Duration::from_secs(60 * 60))
        })
        .build();
    swarm
        .listen_on(
            "/ip4/0.0.0.0/udp/0/quic-v1"
                .parse()
                .map_err(|_| TransportError::Network)?,
        )
        .map_err(|_| TransportError::Network)?;
    swarm
        .listen_on(
            "/ip4/0.0.0.0/tcp/0"
                .parse()
                .map_err(|_| TransportError::Network)?,
        )
        .map_err(|_| TransportError::Network)?;
    swarm
        .dial(relay_address.clone())
        .map_err(|_| TransportError::Network)?;
    let (command_tx, command_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (event_tx, event_rx) = mpsc::channel(CHANNEL_CAPACITY);
    Ok((
        PeerHandle {
            commands: command_tx,
        },
        PeerEvents { events: event_rx },
        Runner {
            swarm,
            local_peer_id: peer_id,
            relay_address,
            relay_peer_id,
            mode: if is_host {
                Mode::Host {
                    relay_listening: false,
                }
            } else {
                Mode::Guest {
                    peer_dial_started: false,
                }
            },
            peer_dial_address,
            learned_relay_address: false,
            informed_relay_address: false,
            capability,
            expected_peer,
            commands: command_rx,
            events: event_tx,
            next_outgoing_sequence: 1,
            next_incoming_sequence: 1,
            pending: HashMap::new(),
            hello_pending: None,
            authenticated_connected: false,
            connected_path: None,
        },
    ))
}

impl Runner {
    fn listen_via_relay(&mut self) -> Result<(), TransportError> {
        let mut address = self.relay_address.clone();
        address.push(Protocol::P2pCircuit);
        self.swarm
            .listen_on(address)
            .map_err(|_| TransportError::Network)?;
        Ok(())
    }

    fn start_peer_connection_when_ready(&mut self) {
        if !self.learned_relay_address || !self.informed_relay_address {
            return;
        }
        match self.mode {
            Mode::Host {
                relay_listening: false,
            } => {
                let reservation_started = self.listen_via_relay().is_ok();
                if reservation_started {
                    self.mode = Mode::Host {
                        relay_listening: true,
                    };
                }
            }
            Mode::Guest {
                peer_dial_started: false,
            } => {
                if let Some(address) = self.peer_dial_address.clone() {
                    if self.swarm.dial(address).is_ok() {
                        self.mode = Mode::Guest {
                            peer_dial_started: true,
                        };
                    }
                }
            }
            _ => {}
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.handle_command(command),
                    None => break,
                },
                event = self.swarm.select_next_some() => self.handle_swarm_event(event).await,
            }
        }
    }

    fn handle_command(&mut self, command: Command) {
        let Command::Send {
            kind,
            payload,
            reply,
        } = command;
        let Some(peer) = self.expected_peer else {
            let _ = reply.send(Err(TransportError::NotConnected));
            return;
        };
        let sequence = self.next_outgoing_sequence;
        let message_id = message_id(&self.capability, sequence, &kind, &payload);
        let Ok(message) = PeerMessage::new(message_id, sequence, kind, payload) else {
            let _ = reply.send(Err(TransportError::InvalidMessage));
            return;
        };
        let wire = wire_request(&self.capability, self.local_peer_id, &message);
        let request_id = self
            .swarm
            .behaviour_mut()
            .messages
            .send_request(&peer, wire);
        self.pending.insert(request_id, Pending { message, reply });
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let path = if endpoint
                    .get_remote_address()
                    .iter()
                    .any(|protocol| protocol == Protocol::P2pCircuit)
                {
                    ConnectionPath::Relayed
                } else {
                    ConnectionPath::Direct
                };
                if self.expected_peer == Some(peer_id)
                    && self.hello_pending.is_none()
                    && !self.authenticated_connected
                {
                    let hello = hello_request(&self.capability, self.local_peer_id);
                    self.hello_pending = Some(
                        self.swarm
                            .behaviour_mut()
                            .messages
                            .send_request(&peer_id, hello),
                    );
                }
                if self.expected_peer == Some(peer_id)
                    && self.connected_path != Some(ConnectionPath::Direct)
                {
                    self.connected_path = Some(path);
                    let _ = self.events.send(PeerEvent::PathChanged(path)).await;
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } if self.expected_peer == Some(peer_id)
                && num_established == 0
                && !self.swarm.is_connected(&peer_id) =>
            {
                self.authenticated_connected = false;
                self.connected_path = None;
                let _ = self.events.send(PeerEvent::Disconnected).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Messages(event)) => {
                self.handle_message_event(event).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                ..
            })) if peer_id == self.relay_peer_id => {
                self.learned_relay_address = true;
                self.start_peer_connection_when_ready();
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Sent {
                peer_id,
                ..
            })) if peer_id == self.relay_peer_id => {
                self.informed_relay_address = true;
                self.start_peer_connection_when_ready();
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            )) => {
                let _ = self.events.send(PeerEvent::RelayReady).await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) if event.result.is_ok() => {
                self.connected_path = Some(ConnectionPath::Direct);
                let _ = self
                    .events
                    .send(PeerEvent::PathChanged(ConnectionPath::Direct))
                    .await;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(_)) => {
                let _ = self.events.send(PeerEvent::HolePunchFailed).await;
            }
            _ => {}
        }
    }

    async fn handle_message_event(
        &mut self,
        event: request_response::Event<WireRequest, WireResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let accepted = self.accept_request(peer, &request).await;
                    let _ = self.swarm.behaviour_mut().messages.send_response(
                        channel,
                        WireResponse {
                            accepted,
                            next_sequence: self.next_incoming_sequence,
                        },
                    );
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if self.hello_pending == Some(request_id) {
                        self.hello_pending = None;
                        if response.accepted {
                            self.authenticated_connected = true;
                            let path = self.connected_path.unwrap_or(ConnectionPath::Relayed);
                            let _ = self
                                .events
                                .send(PeerEvent::Connected {
                                    peer_id: peer,
                                    path,
                                })
                                .await;
                        }
                    } else if let Some(pending) = self.pending.remove(&request_id) {
                        if response.accepted
                            && response.next_sequence
                                == pending.message.sequence().saturating_add(1)
                        {
                            self.next_outgoing_sequence = response.next_sequence;
                            let _ = pending.reply.send(Ok(pending.message));
                        } else {
                            let _ = pending.reply.send(Err(TransportError::Rejected));
                        }
                    }
                }
            },
            request_response::Event::OutboundFailure { request_id, .. } => {
                if self.hello_pending == Some(request_id) {
                    self.hello_pending = None;
                }
                if let Some(pending) = self.pending.remove(&request_id) {
                    let _ = pending.reply.send(Err(TransportError::Network));
                }
            }
            _ => {}
        }
    }

    async fn accept_request(&mut self, peer: PeerId, request: &WireRequest) -> bool {
        if !verify_wire(&self.capability, peer, request) {
            return false;
        }
        if request.kind == HELLO_KIND && request.sequence == 0 {
            if self.expected_peer.is_none() {
                self.expected_peer = Some(peer);
            }
            if self.expected_peer != Some(peer) {
                return false;
            }
            if !self.authenticated_connected {
                self.authenticated_connected = true;
                let path = self.connected_path.unwrap_or(ConnectionPath::Relayed);
                let _ = self
                    .events
                    .send(PeerEvent::Connected {
                        peer_id: peer,
                        path,
                    })
                    .await;
            }
            return true;
        }
        if self.expected_peer != Some(peer) || request.sequence != self.next_incoming_sequence {
            return false;
        }
        let Ok(message) = PeerMessage::new(
            request.message_id,
            request.sequence,
            request.kind.clone(),
            request.payload.clone(),
        ) else {
            return false;
        };
        self.next_incoming_sequence = self.next_incoming_sequence.saturating_add(1);
        self.events.send(PeerEvent::Message(message)).await.is_ok()
    }
}

fn hello_request(capability: &[u8; 32], peer: PeerId) -> WireRequest {
    let sequence = 0;
    let message_id = message_id(capability, sequence, HELLO_KIND, &[]);
    let authentication = authentication(capability, peer, sequence, message_id, HELLO_KIND, &[]);
    WireRequest {
        sequence,
        message_id,
        kind: HELLO_KIND.to_owned(),
        payload: vec![],
        authentication,
    }
}

fn wire_request(capability: &[u8; 32], peer: PeerId, message: &PeerMessage) -> WireRequest {
    let authentication = authentication(
        capability,
        peer,
        message.sequence(),
        message.message_id(),
        message.kind(),
        message.payload(),
    );
    WireRequest {
        sequence: message.sequence(),
        message_id: message.message_id(),
        kind: message.kind().to_owned(),
        payload: message.payload().to_vec(),
        authentication,
    }
}

fn verify_wire(capability: &[u8; 32], peer: PeerId, request: &WireRequest) -> bool {
    if request.payload.len() > MAX_PEER_MESSAGE_BYTES {
        return false;
    }
    let expected_id = message_id(
        capability,
        request.sequence,
        &request.kind,
        &request.payload,
    );
    if expected_id != request.message_id {
        return false;
    }
    let expected = authentication(
        capability,
        peer,
        request.sequence,
        request.message_id,
        &request.kind,
        &request.payload,
    );
    expected == request.authentication
}

fn authentication(
    capability: &[u8; 32],
    peer: PeerId,
    sequence: u64,
    message_id: [u8; 32],
    kind: &str,
    payload: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(capability).unwrap_or_else(|_| unreachable!());
    mac.update(AUTH_TAG);
    mac.update(&peer.to_bytes());
    mac.update(&sequence.to_be_bytes());
    mac.update(&message_id);
    mac.update(&(kind.len() as u64).to_be_bytes());
    mac.update(kind.as_bytes());
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn message_id(capability: &[u8; 32], sequence: u64, kind: &str, payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"BP52/p2p-message-id/v1");
    hash.update(capability);
    hash.update(sequence.to_be_bytes());
    hash.update((kind.len() as u64).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(payload);
    hash.finalize().into()
}

fn validate_relay_address(address: &Multiaddr) -> Result<(), TransportError> {
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        Ok(())
    } else {
        Err(TransportError::InvalidInvite)
    }
}

/// Native P2P setup or delivery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportError {
    /// Invite syntax, peer id, capability, or relay address was malformed.
    #[error("invalid BP52 peer invite")]
    InvalidInvite,
    /// The operating system did not provide secure entropy.
    #[error("secure entropy is unavailable")]
    Entropy,
    /// The durable libp2p identity could not be loaded or created.
    #[error("peer identity storage failed")]
    Identity,
    /// The peer networking task failed.
    #[error("peer network operation failed")]
    Network,
    /// No invite-authenticated opponent is connected yet.
    #[error("opponent is not connected")]
    NotConnected,
    /// The supplied application artifact violated transport bounds.
    #[error("invalid peer message")]
    InvalidMessage,
    /// The opponent rejected an unauthenticated or out-of-order message.
    #[error("opponent rejected peer message")]
    Rejected,
    /// The networking task has stopped.
    #[error("peer network session closed")]
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWJkBxzQ7Q9CWykvM6DbvYsHtcqZxW9YcF1cPpL2gQhM4N"
            .parse()
            .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn invite_round_trip_is_strict() -> Result<(), TransportError> {
        let invite = Invite::new(relay(), generate_identity().public().to_peer_id(), [7; 32])?;
        assert_eq!(Invite::decode(&invite.encode())?, invite);
        assert_eq!(
            Invite::decode("not-an-invite"),
            Err(TransportError::InvalidInvite)
        );
        Ok(())
    }

    #[test]
    fn authentication_binds_peer_order_kind_and_payload() {
        let peer = generate_identity().public().to_peer_id();
        let capability = [9; 32];
        let id = message_id(&capability, 1, "deal-envelope", b"artifact");
        let message = PeerMessage::new(id, 1, "deal-envelope".to_owned(), b"artifact".to_vec())
            .unwrap_or_else(|_| unreachable!());
        let mut wire = wire_request(&capability, peer, &message);
        assert!(verify_wire(&capability, peer, &wire));
        wire.payload.push(0);
        assert!(!verify_wire(&capability, peer, &wire));
    }
}
