//! Thin terminal harness for the native opaque peer transport.

use std::path::{Path, PathBuf};

use bp52_transport_libp2p::{
    ConnectionPath, Invite, PeerEvent, PeerEvents, PeerHandle, TransportError, generate_capability,
    host as start_host, join as start_guest, load_or_create_identity,
};
use libp2p::Multiaddr;
use tokio::io::{AsyncBufReadExt, BufReader};

const KEY_DIRECTORY: &str = ".bp52";
const HOST_KEY: &str = "host-peer.key";
const GUEST_KEY: &str = "guest-peer.key";

pub(crate) async fn host(relay: Multiaddr) -> Result<(), TransportError> {
    let identity_path = identity_path(HOST_KEY);
    let identity = load_or_create_identity(&identity_path)?;
    let capability = generate_capability()?;
    let (invite, handle, mut events) = start_host(identity, relay, capability)?;
    wait_for_relay(&mut events).await?;
    println!("Peer reservation ready. Share this private invite with the other player:\n");
    println!("{}\n", invite.encode());
    run_terminal(handle, events).await
}

pub(crate) async fn join(invite: Invite) -> Result<(), TransportError> {
    let identity_path = identity_path(GUEST_KEY);
    let identity = load_or_create_identity(&identity_path)?;
    let (handle, events) = start_guest(identity, invite)?;
    run_terminal(handle, events).await
}

fn identity_path(filename: &str) -> PathBuf {
    Path::new(KEY_DIRECTORY).join(filename)
}

async fn wait_for_relay(events: &mut PeerEvents) -> Result<(), TransportError> {
    loop {
        match events.next().await {
            Some(PeerEvent::RelayReady) => return Ok(()),
            Some(_) => {}
            None => return Err(TransportError::Closed),
        }
    }
}

async fn run_terminal(handle: PeerHandle, mut events: PeerEvents) -> Result<(), TransportError> {
    println!("Waiting for the other player. Type /quit to stop.");
    println!("Transport debug input: <kind> <UTF-8 payload>");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => match line.map_err(|_| TransportError::Closed)? {
                Some(line) if line.trim() == "/quit" => return Ok(()),
                Some(line) => send_line(&handle, &line).await?,
                None => return Ok(()),
            },
            event = events.next() => match event {
                Some(PeerEvent::Connected { peer_id, path }) => {
                    println!("Opponent connected: {peer_id} ({})", path_name(path));
                }
                Some(PeerEvent::PathChanged(path)) => println!("Network path: {}", path_name(path)),
                Some(PeerEvent::HolePunchFailed) => println!("Direct connection unavailable; continuing through relay."),
                Some(PeerEvent::Message(message)) => println!(
                    "< {} {}",
                    message.kind(),
                    String::from_utf8_lossy(message.payload())
                ),
                Some(PeerEvent::Disconnected) => println!("Opponent disconnected; waiting for reconnection."),
                Some(PeerEvent::RelayReady) => {}
                None => return Err(TransportError::Closed),
            }
        }
    }
}

async fn send_line(handle: &PeerHandle, line: &str) -> Result<(), TransportError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let (kind, payload) = trimmed.split_once(' ').unwrap_or((trimmed, ""));
    let sent = handle
        .send(kind.to_owned(), payload.as_bytes().to_vec())
        .await?;
    println!("> acknowledged {} #{}", sent.kind(), sent.sequence());
    Ok(())
}

const fn path_name(path: ConnectionPath) -> &'static str {
    match path {
        ConnectionPath::Direct => "direct",
        ConnectionPath::Relayed => "relay fallback",
    }
}
