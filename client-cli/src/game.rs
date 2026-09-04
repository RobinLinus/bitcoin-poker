//! Native two-process game setup over the opaque libp2p transport.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::{Network, OutPoint, Transaction};
use bp52_adapter_esplora::EsploraClient;
use bp52_chain_compiler::{
    ConfirmedStateReceipt, HEADS_UP_FIXED_LIMIT_V1_PROFILE, HeadsUpSession,
    RuntimeAuthorizationReceipt,
};
use bp52_chain_types::{
    Action, AuthorizationPolicy, EdgeKind, RevealOrder, Role as ChainRole,
    SignedChainGameDescriptor,
};
use bp52_client_ports::{
    ChainProfile, ChainReader, RawTransaction, TransactionPublisher, TransactionStatus,
};
use bp52_codec::{Decode as _, Encode as _};
use bp52_native_chain::{NativeChainOperation, NativeChainParticipant};
use bp52_origin::{OriginContext, OriginPackage, StagingInput};
use bp52_protocol::Role;
use bp52_protocol::auth::{CanonicalIdentities, derive_game_id};
use bp52_protocol::secp256k1::XOnlyPublicKey;
use bp52_transport_libp2p::{
    Invite, PeerEvent, PeerEvents, PeerHandle, generate_capability, host as start_host,
    join as start_guest, load_or_create_identity,
};
use libp2p::Multiaddr;
use rand::RngCore as _;
use rand::rngs::OsRng;

use crate::deal::{NativeDeal, Status};
use crate::origin_network;
use crate::wallet::NativeWallet;

const IDENTITY_KIND: &str = "game-identity";
const SESSION_KIND: &str = "game-session";
const DEAL_KIND: &str = "deal-envelope";
const ACCEPT_KIND: &str = "deal-acceptance";
const DESCRIPTOR_KIND: &str = "chain-descriptor";
const LAMPORT_KIND: &str = "chain-lamport";
const ROOT_COMMITMENT_KIND: &str = "chain-root-commit";
const ROOT_OPENING_KIND: &str = "chain-root-open";
const PREAUTH_COMMITMENT_KIND: &str = "chain-preauth-commit";
const PREAUTH_OPENING_KIND: &str = "chain-preauth-open";
const INVENTORY_READY_KIND: &str = "chain-inventory-ready";
const ACTIVATION_SIGNATURE_KIND: &str = "chain-activation-sig";
const CHILD_TRANSACTION_KIND: &str = "chain-child-tx";

/// Host a native two-party DEAL session.
pub async fn host(
    relay: Multiaddr,
    network_id: [u8; 32],
    funding_outpoint: [u8; 36],
) -> Result<(), String> {
    let identity =
        load_or_create_identity(&key_path("host-peer.key")).map_err(|error| error.to_string())?;
    let capability = generate_capability().map_err(|error| error.to_string())?;
    let (invite, handle, mut events) =
        start_host(identity, relay, capability).map_err(|error| error.to_string())?;
    wait_relay(&mut events).await?;
    println!(
        "Share this private invite with the other player:\n\n{}\n",
        invite.encode()
    );
    wait_connected(&mut events).await?;
    run_deal(
        handle,
        events,
        NativeWallet::load_or_create(&key_path("host-wallet.key"))?,
        true,
        network_id,
        funding_outpoint,
    )
    .await
}

/// Join a native two-party DEAL session.
pub async fn join(
    invite: Invite,
    network_id: [u8; 32],
    funding_outpoint: [u8; 36],
) -> Result<(), String> {
    let identity =
        load_or_create_identity(&key_path("guest-peer.key")).map_err(|error| error.to_string())?;
    let (handle, mut events) = start_guest(identity, invite).map_err(|error| error.to_string())?;
    wait_connected(&mut events).await?;
    run_deal(
        handle,
        events,
        NativeWallet::load_or_create(&key_path("guest-wallet.key"))?,
        false,
        network_id,
        funding_outpoint,
    )
    .await
}

/// Host origin funding followed by a native DEAL on the confirmed outpoint.
pub async fn funded_host(
    relay: Multiaddr,
    mut client: EsploraClient,
    profile: ChainProfile,
) -> Result<(), String> {
    let identity =
        load_or_create_identity(&key_path("host-peer.key")).map_err(|error| error.to_string())?;
    let capability = generate_capability().map_err(|error| error.to_string())?;
    let (invite, handle, mut events) =
        start_host(identity, relay, capability).map_err(|error| error.to_string())?;
    wait_relay(&mut events).await?;
    println!(
        "Share this private invite with the other player:\n\n{}\n",
        invite.encode()
    );
    wait_connected(&mut events).await?;
    let wallet = NativeWallet::load_or_create(&key_path("host-wallet.key"))?;
    let origin =
        origin_network::create(&handle, &mut events, &wallet, true, &mut client, &profile).await?;
    let mut deal = drive_deal(
        &handle,
        &mut events,
        &wallet,
        origin.network_id,
        origin.outpoint,
        origin.session_nonce,
        origin.identities,
    )
    .await?;
    let accepted_deal = deal.accepted_deal()?;
    let chain = initialize_chain(&mut deal, &wallet, &origin, "host")?;
    run_chain(
        &handle,
        &mut events,
        chain,
        accepted_deal,
        &origin,
        &mut client,
        &profile,
        true,
        "host",
    )
    .await
}

/// Join origin funding followed by a native DEAL on the confirmed outpoint.
pub async fn funded_join(
    invite: Invite,
    mut client: EsploraClient,
    profile: ChainProfile,
) -> Result<(), String> {
    let identity =
        load_or_create_identity(&key_path("guest-peer.key")).map_err(|error| error.to_string())?;
    let (handle, mut events) = start_guest(identity, invite).map_err(|error| error.to_string())?;
    wait_connected(&mut events).await?;
    let wallet = NativeWallet::load_or_create(&key_path("guest-wallet.key"))?;
    let origin =
        origin_network::create(&handle, &mut events, &wallet, false, &mut client, &profile).await?;
    let mut deal = drive_deal(
        &handle,
        &mut events,
        &wallet,
        origin.network_id,
        origin.outpoint,
        origin.session_nonce,
        origin.identities,
    )
    .await?;
    let accepted_deal = deal.accepted_deal()?;
    let chain = initialize_chain(&mut deal, &wallet, &origin, "guest")?;
    run_chain(
        &handle,
        &mut events,
        chain,
        accepted_deal,
        &origin,
        &mut client,
        &profile,
        false,
        "guest",
    )
    .await
}

/// Reconnect a previously checkpointed host terminal and continue gameplay.
pub async fn resume_host(
    relay: Multiaddr,
    mut client: EsploraClient,
    profile: ChainProfile,
) -> Result<(), String> {
    let identity =
        load_or_create_identity(&key_path("host-peer.key")).map_err(|error| error.to_string())?;
    let capability = generate_capability().map_err(|error| error.to_string())?;
    let (invite, handle, mut events) =
        start_host(identity, relay, capability).map_err(|error| error.to_string())?;
    wait_relay(&mut events).await?;
    println!(
        "Share this private resume invite with the other player:\n\n{}\n",
        invite.encode()
    );
    wait_connected(&mut events).await?;
    let mut chain = restore_chain("host")?;
    println!("Restored host CHAIN checkpoint at phase {}.", chain.phase());
    match chain.phase() {
        5 => {
            finish_preauthorization_setup(
                &handle,
                &mut events,
                &mut chain,
                &mut client,
                &profile,
                true,
                "host",
            )
            .await
        }
        7 => {
            activate_game(
                &handle,
                &mut events,
                &mut chain,
                &mut client,
                &profile,
                true,
                "host",
            )
            .await
        }
        8 | 9 => {
            play_game(
                &handle,
                &mut events,
                &mut chain,
                &mut client,
                &profile,
                "host",
            )
            .await
        }
        phase => Err(format!(
            "host checkpoint cannot resume from CHAIN phase {phase}"
        )),
    }
}

/// Reconnect a previously checkpointed guest terminal and continue gameplay.
pub async fn resume_join(
    invite: Invite,
    mut client: EsploraClient,
    profile: ChainProfile,
) -> Result<(), String> {
    let identity =
        load_or_create_identity(&key_path("guest-peer.key")).map_err(|error| error.to_string())?;
    let (handle, mut events) = start_guest(identity, invite).map_err(|error| error.to_string())?;
    wait_connected(&mut events).await?;
    let mut chain = restore_chain("guest")?;
    println!(
        "Restored guest CHAIN checkpoint at phase {}.",
        chain.phase()
    );
    match chain.phase() {
        5 => {
            finish_preauthorization_setup(
                &handle,
                &mut events,
                &mut chain,
                &mut client,
                &profile,
                false,
                "guest",
            )
            .await
        }
        7 => {
            activate_game(
                &handle,
                &mut events,
                &mut chain,
                &mut client,
                &profile,
                false,
                "guest",
            )
            .await
        }
        8 | 9 => {
            play_game(
                &handle,
                &mut events,
                &mut chain,
                &mut client,
                &profile,
                "guest",
            )
            .await
        }
        phase => Err(format!(
            "guest checkpoint cannot resume from CHAIN phase {phase}"
        )),
    }
}

fn restore_chain(state_name: &str) -> Result<NativeChainParticipant, String> {
    let directory = Path::new(".bp52").join("chain");
    let initialization = fs::read(directory.join(format!("{state_name}.init")))
        .map_err(|error| format!("cannot read saved CHAIN initialization: {error}"))?;
    let checkpoint = fs::read(directory.join(format!("{state_name}.checkpoint")))
        .map_err(|error| format!("cannot read saved CHAIN checkpoint: {error}"))?;
    let mut chain = NativeChainParticipant::new(&initialization)?;
    chain.execute(NativeChainOperation::RestoreCheckpoint, &checkpoint)?;
    Ok(chain)
}

async fn run_chain(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    mut chain: NativeChainParticipant,
    accepted_deal: bp52_protocol::messages::AcceptedDeal,
    origin: &origin_network::FundedOrigin,
    client: &mut EsploraClient,
    profile: &ChainProfile,
    host: bool,
    state_name: &str,
) -> Result<(), String> {
    println!("Native CHAIN initialized; compiling the fixed-limit game graph.");
    let descriptor = HEADS_UP_FIXED_LIMIT_V1_PROFILE
        .descriptor(HeadsUpSession {
            network_id: origin.network_id,
            bitcoin_network: Network::Signet,
            deal: accepted_deal,
            funding_outpoint: deserialize::<OutPoint>(&origin.outpoint)
                .map_err(|error| error.to_string())?,
            deal_session_nonce: origin.session_nonce,
            alice_xonly_pk: origin.identities[0],
            bob_xonly_pk: origin.identities[1],
            button: ChainRole::Alice,
            reveal_order: RevealOrder {
                flop_first: ChainRole::Alice,
                turn_first: ChainRole::Bob,
                river_first: ChainRole::Alice,
            },
            split_remainder_recipient: ChainRole::Bob,
        })
        .map_err(|error| error.to_string())?;
    let descriptor_bytes = descriptor
        .encode_to_vec()
        .map_err(|error| error.to_string())?;
    let local_signature = chain.execute(NativeChainOperation::SignDescriptor, &descriptor_bytes)?;
    send_bytes(handle, DESCRIPTOR_KIND, local_signature.clone()).await?;
    let peer_signature = receive(events, DESCRIPTOR_KIND).await?;
    let (signature_a, signature_b) = if chain.local_role() == 0 {
        (
            fixed::<64>(&local_signature)?,
            fixed::<64>(&peer_signature)?,
        )
    } else {
        (
            fixed::<64>(&peer_signature)?,
            fixed::<64>(&local_signature)?,
        )
    };
    let signed = SignedChainGameDescriptor {
        descriptor,
        signature_a,
        signature_b,
    };
    chain.execute(
        NativeChainOperation::InstallSignedDescriptor,
        &signed.encode_to_vec().map_err(|error| error.to_string())?,
    )?;
    persist_checkpoint(&mut chain, state_name)?;
    println!("Descriptor mutually signed. Generating Lamport inventory.");

    let local_lamport = chain.generate_local_lamport_bundle(1)?;
    send_bytes(handle, LAMPORT_KIND, local_lamport).await?;
    let peer_lamport = receive(events, LAMPORT_KIND).await?;
    chain.execute(NativeChainOperation::AcceptLamportBundle, &peer_lamport)?;
    persist_checkpoint(&mut chain, state_name)?;
    println!("Graph compiled and Lamport inventory exchanged.");

    exchange_operation(
        handle,
        events,
        &mut chain,
        ROOT_COMMITMENT_KIND,
        NativeChainOperation::MakeRootCommitment,
        NativeChainOperation::AcceptRootCommitment,
    )
    .await?;
    exchange_operation(
        handle,
        events,
        &mut chain,
        ROOT_OPENING_KIND,
        NativeChainOperation::OpenRoot,
        NativeChainOperation::AcceptRootOpening,
    )
    .await?;
    persist_checkpoint(&mut chain, state_name)?;
    println!("Both graph-root openings agree.");

    finish_preauthorization_setup(
        handle, events, &mut chain, client, profile, host, state_name,
    )
    .await
}

async fn finish_preauthorization_setup(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    chain: &mut NativeChainParticipant,
    client: &mut EsploraClient,
    profile: &ChainProfile,
    host: bool,
    state_name: &str,
) -> Result<(), String> {
    println!("Generating fixed preauthorizations.");
    exchange_operation(
        handle,
        events,
        chain,
        PREAUTH_COMMITMENT_KIND,
        NativeChainOperation::MakePreauthorizationCommitment,
        NativeChainOperation::AcceptPreauthorizationCommitment,
    )
    .await?;
    exchange_operation(
        handle,
        events,
        chain,
        PREAUTH_OPENING_KIND,
        NativeChainOperation::OpenPreauthorizations,
        NativeChainOperation::AcceptPreauthorizationOpening,
    )
    .await?;
    tokio::task::block_in_place(|| chain.execute(NativeChainOperation::AttestInventory, &[]))?;
    let local_ready = chain.execute(NativeChainOperation::MakeInventoryReady, &[])?;
    send_bytes(handle, INVENTORY_READY_KIND, local_ready.clone()).await?;
    let peer_ready = receive(events, INVENTORY_READY_KIND).await?;
    let mut peer_ready_artifact = vec![u8::from(chain.local_role() == 0)];
    peer_ready_artifact.extend_from_slice(&peer_ready);
    chain.execute(
        NativeChainOperation::AcceptInventoryReady,
        &peer_ready_artifact,
    )?;
    persist_checkpoint(chain, state_name)?;
    println!("Both players are ready. Assembling the activation transaction.");

    activate_game(handle, events, chain, client, profile, host, state_name).await
}

async fn activate_game(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    chain: &mut NativeChainParticipant,
    client: &mut EsploraClient,
    profile: &ChainProfile,
    host: bool,
    state_name: &str,
) -> Result<(), String> {
    let activation = chain.execute(NativeChainOperation::ActivationTemplate, &[])?;
    let local_activation_signature =
        chain.execute(NativeChainOperation::SignActivation, &activation)?;
    send_bytes(
        handle,
        ACTIVATION_SIGNATURE_KIND,
        local_activation_signature.clone(),
    )
    .await?;
    let peer_activation_signature = receive(events, ACTIVATION_SIGNATURE_KIND).await?;
    let mut peer_artifact = vec![u8::from(chain.local_role() == 0)];
    peer_artifact.extend_from_slice(&peer_activation_signature);
    chain.execute(
        NativeChainOperation::VerifyActivationArtifact,
        &peer_artifact,
    )?;
    let (alice_signature, bob_signature) = if chain.local_role() == 0 {
        (local_activation_signature, peer_activation_signature)
    } else {
        (peer_activation_signature, local_activation_signature)
    };
    let assembled = assemble_activation_input(&activation, &alice_signature, &bob_signature)?;
    let activation = chain.execute(NativeChainOperation::AssembleActivation, &assembled)?;
    if host {
        let txid = broadcast_transaction(client, profile, &activation)?;
        println!(
            "Activation {txid} broadcast. Waiting for a Mutinynet confirmation.",
            txid = bitcoin::Txid::from_byte_array(txid)
        );
    } else {
        println!("Host is broadcasting activation. Waiting for its Mutinynet confirmation.");
    }
    let (height, tip) = wait_for_confirmation(client, profile, &activation, host).await?;
    let confirmation = confirmation_input(height, tip, &activation)?;
    chain.execute(NativeChainOperation::ConfirmActivation, &confirmation)?;
    persist_checkpoint(chain, state_name)?;
    println!("Activation confirmed at height {height}; gameplay is live.");
    play_game(handle, events, chain, client, profile, state_name).await
}

async fn play_game(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    chain: &mut NativeChainParticipant,
    client: &mut EsploraClient,
    profile: &ChainProfile,
    state_name: &str,
) -> Result<(), String> {
    let local_role = decode_chain_role(chain.local_role())?;
    let mut scripted = std::env::var("BP52_ACTIONS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .rev()
                .map(|item| item.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    loop {
        let state_bytes = chain.execute(NativeChainOperation::ConfirmedStateReceipt, &[])?;
        let state =
            ConfirmedStateReceipt::decode_exact(&state_bytes).map_err(|error| error.to_string())?;
        let balances = state.balances();
        println!(
            "Table: Alice {} sat, Bob {} sat, pot {} sat.",
            balances.alice_stack_sat, balances.bob_stack_sat, balances.pot_sat
        );
        if state.is_terminal() {
            println!(
                "Game complete: terminal settlement confirmed at height {}.",
                state.confirmed_height()
            );
            return Ok(());
        }
        let live_edges = state
            .edges()
            .iter()
            .filter(|edge| !matches!(edge.edge.kind, EdgeKind::Timeout(_)))
            .collect::<Vec<_>>();
        let responsible = live_edges
            .first()
            .map(|edge| authorization_role(edge.edge.authorization))
            .transpose()?
            .flatten();
        let transaction = if responsible == Some(local_role) {
            let operation = select_operation(chain, &live_edges, &mut scripted)?;
            let _witness = chain.execute(operation.0, &operation.1)?;
            persist_checkpoint(chain, state_name)?;
            let receipt_bytes =
                chain.execute(NativeChainOperation::RuntimeAuthorizationReceipt, &[])?;
            let receipt = RuntimeAuthorizationReceipt::decode_exact(&receipt_bytes)
                .map_err(|error| error.to_string())?;
            let transaction = receipt.transaction().to_vec();
            broadcast_transaction(client, profile, &transaction)?;
            send_bytes(handle, CHILD_TRANSACTION_KIND, transaction.clone()).await?;
            println!("Move broadcast; waiting for confirmation.");
            transaction
        } else {
            println!("Waiting for the other player to move.");
            receive(events, CHILD_TRANSACTION_KIND).await?
        };
        let (height, tip) = wait_for_confirmation(
            client,
            profile,
            &transaction,
            responsible == Some(local_role),
        )
        .await?;
        chain.execute(
            NativeChainOperation::ConfirmChild,
            &confirmation_input(height, tip, &transaction)?,
        )?;
        persist_checkpoint(chain, state_name)?;
        print_cards(chain)?;
        println!("Move confirmed at height {height}.");
    }
}

fn authorization_role(policy: AuthorizationPolicy) -> Result<Option<ChainRole>, String> {
    match policy {
        AuthorizationPolicy::BettingAction { actor } => Ok(Some(actor)),
        AuthorizationPolicy::RevealPreimages { revealer } => Ok(Some(revealer)),
        AuthorizationPolicy::AliceScore => Ok(Some(ChainRole::Alice)),
        AuthorizationPolicy::BobLivePayout => Ok(Some(ChainRole::Bob)),
        AuthorizationPolicy::BothPresigned => Ok(None),
        AuthorizationPolicy::Timeout { .. } => {
            Err("timeout edge selected as a live move".to_owned())
        }
    }
}

fn select_operation(
    chain: &mut NativeChainParticipant,
    edges: &[&bp52_chain_compiler::PublicEdgeReceipt],
    scripted: &mut Vec<String>,
) -> Result<(NativeChainOperation, Vec<u8>), String> {
    let first = edges
        .first()
        .ok_or_else(|| "active state has no live edge".to_owned())?;
    match first.edge.kind {
        EdgeKind::Action(_) => {
            let actions = edges
                .iter()
                .filter_map(|edge| match edge.edge.kind {
                    EdgeKind::Action(action) => Some(action),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let action = read_action(&actions, scripted)?;
            Ok((NativeChainOperation::BuildAction, vec![action.code()]))
        }
        EdgeKind::HoleCardReveal { .. } | EdgeKind::CommunityReveal { .. } => {
            println!("Publishing the required committed card shares.");
            Ok((NativeChainOperation::BuildReveal, Vec::new()))
        }
        EdgeKind::AliceShowdown => {
            let cards = card_projection(chain)?;
            let (subset, score) = cards
                .alice
                .ok_or_else(|| "Alice hand is incomplete".to_owned())?;
            let mut input = vec![subset];
            input.extend_from_slice(&score.to_le_bytes());
            println!("Alice proves her best five-card hand (score {score:#08x}).");
            Ok((NativeChainOperation::BuildAliceShowdown, input))
        }
        EdgeKind::BobPayout(_) => {
            let cards = card_projection(chain)?;
            let (subset, score) = cards
                .bob
                .ok_or_else(|| "Bob hand is incomplete".to_owned())?;
            let outcome = cards
                .outcome
                .ok_or_else(|| "showdown outcome is incomplete".to_owned())?;
            let mut input = vec![subset];
            input.extend_from_slice(&score.to_le_bytes());
            input.push(outcome);
            println!("Bob proves his best hand and selects payout outcome {outcome}.");
            Ok((NativeChainOperation::BuildBobPayout, input))
        }
        EdgeKind::Advance { .. } => Ok((
            NativeChainOperation::BuildAdvance,
            first.edge.child_node_id.to_vec(),
        )),
        EdgeKind::Timeout(_) => Err("only timeout edges are available".to_owned()),
    }
}

fn read_action(actions: &[Action], scripted: &mut Vec<String>) -> Result<Action, String> {
    loop {
        let available = actions
            .iter()
            .map(action_name)
            .collect::<Vec<_>>()
            .join("/");
        let value = if let Some(value) = scripted.pop() {
            println!("Your move [{available}]: {value}");
            value
        } else {
            print!("Your move [{available}]: ");
            io::stdout().flush().map_err(|error| error.to_string())?;
            let mut value = String::new();
            io::stdin()
                .read_line(&mut value)
                .map_err(|error| error.to_string())?;
            value.trim().to_owned()
        };
        let selected = match value.to_ascii_lowercase().as_str() {
            "fold" | "f" => Some(Action::Fold),
            "check" | "k" => Some(Action::Check),
            "call" | "c" => Some(Action::Call),
            "bet" | "b" => Some(Action::Bet),
            "raise" | "r" => Some(Action::Raise),
            _ => None,
        };
        if let Some(action) = selected.filter(|action| actions.contains(action)) {
            return Ok(action);
        }
        println!("Choose one of: {available}.");
    }
}

const fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Fold => "fold",
        Action::Check => "check",
        Action::Call => "call",
        Action::Bet => "bet",
        Action::Raise => "raise",
    }
}

fn decode_chain_role(value: u8) -> Result<ChainRole, String> {
    match value {
        0 => Ok(ChainRole::Alice),
        1 => Ok(ChainRole::Bob),
        _ => Err("CHAIN returned a noncanonical role".to_owned()),
    }
}

struct CardProjection {
    local_hole: [u8; 2],
    board: [u8; 5],
    alice: Option<(u8, u32)>,
    bob: Option<(u8, u32)>,
    outcome: Option<u8>,
}

fn card_projection(chain: &mut NativeChainParticipant) -> Result<CardProjection, String> {
    let bytes = chain.execute(NativeChainOperation::ProjectCards, &[])?;
    if bytes.len() != 33 || &bytes[..8] != b"BP52CP01" {
        return Err("CHAIN returned a malformed card projection".to_owned());
    }
    let local_hole = [bytes[9], bytes[10]];
    let board = bytes[11..16]
        .try_into()
        .map_err(|_| "card board has the wrong length".to_owned())?;
    let hand = |offset: usize| {
        (bytes[offset] == 1).then(|| {
            (
                bytes[offset + 1],
                u32::from_le_bytes(bytes[offset + 2..offset + 6].try_into().unwrap_or([0; 4])),
            )
        })
    };
    Ok(CardProjection {
        local_hole,
        board,
        alice: hand(20),
        bob: hand(26),
        outcome: (bytes[32] != u8::MAX).then_some(bytes[32]),
    })
}

fn print_cards(chain: &mut NativeChainParticipant) -> Result<(), String> {
    let cards = card_projection(chain)?;
    let hole = cards
        .local_hole
        .map(render_card)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let board = cards
        .board
        .map(render_card)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    println!(
        "Cards: hole {} {}, board {}.",
        hole[0],
        hole[1],
        board.join(" ")
    );
    Ok(())
}

fn render_card(card: u8) -> Result<String, String> {
    const RANKS: [&str; 13] = [
        "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A",
    ];
    const SUITS: [&str; 4] = ["♣", "♦", "♥", "♠"];

    if card == u8::MAX {
        return Ok("🂠".to_owned());
    }
    if card >= 52 {
        return Err(format!("CHAIN projected invalid card identifier {card}"));
    }
    let rank = RANKS[usize::from(card / 4)];
    let suit = SUITS[usize::from(card % 4)];
    Ok(format!("{rank}{suit}"))
}

/// Run the entire two-participant protocol locally with simulated confirmations.
pub fn self_test(profile: &ChainProfile) -> Result<(), String> {
    let host_wallet = NativeWallet::load_or_create(&key_path("host-wallet.key"))?;
    let guest_wallet = NativeWallet::load_or_create(&key_path("guest-wallet.key"))?;
    let room_id = [0x31; 32];
    let session_nonce = [0x32; 32];
    let context = OriginContext::new(profile.profile_id(), room_id, session_nonce)
        .map_err(|error| error.to_string())?;
    let package = OriginPackage::new(
        context,
        StagingInput::from_display_txid_bytes(
            [0x41; 32],
            0,
            27_000,
            host_wallet.compressed_public_key(),
        )
        .map_err(|error| error.to_string())?,
        StagingInput::from_display_txid_bytes(
            [0x42; 32],
            0,
            27_000,
            guest_wallet.compressed_public_key(),
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let identities = if host_wallet.xonly_public_key() < guest_wallet.xonly_public_key() {
        [
            host_wallet.xonly_public_key(),
            guest_wallet.xonly_public_key(),
        ]
    } else {
        [
            guest_wallet.xonly_public_key(),
            host_wallet.xonly_public_key(),
        ]
    };
    let (alice_wallet, bob_wallet) = if host_wallet.xonly_public_key() == identities[0] {
        (&host_wallet, &guest_wallet)
    } else {
        (&guest_wallet, &host_wallet)
    };
    let mut outpoint = [0_u8; 36];
    let mut consensus_txid = package.funding_txid().to_display_bytes();
    consensus_txid.reverse();
    outpoint[..32].copy_from_slice(&consensus_txid);
    let mut deals = crate::deal::completed_pair(
        identities,
        [alice_wallet.secret_bytes(), bob_wallet.secret_bytes()],
        profile.profile_id(),
        session_nonce,
        outpoint,
    )?;
    let accepted = deals[0].accepted_deal()?;
    let origin = origin_network::FundedOrigin {
        network_id: profile.profile_id(),
        room_id,
        session_nonce,
        outpoint,
        identities,
        witness_script: package.origin_witness_script().to_vec(),
    };
    let mut chains = [
        initialize_chain(&mut deals[0], alice_wallet, &origin, "test-alice")?,
        initialize_chain(&mut deals[1], bob_wallet, &origin, "test-bob")?,
    ];
    setup_pair(&mut chains, accepted, &origin)?;
    println!("local test: activation assembled and confirmed");

    let mut alice_actions = vec![
        "check".to_owned(),
        "check".to_owned(),
        "check".to_owned(),
        "call".to_owned(),
    ];
    let mut bob_actions = vec![
        "check".to_owned(),
        "check".to_owned(),
        "check".to_owned(),
        "check".to_owned(),
    ];
    let mut height = 1_000_u32;
    loop {
        let state = ConfirmedStateReceipt::decode_exact(
            &chains[0].execute(NativeChainOperation::ConfirmedStateReceipt, &[])?,
        )
        .map_err(|error| error.to_string())?;
        if state.is_terminal() {
            println!("local test: full check-down game settled at height {height}");
            return Ok(());
        }
        let edges = state
            .edges()
            .iter()
            .filter(|edge| !matches!(edge.edge.kind, EdgeKind::Timeout(_)))
            .collect::<Vec<_>>();
        let role = authorization_role(
            edges
                .first()
                .ok_or_else(|| "local test state has no live edge".to_owned())?
                .edge
                .authorization,
        )?
        .ok_or_else(|| "local test encountered an automatic edge".to_owned())?;
        let index = usize::from(role.code());
        let scripted = if role == ChainRole::Alice {
            &mut alice_actions
        } else {
            &mut bob_actions
        };
        let operation = select_operation(&mut chains[index], &edges, scripted)?;
        chains[index].execute(operation.0, &operation.1)?;
        let runtime = RuntimeAuthorizationReceipt::decode_exact(
            &chains[index].execute(NativeChainOperation::RuntimeAuthorizationReceipt, &[])?,
        )
        .map_err(|error| error.to_string())?;
        height = height.saturating_add(1);
        let confirmation = confirmation_input(height, height, runtime.transaction())?;
        chains[0].execute(NativeChainOperation::ConfirmChild, &confirmation)?;
        chains[1].execute(NativeChainOperation::ConfirmChild, &confirmation)?;
    }
}

fn setup_pair(
    chains: &mut [NativeChainParticipant; 2],
    accepted_deal: bp52_protocol::messages::AcceptedDeal,
    origin: &origin_network::FundedOrigin,
) -> Result<(), String> {
    let descriptor = HEADS_UP_FIXED_LIMIT_V1_PROFILE
        .descriptor(HeadsUpSession {
            network_id: origin.network_id,
            bitcoin_network: Network::Signet,
            deal: accepted_deal,
            funding_outpoint: deserialize(&origin.outpoint).map_err(|error| error.to_string())?,
            deal_session_nonce: origin.session_nonce,
            alice_xonly_pk: origin.identities[0],
            bob_xonly_pk: origin.identities[1],
            button: ChainRole::Alice,
            reveal_order: RevealOrder {
                flop_first: ChainRole::Alice,
                turn_first: ChainRole::Bob,
                river_first: ChainRole::Alice,
            },
            split_remainder_recipient: ChainRole::Bob,
        })
        .map_err(|error| error.to_string())?;
    let descriptor_bytes = descriptor
        .encode_to_vec()
        .map_err(|error| error.to_string())?;
    let signatures = [
        fixed::<64>(&chains[0].execute(NativeChainOperation::SignDescriptor, &descriptor_bytes)?)?,
        fixed::<64>(&chains[1].execute(NativeChainOperation::SignDescriptor, &descriptor_bytes)?)?,
    ];
    let signed = SignedChainGameDescriptor {
        descriptor,
        signature_a: signatures[0],
        signature_b: signatures[1],
    }
    .encode_to_vec()
    .map_err(|error| error.to_string())?;
    for chain in chains.iter_mut() {
        chain.execute(NativeChainOperation::InstallSignedDescriptor, &signed)?;
    }
    let lamport = [
        chains[0].generate_local_lamport_bundle(1)?,
        chains[1].generate_local_lamport_bundle(1)?,
    ];
    chains[0].execute(NativeChainOperation::AcceptLamportBundle, &lamport[1])?;
    chains[1].execute(NativeChainOperation::AcceptLamportBundle, &lamport[0])?;
    exchange_pair(
        chains,
        NativeChainOperation::MakeRootCommitment,
        NativeChainOperation::AcceptRootCommitment,
    )?;
    exchange_pair(
        chains,
        NativeChainOperation::OpenRoot,
        NativeChainOperation::AcceptRootOpening,
    )?;
    println!("local test: graph roots agree; generating 56,131 preauthorizations");
    exchange_pair(
        chains,
        NativeChainOperation::MakePreauthorizationCommitment,
        NativeChainOperation::AcceptPreauthorizationCommitment,
    )?;
    exchange_pair(
        chains,
        NativeChainOperation::OpenPreauthorizations,
        NativeChainOperation::AcceptPreauthorizationOpening,
    )?;
    for chain in chains.iter_mut() {
        chain.execute(NativeChainOperation::AttestInventory, &[])?;
    }
    let ready = [
        chains[0].execute(NativeChainOperation::MakeInventoryReady, &[])?,
        chains[1].execute(NativeChainOperation::MakeInventoryReady, &[])?,
    ];
    let mut bob_ready = vec![1];
    bob_ready.extend_from_slice(&ready[1]);
    chains[0].execute(NativeChainOperation::AcceptInventoryReady, &bob_ready)?;
    let mut alice_ready = vec![0];
    alice_ready.extend_from_slice(&ready[0]);
    chains[1].execute(NativeChainOperation::AcceptInventoryReady, &alice_ready)?;
    let activation = chains[0].execute(NativeChainOperation::ActivationTemplate, &[])?;
    if chains[1].execute(NativeChainOperation::ActivationTemplate, &[])? != activation {
        return Err("local participants compiled different activation templates".to_owned());
    }
    let signatures = [
        chains[0].execute(NativeChainOperation::SignActivation, &activation)?,
        chains[1].execute(NativeChainOperation::SignActivation, &activation)?,
    ];
    let assembled = assemble_activation_input(&activation, &signatures[0], &signatures[1])?;
    let transaction = chains[0].execute(NativeChainOperation::AssembleActivation, &assembled)?;
    if chains[1].execute(NativeChainOperation::AssembleActivation, &assembled)? != transaction {
        return Err("local participants assembled different activation transactions".to_owned());
    }
    let confirmation = confirmation_input(1_000, 1_000, &transaction)?;
    chains[0].execute(NativeChainOperation::ConfirmActivation, &confirmation)?;
    chains[1].execute(NativeChainOperation::ConfirmActivation, &confirmation)?;
    Ok(())
}

fn exchange_pair(
    chains: &mut [NativeChainParticipant; 2],
    make: NativeChainOperation,
    accept: NativeChainOperation,
) -> Result<(), String> {
    let artifacts = [chains[0].execute(make, &[])?, chains[1].execute(make, &[])?];
    chains[0].execute(accept, &artifacts[0])?;
    chains[1].execute(accept, &artifacts[1])?;
    chains[0].execute(accept, &artifacts[1])?;
    chains[1].execute(accept, &artifacts[0])?;
    Ok(())
}

async fn exchange_operation(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    chain: &mut NativeChainParticipant,
    kind: &str,
    make: NativeChainOperation,
    accept: NativeChainOperation,
) -> Result<(), String> {
    // Some setup operations generate or verify hundreds of thousands of
    // signatures. Keep that synchronous CPU work off Tokio's worker so the
    // libp2p runner can acknowledge the faster peer before its request timeout.
    let local = tokio::task::block_in_place(|| chain.execute(make, &[]))?;
    tokio::task::block_in_place(|| chain.execute(accept, &local))?;
    send_bytes(handle, kind, local).await?;
    let peer = receive(events, kind).await?;
    tokio::task::block_in_place(|| chain.execute(accept, &peer))?;
    Ok(())
}

async fn send_bytes(handle: &PeerHandle, kind: &str, value: Vec<u8>) -> Result<(), String> {
    handle
        .send(kind.to_owned(), value)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn assemble_activation_input(
    transaction: &[u8],
    alice_signature: &[u8],
    bob_signature: &[u8],
) -> Result<Vec<u8>, String> {
    let mut frame = Vec::new();
    push_vector(&mut frame, transaction)?;
    push_vector(&mut frame, alice_signature)?;
    push_vector(&mut frame, bob_signature)?;
    Ok(frame)
}

fn broadcast_transaction(
    client: &mut EsploraClient,
    profile: &ChainProfile,
    bytes: &[u8],
) -> Result<[u8; 32], String> {
    let transaction: Transaction = deserialize(bytes).map_err(|error| error.to_string())?;
    let chain = client
        .verify_chain_identity(profile)
        .map_err(|error| error.to_string())?;
    let txid = transaction.compute_txid().to_byte_array();
    if client
        .transaction_status(&chain, txid)
        .map_err(|error| error.to_string())?
        != TransactionStatus::Unknown
    {
        return Ok(txid);
    }
    let raw = RawTransaction::new(txid, bytes.to_vec()).map_err(|error| error.to_string())?;
    client
        .broadcast(&chain, &raw)
        .map_err(|error| error.to_string())
}

async fn wait_for_confirmation(
    client: &mut EsploraClient,
    profile: &ChainProfile,
    bytes: &[u8],
    rebroadcast: bool,
) -> Result<(u32, u32), String> {
    let transaction: Transaction = deserialize(bytes).map_err(|error| error.to_string())?;
    let txid = transaction.compute_txid().to_byte_array();
    let chain = client
        .verify_chain_identity(profile)
        .map_err(|error| error.to_string())?;
    let mut unknown_polls = 0_u32;
    loop {
        match client
            .transaction_status(&chain, txid)
            .map_err(|error| error.to_string())?
        {
            TransactionStatus::Confirmed { block } => {
                let tip = client.tip(&chain).map_err(|error| error.to_string())?;
                return Ok((block.height, tip.block.height));
            }
            TransactionStatus::Unknown => {
                unknown_polls = unknown_polls.saturating_add(1);
                if rebroadcast && unknown_polls % 3 == 0 {
                    match broadcast_transaction(client, profile, bytes) {
                        Ok(_) => println!(
                            "Transaction {txid} was absent; rebroadcast submitted.",
                            txid = transaction.compute_txid()
                        ),
                        Err(error) => eprintln!(
                            "Transaction {txid} rebroadcast was not accepted yet: {error}",
                            txid = transaction.compute_txid()
                        ),
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            TransactionStatus::Mempool => {
                unknown_polls = 0;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

fn confirmation_input(height: u32, tip: u32, transaction: &[u8]) -> Result<Vec<u8>, String> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&height.to_le_bytes());
    frame.extend_from_slice(&tip.to_le_bytes());
    push_vector(&mut frame, transaction)?;
    Ok(frame)
}

fn persist_checkpoint(chain: &mut NativeChainParticipant, state_name: &str) -> Result<(), String> {
    let bytes = chain.execute(NativeChainOperation::SealCheckpoint, &[])?;
    persist_private_state(state_name, "checkpoint", &bytes)
}

fn persist_private_state(state_name: &str, suffix: &str, bytes: &[u8]) -> Result<(), String> {
    let directory = Path::new(".bp52").join("chain");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let temporary = directory.join(format!("{state_name}.{suffix}.tmp"));
    let final_path = directory.join(format!("{state_name}.{suffix}"));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    if temporary.exists() {
        fs::remove_file(&temporary).map_err(|error| error.to_string())?;
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(&temporary, &final_path).map_err(|error| error.to_string())?;
    Ok(())
}

async fn run_deal(
    handle: PeerHandle,
    mut events: PeerEvents,
    wallet: NativeWallet,
    host: bool,
    network_id: [u8; 32],
    funding_outpoint: [u8; 36],
) -> Result<(), String> {
    handle
        .send(IDENTITY_KIND.to_owned(), wallet.xonly_public_key().to_vec())
        .await
        .map_err(|error| error.to_string())?;
    let peer_identity = fixed::<32>(&receive(&mut events, IDENTITY_KIND).await?)?;
    let local_identity = wallet.xonly_public_key();
    let identities = CanonicalIdentities::new(
        XOnlyPublicKey::from_slice(&local_identity).map_err(|error| error.to_string())?,
        XOnlyPublicKey::from_slice(&peer_identity).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let session_nonce = if host {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        handle
            .send(SESSION_KIND.to_owned(), nonce.to_vec())
            .await
            .map_err(|error| error.to_string())?;
        nonce
    } else {
        fixed::<32>(&receive(&mut events, SESSION_KIND).await?)?
    };
    let (alice, bob) = identities.serialized();
    drive_deal(
        &handle,
        &mut events,
        &wallet,
        network_id,
        funding_outpoint,
        session_nonce,
        [alice, bob],
    )
    .await
    .map(|_| ())
}

async fn drive_deal(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    wallet: &NativeWallet,
    network_id: [u8; 32],
    funding_outpoint: [u8; 36],
    session_nonce: [u8; 32],
    identity_keys: [[u8; 32]; 2],
) -> Result<NativeDeal, String> {
    let alice = XOnlyPublicKey::from_slice(&identity_keys[0]).map_err(|error| error.to_string())?;
    let bob = XOnlyPublicKey::from_slice(&identity_keys[1]).map_err(|error| error.to_string())?;
    let identities = CanonicalIdentities::new(alice, bob).map_err(|error| error.to_string())?;
    let game_id = derive_game_id(&network_id, &funding_outpoint, &identities, &session_nonce);
    let mut deal = NativeDeal::new(
        identity_keys,
        wallet.secret_bytes(),
        network_id,
        session_nonce,
        game_id,
    )?;
    println!("Native DEAL started as {:?}.", deal.local_role);

    loop {
        if matches!(deal.status(), Status::LocalEnvelope | Status::PeerEnvelope) {
            match deal.next_sequence() {
                6 => {
                    println!("Preparing private card proofs alongside the opponent…");
                    let started = Instant::now();
                    deal.prepare_bundle()?;
                    println!(
                        "Private card proofs ready in {:.1}s.",
                        started.elapsed().as_secs_f64()
                    );
                }
                12 => {
                    let started = Instant::now();
                    deal.prepare_partial_decryption()?;
                    println!(
                        "Showdown decryption proof ready in {:.1}s.",
                        started.elapsed().as_secs_f64()
                    );
                }
                _ => {}
            }
        }
        match deal.status() {
            Status::LocalEnvelope => {
                let sequence = deal.next_sequence();
                let envelope = deal.generate_next()?;
                handle
                    .send(DEAL_KIND.to_owned(), envelope)
                    .await
                    .map_err(|error| error.to_string())?;
                println!("DEAL envelope {sequence}/15 sent and locally verified.");
            }
            Status::PeerEnvelope => {
                let sequence = deal.next_sequence();
                let envelope = receive(events, DEAL_KIND).await?;
                deal.accept_envelope(&envelope)?;
                println!("DEAL envelope {sequence} verified.");
            }
            Status::RetryApproval => {
                let next = deal.attempt_number().saturating_add(1);
                println!("Verified neutral collision; retrying as attempt {next}.");
                deal.start_retry(next)?;
            }
            Status::LocalAcceptanceSignature | Status::PeerAcceptanceSignature => break,
            Status::Accepted => break,
            Status::Faulted => return Err("native DEAL participant faulted".to_owned()),
        }
    }

    let body = deal.accepted_body_bytes()?;
    let signature = deal.make_acceptance_signature(&body)?;
    handle
        .send(ACCEPT_KIND.to_owned(), signature.to_vec())
        .await
        .map_err(|error| error.to_string())?;
    let peer_signature = fixed::<64>(&receive(events, ACCEPT_KIND).await?)?;
    let peer_role = match deal.local_role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    };
    deal.accept_acceptance_signature(peer_role, peer_signature)?;
    if deal.status() != Status::Accepted {
        return Err("mutual DEAL acceptance did not complete".to_owned());
    }
    println!("DEAL complete: both CLIs accepted the same committed nine-card deal.");
    Ok(deal)
}

async fn wait_relay(events: &mut PeerEvents) -> Result<(), String> {
    loop {
        match events.next().await {
            Some(PeerEvent::RelayReady) => return Ok(()),
            Some(_) => {}
            None => return Err("peer transport closed".to_owned()),
        }
    }
}

async fn wait_connected(events: &mut PeerEvents) -> Result<(), String> {
    loop {
        match events.next().await {
            Some(PeerEvent::Connected { peer_id, path }) => {
                println!("Opponent connected: {peer_id} ({path:?}).");
                return Ok(());
            }
            Some(PeerEvent::HolePunchFailed) => {
                println!("Direct path unavailable; using encrypted relay fallback.");
            }
            Some(_) => {}
            None => return Err("peer transport closed".to_owned()),
        }
    }
}

pub(crate) async fn receive(events: &mut PeerEvents, expected: &str) -> Result<Vec<u8>, String> {
    loop {
        match events.next().await {
            Some(PeerEvent::Message(message)) if message.kind() == expected => {
                return Ok(message.payload().to_vec());
            }
            Some(PeerEvent::Message(_)) => return Err("unexpected game message".to_owned()),
            Some(PeerEvent::Disconnected) => return Err("opponent disconnected".to_owned()),
            Some(PeerEvent::HolePunchFailed) => {
                println!("Direct path unavailable; continuing through relay.");
            }
            Some(_) => {}
            None => return Err("peer transport closed".to_owned()),
        }
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| "peer message has the wrong length".to_owned())
}

fn key_path(filename: &str) -> PathBuf {
    Path::new(".bp52").join(filename)
}

fn initialize_chain(
    deal: &mut NativeDeal,
    wallet: &NativeWallet,
    origin: &origin_network::FundedOrigin,
    state_name: &str,
) -> Result<NativeChainParticipant, String> {
    let certificate = deal.accepted_deal_bytes()?;
    let attestation = deal.verification_attestation_bytes()?;
    let storage_key = random_nonzero();
    let mut sealing_key = storage_key;
    let sealed = deal.seal_retained_preimages(&mut sealing_key)?;
    let entropy = random_nonzero();
    let snapshot_key = random_nonzero();
    let mut frame = Vec::new();
    frame.extend_from_slice(b"BP52CH05");
    frame.push(1);
    frame.extend_from_slice(&origin.network_id);
    frame.push(2);
    frame.extend_from_slice(&origin.network_id);
    frame.extend_from_slice(&origin.room_id);
    frame.extend_from_slice(&origin.session_nonce);
    frame.extend_from_slice(&origin.outpoint);
    frame.extend_from_slice(&origin.identities[0]);
    frame.extend_from_slice(&origin.identities[1]);
    frame.extend_from_slice(&wallet.secret_bytes());
    frame.extend_from_slice(&entropy);
    frame.extend_from_slice(&origin.witness_script);
    push_vector(&mut frame, &certificate)?;
    push_vector(&mut frame, &attestation)?;
    push_vector(&mut frame, &sealed)?;
    frame.extend_from_slice(&storage_key);
    frame.extend_from_slice(&snapshot_key);
    let participant = NativeChainParticipant::new(&frame)?;
    persist_private_state(state_name, "init", &frame)?;
    Ok(participant)
}

fn push_vector(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "CHAIN vector is too large".to_owned())?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn random_nonzero() -> [u8; 32] {
    loop {
        let mut value = [0_u8; 32];
        OsRng.fill_bytes(&mut value);
        if value != [0; 32] {
            return value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::render_card;

    #[test]
    fn cards_render_with_protocol_rank_and_unicode_suit() -> Result<(), String> {
        assert_eq!(render_card(0)?, "2♣");
        assert_eq!(render_card(12)?, "5♣");
        assert_eq!(render_card(13)?, "5♦");
        assert_eq!(render_card(48)?, "A♣");
        assert_eq!(render_card(34)?, "10♥");
        assert_eq!(render_card(51)?, "A♠");
        assert_eq!(render_card(u8::MAX)?, "🂠");
        Ok(())
    }

    #[test]
    fn invalid_projected_card_is_rejected() {
        assert!(render_card(52).is_err());
        assert!(render_card(254).is_err());
    }
}
