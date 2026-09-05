//! Bulk-memory WebAssembly boundary for the real BP52 game-session reducer.
//!
//! This bridge performs no browser, relay, wallet, clock, storage, or chain
//! I/O. JavaScript copies one bounded canonical frame into the exported input
//! region, invokes a reducer operation, and immediately copies the selected
//! output region. No JSON crosses the Wasm boundary.
//!
//! Only explicitly selected audited protocol/economics bundles are accepted.
//! Exact network identity remains a deployment input. Arbitrary economics and
//! fee policies are intentionally not decodable.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", allow(unsafe_code))]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use std::num::NonZeroU16;
use std::sync::{Mutex, OnceLock};

use bitcoin::{Network, secp256k1::XOnlyPublicKey};
use bp52_chain_bitcoin::FeePolicy;
use bp52_chain_compiler::{HEADS_UP_FIXED_LIMIT_V1_PROFILE, HeadsUpProfile};
use bp52_chain_types::{RevealOrder, Role};
use bp52_client_ports::{MAX_SESSION_SNAPSHOT_BYTES, OutPointRef};
use bp52_codec::{Decode, Encode, Reader, Writer};
use bp52_game_session::{
    BroadcastPurpose, DescriptorTerms, EventSource, GameSession, SessionConfig, SessionEvent,
    SessionIntent, SessionPhase, SessionStatus,
};
use bp52_protocol::{CanonicalIdentities, messages::Envelope};

const ABI_VERSION: u32 = 9;
const CONFIG_MAGIC: &[u8; 8] = b"BP52GM02";
const APPLY_MAGIC: &[u8; 8] = b"BP52GA01";
const EXCHANGE_RESULT_MAGIC: &[u8; 8] = b"BP52GX01";
const PROJECTION_MAGIC: &[u8; 8] = b"BP52GP07";
const PROFILE_HEADS_UP_FIXED_LIMIT_V1: u8 = 1;
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_INPUT_BYTES: usize = MAX_SESSION_SNAPSHOT_BYTES + MAX_CONFIG_BYTES + 16;
const MAX_ERROR_BYTES: usize = 2 * 1024;
const MAX_HALT_REASON_BYTES: usize = 2 * 1024;

static POLICY: OnceLock<bp52_chain_bitcoin::ClassFeePolicy> = OnceLock::new();
static MODULE: Mutex<ModuleState> = Mutex::new(ModuleState::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AppendDisposition {
    NotApplicable = 0,
    Duplicate = 1,
    Appended = 2,
}

struct SessionEngine {
    session: GameSession<'static>,
}

impl SessionEngine {
    fn new(config_bytes: &[u8]) -> Result<Self, String> {
        let config = decode_config(config_bytes)?;
        let session =
            GameSession::new(config, audited_policy()?).map_err(|error| error.to_string())?;
        Ok(Self { session })
    }

    fn replay(config_bytes: &[u8], snapshot: &[u8]) -> Result<Self, String> {
        let config = decode_config(config_bytes)?;
        let session = GameSession::replay(config, audited_policy()?, snapshot)
            .map_err(|error| error.to_string())?;
        Ok(Self { session })
    }

    fn apply(&mut self, source: EventSource, event_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let event = SessionEvent::decode(event_bytes).map_err(|error| error.to_string())?;
        self.apply_decoded(source, &event)
    }

    fn apply_exchange(&mut self, sender: Role, event_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let event = SessionEvent::decode(event_bytes)
            .map_err(|error| format!("invalid canonical session event: {error}"))?;
        validate_exchange_sender(sender, &event)?;
        let projection = self.apply_decoded(EventSource::Exchange, &event)?;
        encode_exchange_result(&projection, &event)
    }

    fn apply_graph_prepared_receipt(&mut self, receipt: &[u8]) -> Result<Vec<u8>, String> {
        self.apply_local_receipt(SessionEvent::GraphPrepared(receipt.to_vec()))
    }

    fn apply_runtime_authorization_receipt(&mut self, receipt: &[u8]) -> Result<Vec<u8>, String> {
        self.apply_local_receipt(SessionEvent::RuntimeAuthorized(receipt.to_vec()))
    }

    fn apply_confirmed_state_receipt(&mut self, receipt: &[u8]) -> Result<Vec<u8>, String> {
        self.apply_local_receipt(SessionEvent::StateConfirmed(receipt.to_vec()))
    }

    fn apply_offchain_state_receipt(&mut self, receipt: &[u8]) -> Result<Vec<u8>, String> {
        self.apply_local_receipt(SessionEvent::StateAdvancedOffchain(receipt.to_vec()))
    }

    fn apply_local_receipt(&mut self, event: SessionEvent) -> Result<Vec<u8>, String> {
        self.apply_decoded(EventSource::LocalRuntime, &event)
    }

    fn apply_decoded(
        &mut self,
        source: EventSource,
        event: &SessionEvent,
    ) -> Result<Vec<u8>, String> {
        let result = self
            .session
            .apply_from(source, event)
            .map_err(|error| error.to_string())?;
        encode_projection(
            &self.session.status(),
            self.session.game_id(),
            self.session.shared_config_hash(),
            &result.intents,
            if result.appended {
                AppendDisposition::Appended
            } else {
                AppendDisposition::Duplicate
            },
        )
    }

    fn projection(&self) -> Result<Vec<u8>, String> {
        let intents = self.session.intents().map_err(|error| error.to_string())?;
        encode_projection(
            &self.session.status(),
            self.session.game_id(),
            self.session.shared_config_hash(),
            &intents,
            AppendDisposition::NotApplicable,
        )
    }

    fn snapshot(&self) -> Result<Vec<u8>, String> {
        self.session.snapshot().map_err(|error| error.to_string())
    }
}

struct ModuleState {
    input: Vec<u8>,
    output: Vec<u8>,
    last_error: Vec<u8>,
    engine: Option<SessionEngine>,
}

impl ModuleState {
    const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            last_error: Vec::new(),
            engine: None,
        }
    }

    fn clear_error(&mut self) {
        self.last_error.clear();
    }

    fn fail(&mut self, code: i32, message: impl AsRef<str>) -> i32 {
        self.output.clear();
        self.last_error.clear();
        self.last_error
            .extend_from_slice(message.as_ref().as_bytes());
        self.last_error.truncate(MAX_ERROR_BYTES);
        code
    }

    fn set_output(&mut self, output: Vec<u8>) -> i32 {
        self.output = output;
        self.last_error.clear();
        0
    }
}

fn audited_policy() -> Result<&'static bp52_chain_bitcoin::ClassFeePolicy, String> {
    if let Some(policy) = POLICY.get() {
        return Ok(policy);
    }
    let policy = HEADS_UP_FIXED_LIMIT_V1_PROFILE
        .fee_policy()
        .map_err(|error| error.to_string())?;
    let _ = POLICY.set(policy);
    POLICY
        .get()
        .ok_or_else(|| "failed to retain the audited game fee policy".to_owned())
}

fn audited_profile(code: u8) -> Result<HeadsUpProfile, String> {
    match code {
        PROFILE_HEADS_UP_FIXED_LIMIT_V1 => Ok(HEADS_UP_FIXED_LIMIT_V1_PROFILE),
        _ => Err("unsupported game-session profile".to_owned()),
    }
}

// This profile-specific codec deliberately exposes no general fee/session
// policy knobs. Exact origin/activation economics and the witness-script
// binding are reconstructed against the audited profile below, while network
// identity is supplied by the resolved deployment configuration.
fn decode_config(bytes: &[u8]) -> Result<SessionConfig, String> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err("game config exceeds its fixed browser bound".to_owned());
    }
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != CONFIG_MAGIC {
        return Err("game config has the wrong magic".to_owned());
    }
    let profile = audited_profile(reader.read_u8().map_err(codec)?)?;
    let bitcoin_network = read_bitcoin_network(&mut reader)?;
    let network_id = reader.read_array().map_err(codec)?;
    let origin_display_txid: [u8; 32] = reader.read_array().map_err(codec)?;
    let origin_consensus_txid: [u8; 32] = reader.read_array().map_err(codec)?;
    if origin_display_txid
        .iter()
        .rev()
        .copied()
        .ne(origin_consensus_txid)
    {
        return Err("origin display txid does not reverse to consensus order".to_owned());
    }
    let origin_outpoint = OutPointRef {
        txid: origin_consensus_txid,
        vout: reader.read_u32().map_err(codec)?,
    };
    let relay_room_id = reader.read_array().map_err(codec)?;
    let deal_session_nonce = reader.read_array().map_err(codec)?;
    let alice = XOnlyPublicKey::from_slice(&reader.read_array::<32>().map_err(codec)?)
        .map_err(|_| "Alice identity is not a valid x-only key".to_owned())?;
    let bob = XOnlyPublicKey::from_slice(&reader.read_array::<32>().map_err(codec)?)
        .map_err(|_| "Bob identity is not a valid x-only key".to_owned())?;
    let identities = CanonicalIdentities::new(alice, bob).map_err(|error| error.to_string())?;
    if identities.alice() != &alice || identities.bob() != &bob {
        return Err("game config identities are not in canonical order".to_owned());
    }
    let local_role = read_role(&mut reader)?;
    let origin_confirmation_depth = NonZeroU16::new(reader.read_u16().map_err(codec)?)
        .ok_or_else(|| "origin confirmation depth is zero".to_owned())?;
    let gameplay_confirmation_depth = NonZeroU16::new(reader.read_u16().map_err(codec)?)
        .ok_or_else(|| "gameplay confirmation depth is zero".to_owned())?;
    let button = read_role(&mut reader)?;
    let reveal_order = RevealOrder {
        flop_first: read_role(&mut reader)?,
        turn_first: read_role(&mut reader)?,
        river_first: read_role(&mut reader)?,
    };
    let split_remainder_recipient = read_role(&mut reader)?;
    let origin_value_sat = reader.read_u64().map_err(codec)?;
    let activation_fee_sat = reader.read_u64().map_err(codec)?;
    let origin_witness_script = reader.read_array().map_err(codec)?;
    reader.finish().map_err(codec)?;
    let policy = audited_policy()?;
    if origin_value_sat != profile.origin_value_sat
        || activation_fee_sat != profile.activation_fee_sat
    {
        return Err("origin economics differ from the selected audited profile".to_owned());
    }
    Ok(SessionConfig {
        profile_id: network_id,
        network_id,
        bitcoin_network,
        origin_outpoint,
        origin_value_sat,
        relay_room_id,
        origin_witness_script,
        deal_session_nonce,
        identities,
        local_role,
        origin_confirmation_depth,
        gameplay_confirmation_depth,
        terms: DescriptorTerms {
            chain_protocol_version: profile.chain_protocol_version,
            button,
            unit_sat: profile.unit_sat,
            max_bets_per_street: profile.max_bets_per_street,
            alice_starting_stack_sat: profile.stack_per_player_sat,
            bob_starting_stack_sat: profile.stack_per_player_sat,
            fee_reserve_sat: profile.fee_reserve_sat,
            activation_fee_sat,
            action_csv: profile.csv_blocks,
            reveal_csv: profile.csv_blocks,
            showdown_csv: profile.csv_blocks,
            reveal_order,
            split_remainder_recipient,
            fee_policy_id: policy.policy_id(),
            compiler_id: profile.compiler_id(),
        },
    })
}

fn encode_projection(
    status: &SessionStatus,
    deal_game_id: [u8; 32],
    shared_config_hash: [u8; 32],
    intents: &[SessionIntent],
    disposition: AppendDisposition,
) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.write_bytes(PROJECTION_MAGIC);
    writer.write_u8(disposition as u8);
    writer.write_u8(phase_code(status.phase));
    writer.write_bytes(&deal_game_id);
    writer.write_bytes(&shared_config_hash);
    writer.write_u32(status.deal_attempt);
    writer.write_u32(status.deal_envelopes);
    write_optional_fixed(&mut writer, status.chain_game_id);
    write_optional_fixed(&mut writer, status.graph_root);
    write_optional_display_txid(&mut writer, status.activation_txid);
    write_optional_fixed(&mut writer, status.node_id);
    writer.write_u64(status.table_balances.alice_stack_sat);
    writer.write_u64(status.table_balances.bob_stack_sat);
    writer.write_u64(status.table_balances.pot_sat);
    write_bounded_text(&mut writer, status.halt_reason.as_deref())?;
    let intent_count = u16::try_from(intents.len())
        .map_err(|_| "session emitted too many simultaneous intents".to_owned())?;
    writer.write_u16(intent_count);
    for intent in intents {
        let encoded = encode_intent(intent)?;
        writer.write_byte_vector(&encoded).map_err(codec)?;
    }
    Ok(writer.into_bytes())
}

fn encode_exchange_result(projection: &[u8], event: &SessionEvent) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.write_bytes(EXCHANGE_RESULT_MAGIC);
    writer.write_byte_vector(projection).map_err(codec)?;
    match event {
        SessionEvent::DealEnvelope(envelope) => {
            writer.write_u8(1);
            writer.write_byte_vector(envelope).map_err(codec)?;
        }
        SessionEvent::AcceptedDealSignature { role, signature } => {
            writer.write_u8(2);
            write_role(&mut writer, *role);
            writer.write_bytes(signature);
        }
        SessionEvent::DealRetrySignature {
            next_attempt,
            role,
            signature,
        } => {
            writer.write_u8(3);
            writer.write_u32(*next_attempt);
            write_role(&mut writer, *role);
            writer.write_bytes(signature);
        }
        _ => writer.write_u8(0),
    }
    Ok(writer.into_bytes())
}

fn validate_exchange_sender(sender: Role, event: &SessionEvent) -> Result<(), String> {
    let artifact_role = match event {
        SessionEvent::DealEnvelope(bytes) => {
            let envelope = Envelope::decode_exact(bytes)
                .map_err(|error| format!("invalid DEAL envelope: {error}"))?;
            Some(match envelope.unsigned.sender_role {
                bp52_protocol::Role::Alice => Role::Alice,
                bp52_protocol::Role::Bob => Role::Bob,
            })
        }
        SessionEvent::AcceptedDealSignature { role, .. }
        | SessionEvent::DealRetrySignature { role, .. }
        | SessionEvent::DescriptorSignature { role, .. } => Some(*role),
        _ => None,
    };
    if artifact_role.is_none_or(|role| role == sender) {
        Ok(())
    } else {
        Err("authenticated relay sender differs from the session event role".to_owned())
    }
}

// Keeping the complete discriminant table in one match makes the browser wire
// mapping visibly exhaustive when SessionIntent changes.
#[allow(clippy::too_many_lines)]
fn encode_intent(intent: &SessionIntent) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    match intent {
        SessionIntent::ObserveOrigin { outpoint } => {
            writer.write_u8(0);
            write_outpoint(&mut writer, *outpoint);
        }
        SessionIntent::DealEnvelopeDue {
            attempt,
            sequence,
            round,
            sender,
            payload_type,
            previous_message_hash,
        } => {
            writer.write_u8(1);
            writer.write_u32(*attempt);
            writer.write_u32(*sequence);
            writer.write_u16(*round);
            write_role(&mut writer, *sender);
            writer.write_u16(payload_type.to_u16());
            writer.write_bytes(previous_message_hash);
        }
        SessionIntent::ApproveDealRetry {
            next_attempt,
            digest,
        } => {
            writer.write_u8(2);
            writer.write_u32(*next_attempt);
            writer.write_bytes(digest);
        }
        SessionIntent::SignAcceptedDeal { body, digest } => {
            writer.write_u8(3);
            writer
                .write_byte_vector(&body.encode_to_vec().map_err(codec)?)
                .map_err(codec)?;
            writer.write_bytes(digest);
        }
        SessionIntent::SignDescriptor { descriptor, digest } => {
            writer.write_u8(4);
            writer.write_byte_vector(descriptor).map_err(codec)?;
            writer.write_bytes(digest);
        }
        SessionIntent::PrepareGraph => {
            writer.write_u8(5);
        }
        SessionIntent::AuthorizeActivation {
            unsigned_transaction,
        } => {
            writer.write_u8(6);
            writer
                .write_byte_vector(unsigned_transaction)
                .map_err(codec)?;
        }
        SessionIntent::BroadcastTransaction {
            txid,
            transaction,
            purpose,
        } => {
            writer.write_u8(7);
            write_display_txid(&mut writer, *txid);
            writer.write_byte_vector(transaction).map_err(codec)?;
            writer.write_u8(match purpose {
                BroadcastPurpose::Activation => 0,
                BroadcastPurpose::Gameplay => 1,
            });
        }
        SessionIntent::ObserveState { outpoint } => {
            writer.write_u8(8);
            write_outpoint(&mut writer, *outpoint);
        }
        SessionIntent::ChooseRuntimeEdge {
            node_id,
            node_kind,
            edges,
            timeout_matures_at,
        } => {
            writer.write_u8(9);
            writer.write_bytes(node_id);
            writer.write_u8(node_kind.code());
            writer.write_u32(
                u32::try_from(edges.len()).map_err(|_| "runtime edge count overflow".to_owned())?,
            );
            for edge in edges {
                writer.write_bytes(&edge.child_node_id);
                let kind = edge.kind.encode_to_vec().map_err(codec)?;
                let authorization = edge.authorization.encode_to_vec().map_err(codec)?;
                writer.write_byte_vector(&kind).map_err(codec)?;
                writer.write_byte_vector(&authorization).map_err(codec)?;
                writer.write_bytes(&edge.sighash);
            }
            match timeout_matures_at {
                Some(height) => {
                    writer.write_u8(1);
                    writer.write_u32(*height);
                }
                None => writer.write_u8(0),
            }
        }
        SessionIntent::SettlementConfirmed { node_id, txid } => {
            writer.write_u8(10);
            writer.write_bytes(node_id);
            write_display_txid(&mut writer, *txid);
        }
        SessionIntent::SettlementOffchain { node_id } => {
            writer.write_u8(12);
            writer.write_bytes(node_id);
        }
        SessionIntent::Halted { reason } => {
            writer.write_u8(11);
            write_required_bounded_text(&mut writer, reason)?;
        }
    }
    Ok(writer.into_bytes())
}

fn phase_code(phase: SessionPhase) -> u8 {
    match phase {
        SessionPhase::AwaitingOrigin => 0,
        SessionPhase::Dealing => 1,
        SessionPhase::AcceptingDeal => 2,
        SessionPhase::SigningDescriptor => 3,
        SessionPhase::PreparingGraph => 4,
        SessionPhase::AuthorizingActivation => 5,
        SessionPhase::AwaitingActivation => 6,
        SessionPhase::Active => 7,
        SessionPhase::Settled => 8,
        SessionPhase::Halted => 9,
    }
}

fn write_optional_fixed(writer: &mut Writer, value: Option<[u8; 32]>) {
    match value {
        Some(bytes) => {
            writer.write_u8(1);
            writer.write_bytes(&bytes);
        }
        None => writer.write_u8(0),
    }
}

fn write_optional_display_txid(writer: &mut Writer, value: Option<[u8; 32]>) {
    match value {
        Some(consensus_txid) => {
            writer.write_u8(1);
            write_display_txid(writer, consensus_txid);
        }
        None => writer.write_u8(0),
    }
}

fn write_bounded_text(writer: &mut Writer, value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        writer.write_u8(1);
        write_required_bounded_text(writer, value)
    } else {
        writer.write_u8(0);
        Ok(())
    }
}

fn write_required_bounded_text(writer: &mut Writer, value: &str) -> Result<(), String> {
    if value.len() > MAX_HALT_REASON_BYTES {
        return Err("halt reason exceeds the browser projection bound".to_owned());
    }
    writer.write_byte_vector(value.as_bytes()).map_err(codec)
}

fn write_outpoint(writer: &mut Writer, outpoint: OutPointRef) {
    write_display_txid(writer, outpoint.txid);
    writer.write_u32(outpoint.vout);
}

fn write_display_txid(writer: &mut Writer, consensus_txid: [u8; 32]) {
    let display_txid: [u8; 32] = core::array::from_fn(|index| consensus_txid[31 - index]);
    writer.write_bytes(&display_txid);
}

fn read_role(reader: &mut Reader<'_>) -> Result<Role, String> {
    match reader.read_u8().map_err(codec)? {
        0 => Ok(Role::Alice),
        1 => Ok(Role::Bob),
        _ => Err("role byte is noncanonical".to_owned()),
    }
}

fn read_bitcoin_network(reader: &mut Reader<'_>) -> Result<Network, String> {
    match reader.read_u8().map_err(codec)? {
        0 => Ok(Network::Bitcoin),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Signet),
        3 => Ok(Network::Regtest),
        4 => Ok(Network::Testnet4),
        _ => Err("game config has an unknown Bitcoin network code".to_owned()),
    }
}

fn write_role(writer: &mut Writer, role: Role) {
    writer.write_u8(role.code());
}

fn codec(error: bp52_codec::CodecError) -> String {
    error.to_string()
}

fn with_module(operation: impl FnOnce(&mut ModuleState) -> i32) -> i32 {
    match MODULE.lock() {
        Ok(mut state) => operation(&mut state),
        Err(_) => -127,
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm_exports {
    use super::*;

    /// Return the raw bulk-memory ABI version.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_abi_version() -> u32 {
        ABI_VERSION
    }

    /// Resize the bounded input region. Returns zero on success.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_begin_input(length: u32) -> i32 {
        with_module(|state| {
            state.clear_error();
            let Ok(length) = usize::try_from(length) else {
                return state.fail(2, "input length overflow");
            };
            if length > MAX_INPUT_BYTES {
                return state.fail(2, "input exceeds the game-session ABI bound");
            }
            state.input.clear();
            state.input.resize(length, 0);
            0
        })
    }

    /// Return the current input-region pointer. Copy before invoking an operation.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_input_ptr() -> u32 {
        match MODULE.lock() {
            Ok(mut state) => u32::try_from(state.input.as_mut_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Construct a fresh reducer from the staged canonical config.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_init() -> i32 {
        with_module(|state| {
            state.clear_error();
            if state.engine.is_some() {
                return state.fail(3, "game-session reducer is already initialized");
            }
            let input = std::mem::take(&mut state.input);
            let result = SessionEngine::new(&input).and_then(|engine| {
                let projection = engine.projection()?;
                Ok((engine, projection))
            });
            match result {
                Ok((engine, projection)) => {
                    state.engine = Some(engine);
                    state.set_output(projection)
                }
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Replay a staged recovery frame into a fresh reducer.
    ///
    /// Framing: `BP52GR01 || config_len:u32 || snapshot_len:u32 || config || snapshot`.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_replay() -> i32 {
        with_module(|state| {
            state.clear_error();
            if state.engine.is_some() {
                return state.fail(3, "game-session reducer is already initialized");
            }
            let input = std::mem::take(&mut state.input);
            let (config, snapshot) = match decode_recovery(&input) {
                Ok(value) => value,
                Err(error) => return state.fail(2, error),
            };
            let result = SessionEngine::replay(config, snapshot).and_then(|engine| {
                let projection = engine.projection()?;
                Ok((engine, projection))
            });
            match result {
                Ok((engine, projection)) => {
                    state.engine = Some(engine);
                    state.set_output(projection)
                }
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Decode, verify, and transactionally apply the staged canonical event.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_apply() -> i32 {
        with_module(|state| {
            state.clear_error();
            let input = std::mem::take(&mut state.input);
            let (source, event) = match decode_apply_frame(&input) {
                Ok(value) => value,
                Err(error) => return state.fail(2, error),
            };
            let Some(engine) = state.engine.as_mut() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.apply(source, event) {
                Ok(projection) => state.set_output(projection),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Authenticate the relay sender, apply one exact exchange event, and
    /// return the reducer projection plus any validated DEAL-Worker dispatch.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_apply_exchange() -> i32 {
        with_module(|state| {
            state.clear_error();
            let input = std::mem::take(&mut state.input);
            let (sender, event) = match decode_exchange_frame(&input) {
                Ok(value) => value,
                Err(error) => return state.fail(2, error),
            };
            let Some(engine) = state.engine.as_mut() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.apply_exchange(sender, event) {
                Ok(result) => state.set_output(result),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Strictly decode and apply the local CHAIN graph-setup receipt.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_apply_graph_prepared_receipt() -> i32 {
        with_module(|state| {
            state.clear_error();
            let receipt = std::mem::take(&mut state.input);
            let Some(engine) = state.engine.as_mut() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.apply_graph_prepared_receipt(&receipt) {
                Ok(projection) => state.set_output(projection),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Strictly decode and apply one local CHAIN runtime-authorization receipt.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_apply_runtime_authorization_receipt() -> i32 {
        with_module(|state| {
            state.clear_error();
            let receipt = std::mem::take(&mut state.input);
            let Some(engine) = state.engine.as_mut() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.apply_runtime_authorization_receipt(&receipt) {
                Ok(projection) => state.set_output(projection),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Strictly decode and apply one local CHAIN confirmed-state receipt.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_apply_confirmed_state_receipt() -> i32 {
        with_module(|state| {
            state.clear_error();
            let receipt = std::mem::take(&mut state.input);
            let Some(engine) = state.engine.as_mut() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.apply_confirmed_state_receipt(&receipt) {
                Ok(projection) => state.set_output(projection),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Strictly decode and apply one locally verified cooperative state.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_apply_offchain_state_receipt() -> i32 {
        with_module(|state| {
            state.clear_error();
            let receipt = std::mem::take(&mut state.input);
            let Some(engine) = state.engine.as_mut() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.apply_offchain_state_receipt(&receipt) {
                Ok(projection) => state.set_output(projection),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Select the current status and complete intent projection.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_project() -> i32 {
        with_module(|state| {
            state.clear_error();
            let Some(engine) = state.engine.as_ref() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.projection() {
                Ok(projection) => state.set_output(projection),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Select the canonical hash-chained journal snapshot.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_snapshot() -> i32 {
        with_module(|state| {
            state.clear_error();
            let Some(engine) = state.engine.as_ref() else {
                return state.fail(1, "game-session reducer is not initialized");
            };
            match engine.snapshot() {
                Ok(snapshot) => state.set_output(snapshot),
                Err(error) => state.fail(4, error),
            }
        })
    }

    /// Return the current output-region pointer. Copy before the next ABI call.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_output_ptr() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.output.as_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Return the current output-region length.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_output_len() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.output.len()).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }

    /// Return the latest bounded diagnostic-region pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_last_error_ptr() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.last_error.as_ptr() as usize).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Return the latest bounded diagnostic-region length.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_last_error_len() -> u32 {
        match MODULE.lock() {
            Ok(state) => u32::try_from(state.last_error.len()).unwrap_or(u32::MAX),
            Err(_) => 0,
        }
    }

    /// Drop the reducer and release every public graph/journal allocation.
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_game_clear() {
        if let Ok(mut state) = MODULE.lock() {
            state.engine.take();
            state.input.clear();
            state.output.clear();
            state.last_error.clear();
        }
    }
}

fn decode_apply_frame(bytes: &[u8]) -> Result<(EventSource, &[u8]), String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != APPLY_MAGIC {
        return Err("game apply frame has the wrong magic".to_owned());
    }
    let source = match reader.read_u8().map_err(codec)? {
        0 => EventSource::Chain,
        1 => {
            return Err("exchange events require the authenticated exchange operation".to_owned());
        }
        2 => EventSource::LocalRuntime,
        3 => EventSource::LocalWallet,
        _ => return Err("game event has an unknown provenance source".to_owned()),
    };
    let event_len = usize::try_from(reader.read_u32().map_err(codec)?)
        .map_err(|_| "game event length overflow".to_owned())?;
    if event_len > bp52_game_session::MAX_EVENT_ARTIFACT_BYTES + 256 {
        return Err("game event exceeds its fixed bound".to_owned());
    }
    let event = reader.read_bytes(event_len).map_err(codec)?;
    reader.finish().map_err(codec)?;
    Ok((source, event))
}

fn decode_exchange_frame(bytes: &[u8]) -> Result<(Role, &[u8]), String> {
    let Some((&sender, event)) = bytes.split_first() else {
        return Err("authenticated game exchange frame is empty".to_owned());
    };
    let sender = match sender {
        0 => Role::Alice,
        1 => Role::Bob,
        _ => return Err("authenticated game exchange sender is noncanonical".to_owned()),
    };
    if event.len() > bp52_game_session::MAX_EVENT_ARTIFACT_BYTES + 256 {
        return Err("game exchange event exceeds its fixed bound".to_owned());
    }
    Ok((sender, event))
}

fn decode_recovery(bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != b"BP52GR01" {
        return Err("game recovery frame has the wrong magic".to_owned());
    }
    let config_len = usize::try_from(reader.read_u32().map_err(codec)?)
        .map_err(|_| "config length overflow".to_owned())?;
    let snapshot_len = usize::try_from(reader.read_u32().map_err(codec)?)
        .map_err(|_| "snapshot length overflow".to_owned())?;
    if config_len > MAX_CONFIG_BYTES || snapshot_len > MAX_SESSION_SNAPSHOT_BYTES {
        return Err("game recovery component exceeds its fixed bound".to_owned());
    }
    let config = reader.read_bytes(config_len).map_err(codec)?;
    let snapshot = reader.read_bytes(snapshot_len).map_err(codec)?;
    reader.finish().map_err(codec)?;
    Ok((config, snapshot))
}

#[cfg(test)]
mod tests {
    use bitcoin::Script;
    use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
    use bp52_chain_bitcoin::custom_signet_network_id;
    use bp52_origin::OriginContext;

    use super::*;

    #[test]
    fn graph_preparation_intent_is_constant_size() -> Result<(), String> {
        let encoded = encode_intent(&SessionIntent::PrepareGraph)?;
        assert_eq!(encoded, [5]);
        Ok(())
    }

    fn test_key(marker: u8) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secret = SecretKey::from_slice(&[marker; 32])?;
        Ok(Keypair::from_secret_key(&Secp256k1::new(), &secret))
    }

    fn config_bytes() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let profile_code = PROFILE_HEADS_UP_FIXED_LIMIT_V1;
        let mut keys = [test_key(1)?, test_key(2)?];
        keys.sort_unstable_by_key(|key| key.x_only_public_key().0.serialize());
        let network_id = custom_signet_network_id(Script::from_bytes(&[0x51]));
        let relay_room_id = [5; 32];
        let session_nonce = [4; 32];
        let context = OriginContext::new(network_id, relay_room_id, session_nonce)?;
        let mut origin_witness_script = [0_u8; 104];
        origin_witness_script[0] = 32;
        origin_witness_script[1..33].copy_from_slice(&context.commitment());
        origin_witness_script[33] = 0x75;
        origin_witness_script[34] = 33;
        origin_witness_script[35..68]
            .copy_from_slice(&PublicKey::from_keypair(&keys[0]).serialize());
        origin_witness_script[68] = 0xad;
        origin_witness_script[69] = 33;
        origin_witness_script[70..103]
            .copy_from_slice(&PublicKey::from_keypair(&keys[1]).serialize());
        origin_witness_script[103] = 0xac;
        let mut writer = Writer::new();
        writer.write_bytes(CONFIG_MAGIC);
        writer.write_u8(profile_code);
        writer.write_u8(2);
        writer.write_bytes(&network_id);
        let display_txid: [u8; 32] = core::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
        let consensus_txid: [u8; 32] = core::array::from_fn(|index| display_txid[31 - index]);
        writer.write_bytes(&display_txid);
        writer.write_bytes(&consensus_txid);
        writer.write_u32(0);
        writer.write_bytes(&relay_room_id);
        writer.write_bytes(&session_nonce);
        writer.write_bytes(&keys[0].x_only_public_key().0.serialize());
        writer.write_bytes(&keys[1].x_only_public_key().0.serialize());
        writer.write_u8(Role::Alice.code());
        writer.write_u16(1);
        writer.write_u16(1);
        writer.write_u8(Role::Alice.code());
        writer.write_u8(Role::Alice.code());
        writer.write_u8(Role::Bob.code());
        writer.write_u8(Role::Alice.code());
        writer.write_u8(Role::Bob.code());
        let profile = audited_profile(profile_code).map_err(std::io::Error::other)?;
        writer.write_u64(profile.origin_value_sat);
        writer.write_u64(profile.activation_fee_sat);
        writer.write_bytes(&origin_witness_script);
        Ok(writer.into_bytes())
    }

    fn decode_hex_fixture(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let value = value.trim();
        if value.len() % 2 != 0 {
            return Err(std::io::Error::other("hex fixture has an odd length").into());
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair)?;
                Ok(u8::from_str_radix(pair, 16)?)
            })
            .collect()
    }

    #[test]
    fn browser_config_contract_fixture_decodes_in_rust() -> Result<(), Box<dyn std::error::Error>> {
        let bytes =
            decode_hex_fixture(include_str!("../../../browser/fixtures/game-config-v2.hex"))?;
        let config = decode_config(&bytes)?;
        assert_eq!(config.origin_outpoint.vout, 7);
        assert_eq!(config.origin_confirmation_depth.get(), 1);
        assert_eq!(config.gameplay_confirmation_depth.get(), 2);
        assert_eq!(config.origin_value_sat, 53_500);
        assert_eq!(config.terms.activation_fee_sat, 500);
        assert_eq!(config.terms.unit_sat, 100);
        assert_eq!(config.terms.max_bets_per_street, 4);
        assert_eq!(config.terms.alice_starting_stack_sat, 20_000);
        Ok(())
    }

    #[test]
    fn current_profile_selector_uses_bounded_fixed_limit_terms()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = config_bytes()?;
        let config = decode_config(&bytes)?;
        assert_eq!(
            config.terms.chain_protocol_version,
            bp52_chain_types::CHAIN_PROTOCOL_VERSION
        );
        assert_eq!(config.terms.unit_sat, 100);
        assert_eq!(config.terms.max_bets_per_street, 4);
        assert_eq!(config.terms.alice_starting_stack_sat, 20_000);
        assert_eq!(config.terms.bob_starting_stack_sat, 20_000);
        assert_eq!(config.terms.fee_reserve_sat, 13_000);
        assert_eq!(
            config.terms.compiler_id,
            HEADS_UP_FIXED_LIMIT_V1_PROFILE.compiler_id()
        );
        let engine = SessionEngine::new(&bytes)?;
        let snapshot = engine.snapshot()?;
        assert_eq!(
            SessionEngine::replay(&bytes, &snapshot)?.snapshot()?,
            snapshot
        );
        Ok(())
    }

    #[test]
    fn configured_signet_projects_and_replays_empty_journal()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = config_bytes()?;
        let engine = SessionEngine::new(&config)?;
        let decoded = decode_config(&config)?;
        let expected_game_id = [
            0xc1, 0x2c, 0xc2, 0x39, 0x9f, 0x8a, 0xf0, 0x36, 0xbb, 0x55, 0xe1, 0x05, 0x3d, 0xc2,
            0xa7, 0x4e, 0xc8, 0x84, 0xdf, 0x12, 0xdb, 0x8b, 0x04, 0x59, 0xd3, 0x7d, 0x32, 0x1e,
            0x4b, 0x07, 0xc5, 0x75,
        ];
        assert_eq!(engine.session.game_id(), expected_game_id);
        assert_eq!(
            decoded.origin_outpoint.txid,
            core::array::from_fn(|index| u8::try_from(31 - index).unwrap_or(0))
        );
        let projection = engine.projection()?;
        assert_eq!(&projection[..8], PROJECTION_MAGIC);
        assert_eq!(projection[8], AppendDisposition::NotApplicable as u8);
        assert_eq!(projection[9], phase_code(SessionPhase::AwaitingOrigin));
        assert_eq!(&projection[10..42], &expected_game_id);
        assert_eq!(&projection[42..74], &engine.session.shared_config_hash());
        let snapshot = engine.snapshot()?;
        let replayed = SessionEngine::replay(&config, &snapshot)?;
        assert_eq!(replayed.snapshot()?, snapshot);
        assert_eq!(replayed.projection()?, projection);
        Ok(())
    }

    #[test]
    fn activation_status_txid_is_projected_in_display_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let consensus_txid: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let display_txid: [u8; 32] = core::array::from_fn(|index| consensus_txid[31 - index]);
        let status = SessionStatus {
            phase: SessionPhase::Active,
            deal_attempt: 0,
            deal_envelopes: 16,
            chain_game_id: None,
            graph_root: None,
            activation_txid: Some(consensus_txid),
            node_id: None,
            table_balances: bp52_game_session::TableBalances {
                alice_stack_sat: 5_686,
                bob_stack_sat: 5_686,
                pot_sat: 0,
            },
            halt_reason: None,
        };
        let projection = encode_projection(
            &status,
            [0x11; 32],
            [0x22; 32],
            &[],
            AppendDisposition::NotApplicable,
        )?;
        assert_eq!(projection[84], 1);
        assert_eq!(&projection[85..117], &display_txid);
        assert_eq!(u64::from_le_bytes(projection[118..126].try_into()?), 5_686);
        assert_eq!(u64::from_le_bytes(projection[126..134].try_into()?), 5_686);
        assert_eq!(u64::from_le_bytes(projection[134..142].try_into()?), 0);
        Ok(())
    }

    #[test]
    fn config_rejects_arbitrary_profile_and_trailing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut wrong_profile = config_bytes()?;
        wrong_profile[8] = u8::MAX;
        assert!(decode_config(&wrong_profile).is_err());

        let mut trailing = config_bytes()?;
        trailing.push(0);
        assert!(decode_config(&trailing).is_err());

        let mut mismatched_txid = config_bytes()?;
        // Display txid begins at 41 and the consensus copy begins at 73.
        mismatched_txid[73] ^= 1;
        assert!(decode_config(&mismatched_txid).is_err());

        let mut mismatched_script = config_bytes()?;
        let last = mismatched_script.len() - 1;
        mismatched_script[last] ^= 1;
        assert!(SessionEngine::new(&mismatched_script).is_err());
        Ok(())
    }

    #[test]
    fn recovery_codec_is_exact_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let config = config_bytes()?;
        let snapshot = SessionEngine::new(&config)?.snapshot()?;
        let mut writer = Writer::new();
        writer.write_bytes(b"BP52GR01");
        writer.write_u32(u32::try_from(config.len())?);
        writer.write_u32(u32::try_from(snapshot.len())?);
        writer.write_bytes(&config);
        writer.write_bytes(&snapshot);
        let frame = writer.into_bytes();
        assert_eq!(
            decode_recovery(&frame)?,
            (config.as_slice(), snapshot.as_slice())
        );

        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_recovery(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_exchange_wire_binds_sender_and_returns_rust_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let event = SessionEvent::AcceptedDealSignature {
            role: Role::Alice,
            signature: [9; 64],
        };
        let event_bytes = event.encode()?;
        let mut frame = vec![Role::Alice.code()];
        frame.extend_from_slice(&event_bytes);
        let (sender, encoded) = decode_exchange_frame(&frame)?;
        let decoded = SessionEvent::decode(encoded)?;
        validate_exchange_sender(sender, &decoded)?;
        assert!(validate_exchange_sender(Role::Bob, &decoded).is_err());

        let result = encode_exchange_result(&[1, 2], &decoded)?;
        let mut reader = Reader::new(&result);
        assert_eq!(reader.read_array::<8>()?, *EXCHANGE_RESULT_MAGIC);
        assert_eq!(reader.read_byte_vector(2)?, [1, 2]);
        assert_eq!(reader.read_u8()?, 2);
        assert_eq!(reader.read_u8()?, Role::Alice.code());
        assert_eq!(reader.read_array::<64>()?, [9; 64]);
        reader.finish()?;

        let mut wrong_sender = frame.clone();
        wrong_sender[0] = 2;
        assert!(decode_exchange_frame(&wrong_sender).is_err());
        let mut trailing = event_bytes;
        trailing.push(0);
        assert!(SessionEvent::decode(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn generic_apply_wire_rejects_exchange_provenance() -> Result<(), Box<dyn std::error::Error>> {
        let event = SessionEvent::DealRetrySignature {
            next_attempt: 1,
            role: Role::Alice,
            signature: [1; 64],
        }
        .encode()?;
        let mut writer = Writer::new();
        writer.write_bytes(APPLY_MAGIC);
        writer.write_u8(1);
        writer.write_u32(u32::try_from(event.len())?);
        writer.write_bytes(&event);
        assert!(decode_apply_frame(&writer.into_bytes()).is_err());
        Ok(())
    }
}
