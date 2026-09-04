//! Secret-owning browser runtime for audited BP52 heads-up graph profiles.
//!
//! This module is designed to run alone in a dedicated Web Worker. Its raw
//! bulk-memory ABI accepts bounded canonical byte frames and never exposes the
//! identity secret, Lamport secret halves, retained DEAL preimages, or private
//! runtime-signature inventory. Public outputs are limited to authenticated
//! exchange artifacts, activation signatures/transactions, runtime witnesses,
//! erasure attestations, and verified card identifiers.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", allow(unsafe_code))]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod lamport_inventory;

use std::collections::BTreeSet;
use std::num::NonZeroU16;
use std::sync::{Mutex, OnceLock};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Network, ScriptBuf, Transaction, TxOut, Witness as BitcoinWitness};
use bp52_bitcoin::{
    ALICE_HOLE_SLOTS, BOB_HOLE_SLOTS, CommunityStage, verify_community_reveal,
    verify_hole_card_delivery, verify_showdown_reveal,
};
use bp52_chain_bitcoin::{
    DefaultSighashSignature, RevealPattern, ensure_non_mainnet, sign_sighash_default,
    validate_network_identity,
};
use bp52_chain_compiler::{
    AgreedGraphRoot, CompiledGraphSummary, GraphRootOpening, HEADS_UP_FIXED_LIMIT_V1_PROFILE,
    HeadsUpProfile, LamportPublicMaterial, LogicalGraphPlan, MaterializedGraphWindow,
    OracleSignatureRequests, PlannedState, Preauthorization, PreauthorizationBundle,
    PreauthorizationVerifiedReceipt, PreparedChainGraph, PublicEdgeReceipt, PublicStateBalances,
    RuntimeAuthorizationReceipt, SignatureBundleOpening, SignedCommitment, commit_graph_root,
    commit_signature_bundle, compile_graph_oracle, compile_graph_oracle_window,
    issue_confirmed_state_receipt, issue_externally_verified_preauthorization_receipt,
    issue_graph_prepared_receipt, issue_locally_generated_preauthorization_receipt,
    issue_preauthorization_verified_receipt, issue_runtime_authorization_receipt,
    prepare_chain_graph, prepare_chain_graph_from_plan, signature_bundle_opening_digest,
    verify_matching_graph_roots, verify_preauthorization_verified_receipt,
    verify_signature_bundle_binding,
};
use bp52_chain_runtime::{
    AuthorizedGraph, BitcoinSigner, ChainBackend, ChainMonitor, MonitorState,
    PreauthorizationSource, PublicPreimageStore, RuntimeError, SecretEraser, SignerError,
    build_action_witness, build_alice_showdown_witness, build_bob_payout_witness,
    build_reveal_witness, build_timeout_witness,
};
use bp52_chain_types::{
    Action, ChainGameDescriptor, EdgeKind, LogicalOutput, NodeId, Role, ShowdownOutcome,
    SignedChainGameDescriptor, Street, chain_game_id, descriptor_signature_digest, root_node_id,
    verify_signed_chain_descriptor,
};
use bp52_codec::{Decode, Encode, Reader, Writer};
use bp52_game_session::SessionEvent;
use bp52_lamport::{
    HASH_SIZE, KeyContext, LamportPublicBundle, LamportPublicKey, LamportPurpose, LamportRole,
};
use bp52_poker::{SUBSETS_5_OF_7, evaluate_five_cards};
use bp52_protocol::auth::derive_game_id;
use bp52_protocol::messages::AcceptedDeal;
use bp52_protocol::{
    CanonicalIdentities, DealVerificationAttestation, PreimageStorageKey, RetainedPreimages,
    SealedRetainedPreimages, VerifiedAcceptedDeal, verify_attested_accepted_deal,
    verify_deal_verification,
};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const ABI_VERSION: u32 = 5;
const INIT_MAGIC: &[u8; 8] = b"BP52CH05";
const PROFILE_HEADS_UP_FIXED_LIMIT_V1: u8 = 1;
const CARD_MAGIC: &[u8; 8] = b"BP52CP01";
const CONTEXT_MAGIC: &[u8; 8] = b"BP52CT01";
const SNAPSHOT_MAGIC: &[u8; 8] = b"BP52CS04";
const SNAPSHOT_BODY_MAGIC: &[u8; 8] = b"BP52SB04";
const RUNTIME_STATUS_MAGIC: &[u8; 8] = b"BP52RS01";
const SESSION_EVENT_RESULT_MAGIC: &[u8; 8] = b"BP52SE02";
const SETUP_EXCHANGE_MAGIC: &[u8; 8] = b"BP52CX01";
const PREAUTHORIZATION_PLAN_MAGIC: &[u8; 8] = b"BP52PP01";
const PREAUTHORIZATION_BATCH_MAGIC: &[u8; 8] = b"BP52PB01";
const PREAUTHORIZATION_GENERATION_PLAN_MAGIC: &[u8; 8] = b"BP52PG01";
const PREAUTHORIZATION_SIGNING_BATCH_MAGIC: &[u8; 8] = b"BP52PS01";
const PREAUTHORIZATION_SIGNING_RESULT_MAGIC: &[u8; 8] = b"BP52PR01";
const PREAUTHORIZATION_GENERATION_RESULT_MAGIC: &[u8; 8] = b"BP52GR01";
const LAMPORT_GENERATION_PLAN_MAGIC: &[u8; 8] = b"BP52LG01";
const LAMPORT_GENERATION_BATCH_MAGIC: &[u8; 8] = b"BP52LB01";
const LAMPORT_GENERATION_SHARD_MAGIC: &[u8; 8] = b"BP52LS01";
const LAMPORT_GENERATION_RESULT_MAGIC: &[u8; 8] = b"BP52LR01";
const SNAPSHOT_VERSION: u16 = 4;
const INVENTORY_TAG: &[u8] = b"BP52/runtime-inventory-ready/v1";
const PEER_INVENTORY_TAG: &[u8] = b"BP52/chain-inventory-ready/v1";
const ERASURE_TAG: &[u8] = b"BP52/secret-erasure/v1";
const RNG_TAG: &[u8] = b"BP52/browser-chain-worker-rng/v1";
const LAMPORT_BUNDLE_AUX_TAG: &[u8] = b"BP52/browser-chain-lamport-bundle-aux/v1";
const SNAPSHOT_KEY_TAG: &[u8] = b"BP52/browser-chain-snapshot-key/v1";
const PREAUTH_SIGNATURE_AUX_TAG: &[u8] = b"BP52/browser-chain-preauth-signature-aux/v1";
const ORIGIN_SCRIPT_BYTES: usize = 104;
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 2 * 1024;
const MAX_DEAL_ATTESTATION_BYTES: usize = 2 * 1024;
const MAX_SEALED_PREIMAGE_BYTES: usize = 1_024;
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LAMPORT_BUNDLE_BYTES: usize = 12 * 1024 * 1024;
const MAX_PREAUTHORIZATION_OPENING_BYTES: usize = 3 * 1024 * 1024;
const MAX_PREAUTHORIZATION_VERIFIERS: usize = 8;
const MAX_LAMPORT_KEY_STATES: u16 = 8_192;
const MAX_LAMPORT_STATE_BYTES: usize = (MAX_LAMPORT_KEY_STATES as usize).div_ceil(4);
const MAX_CONFIRMATION_RECORDS: u16 = HEADS_UP_FIXED_LIMIT_V1_PROFILE.maximum_path_length + 1;
const MAX_CACHED_WITNESS_BYTES: usize = 2 * 1024 * 1024;
const MISSING_CARD: u8 = u8::MAX;

static POLICY: OnceLock<bp52_chain_bitcoin::ClassFeePolicy> = OnceLock::new();
static MODULE: Mutex<ModuleState> = Mutex::new(ModuleState::new());

use lamport_inventory::DeterministicLamportInventory;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
enum Phase {
    Empty = 0,
    AcceptedDeal = 1,
    DescriptorCandidate = 2,
    LamportReady = 3,
    GraphReady = 4,
    RootAgreed = 5,
    PreauthorizationsReady = 6,
    InventoryVerified = 7,
    Active = 8,
    Settled = 9,
    Halted = 10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum SetupEventKind {
    DescriptorSignature = 0,
    LamportPublicBundle = 1,
    GraphRootCommitment = 2,
    GraphRootOpening = 3,
    PreauthorizationCommitment = 4,
    PreauthorizationOpening = 5,
    NotApplicable = 255,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum SetupEventStatus {
    Applied = 0,
    Duplicate = 1,
    NotApplicable = 2,
}

struct IdentitySecret {
    bytes: Zeroizing<[u8; 32]>,
}

impl IdentitySecret {
    fn new(bytes: [u8; 32]) -> Result<Self, String> {
        SecretKey::from_slice(&bytes).map_err(|_| "invalid local identity secret".to_owned())?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    fn keypair(&self) -> Result<Keypair, String> {
        Keypair::from_seckey_slice(&Secp256k1::new(), self.bytes.as_ref())
            .map_err(|_| "local identity secret became invalid".to_owned())
    }

    fn secret_key(&self) -> Result<SecretKey, String> {
        SecretKey::from_slice(self.bytes.as_ref())
            .map_err(|_| "local identity secret became invalid".to_owned())
    }
}

type WorkerRng = ChaCha20Rng;

struct ModuleState {
    input: Vec<u8>,
    output: Vec<u8>,
    last_error: Vec<u8>,
    engine: Option<ChainEngine>,
    permanently_cleared: bool,
}

impl ModuleState {
    const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            last_error: Vec::new(),
            engine: None,
            permanently_cleared: false,
        }
    }

    fn fail(&mut self, code: i32, message: impl AsRef<str>) -> i32 {
        self.output.zeroize();
        self.output.clear();
        self.last_error.clear();
        self.last_error
            .extend_from_slice(message.as_ref().as_bytes());
        self.last_error.truncate(MAX_ERROR_BYTES);
        code
    }

    fn succeed(&mut self, output: Vec<u8>) -> i32 {
        self.output.zeroize();
        self.output = output;
        self.last_error.clear();
        0
    }
}

struct AuthorizationCache {
    node_id: NodeId,
    request: Vec<u8>,
    witness: Vec<u8>,
}

struct ErasureCache {
    parent_node_id: NodeId,
    child_txid: [u8; 32],
    attestation: [u8; 64],
}

struct OpenedCheckpoint {
    counter: u64,
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    nonce: [u8; 24],
    body: Zeroizing<Vec<u8>>,
}

enum ConfirmedRecord {
    Activation {
        confirmed_height: u32,
        tip_height: u32,
        transaction: Vec<u8>,
    },
    Child {
        confirmed_height: u32,
        tip_height: u32,
        transaction: Vec<u8>,
    },
}

struct ChainEngine {
    phase: Phase,
    profile: HeadsUpProfile,
    secret: IdentitySecret,
    rng: WorkerRng,
    snapshot_key: Zeroizing<[u8; 32]>,
    snapshot_nonces: BTreeSet<[u8; 24]>,
    checkpoint_counter: u64,
    shared_config_hash: [u8; 32],
    network_id: [u8; 32],
    bitcoin_network: Network,
    relay_room_id: [u8; 32],
    session_nonce: [u8; 32],
    origin_outpoint: [u8; 36],
    identities: CanonicalIdentities,
    local_role: Role,
    origin_witness_script: [u8; ORIGIN_SCRIPT_BYTES],
    origin_output: TxOut,
    verified_deal: VerifiedAcceptedDeal,
    retained_preimages: Option<RetainedPreimages>,
    descriptor_candidate: Option<ChainGameDescriptor>,
    descriptor_signature: Option<[u8; 64]>,
    descriptor_event_signatures: [Option<[u8; 64]>; 2],
    signed_descriptor_bytes: Option<Vec<u8>>,
    verified_descriptor: Option<bp52_chain_types::VerifiedChainDescriptor>,
    lamport_inventory: Option<DeterministicLamportInventory>,
    lamport_bundles: [Option<LamportPublicBundle>; 2],
    logical_plan: Option<LogicalGraphPlan>,
    pending_local_lamport_generation: bool,
    graph_summary: Option<CompiledGraphSummary>,
    graph_window: Option<MaterializedGraphWindow>,
    setup_signature_requests: Option<OracleSignatureRequests>,
    root_commitments: [Option<SignedCommitment>; 2],
    root_openings: [Option<GraphRootOpening>; 2],
    agreed_root: Option<AgreedGraphRoot>,
    preauth_commitments: [Option<SignedCommitment>; 2],
    transient_local_preauth_opening: Option<SignatureBundleOpening>,
    pending_local_preauth_generation: bool,
    pending_peer_preauth_opening: Option<SignatureBundleOpening>,
    preauth_openings: [Option<SignatureBundleOpening>; 2],
    preauth_verified: [bool; 2],
    preauth_receipts: [Option<PreauthorizationVerifiedReceipt>; 2],
    local_preauth_nonce: Option<[u8; 32]>,
    inventory_verified: bool,
    inventory_attestation: Option<[u8; 64]>,
    inventory_ready: [Option<[u8; 64]>; 2],
    monitor: Option<ChainMonitor>,
    public_preimages: Option<PublicPreimageStore>,
    authorization_cache: Option<AuthorizationCache>,
    last_erasure: Option<ErasureCache>,
    confirmed_history: Vec<ConfirmedRecord>,
}

impl ChainEngine {
    #[allow(clippy::too_many_lines)]
    fn initialize(bytes: &[u8]) -> Result<Self, String> {
        let mut reader = Reader::new(bytes);
        let magic = reader.read_array::<8>().map_err(codec)?;
        if &magic != INIT_MAGIC {
            return Err("CHAIN initialization has the wrong magic".to_owned());
        }
        let profile = audited_profile(reader.read_u8().map_err(codec)?)?;
        let shared_config_hash = reader.read_array().map_err(codec)?;
        let bitcoin_network = read_bitcoin_network(&mut reader)?;
        let network_id = reader.read_array().map_err(codec)?;
        let relay_room_id = reader.read_array().map_err(codec)?;
        let session_nonce = reader.read_array().map_err(codec)?;
        if shared_config_hash == [0; 32] || relay_room_id == [0; 32] || session_nonce == [0; 32] {
            return Err("CHAIN initialization contains a zero session binding".to_owned());
        }
        validate_network_identity(network_id, bitcoin_network)
            .map_err(|error| error.to_string())?;
        ensure_non_mainnet(bitcoin_network).map_err(|error| error.to_string())?;
        let origin_outpoint = reader.read_array().map_err(codec)?;
        if origin_outpoint[..32].iter().all(|byte| *byte == 0)
            && origin_outpoint[32..] == u32::MAX.to_le_bytes()
        {
            return Err("CHAIN initialization contains the null origin outpoint".to_owned());
        }
        let alice_bytes = reader.read_array::<32>().map_err(codec)?;
        let bob_bytes = reader.read_array::<32>().map_err(codec)?;
        let alice = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&alice_bytes)
            .map_err(|_| "invalid Alice x-only identity".to_owned())?;
        let bob = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bob_bytes)
            .map_err(|_| "invalid Bob x-only identity".to_owned())?;
        let identities = CanonicalIdentities::new(alice, bob).map_err(|error| error.to_string())?;
        if identities.alice() != &alice || identities.bob() != &bob {
            return Err("CHAIN identities are not in canonical order".to_owned());
        }
        let mut secret_bytes = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
        let secret = IdentitySecret::new(*secret_bytes)?;
        secret_bytes.zeroize();
        let keypair = secret.keypair()?;
        let local_xonly = keypair.x_only_public_key().0;
        let local_role = if &local_xonly == identities.alice() {
            Role::Alice
        } else if &local_xonly == identities.bob() {
            Role::Bob
        } else {
            return Err("local identity secret is not a session participant".to_owned());
        };
        let mut entropy = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
        if entropy.iter().all(|byte| *byte == 0) {
            return Err("CHAIN entropy seed is zero".to_owned());
        }
        let origin_witness_script = reader.read_array().map_err(codec)?;
        validate_origin_script(&origin_witness_script, &identities)?;
        let certificate_bytes = reader.read_byte_vector(1_024).map_err(codec)?;
        let attestation_bytes = reader
            .read_byte_vector(MAX_DEAL_ATTESTATION_BYTES)
            .map_err(codec)?;
        let sealed_bytes = reader
            .read_byte_vector(MAX_SEALED_PREIMAGE_BYTES)
            .map_err(codec)?;
        let mut storage_key_bytes = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
        let snapshot_key = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
        reader.finish().map_err(codec)?;
        if snapshot_key.iter().all(|byte| *byte == 0) {
            return Err("CHAIN snapshot key is zero".to_owned());
        }

        let deal =
            AcceptedDeal::decode_exact(&certificate_bytes).map_err(|error| error.to_string())?;
        let expected_game_id =
            derive_game_id(&network_id, &origin_outpoint, &identities, &session_nonce);
        if deal.game_id != expected_game_id {
            return Err("accepted DEAL belongs to another funded session".to_owned());
        }
        let attestation = DealVerificationAttestation::decode_exact(&attestation_bytes)
            .map_err(|error| error.to_string())?;
        let verification = verify_deal_verification(
            &Secp256k1::verification_only(),
            &identities,
            to_deal_role(local_role),
            shared_config_hash,
            session_nonce,
            expected_game_id,
            deal.attempt,
            deal.verification_transcript_root,
            &attestation,
        )
        .map_err(|error| error.to_string())?;
        let verified_deal = verify_attested_accepted_deal(
            &Secp256k1::verification_only(),
            &identities,
            &verification,
            &deal,
        )
        .map_err(|error| error.to_string())?;
        let storage_key = PreimageStorageKey::from_bytes(*storage_key_bytes);
        storage_key_bytes.zeroize();
        let sealed = SealedRetainedPreimages::from_bytes(&sealed_bytes)
            .map_err(|error| error.to_string())?;
        let retained_preimages = sealed
            .open(
                verified_deal.as_deal(),
                to_deal_role(local_role),
                &storage_key,
            )
            .map_err(|error| error.to_string())?;
        drop(storage_key);

        let mut seed = Sha256::new();
        seed.update(RNG_TAG);
        seed.update(&entropy[..]);
        seed.update(shared_config_hash);
        seed.update(network_id);
        seed.update([bitcoin_network_code(bitcoin_network)]);
        seed.update(session_nonce);
        seed.update(verified_deal.as_deal().game_id);
        seed.update(local_xonly.serialize());
        let seed: [u8; 32] = seed.finalize().into();
        entropy.zeroize();
        let script_hash = sha256::Hash::hash(&origin_witness_script).to_byte_array();
        let mut script_pubkey = Vec::with_capacity(34);
        script_pubkey.extend_from_slice(&[0, 32]);
        script_pubkey.extend_from_slice(&script_hash);
        let origin_output = profile.origin_output(ScriptBuf::from_bytes(script_pubkey));

        Ok(Self {
            phase: Phase::AcceptedDeal,
            profile,
            secret,
            rng: WorkerRng::from_seed(seed),
            snapshot_key: Zeroizing::new(*snapshot_key),
            snapshot_nonces: BTreeSet::new(),
            checkpoint_counter: 0,
            shared_config_hash,
            network_id,
            bitcoin_network,
            relay_room_id,
            session_nonce,
            origin_outpoint,
            identities,
            local_role,
            origin_witness_script,
            origin_output,
            verified_deal,
            retained_preimages: Some(retained_preimages),
            descriptor_candidate: None,
            descriptor_signature: None,
            descriptor_event_signatures: std::array::from_fn(|_| None),
            signed_descriptor_bytes: None,
            verified_descriptor: None,
            lamport_inventory: None,
            lamport_bundles: std::array::from_fn(|_| None),
            logical_plan: None,
            pending_local_lamport_generation: false,
            graph_summary: None,
            graph_window: None,
            setup_signature_requests: None,
            root_commitments: std::array::from_fn(|_| None),
            root_openings: std::array::from_fn(|_| None),
            agreed_root: None,
            preauth_commitments: std::array::from_fn(|_| None),
            transient_local_preauth_opening: None,
            pending_local_preauth_generation: false,
            pending_peer_preauth_opening: None,
            preauth_openings: std::array::from_fn(|_| None),
            preauth_verified: [false; 2],
            preauth_receipts: std::array::from_fn(|_| None),
            local_preauth_nonce: None,
            inventory_verified: false,
            inventory_attestation: None,
            inventory_ready: std::array::from_fn(|_| None),
            monitor: None,
            public_preimages: None,
            authorization_cache: None,
            last_erasure: None,
            confirmed_history: Vec::new(),
        })
    }

    fn accept_session_event(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let (sender, event) = decode_authenticated_session_event(bytes)?;
        let SessionEvent::DescriptorSignature {
            role,
            descriptor,
            signature,
        } = event
        else {
            return encode_setup_event_result(
                SetupEventKind::NotApplicable,
                SetupEventStatus::NotApplicable,
                self.phase,
                &[],
            );
        };
        let (status, bundle) =
            self.accept_descriptor_event(sender, role, &descriptor, signature)?;
        encode_setup_event_result(
            SetupEventKind::DescriptorSignature,
            status,
            self.phase,
            &bundle,
        )
    }

    fn accept_setup_exchange(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let (sender, kind, artifact) = decode_setup_exchange(bytes)?;
        let (status, receipt) = match kind {
            SetupEventKind::LamportPublicBundle => {
                let bundle = LamportPublicBundle::decode(&artifact)
                    .map_err(|error| format!("invalid Lamport public bundle: {error}"))?;
                require_event_sender(sender, from_lamport_role(bundle.role()))?;
                let status = match self.lamport_bundle(sender) {
                    Some(existing) if existing == &bundle => SetupEventStatus::Duplicate,
                    Some(_) => return self.halt("conflicting Lamport bundle"),
                    None => {
                        self.accept_lamport_bundle(&artifact)?;
                        SetupEventStatus::Applied
                    }
                };
                (status, Vec::new())
            }
            SetupEventKind::GraphRootCommitment => {
                let commitment = SignedCommitment::decode_exact(&artifact)
                    .map_err(|error| format!("invalid graph-root commitment: {error}"))?;
                require_event_sender(sender, commitment.role())?;
                if commitment.purpose() != bp52_chain_compiler::CommitmentPurpose::GraphRoot {
                    return Err("setup exchange has the wrong graph-root purpose".to_owned());
                }
                let index = role_index(sender);
                let status = match self.root_commitments[index] {
                    Some(existing) if existing == commitment => SetupEventStatus::Duplicate,
                    Some(_) => return self.halt("conflicting graph-root commitment"),
                    None => {
                        self.accept_root_commitment(&artifact)?;
                        SetupEventStatus::Applied
                    }
                };
                (status, Vec::new())
            }
            SetupEventKind::GraphRootOpening => {
                let opening = GraphRootOpening::decode_exact(&artifact)
                    .map_err(|error| format!("invalid graph-root opening: {error}"))?;
                require_event_sender(sender, opening.role())?;
                let index = role_index(sender);
                let status = match self.root_openings[index] {
                    Some(existing) if existing == opening => SetupEventStatus::Duplicate,
                    Some(_) => return self.halt("conflicting graph-root opening"),
                    None => {
                        self.accept_root_opening(&artifact)?;
                        SetupEventStatus::Applied
                    }
                };
                (status, Vec::new())
            }
            SetupEventKind::PreauthorizationCommitment => {
                let commitment = SignedCommitment::decode_exact(&artifact)
                    .map_err(|error| format!("invalid preauthorization commitment: {error}"))?;
                require_event_sender(sender, commitment.role())?;
                if commitment.purpose()
                    != bp52_chain_compiler::CommitmentPurpose::PreauthorizationBundle
                {
                    return Err("setup exchange has the wrong preauthorization purpose".to_owned());
                }
                let index = role_index(sender);
                let status = match self.preauth_commitments[index] {
                    Some(existing) if existing == commitment => SetupEventStatus::Duplicate,
                    Some(_) => return self.halt("conflicting preauthorization commitment"),
                    None => {
                        self.accept_preauth_commitment(&artifact)?;
                        SetupEventStatus::Applied
                    }
                };
                (status, Vec::new())
            }
            SetupEventKind::PreauthorizationOpening => {
                let opening = SignatureBundleOpening::decode_exact(&artifact)
                    .map_err(|error| format!("invalid preauthorization opening: {error}"))?;
                require_event_sender(sender, opening.bundle().role())?;
                let index = role_index(sender);
                let status = if self.preauth_receipts[index].is_some() {
                    SetupEventStatus::Duplicate
                } else {
                    SetupEventStatus::Applied
                };
                let receipt = self.accept_preauthorization_opening(&artifact)?;
                (status, receipt)
            }
            SetupEventKind::DescriptorSignature | SetupEventKind::NotApplicable => {
                return Err("setup exchange package kind is not relayable".to_owned());
            }
        };
        encode_setup_event_result(kind, status, self.phase, &receipt)
    }

    fn accept_descriptor_event(
        &mut self,
        sender: Role,
        role: Role,
        descriptor_bytes: &[u8],
        signature: [u8; 64],
    ) -> Result<(SetupEventStatus, Vec<u8>), String> {
        require_event_sender(sender, role)?;
        let descriptor = ChainGameDescriptor::decode_exact(descriptor_bytes)
            .map_err(|error| format!("invalid chain descriptor: {error}"))?;
        self.validate_descriptor_candidate(&descriptor)?;
        let digest = descriptor_signature_digest(&descriptor).map_err(codec)?;
        self.verify_identity_signature(role, digest, signature)?;

        if self
            .descriptor_candidate
            .is_some_and(|existing| existing != descriptor)
        {
            return self.halt("conflicting descriptor candidate");
        }
        let index = role_index(role);
        let duplicate = match self.descriptor_event_signatures[index] {
            Some(existing) if existing == signature => true,
            Some(_) => return self.halt("conflicting descriptor signature"),
            None => false,
        };
        if let Some(signed_bytes) = &self.signed_descriptor_bytes {
            let signed = SignedChainGameDescriptor::decode_exact(signed_bytes)
                .map_err(|error| format!("stored signed descriptor is invalid: {error}"))?;
            let expected = match role {
                Role::Alice => signed.signature_a,
                Role::Bob => signed.signature_b,
            };
            if signed.descriptor != descriptor || expected != signature {
                return self
                    .halt("session descriptor event conflicts with the installed descriptor");
            }
            let bundle = self.local_lamport_bundle_owned()?.encode();
            return Ok((SetupEventStatus::Duplicate, bundle));
        }
        if !matches!(self.phase, Phase::AcceptedDeal | Phase::DescriptorCandidate) {
            return Err("descriptor session event is unavailable in the current phase".to_owned());
        }
        self.descriptor_candidate = Some(descriptor);
        self.descriptor_event_signatures[index] = Some(signature);
        if role == self.local_role {
            if self
                .descriptor_signature
                .is_some_and(|existing| existing != signature)
            {
                return self.halt("relay descriptor signature conflicts with the local signature");
            }
            self.descriptor_signature = Some(signature);
        }
        self.phase = Phase::DescriptorCandidate;

        if let [Some(signature_a), Some(signature_b)] = self.descriptor_event_signatures {
            let signed = SignedChainGameDescriptor {
                descriptor,
                signature_a,
                signature_b,
            };
            let signed_bytes = signed.encode_to_vec().map_err(codec)?;
            let bundle = self.install_signed_descriptor(&signed_bytes)?;
            return Ok((SetupEventStatus::Applied, bundle));
        }
        Ok((
            if duplicate {
                SetupEventStatus::Duplicate
            } else {
                SetupEventStatus::Applied
            },
            Vec::new(),
        ))
    }

    fn sign_descriptor(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if !matches!(self.phase, Phase::AcceptedDeal | Phase::DescriptorCandidate) {
            return Err("descriptor signing is unavailable in the current phase".to_owned());
        }
        let descriptor =
            ChainGameDescriptor::decode_exact(bytes).map_err(|error| error.to_string())?;
        self.validate_descriptor_candidate(&descriptor)?;
        if let Some(existing) = self.descriptor_candidate {
            if existing != descriptor {
                return self.halt("conflicting descriptor candidate");
            }
            if let Some(signature) = self.descriptor_signature {
                return Ok(signature.to_vec());
            }
        }
        let digest = descriptor_signature_digest(&descriptor).map_err(|error| error.to_string())?;
        let signature = self.sign_bip340(digest)?;
        self.descriptor_candidate = Some(descriptor);
        self.descriptor_signature = Some(signature);
        self.descriptor_event_signatures[role_index(self.local_role)] = Some(signature);
        self.phase = Phase::DescriptorCandidate;
        Ok(signature.to_vec())
    }

    fn validate_descriptor_candidate(
        &self,
        descriptor: &ChainGameDescriptor,
    ) -> Result<(), String> {
        self.profile
            .validate_descriptor(descriptor)
            .map_err(|error| error.to_string())?;
        if descriptor.deal != *self.verified_deal.as_deal()
            || descriptor.alice_xonly_pk != self.identities.alice().serialize()
            || descriptor.bob_xonly_pk != self.identities.bob().serialize()
            || descriptor.network_id != self.network_id
            || descriptor.funding_outpoint != self.origin_outpoint
            || descriptor.deal_session_nonce != self.session_nonce
        {
            return Err("descriptor differs from the verified local DEAL/session".to_owned());
        }
        validate_origin_context(
            &self.origin_witness_script,
            descriptor.network_id,
            self.relay_room_id,
            descriptor.deal_session_nonce,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn install_signed_descriptor(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let signed =
            SignedChainGameDescriptor::decode_exact(bytes).map_err(|error| error.to_string())?;
        if let Some(existing) = &self.signed_descriptor_bytes {
            if existing.as_slice() != bytes {
                return self.halt("conflicting fully signed descriptor");
            }
            return Ok(self
                .lamport_bundle(self.local_role)
                .map_or_else(Vec::new, LamportPublicBundle::encode));
        }
        if !matches!(self.phase, Phase::DescriptorCandidate | Phase::LamportReady) {
            return Err("signed descriptor is unavailable in the current phase".to_owned());
        }
        if self.descriptor_candidate != Some(signed.descriptor) {
            return self.halt("signed descriptor differs from the locally approved descriptor");
        }
        let verified =
            verify_signed_chain_descriptor(&signed).map_err(|error| error.to_string())?;
        self.profile
            .validate_descriptor(verified.as_descriptor())
            .map_err(|error| error.to_string())?;
        let signatures = [signed.signature_a, signed.signature_b];
        for (index, signature) in signatures.into_iter().enumerate() {
            if self.descriptor_event_signatures[index].is_some_and(|existing| existing != signature)
            {
                return self.halt("signed descriptor conflicts with an accepted role signature");
            }
        }
        let local_signature = signatures[role_index(self.local_role)];
        if self
            .descriptor_signature
            .is_some_and(|existing| existing != local_signature)
        {
            return self.halt("signed descriptor conflicts with the local descriptor signature");
        }
        let exact_count = self
            .profile
            .lamport_key_count(verified.as_descriptor().button, self.local_role);
        if exact_count != 1 {
            return self.halt("selected profile does not use one game-bound score key");
        }
        self.verified_descriptor = Some(verified);
        self.descriptor_signature = Some(local_signature);
        self.descriptor_event_signatures = signatures.map(Some);
        self.signed_descriptor_bytes = Some(bytes.to_vec());
        self.logical_plan = None;
        self.pending_local_lamport_generation = false;
        Ok(Vec::new())
    }

    fn prepare_local_lamport_generation(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let requested_workers = usize::from(exact_u8(bytes)?);
        if requested_workers == 0 || requested_workers > MAX_PREAUTHORIZATION_VERIFIERS {
            return Err("Lamport generator count is out of bounds".to_owned());
        }
        if let Some(bundle) = self.lamport_bundle(self.local_role) {
            return encode_completed_lamport_generation_plan(&bundle.encode());
        }
        let (game_id, expected) = self.local_lamport_expectations()?;
        let result = encode_lamport_generation_plan(
            &self.snapshot_key,
            self.shared_config_hash,
            game_id,
            self.local_role,
            &expected,
            requested_workers,
        )?;
        self.pending_local_lamport_generation = true;
        Ok(result)
    }

    fn complete_local_lamport_generation(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if !self.pending_local_lamport_generation {
            return Err("no local Lamport generation is pending".to_owned());
        }
        let (game_id, expected) = self.local_lamport_expectations()?;
        let public = decode_lamport_generation_results(bytes, game_id, &expected)?;
        let mut inventory = DeterministicLamportInventory::fresh(expected.len());
        let signature = self.sign_bip340_for_bundle(game_id, self.local_role, &public)?;
        let bundle =
            LamportPublicBundle::sign(game_id, to_lamport_role(self.local_role), &public, |_| {
                signature
            })
            .map_err(|error| error.to_string())?;
        inventory.bind_bundle(&bundle, game_id, self.local_role)?;
        let encoded = bundle.encode();
        self.lamport_bundles[role_index(self.local_role)] = Some(bundle);
        self.lamport_inventory = Some(inventory);
        self.pending_local_lamport_generation = false;
        self.phase = Phase::LamportReady;
        Ok(encoded)
    }

    fn local_lamport_expectations(
        &self,
    ) -> Result<([u8; 32], [bp52_lamport::ExpectedLamportEntry; 1]), String> {
        let descriptor = self
            .verified_descriptor
            .as_ref()
            .ok_or_else(|| "verified descriptor is unavailable".to_owned())?
            .as_descriptor();
        let game_id = chain_game_id(descriptor).map_err(|error| error.to_string())?;
        let purpose = match self.local_role {
            Role::Alice => LamportPurpose::AliceScore24Bit,
            Role::Bob => LamportPurpose::BobScore24Bit,
        };
        Ok((
            game_id,
            [bp52_lamport::ExpectedLamportEntry::new(
                root_node_id(&game_id),
                purpose,
            )],
        ))
    }

    fn sign_bip340_for_bundle(
        &self,
        game_id: [u8; 32],
        role: Role,
        public: &[bp52_lamport::LamportPublicKey],
    ) -> Result<[u8; 64], String> {
        let placeholder =
            LamportPublicBundle::sign(game_id, to_lamport_role(role), public, |_| [0; 64])
                .map_err(|error| error.to_string())?;
        let digest = placeholder.signing_digest();
        let mut material = Zeroizing::new(Vec::with_capacity(129));
        material.extend_from_slice(self.snapshot_key.as_ref());
        material.extend_from_slice(&self.shared_config_hash);
        material.extend_from_slice(&game_id);
        material.push(role.code());
        material.extend_from_slice(&digest);
        let mut aux = tagged_hash(LAMPORT_BUNDLE_AUX_TAG, &material);
        let signature = Secp256k1::new()
            .sign_schnorr_with_aux_rand(
                &Message::from_digest(digest),
                &self.secret.keypair()?,
                &aux,
            )
            .serialize();
        aux.zeroize();
        Ok(signature)
    }

    fn local_lamport_bundle_owned(&self) -> Result<LamportPublicBundle, String> {
        if let Some(bundle) = self.lamport_bundle(self.local_role) {
            return Ok(bundle.clone());
        }
        let (game_id, expected) = self.local_lamport_expectations()?;
        let (fresh, public) = DeterministicLamportInventory::generate_public_keys(
            &self.snapshot_key,
            self.shared_config_hash,
            game_id,
            self.local_role,
            &expected,
        )?;
        let inventory = self
            .lamport_inventory
            .as_ref()
            .ok_or_else(|| "local Lamport inventory is unavailable".to_owned())?;
        if fresh.len() != inventory.len() {
            return Err("regenerated local Lamport count differs from its receipt".to_owned());
        }
        let signature = self.sign_bip340_for_bundle(game_id, self.local_role, &public)?;
        let bundle =
            LamportPublicBundle::sign(game_id, to_lamport_role(self.local_role), &public, |_| {
                signature
            })
            .map_err(|error| error.to_string())?;
        inventory.verify_regenerated_bundle(&bundle)?;
        Ok(bundle)
    }

    fn accept_lamport_bundle(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if !matches!(self.phase, Phase::LamportReady | Phase::GraphReady) {
            return Err("Lamport bundle is unavailable in the current phase".to_owned());
        }
        let bundle = LamportPublicBundle::decode(bytes).map_err(|error| error.to_string())?;
        let role = from_lamport_role(bundle.role());
        if let Some(existing) = self.lamport_bundle(role) {
            if existing != &bundle {
                return self.halt("conflicting Lamport bundle");
            }
            return Ok(Vec::new());
        }
        self.lamport_bundles[role_index(role)] = Some(bundle);
        if self.lamport_bundles.iter().all(Option::is_some) {
            self.materialize_graph()?;
        }
        Ok(Vec::new())
    }

    fn materialize_graph(&mut self) -> Result<(), String> {
        let cached_plan = self.logical_plan.take();
        let prepared = self.prepare_graph_with_plan(cached_plan)?;
        let activation = prepared
            .canonical_activation_template()
            .map_err(|error| error.to_string())?;
        let mut oracle =
            compile_graph_oracle(prepared, activation).map_err(|error| error.to_string())?;
        self.profile
            .validate_graph_summary(&oracle.summary)
            .map_err(|error| error.to_string())?;
        oracle.requests.discard_runtime_requests();
        let summary = oracle.summary;
        let window = oracle.window;
        self.setup_signature_requests = Some(oracle.requests);
        let monitor = ChainMonitor::new(
            summary.manifest().chain_game_id,
            summary.manifest().graph_root,
            summary.root_node_id(),
            NonZeroU16::MIN,
        );
        let public_preimages = PublicPreimageStore::new(
            summary.manifest().chain_game_id,
            *self.verified_deal.as_deal(),
        );
        self.graph_summary = Some(summary);
        self.graph_window = Some(window);
        self.monitor = Some(monitor);
        self.public_preimages = Some(public_preimages);
        self.phase = Phase::GraphReady;
        Ok(())
    }

    fn prepare_graph(&self) -> Result<PreparedChainGraph, String> {
        self.prepare_graph_with_plan(None)
    }

    fn prepare_graph_with_plan(
        &self,
        cached_plan: Option<LogicalGraphPlan>,
    ) -> Result<PreparedChainGraph, String> {
        let verified = self
            .verified_descriptor
            .as_ref()
            .ok_or_else(|| "verified descriptor is unavailable".to_owned())?;
        let local = self.local_lamport_bundle_owned()?;
        let peer = self
            .lamport_bundle(self.local_role.other())
            .cloned()
            .ok_or_else(|| "peer Lamport bundle is unavailable".to_owned())?;
        let (alice, bob) = match self.local_role {
            Role::Alice => (local, peer),
            Role::Bob => (peer, local),
        };
        let public_material = LamportPublicMaterial::new(alice, bob);
        let prepared = if let Some(plan) = cached_plan {
            prepare_chain_graph_from_plan(
                self.bitcoin_network,
                verified,
                &self.verified_deal,
                plan,
                &public_material,
                self.origin_output.clone(),
                policy()?,
            )
        } else {
            prepare_chain_graph(
                self.bitcoin_network,
                verified,
                &self.verified_deal,
                &public_material,
                self.origin_output.clone(),
                policy()?,
            )
        }
        .map_err(|error| error.to_string())?;
        if prepared.activation_fee_sat() != self.profile.activation_fee_sat {
            return Err(
                "compiled activation fee differs from the selected heads-up profile".to_owned(),
            );
        }
        Ok(prepared)
    }

    fn make_root_commitment(&mut self) -> Result<Vec<u8>, String> {
        if !matches!(self.phase, Phase::GraphReady | Phase::RootAgreed) {
            return Err("graph-root commitment is unavailable".to_owned());
        }
        let index = role_index(self.local_role);
        if let Some(existing) = self.root_commitments[index] {
            return existing.encode_to_vec().map_err(|error| error.to_string());
        }
        let verified = self.verified_descriptor_value()?;
        let graph_root = self.graph_summary_ref()?.manifest().graph_root;
        let nonce = self.random_nonzero()?;
        let mut aux = self.random_array();
        let keypair = self.secret.keypair()?;
        let secp = Secp256k1::new();
        let (commitment, opening) =
            commit_graph_root(&verified, self.local_role, graph_root, nonce, |digest| {
                secp.sign_schnorr_with_aux_rand(&Message::from_digest(digest), &keypair, &aux)
                    .serialize()
            })
            .map_err(|error| error.to_string())?;
        aux.zeroize();
        self.root_commitments[index] = Some(commitment);
        self.root_openings[index] = Some(opening);
        commitment
            .encode_to_vec()
            .map_err(|error| error.to_string())
    }

    fn accept_root_commitment(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.phase != Phase::GraphReady {
            return Err("graph-root commitment is unavailable in the current phase".to_owned());
        }
        let value = SignedCommitment::decode_exact(bytes).map_err(|error| error.to_string())?;
        if value.purpose() != bp52_chain_compiler::CommitmentPurpose::GraphRoot {
            return Err("graph-root commitment has the wrong purpose".to_owned());
        }
        let index = role_index(value.role());
        if let Some(existing) = self.root_commitments[index] {
            if existing != value {
                return self.halt("conflicting graph-root commitment");
            }
        } else {
            self.root_commitments[index] = Some(value);
        }
        Ok(Vec::new())
    }

    fn open_root(&self) -> Result<Vec<u8>, String> {
        if self.root_commitments.iter().any(Option::is_none) {
            return Err("both graph-root commitments are required before opening".to_owned());
        }
        self.root_openings[role_index(self.local_role)]
            .ok_or_else(|| "local graph-root opening is unavailable".to_owned())?
            .encode_to_vec()
            .map_err(|error| error.to_string())
    }

    fn accept_root_opening(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.phase != Phase::GraphReady || self.root_commitments.iter().any(Option::is_none) {
            return Err("graph-root opening requires both commitments".to_owned());
        }
        let value = GraphRootOpening::decode_exact(bytes).map_err(|error| error.to_string())?;
        let index = role_index(value.role());
        if let Some(existing) = self.root_openings[index] {
            if existing != value {
                return self.halt("conflicting graph-root opening");
            }
        } else {
            self.root_openings[index] = Some(value);
        }
        if let ([Some(commit_a), Some(commit_b)], [Some(open_a), Some(open_b)]) =
            (&self.root_commitments, &self.root_openings)
        {
            let verified = self.verified_descriptor_ref()?;
            let agreed =
                verify_matching_graph_roots(verified, (commit_a, open_a), (commit_b, open_b))
                    .map_err(|error| error.to_string())?;
            if agreed.graph_root() != self.graph_summary_ref()?.manifest().graph_root {
                return self.halt("authenticated graph root differs from local compilation");
            }
            self.agreed_root = Some(agreed);
            // Once both authenticated openings agree, the compact inventory's
            // signed root/count receipt is sufficient to regenerate our public
            // bundle when setup needs it again. CHAIN retains only the peer's
            // public bundle, which is required to verify their live witnesses.
            self.lamport_bundles[role_index(self.local_role)] = None;
            self.phase = Phase::RootAgreed;
        }
        Ok(Vec::new())
    }

    #[allow(clippy::too_many_lines)]
    fn make_preauthorization_commitment(&mut self) -> Result<Vec<u8>, String> {
        if !matches!(
            self.phase,
            Phase::RootAgreed | Phase::PreauthorizationsReady
        ) {
            return Err("preauthorization commitment is unavailable".to_owned());
        }
        let index = role_index(self.local_role);
        if let Some(existing) = self.preauth_commitments[index] {
            return existing.encode_to_vec().map_err(|error| error.to_string());
        }
        let bundle = self.build_local_preauthorization_bundle()?;
        self.commit_local_preauthorization_bundle(bundle)
    }

    fn commit_local_preauthorization_bundle(
        &mut self,
        bundle: PreauthorizationBundle,
    ) -> Result<Vec<u8>, String> {
        let index = role_index(self.local_role);
        let nonce = self.random_nonzero()?;
        let mut aux = self.random_array();
        let verified = self.verified_descriptor_value()?;
        let keypair = self.secret.keypair()?;
        let secp = Secp256k1::new();
        let (commitment, opening) = commit_signature_bundle(&verified, nonce, bundle, |digest| {
            secp.sign_schnorr_with_aux_rand(&Message::from_digest(digest), &keypair, &aux)
                .serialize()
        })
        .map_err(|error| error.to_string())?;
        aux.zeroize();

        self.local_preauth_nonce = Some(nonce);
        self.preauth_commitments[index] = Some(commitment);
        // Keep the just-generated vector only in this Worker's transient
        // memory until the durable relay echo arrives. It is deliberately not
        // checkpointed and is erased after the echo, so the normal path signs
        // every state once without retaining our signatures long-term.
        self.transient_local_preauth_opening = Some(opening);
        self.preauth_openings[index] = None;
        debug_assert!(self.preauth_openings[index].is_none());
        commitment
            .encode_to_vec()
            .map_err(|error| error.to_string())
    }

    fn prepare_local_preauthorization_generation(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let requested_workers = usize::from(exact_u8(bytes)?);
        if requested_workers == 0 || requested_workers > MAX_PREAUTHORIZATION_VERIFIERS {
            return Err("preauthorization signer count is out of bounds".to_owned());
        }
        if !matches!(
            self.phase,
            Phase::RootAgreed | Phase::PreauthorizationsReady
        ) {
            return Err("preauthorization commitment is unavailable".to_owned());
        }
        let index = role_index(self.local_role);
        if let Some(existing) = self.preauth_commitments[index] {
            let artifact = existing
                .encode_to_vec()
                .map_err(|error| error.to_string())?;
            return encode_completed_preauthorization_generation_plan(&artifact);
        }
        let summary = self.graph_summary_ref()?;
        let game_id = summary.manifest().chain_game_id;
        let graph_root = summary.manifest().graph_root;
        let requests = self
            .setup_signature_requests
            .as_ref()
            .ok_or_else(|| "transient setup signature requests are unavailable".to_owned())?
            .preauthorizations(self.local_role);
        let plan = encode_preauthorization_generation_plan(
            &self.secret.bytes,
            &self.snapshot_key,
            self.shared_config_hash,
            game_id,
            graph_root,
            self.local_role,
            requests,
            requested_workers,
        )?;
        self.pending_local_preauth_generation = true;
        Ok(plan)
    }

    fn complete_local_preauthorization_generation(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.pending_local_preauth_generation {
            return Err("no local preauthorization generation is pending".to_owned());
        }
        let summary = self.graph_summary_ref()?;
        let game_id = summary.manifest().chain_game_id;
        let graph_root = summary.manifest().graph_root;
        let requests = self
            .setup_signature_requests
            .as_ref()
            .ok_or_else(|| "transient setup signature requests are unavailable".to_owned())?
            .preauthorizations(self.local_role);
        let signatures = decode_preauthorization_generation_results(bytes, requests.len())?;
        let entries = requests
            .iter()
            .zip(signatures)
            .map(|(request, signature)| Preauthorization {
                request: *request,
                signature,
            })
            .collect();
        let bundle = PreauthorizationBundle::new(game_id, graph_root, self.local_role, entries)
            .map_err(|error| error.to_string())?;
        self.pending_local_preauth_generation = false;
        self.commit_local_preauthorization_bundle(bundle)
    }

    fn build_local_preauthorization_bundle(&self) -> Result<PreauthorizationBundle, String> {
        let summary = self.graph_summary_ref()?;
        let game_id = summary.manifest().chain_game_id;
        let graph_root = summary.manifest().graph_root;
        let requests = self
            .setup_signature_requests
            .as_ref()
            .ok_or_else(|| "transient setup signature requests are unavailable".to_owned())?
            .preauthorizations(self.local_role);
        let secp = Secp256k1::new();
        let keypair = self.secret.keypair()?;
        let mut entries = Vec::with_capacity(requests.len());
        for request in requests {
            let signature = deterministic_preauthorization_signature_with(
                &secp,
                &keypair,
                &self.snapshot_key,
                self.shared_config_hash,
                game_id,
                graph_root,
                self.local_role,
                request,
            )?
            .to_bytes();
            entries.push(Preauthorization {
                request: *request,
                signature,
            });
        }
        PreauthorizationBundle::new(game_id, graph_root, self.local_role, entries)
            .map_err(|error| error.to_string())
    }

    fn regenerate_local_preauthorization_opening(&self) -> Result<SignatureBundleOpening, String> {
        let nonce = self
            .local_preauth_nonce
            .ok_or_else(|| "local preauthorization nonce is unavailable".to_owned())?;
        SignatureBundleOpening::new(nonce, self.build_local_preauthorization_bundle()?)
            .map_err(|error| error.to_string())
    }

    fn accept_preauth_commitment(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.phase != Phase::RootAgreed {
            return Err(
                "preauthorization commitment is unavailable in the current phase".to_owned(),
            );
        }
        let value = SignedCommitment::decode_exact(bytes).map_err(|error| error.to_string())?;
        if value.purpose() != bp52_chain_compiler::CommitmentPurpose::PreauthorizationBundle {
            return Err("preauthorization commitment has the wrong purpose".to_owned());
        }
        let index = role_index(value.role());
        if let Some(existing) = self.preauth_commitments[index] {
            if existing != value {
                return self.halt("conflicting preauthorization commitment");
            }
        } else {
            self.preauth_commitments[index] = Some(value);
        }
        Ok(Vec::new())
    }

    fn open_preauthorizations(&self) -> Result<Vec<u8>, String> {
        if self.preauth_commitments.iter().any(Option::is_none) {
            return Err("both preauthorization commitments are required before opening".to_owned());
        }
        if let Some(opening) = &self.transient_local_preauth_opening {
            opening.encode_to_vec().map_err(|error| error.to_string())
        } else {
            self.regenerate_local_preauthorization_opening()?
                .encode_to_vec()
                .map_err(|error| error.to_string())
        }
    }

    fn accept_preauthorization_opening(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let opening =
            SignatureBundleOpening::decode_exact(bytes).map_err(|error| error.to_string())?;
        self.install_preauthorization_opening(opening, false)
    }

    fn install_preauthorization_opening(
        &mut self,
        opening: SignatureBundleOpening,
        externally_verified: bool,
    ) -> Result<Vec<u8>, String> {
        if self.phase != Phase::RootAgreed || self.preauth_commitments.iter().any(Option::is_none) {
            return Err("preauthorization opening requires both commitments".to_owned());
        }
        let role = opening.bundle().role();
        let index = role_index(role);
        let commitment = self.preauth_commitments[index]
            .ok_or_else(|| "preauthorization opening arrived before its commitment".to_owned())?;
        if let Some(receipt) = self.preauth_receipts[index] {
            let digest =
                signature_bundle_opening_digest(&opening).map_err(|error| error.to_string())?;
            if digest != receipt.opening_digest() {
                return self.halt("conflicting preauthorization opening");
            }
            return receipt.encode_to_vec().map_err(|error| error.to_string());
        }
        let verified = self.verified_descriptor_value()?;
        let graph_root = self.graph_summary_ref()?.manifest().graph_root;
        let requests = self
            .setup_signature_requests
            .as_ref()
            .ok_or_else(|| "transient setup signature requests are unavailable".to_owned())?
            .preauthorizations(role);
        let keypair = self.secret.keypair()?;
        let secp = Secp256k1::new();
        let sign_receipt = |digest| {
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                .serialize()
        };
        let receipt = if role == self.local_role {
            issue_locally_generated_preauthorization_receipt(
                &verified,
                self.shared_config_hash,
                graph_root,
                &commitment,
                &opening,
                requests,
                self.local_role,
                sign_receipt,
            )
        } else if externally_verified {
            issue_externally_verified_preauthorization_receipt(
                &verified,
                self.shared_config_hash,
                graph_root,
                &commitment,
                &opening,
                requests,
                self.local_role,
                sign_receipt,
            )
        } else {
            issue_preauthorization_verified_receipt(
                &verified,
                self.shared_config_hash,
                graph_root,
                &commitment,
                &opening,
                requests,
                self.local_role,
                sign_receipt,
            )
        }
        .map_err(|error| error.to_string())?;
        self.preauth_verified[index] = true;
        if role == self.local_role {
            // Our fixed signatures are needed only by the peer. Once the
            // durable relay echo has been verified, retain only the nonce and
            // regenerate the exact opening for retransmission or recovery.
            self.preauth_openings[index] = None;
            self.transient_local_preauth_opening = None;
        } else {
            // CHAIN is the sole long-lived owner of the peer's packed vector.
            // The deterministic graph and GAME reducer retain no copy.
            self.preauth_openings[index] = Some(opening);
        }
        self.preauth_receipts[index] = Some(receipt);
        if self.preauth_verified.into_iter().all(|verified| verified) {
            let summary = self.graph_summary_ref()?;
            let expected = self.profile.inventory(summary.descriptor().button);
            if summary.preauthorization_count(Role::Alice) != expected.alice_preauthorizations
                || summary.preauthorization_count(Role::Bob) != expected.bob_preauthorizations
            {
                return self.halt("installed preauthorization inventory is incomplete");
            }
            self.phase = Phase::PreauthorizationsReady;
            self.setup_signature_requests = None;
        }
        receipt.encode_to_vec().map_err(|error| error.to_string())
    }

    fn prepare_peer_preauthorization_verification(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (&requested_workers, setup) = bytes
            .split_first()
            .ok_or_else(|| "preauthorization verification plan is empty".to_owned())?;
        if requested_workers == 0 || usize::from(requested_workers) > MAX_PREAUTHORIZATION_VERIFIERS
        {
            return Err("preauthorization verifier count is out of bounds".to_owned());
        }
        let (sender, kind, artifact) = decode_setup_exchange(setup)?;
        if kind != SetupEventKind::PreauthorizationOpening || sender == self.local_role {
            return Err("parallel verification requires the opponent's opening".to_owned());
        }
        let opening = SignatureBundleOpening::decode_exact(&artifact)
            .map_err(|error| format!("invalid preauthorization opening: {error}"))?;
        require_event_sender(sender, opening.bundle().role())?;
        let index = role_index(sender);
        if self.preauth_receipts[index].is_some() {
            let receipt = self.install_preauthorization_opening(opening, false)?;
            let result = encode_setup_event_result(
                SetupEventKind::PreauthorizationOpening,
                SetupEventStatus::Duplicate,
                self.phase,
                &receipt,
            )?;
            return encode_completed_preauthorization_plan(&result);
        }
        if self.phase != Phase::RootAgreed || self.preauth_commitments.iter().any(Option::is_none) {
            return Err("preauthorization opening requires both commitments".to_owned());
        }
        let commitment = self.preauth_commitments[index]
            .ok_or_else(|| "preauthorization opening arrived before its commitment".to_owned())?;
        let verified = self.verified_descriptor_value()?;
        let graph_root = self.graph_summary_ref()?.manifest().graph_root;
        let requests = self
            .setup_signature_requests
            .as_ref()
            .ok_or_else(|| "transient setup signature requests are unavailable".to_owned())?
            .preauthorizations(sender);
        verify_signature_bundle_binding(&verified, graph_root, &commitment, &opening, requests)
            .map_err(|error| error.to_string())?;
        let identity_key = *verified.as_descriptor().identity_key(sender);
        let plan = encode_preauthorization_verification_plan(
            identity_key,
            requests,
            opening.bundle().signatures(),
            usize::from(requested_workers),
        )?;
        self.pending_peer_preauth_opening = Some(opening);
        Ok(plan)
    }

    fn complete_peer_preauthorization_verification(&mut self) -> Result<Vec<u8>, String> {
        let opening = self
            .pending_peer_preauth_opening
            .take()
            .ok_or_else(|| "no peer preauthorization verification is pending".to_owned())?;
        let receipt = self.install_preauthorization_opening(opening, true)?;
        encode_setup_event_result(
            SetupEventKind::PreauthorizationOpening,
            SetupEventStatus::Applied,
            self.phase,
            &receipt,
        )
    }

    fn attest_inventory(&mut self) -> Result<Vec<u8>, String> {
        if let Some(signature) = self.inventory_attestation {
            return Ok(signature.to_vec());
        }
        if self.phase != Phase::PreauthorizationsReady {
            return Err("runtime inventory cannot be attested yet".to_owned());
        }
        // Runtime edges are signed once, on selection. Readiness proves the
        // deterministic signer binding and exact request count without ever
        // allocating the profile's thousands of unused signatures.
        let keys_count = self
            .lamport_inventory
            .as_ref()
            .ok_or_else(|| "local Lamport inventory is unavailable".to_owned())?
            .fresh_count()?;
        let preimages = self
            .retained_preimages
            .as_ref()
            .ok_or_else(|| "retained DEAL preimages are unavailable".to_owned())?;
        if preimages.len() != 9 {
            return self.halt("verified inventory does not contain nine DEAL preimages");
        }
        let summary = self.graph_summary_ref()?;
        let chain_game_id = summary.manifest().chain_game_id;
        let graph_root = summary.manifest().graph_root;
        let signatures_count = summary.runtime_signature_count(self.local_role);
        let digest = inventory_digest(
            self.shared_config_hash,
            chain_game_id,
            graph_root,
            self.local_role,
            keys_count,
            signatures_count,
        );
        self.inventory_verified = true;
        self.phase = Phase::InventoryVerified;
        let signature = self.sign_bip340(digest)?;
        self.inventory_attestation = Some(signature);
        Ok(signature.to_vec())
    }

    fn graph_prepared_receipt(&self) -> Result<Vec<u8>, String> {
        if !self.inventory_verified {
            return Err("graph receipt is unavailable before inventory verification".to_owned());
        }
        let keypair = self.secret.keypair()?;
        let secp = Secp256k1::new();
        issue_graph_prepared_receipt(
            self.graph_summary_ref()?,
            self.shared_config_hash,
            self.local_role,
            |digest| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                    .serialize()
            },
        )
        .and_then(|receipt| receipt.encode_to_vec().map_err(Into::into))
        .map_err(|error: bp52_chain_compiler::CompilerError| error.to_string())
    }

    fn make_inventory_ready(&mut self) -> Result<Vec<u8>, String> {
        if !self.inventory_verified {
            return Err(
                "inventory-ready cannot be issued before local inventory verification".to_owned(),
            );
        }
        let index = role_index(self.local_role);
        if let Some(signature) = self.inventory_ready[index] {
            return Ok(signature.to_vec());
        }
        let digest = self.peer_inventory_digest(self.local_role)?;
        let signature = self.sign_bip340(digest)?;
        self.inventory_ready[index] = Some(signature);
        Ok(signature.to_vec())
    }

    fn accept_inventory_ready(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if bytes.len() != 65 {
            return Err(
                "inventory-ready artifact must contain role plus 64-byte signature".to_owned(),
            );
        }
        let role = match bytes[0] {
            0 => Role::Alice,
            1 => Role::Bob,
            _ => return Err("inventory-ready role is not canonical".to_owned()),
        };
        let signature: [u8; 64] = bytes[1..]
            .try_into()
            .map_err(|_| "inventory-ready signature has the wrong length".to_owned())?;
        let public = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            self.graph_summary_ref()?.descriptor().identity_key(role),
        )
        .map_err(|error| error.to_string())?;
        let signature_value = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
            .map_err(|error| error.to_string())?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature_value,
                &Message::from_digest(self.peer_inventory_digest(role)?),
                &public,
            )
            .map_err(|_| "inventory-ready identity signature is invalid".to_owned())?;
        let index = role_index(role);
        if self.inventory_ready[index].is_some_and(|existing| existing != signature) {
            return self.halt("conflicting inventory-ready signature");
        }
        self.inventory_ready[index] = Some(signature);
        Ok(Vec::new())
    }

    fn peer_inventory_digest(&self, role: Role) -> Result<[u8; 32], String> {
        let summary = self.graph_summary_ref()?;
        let profile = self.profile.inventory(summary.descriptor().button);
        let (lamport, runtime) = match role {
            Role::Alice => (profile.alice_lamport_keys, profile.alice_runtime_signatures),
            Role::Bob => (profile.bob_lamport_keys, profile.bob_runtime_signatures),
        };
        let mut bytes = Vec::with_capacity(32 * 6 + 1 + 8);
        bytes.extend_from_slice(&summary.descriptor().network_id);
        bytes.extend_from_slice(&self.relay_room_id);
        bytes.extend_from_slice(&self.origin_outpoint);
        bytes.extend_from_slice(&summary.descriptor().deal.game_id);
        bytes.extend_from_slice(&summary.manifest().chain_game_id);
        bytes.extend_from_slice(&summary.manifest().graph_root);
        bytes.push(role.code());
        bytes.extend_from_slice(&lamport.to_le_bytes());
        bytes.extend_from_slice(&runtime.to_le_bytes());
        Ok(tagged_hash(PEER_INVENTORY_TAG, &bytes))
    }

    fn sign_activation(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if !self.inventory_verified {
            return Err("activation cannot be signed before inventory verification".to_owned());
        }
        if self.inventory_ready.iter().any(Option::is_none) {
            return Err(
                "activation cannot be signed before both inventory-ready handshakes".to_owned(),
            );
        }
        let transaction: Transaction = deserialize(bytes).map_err(|error| error.to_string())?;
        if serialize(&transaction) != bytes {
            return Err("activation transaction is not canonically encoded".to_owned());
        }
        let summary = self.graph_summary_ref()?;
        if &transaction != summary.activation_template().transaction() {
            return self.halt("activation transaction differs from the compiled template");
        }
        let digest = SighashCache::new(&transaction)
            .p2wsh_signature_hash(
                0,
                ScriptBuf::from_bytes(self.origin_witness_script.to_vec()).as_script(),
                summary.origin_output().value,
                EcdsaSighashType::All,
            )
            .map_err(|error| error.to_string())?
            .to_byte_array();
        let signature =
            Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &self.secret.secret_key()?);
        let mut encoded = signature.serialize_der().to_vec();
        encoded.push(EcdsaSighashType::All as u8);
        Ok(encoded)
    }

    fn assemble_activation(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.inventory_ready.iter().any(Option::is_none) {
            return Err(
                "activation cannot be assembled before both inventory-ready handshakes".to_owned(),
            );
        }
        let mut reader = Reader::new(bytes);
        let unsigned_bytes = reader.read_byte_vector(1_000_000).map_err(codec)?;
        let alice_signature = reader.read_byte_vector(80).map_err(codec)?;
        let bob_signature = reader.read_byte_vector(80).map_err(codec)?;
        reader.finish().map_err(codec)?;
        let mut transaction: Transaction =
            deserialize(&unsigned_bytes).map_err(|error| error.to_string())?;
        if &transaction
            != self
                .graph_summary_ref()?
                .activation_template()
                .transaction()
        {
            return self.halt("activation assembly changed the compiled template");
        }
        verify_activation_signature(self, Role::Alice, &transaction, &alice_signature)?;
        verify_activation_signature(self, Role::Bob, &transaction, &bob_signature)?;
        let mut witness = BitcoinWitness::new();
        witness.push(bob_signature);
        witness.push(alice_signature);
        witness.push(self.origin_witness_script);
        transaction.input[0].witness = witness;
        Ok(serialize(&transaction))
    }

    fn activation_template(&self) -> Result<Vec<u8>, String> {
        Ok(serialize(
            self.graph_summary_ref()?
                .activation_template()
                .transaction(),
        ))
    }

    fn verify_activation_artifact(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let Some((&role, signature)) = bytes.split_first() else {
            return Err("activation artifact is empty".to_owned());
        };
        let role = decode_role(role)?;
        verify_activation_signature(
            self,
            role,
            self.graph_summary_ref()?
                .activation_template()
                .transaction(),
            signature,
        )?;
        Ok(Vec::new())
    }

    fn confirm_activation(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut reader = Reader::new(bytes);
        let confirmed_height = reader.read_u32().map_err(codec)?;
        let tip_height = reader.read_u32().map_err(codec)?;
        let transaction_bytes = reader.read_byte_vector(1_000_000).map_err(codec)?;
        reader.finish().map_err(codec)?;
        let transaction: Transaction =
            deserialize(&transaction_bytes).map_err(|error| error.to_string())?;
        if let Some(ConfirmedRecord::Activation {
            confirmed_height: prior_confirmed,
            tip_height: prior_tip,
            transaction: prior_transaction,
        }) = self.confirmed_history.first()
        {
            if *prior_confirmed == confirmed_height
                && *prior_tip == tip_height
                && prior_transaction == &transaction_bytes
            {
                return self.card_projection();
            }
            return self.halt("conflicting activation confirmation");
        }
        verify_signed_activation(self, &transaction)?;
        let graph = self
            .graph_window
            .as_ref()
            .ok_or_else(|| "root graph window is unavailable".to_owned())?;
        let monitor = self
            .monitor
            .as_mut()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        monitor
            .confirm_funding(
                graph,
                graph.summary().root_state_outpoint(),
                graph.summary().root_state_output(),
                confirmed_height,
                tip_height,
            )
            .map_err(|error| error.to_string())?;
        self.confirmed_history.push(ConfirmedRecord::Activation {
            confirmed_height,
            tip_height,
            transaction: transaction_bytes,
        });
        self.phase = Phase::Active;
        self.card_projection()
    }

    fn observe_tip(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let height = decode_tip_height(bytes)?;
        self.monitor
            .as_mut()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?
            .observe_tip(height)
            .map_err(|error| error.to_string())?;
        Ok(Vec::new())
    }

    fn build_action(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let action = match exact_u8(bytes)? {
            0 => Action::Fold,
            1 => Action::Check,
            2 => Action::Call,
            3 => Action::Bet,
            4 => Action::Raise,
            _ => return Err("unknown betting action".to_owned()),
        };
        let request = authorization_request(0, bytes);
        if let Some(cached) = self.cached_authorization(&request)? {
            return Ok(cached);
        }
        let node_id = self.active_node_id()?;
        let graph = self
            .graph_window
            .as_ref()
            .ok_or_else(|| "active graph window is unavailable".to_owned())?;
        let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
            .as_ref()
            .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
        let preauthorizations = PackedPreauthorizationSource {
            graph,
            local_role: self.local_role,
            secret: &self.secret,
            snapshot_key: &self.snapshot_key,
            shared_config_hash: self.shared_config_hash,
            peer_opening,
        };
        let graph = AuthorizedGraph::new(graph, &preauthorizations);
        let signer = LocalSigner::new(self.local_role, &self.secret);
        let monitor = self
            .monitor
            .as_mut()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        let witness = build_action_witness(&graph, monitor, action, &signer)
            .and_then(|witness| witness.encode())
            .map_err(|error| error.to_string())?;
        self.retain_authorization(node_id, request, witness)
    }

    fn build_advance(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let _ = bytes;
        Err("the fixed-limit profile has no advance transitions".to_owned())
    }

    fn build_reveal(&mut self) -> Result<Vec<u8>, String> {
        let request = authorization_request(1, &[]);
        if let Some(cached) = self.cached_authorization(&request)? {
            return Ok(cached);
        }
        let node_id = self.active_node_id()?;
        let graph = self
            .graph_window
            .as_ref()
            .ok_or_else(|| "active graph window is unavailable".to_owned())?;
        let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
            .as_ref()
            .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
        let preauthorizations = PackedPreauthorizationSource {
            graph,
            local_role: self.local_role,
            secret: &self.secret,
            snapshot_key: &self.snapshot_key,
            shared_config_hash: self.shared_config_hash,
            peer_opening,
        };
        let graph = AuthorizedGraph::new(graph, &preauthorizations);
        let signer = LocalSigner::new(self.local_role, &self.secret);
        let monitor = self
            .monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        let active = monitor
            .confirmed_active_node(&graph)
            .map_err(|error| error.to_string())?;
        let pattern = reveal_pattern_for_active(&graph, active.node_id())?;
        if pattern.revealer() != self.local_role {
            return Err("the peer is the required revealer at this node".to_owned());
        }
        let retained = self
            .retained_preimages
            .as_ref()
            .ok_or_else(|| "retained DEAL preimages are unavailable".to_owned())?;
        let preimages = pattern
            .slots()
            .iter()
            .map(|slot| {
                retained
                    .get(usize::from(*slot))
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| "retained DEAL preimage is unavailable".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let witness = build_reveal_witness(&graph, &active, &preimages, &signer)
            .and_then(|witness| witness.encode())
            .map_err(|error| error.to_string())?;
        self.retain_authorization(node_id, request, witness)
    }

    fn build_alice_showdown(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.local_role != Role::Alice {
            return Err("only Alice can issue the Alice showdown witness".to_owned());
        }
        let (subset, score) = decode_showdown_choice(bytes)?;
        let request = authorization_request(2, bytes);
        if let Some(cached) = self.cached_authorization(&request)? {
            return Ok(cached);
        }
        let node_id = self.active_node_id()?;
        let (key_index, mut key) =
            self.derive_active_lamport_key(LamportPurpose::AliceScore24Bit)?;
        let built = {
            let graph = self
                .graph_window
                .as_ref()
                .ok_or_else(|| "active graph window is unavailable".to_owned())?;
            let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
                .as_ref()
                .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
            let preauthorizations = PackedPreauthorizationSource {
                graph,
                local_role: self.local_role,
                secret: &self.secret,
                snapshot_key: &self.snapshot_key,
                shared_config_hash: self.shared_config_hash,
                peer_opening,
            };
            let graph = AuthorizedGraph::new(graph, &preauthorizations);
            let signer = LocalSigner::new(self.local_role, &self.secret);
            let public = self
                .public_preimages
                .as_ref()
                .ok_or_else(|| "public preimage store is unavailable".to_owned())?;
            let retained = self
                .retained_preimages
                .as_ref()
                .ok_or_else(|| "retained DEAL preimages are unavailable".to_owned())?;
            let monitor = self
                .monitor
                .as_mut()
                .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
            build_alice_showdown_witness(
                &graph, monitor, public, retained, subset, score, &mut key, &signer,
            )
            .and_then(|witness| witness.encode())
        };
        self.lamport_inventory
            .as_mut()
            .ok_or_else(|| "Lamport inventory is unavailable".to_owned())?
            .record_key_state(key_index, &key)?;
        let witness = built.map_err(|error| error.to_string())?;
        self.retain_authorization(node_id, request, witness)
    }

    fn build_bob_payout(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.local_role != Role::Bob {
            return Err("only Bob can issue the terminal payout witness".to_owned());
        }
        let mut reader = Reader::new(bytes);
        let subset = reader.read_u8().map_err(codec)?;
        let score = reader.read_u32().map_err(codec)?;
        let outcome = decode_outcome(reader.read_u8().map_err(codec)?)?;
        reader.finish().map_err(codec)?;
        let request = authorization_request(3, bytes);
        if let Some(cached) = self.cached_authorization(&request)? {
            return Ok(cached);
        }
        let node_id = self.active_node_id()?;
        let (key_index, mut key) = self.derive_active_lamport_key(LamportPurpose::BobScore24Bit)?;
        let built = {
            let graph = self
                .graph_window
                .as_ref()
                .ok_or_else(|| "active graph window is unavailable".to_owned())?;
            let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
                .as_ref()
                .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
            let preauthorizations = PackedPreauthorizationSource {
                graph,
                local_role: self.local_role,
                secret: &self.secret,
                snapshot_key: &self.snapshot_key,
                shared_config_hash: self.shared_config_hash,
                peer_opening,
            };
            let graph = AuthorizedGraph::new(graph, &preauthorizations);
            let public = self
                .public_preimages
                .as_ref()
                .ok_or_else(|| "public preimage store is unavailable".to_owned())?;
            let retained = self
                .retained_preimages
                .as_ref()
                .ok_or_else(|| "retained DEAL preimages are unavailable".to_owned())?;
            let signer = LocalSigner::new(self.local_role, &self.secret);
            let monitor = self
                .monitor
                .as_mut()
                .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
            build_bob_payout_witness(
                &graph, monitor, public, retained, subset, score, outcome, &mut key, &signer,
            )
            .and_then(|witness| witness.encode())
        };
        self.lamport_inventory
            .as_mut()
            .ok_or_else(|| "Lamport inventory is unavailable".to_owned())?
            .record_key_state(key_index, &key)?;
        let witness = built.map_err(|error| error.to_string())?;
        self.retain_authorization(node_id, request, witness)
    }

    fn build_timeout(&mut self) -> Result<Vec<u8>, String> {
        let request = authorization_request(4, &[]);
        if let Some(cached) = self.cached_authorization(&request)? {
            return Ok(cached);
        }
        let node_id = self.active_node_id()?;
        let graph = self
            .graph_window
            .as_ref()
            .ok_or_else(|| "active graph window is unavailable".to_owned())?;
        let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
            .as_ref()
            .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
        let preauthorizations = PackedPreauthorizationSource {
            graph,
            local_role: self.local_role,
            secret: &self.secret,
            snapshot_key: &self.snapshot_key,
            shared_config_hash: self.shared_config_hash,
            peer_opening,
        };
        let graph = AuthorizedGraph::new(graph, &preauthorizations);
        let monitor = self
            .monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        let mature = monitor
            .mature_timeout(&graph)
            .map_err(|error| error.to_string())?;
        let signer = LocalSigner::new(self.local_role, &self.secret);
        let witness = build_timeout_witness(&graph, &mature, &signer)
            .and_then(|witness| witness.encode())
            .map_err(|error| error.to_string())?;
        self.retain_authorization(node_id, request, witness)
    }

    fn confirm_child(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut reader = Reader::new(bytes);
        let confirmed_height = reader.read_u32().map_err(codec)?;
        let tip_height = reader.read_u32().map_err(codec)?;
        let transaction_bytes = reader.read_byte_vector(4 * 1024 * 1024).map_err(codec)?;
        reader.finish().map_err(codec)?;
        let transaction: Transaction =
            deserialize(&transaction_bytes).map_err(|error| error.to_string())?;
        if let Some(ConfirmedRecord::Child {
            confirmed_height: prior_confirmed,
            tip_height: prior_tip,
            transaction: prior_transaction,
        }) = self.confirmed_history.last()
        {
            if *prior_confirmed == confirmed_height
                && *prior_tip == tip_height
                && prior_transaction == &transaction_bytes
            {
                return self
                    .last_erasure
                    .as_ref()
                    .map(|value| value.attestation.to_vec())
                    .ok_or_else(|| "duplicate confirmation has no erasure attestation".to_owned());
            }
        }
        if serialize(&transaction) != transaction_bytes {
            return Err("confirmed child transaction is not canonical".to_owned());
        }
        let graph = self
            .graph_window
            .as_ref()
            .ok_or_else(|| "active graph window is unavailable".to_owned())?;
        let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
            .as_ref()
            .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
        let preauthorizations = PackedPreauthorizationSource {
            graph,
            local_role: self.local_role,
            secret: &self.secret,
            snapshot_key: &self.snapshot_key,
            shared_config_hash: self.shared_config_hash,
            peer_opening,
        };
        let authorized_graph = AuthorizedGraph::new(graph, &preauthorizations);
        self.monitor
            .as_mut()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?
            .observe_tip(tip_height)
            .map_err(|error| error.to_string())?;
        let parent_id = self
            .monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?
            .confirmed_active_node(&authorized_graph)
            .map_err(|error| error.to_string())?
            .node_id();
        let child_id = graph
            .node(parent_id)
            .ok_or_else(|| "active graph node is unavailable".to_owned())?
            .child_node_ids
            .iter()
            .copied()
            .find(|child| {
                graph.transaction_template(*child).is_some_and(|template| {
                    template.txid() == transaction.compute_txid().to_byte_array()
                })
            })
            .ok_or_else(|| "confirmed transaction is not an active child".to_owned())?;
        let prepared = self.prepare_graph()?;
        let activation = prepared
            .canonical_activation_template()
            .map_err(|error| error.to_string())?;
        let summary = self.graph_summary_ref()?.clone();
        let next_window = compile_graph_oracle_window(prepared, activation, &summary, child_id)
            .map_err(|error| error.to_string())?
            .window;
        let local_purpose = match self.local_role {
            Role::Alice => LamportPurpose::AliceScore24Bit,
            Role::Bob => LamportPurpose::BobScore24Bit,
        };
        let key_index = graph.lamport_key_index(parent_id, local_purpose);
        let inventory = self
            .lamport_inventory
            .as_mut()
            .ok_or_else(|| "Lamport inventory is unavailable".to_owned())?;
        let public = self
            .public_preimages
            .as_mut()
            .ok_or_else(|| "public preimage store is unavailable".to_owned())?;
        let mut eraser = LocalEraser {
            inventory,
            key_index,
            expected_game_id: graph.summary().manifest().chain_game_id,
            expected_node_id: parent_id,
        };
        let monitor = self
            .monitor
            .as_mut()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        monitor
            .confirm_child(
                &authorized_graph,
                child_id,
                &transaction,
                confirmed_height,
                public,
                &mut eraser,
            )
            .map_err(|error| error.to_string())?;
        self.phase = match monitor.state() {
            MonitorState::Terminal { .. } => Phase::Settled,
            MonitorState::Active { .. } => Phase::Active,
            _ => Phase::Halted,
        };
        let digest = erasure_digest(
            self.shared_config_hash,
            graph.summary().manifest().chain_game_id,
            parent_id,
            transaction.compute_txid().to_byte_array(),
        );
        let attestation = self.sign_bip340(digest)?;
        self.authorization_cache = None;
        self.graph_window = Some(next_window);
        self.last_erasure = Some(ErasureCache {
            parent_node_id: parent_id,
            child_txid: transaction.compute_txid().to_byte_array(),
            attestation,
        });
        self.confirmed_history.push(ConfirmedRecord::Child {
            confirmed_height,
            tip_height,
            transaction: transaction_bytes,
        });
        Ok(attestation.to_vec())
    }

    fn confirmed_state_receipt(&self) -> Result<Vec<u8>, String> {
        if !matches!(self.phase, Phase::Active | Phase::Settled) {
            return Err("confirmed-state receipt is unavailable before activation".to_owned());
        }
        let graph = self.graph_ref()?;
        let summary = graph.summary();
        let monitor = self
            .monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        let (node_id, confirmed_height) = match monitor.state() {
            MonitorState::Active {
                node_id,
                confirmed_height,
                ..
            }
            | MonitorState::Terminal {
                node_id,
                confirmed_height,
                ..
            } => (node_id, confirmed_height),
            MonitorState::AwaitingFunding { .. } | MonitorState::Halted => {
                return Err("confirmed-state receipt has no confirmed state".to_owned());
            }
        };
        if graph.active_node_id() != node_id {
            return Err("active graph page differs from the chain monitor".to_owned());
        }
        let record = graph
            .node(node_id)
            .ok_or_else(|| "confirmed node is absent from the active graph page".to_owned())?
            .clone();
        let (spent_outpoint, state_outpoint, state_output) =
            if node_id == summary.root_node_id() {
                (
                    consensus_outpoint_bytes(summary.origin_outpoint()),
                    consensus_outpoint_bytes(summary.root_state_outpoint()),
                    Some(logical_output(summary.root_state_output())),
                )
            } else {
                let transaction = record.transaction.as_ref().ok_or_else(|| {
                    "confirmed non-root node has no creating transaction".to_owned()
                })?;
                let mut outpoint = [0; 36];
                outpoint[..32].copy_from_slice(&transaction.txid);
                let output =
                    if record.node_kind.is_terminal() {
                        None
                    } else {
                        Some(transaction.outputs.first().cloned().ok_or_else(|| {
                            "confirmed state transaction has no output".to_owned()
                        })?)
                    };
                (transaction.input_outpoint, outpoint, output)
            };
        let edges = record
            .child_node_ids
            .iter()
            .map(|child| {
                let edge = graph
                    .edge(node_id, *child)
                    .ok_or_else(|| "confirmed page omits an advertised edge".to_owned())?
                    .clone();
                let sighash = graph
                    .signature_digest(node_id, *child)
                    .map_err(|error| error.to_string())?;
                Ok(PublicEdgeReceipt { edge, sighash })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let balances = public_state_balances(graph.active_state());
        let unsigned = bp52_chain_compiler::ConfirmedStateReceipt::unsigned(
            self.shared_config_hash,
            summary.manifest().chain_game_id,
            summary.manifest().graph_root,
            record.parent_node_id,
            spent_outpoint,
            state_outpoint,
            state_output,
            record,
            balances,
            confirmed_height,
            edges,
            self.local_role,
        );
        let keypair = self.secret.keypair()?;
        let secp = Secp256k1::new();
        issue_confirmed_state_receipt(self.verified_descriptor_ref()?, unsigned, |digest| {
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                .serialize()
        })
        .and_then(|receipt| receipt.encode_to_vec().map_err(Into::into))
        .map_err(|error: bp52_chain_compiler::CompilerError| error.to_string())
    }

    fn runtime_authorization_receipt(&self) -> Result<Vec<u8>, String> {
        if self.phase != Phase::Active {
            return Err("runtime receipt is unavailable outside active gameplay".to_owned());
        }
        let cached = self
            .authorization_cache
            .as_ref()
            .ok_or_else(|| "no runtime edge has been authorized".to_owned())?;
        let graph = self.graph_ref()?;
        if graph.active_node_id() != cached.node_id {
            return Err("runtime authorization belongs to a stale graph page".to_owned());
        }
        let witness = bp52_chain_runtime::Witness::decode(&cached.witness)
            .map_err(|error| error.to_string())?;
        let peer_opening = self.preauth_openings[role_index(self.local_role.other())]
            .as_ref()
            .ok_or_else(|| "verified peer preauthorizations are unavailable".to_owned())?;
        let preauthorizations = PackedPreauthorizationSource {
            graph,
            local_role: self.local_role,
            secret: &self.secret,
            snapshot_key: &self.snapshot_key,
            shared_config_hash: self.shared_config_hash,
            peer_opening,
        };
        let authorized_graph = AuthorizedGraph::new(graph, &preauthorizations);
        let monitor = self
            .monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?;
        let prepared = if witness.edge_kind().is_timeout() {
            let maturity = monitor
                .mature_timeout(&authorized_graph)
                .map_err(|error| error.to_string())?;
            bp52_chain_runtime::attach_timeout_witness(&authorized_graph, &maturity, &witness)
        } else {
            let active = monitor
                .confirmed_active_node(&authorized_graph)
                .map_err(|error| error.to_string())?;
            bp52_chain_runtime::attach_witness(&authorized_graph, &active, &witness)
        }
        .map_err(|error| error.to_string())?;
        let (parent_node_id, child_node_id) = prepared.endpoints();
        let state_outpoint = active_state_outpoint(graph, parent_node_id)?;
        let transaction = serialize(prepared.transaction());
        let unsigned = RuntimeAuthorizationReceipt::unsigned(
            self.shared_config_hash,
            graph.summary().manifest().chain_game_id,
            graph.summary().manifest().graph_root,
            parent_node_id,
            child_node_id,
            state_outpoint,
            prepared.template_txid(),
            transaction,
            self.local_role,
        );
        let keypair = self.secret.keypair()?;
        let secp = Secp256k1::new();
        issue_runtime_authorization_receipt(self.verified_descriptor_ref()?, unsigned, |digest| {
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                .serialize()
        })
        .and_then(|receipt| receipt.encode_to_vec().map_err(Into::into))
        .map_err(|error: bp52_chain_compiler::CompilerError| error.to_string())
    }

    fn card_projection(&self) -> Result<Vec<u8>, String> {
        let retained = self
            .retained_preimages
            .as_ref()
            .ok_or_else(|| "retained DEAL preimages are unavailable".to_owned())?;
        let public = self
            .public_preimages
            .as_ref()
            .ok_or_else(|| "public preimages are unavailable".to_owned())?;
        let hole_slots = match self.local_role {
            Role::Alice => ALICE_HOLE_SLOTS,
            Role::Bob => BOB_HOLE_SLOTS,
        };
        let mut local_hole = [MISSING_CARD; 2];
        for (position, slot) in hole_slots.into_iter().enumerate() {
            let peer = public.get(self.local_role.other(), slot);
            let own = retained.get(usize::from(slot));
            if let (Some(own), Some(peer)) = (own, peer) {
                local_hole[position] = verify_hole_card_delivery(
                    &self.verified_deal,
                    to_deal_role(self.local_role),
                    slot,
                    own,
                    peer,
                )
                .map_err(|error| error.to_string())?
                .card();
            }
        }
        let board = project_public_board(public, |stage, slot, a, b, claimed| {
            verify_community_reveal(&self.verified_deal, stage, slot, a, b, claimed)
                .map(|verified| verified.card())
                .map_err(|error| error.to_string())
        })?;
        let mut alice_hole = [MISSING_CARD; 2];
        let mut bob_hole = [MISSING_CARD; 2];
        for (role, slots, destination) in [
            (Role::Alice, ALICE_HOLE_SLOTS, &mut alice_hole),
            (Role::Bob, BOB_HOLE_SLOTS, &mut bob_hole),
        ] {
            for (position, slot) in slots.into_iter().enumerate() {
                if let (Some(a), Some(b)) =
                    (public.get(Role::Alice, slot), public.get(Role::Bob, slot))
                {
                    let claimed = card_from_preimages(a, b)?;
                    destination[position] = verify_showdown_reveal(
                        &self.verified_deal,
                        to_deal_role(role),
                        slot,
                        a,
                        b,
                        claimed,
                    )
                    .map_err(|error| error.to_string())?
                    .card();
                }
            }
        }
        if self.local_role == Role::Alice && local_hole.iter().all(|card| *card != MISSING_CARD) {
            alice_hole = local_hole;
        }
        if self.local_role == Role::Bob && local_hole.iter().all(|card| *card != MISSING_CARD) {
            bob_hole = local_hole;
        }
        let alice_score = complete_seven(alice_hole, board)
            .map(best_hand)
            .transpose()?;
        let bob_score = complete_seven(bob_hole, board).map(best_hand).transpose()?;
        let outcome = match (alice_score, bob_score) {
            (Some((_, alice)), Some((_, bob))) if alice > bob => 0,
            (Some((_, alice)), Some((_, bob))) if alice < bob => 1,
            (Some(_), Some(_)) => 2,
            _ => u8::MAX,
        };
        let mut writer = Writer::new();
        writer.write_bytes(CARD_MAGIC);
        writer.write_u8(self.local_role.code());
        writer.write_bytes(&local_hole);
        writer.write_bytes(&board);
        writer.write_bytes(&alice_hole);
        writer.write_bytes(&bob_hole);
        write_optional_hand(&mut writer, alice_score);
        write_optional_hand(&mut writer, bob_score);
        writer.write_u8(outcome);
        Ok(writer.into_bytes())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn public_context(&self) -> Result<Vec<u8>, String> {
        let mut writer = Writer::new();
        writer.write_bytes(CONTEXT_MAGIC);
        writer.write_bytes(&self.network_id);
        writer.write_bytes(&self.relay_room_id);
        writer.write_bytes(&self.origin_outpoint);
        writer.write_bytes(&self.verified_deal.as_deal().game_id);
        if let Some(summary) = &self.graph_summary {
            writer.write_u8(1);
            writer.write_bytes(&summary.manifest().chain_game_id);
            writer.write_bytes(&summary.manifest().graph_root);
        } else {
            writer.write_u8(0);
            let chain_game_id = self
                .verified_descriptor
                .as_ref()
                .and_then(|verified| chain_game_id(verified.as_descriptor()).ok())
                .unwrap_or([0; 32]);
            writer.write_bytes(&chain_game_id);
            writer.write_bytes(&[0; 32]);
        }
        writer.write_u8(self.local_role.code());
        Ok(writer.into_bytes())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn public_runtime_status(&self) -> Result<Vec<u8>, String> {
        let mut writer = Writer::new();
        writer.write_bytes(RUNTIME_STATUS_MAGIC);
        writer.write_u8(self.phase as u8);
        writer.write_u8(self.local_role.code());
        writer.write_u8(u8::from(self.inventory_verified));
        write_optional_fixed(&mut writer, self.inventory_attestation.as_ref());
        let ready_mask = u8::from(self.inventory_ready[0].is_some())
            | (u8::from(self.inventory_ready[1].is_some()) << 1);
        writer.write_u8(ready_mask);
        writer.write_u8(u8::from(self.authorization_cache.is_some()));
        writer.write_u8(u8::from(self.last_erasure.is_some()));
        Ok(writer.into_bytes())
    }

    fn seal_checkpoint(&mut self) -> Result<Vec<u8>, String> {
        let counter = self
            .checkpoint_counter
            .checked_add(1)
            .ok_or_else(|| "CHAIN checkpoint counter overflow".to_owned())?;
        let body = Zeroizing::new(self.checkpoint_body(counter)?);
        let (chain_game_id, graph_root) =
            self.graph_summary
                .as_ref()
                .map_or(([0; 32], [0; 32]), |summary| {
                    (
                        summary.manifest().chain_game_id,
                        summary.manifest().graph_root,
                    )
                });
        let mut nonce = [0; 24];
        self.rng.fill_bytes(&mut nonce);
        if !self.snapshot_nonces.insert(nonce) {
            nonce.zeroize();
            return self.halt("CHAIN checkpoint nonce repeated");
        }
        let ciphertext_len = body
            .len()
            .checked_add(16)
            .ok_or_else(|| "CHAIN checkpoint length overflow".to_owned())?;
        let ciphertext_len = u32::try_from(ciphertext_len)
            .map_err(|_| "CHAIN checkpoint exceeds its fixed bound".to_owned())?;
        let mut header = Writer::new();
        header.write_bytes(SNAPSHOT_MAGIC);
        header.write_u16(SNAPSHOT_VERSION);
        header.write_u64(counter);
        header.write_bytes(&self.shared_config_hash);
        header.write_bytes(&self.relay_room_id);
        header.write_bytes(&self.session_nonce);
        header.write_bytes(&self.origin_outpoint);
        header.write_bytes(&self.verified_deal.as_deal().game_id);
        header.write_bytes(&chain_game_id);
        header.write_bytes(&graph_root);
        header.write_u8(self.local_role.code());
        header.write_bytes(&nonce);
        header.write_u32(ciphertext_len);
        let mut key_bytes = Zeroizing::new(self.checkpoint_key());
        let key = Key::try_from(key_bytes.as_ref())
            .map_err(|_| "CHAIN checkpoint key has the wrong length".to_owned())?;
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "CHAIN checkpoint nonce has the wrong length".to_owned())?;
        let cipher = XChaCha20Poly1305::new(&key);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: body.as_ref(),
                    aad: header.as_bytes(),
                },
            )
            .map_err(|_| "CHAIN checkpoint encryption failed".to_owned())?;
        key_bytes.zeroize();
        nonce.zeroize();
        let mut output = header.into_bytes();
        output.extend_from_slice(&ciphertext);
        if output.len() > MAX_SNAPSHOT_BYTES {
            output.zeroize();
            return self.halt("CHAIN checkpoint exceeds its fixed bound");
        }
        self.checkpoint_counter = counter;
        Ok(output)
    }

    fn verify_checkpoint(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let opened = self.open_checkpoint(bytes)?;
        if opened.counter != self.checkpoint_counter {
            return Err("CHAIN checkpoint readback is stale".to_owned());
        }
        validate_checkpoint_body(&opened.body, opened.counter)?;
        Ok(tagged_hash(b"BP52/browser-chain-checkpoint-receipt/v1", &opened.body).to_vec())
    }

    fn restore_checkpoint(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if self.phase != Phase::AcceptedDeal
            || self.descriptor_candidate.is_some()
            || self.checkpoint_counter != 0
        {
            return Err(
                "CHAIN checkpoint restore is only available immediately after init".to_owned(),
            );
        }
        let opened = self.open_checkpoint(bytes)?;
        if opened.counter == 0 {
            return Err("CHAIN checkpoint counter must be positive".to_owned());
        }
        let receipt = tagged_hash(b"BP52/browser-chain-checkpoint-receipt/v1", &opened.body);
        let state = decode_checkpoint_body(&opened.body, opened.counter)?;
        let restored = self.apply_checkpoint_state(state, opened.chain_game_id, opened.graph_root);
        if let Err(error) = restored {
            self.phase = Phase::Halted;
            return Err(error);
        }
        self.checkpoint_counter = opened.counter;
        self.snapshot_nonces.insert(opened.nonce);
        let mut output = Vec::with_capacity(40);
        output.extend_from_slice(&opened.counter.to_le_bytes());
        output.extend_from_slice(&receipt);
        Ok(output)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_checkpoint_state(
        &mut self,
        state: CheckpointState,
        checkpoint_game_id: [u8; 32],
        checkpoint_graph_root: [u8; 32],
    ) -> Result<(), String> {
        if state.descriptor_candidate.is_empty() {
            if state.phase != Phase::AcceptedDeal
                || !state.signed_descriptor.is_empty()
                || state.monitor_state.is_some()
                || state
                    .descriptor_event_signatures
                    .iter()
                    .any(Option::is_some)
            {
                return Err("empty CHAIN checkpoint has inconsistent descriptor state".to_owned());
            }
            return Ok(());
        }
        let descriptor = ChainGameDescriptor::decode_exact(&state.descriptor_candidate)
            .map_err(|error| error.to_string())?;
        self.profile
            .validate_descriptor(&descriptor)
            .map_err(|error| error.to_string())?;
        if descriptor.deal != *self.verified_deal.as_deal()
            || descriptor.alice_xonly_pk != self.identities.alice().serialize()
            || descriptor.bob_xonly_pk != self.identities.bob().serialize()
            || descriptor.network_id != self.network_id
            || descriptor.funding_outpoint != self.origin_outpoint
            || descriptor.deal_session_nonce != self.session_nonce
        {
            return Err("checkpoint descriptor differs from the verified DEAL/session".to_owned());
        }
        validate_origin_context(
            &self.origin_witness_script,
            descriptor.network_id,
            self.relay_room_id,
            descriptor.deal_session_nonce,
        )?;
        let descriptor_signature = state.descriptor_signature;
        if let Some(signature) = descriptor_signature {
            self.verify_identity_signature(
                self.local_role,
                descriptor_signature_digest(&descriptor).map_err(codec)?,
                signature,
            )?;
        }
        self.descriptor_candidate = Some(descriptor);
        self.descriptor_signature = descriptor_signature;
        let mut event_signatures = state.descriptor_event_signatures;
        let local_index = role_index(self.local_role);
        match (event_signatures[local_index], descriptor_signature) {
            (Some(relay), Some(local)) if relay != local => {
                return Err(
                    "checkpoint relay signature differs from the local descriptor signature"
                        .to_owned(),
                );
            }
            (Some(relay), None) => self.descriptor_signature = Some(relay),
            (None, Some(local)) => event_signatures[local_index] = Some(local),
            _ => {}
        }
        let digest = descriptor_signature_digest(&descriptor).map_err(codec)?;
        for (index, signature) in event_signatures.iter().enumerate() {
            if let Some(signature) = signature {
                let role = if index == 0 { Role::Alice } else { Role::Bob };
                self.verify_identity_signature(role, digest, *signature)?;
            }
        }
        if event_signatures.iter().all(Option::is_none) {
            return Err("checkpoint descriptor has no authenticated signature".to_owned());
        }
        self.descriptor_event_signatures = event_signatures;
        self.phase = Phase::DescriptorCandidate;
        if state.signed_descriptor.is_empty() {
            if state.phase != Phase::DescriptorCandidate {
                return Err("unsigned checkpoint descriptor has an advanced phase".to_owned());
            }
            return Ok(());
        }
        let _ = self.install_signed_descriptor(&state.signed_descriptor)?;
        if !state.lamport_bundles[local_index].is_empty() {
            return Err(
                "CHAIN checkpoint redundantly contains its local Lamport bundle".to_owned(),
            );
        }
        if state.lamport_key_count == 0 {
            return Err("signed CHAIN checkpoint has no local Lamport inventory".to_owned());
        }
        let (chain_game_id, expected) = self.local_lamport_expectations()?;
        let (mut inventory, public) = DeterministicLamportInventory::generate_public_keys(
            &self.snapshot_key,
            self.shared_config_hash,
            chain_game_id,
            self.local_role,
            &expected,
        )?;
        if usize::from(state.lamport_key_count) != inventory.len() {
            return Err("restored Lamport key count differs from the graph".to_owned());
        }
        let signature = self.sign_bip340_for_bundle(chain_game_id, self.local_role, &public)?;
        let local_bundle = LamportPublicBundle::sign(
            chain_game_id,
            to_lamport_role(self.local_role),
            &public,
            |_| signature,
        )
        .map_err(|error| error.to_string())?;
        inventory.bind_bundle(&local_bundle, chain_game_id, self.local_role)?;
        inventory.restore_packed(&state.lamport_key_states)?;
        self.lamport_inventory = Some(inventory);
        self.lamport_bundles[local_index] = Some(local_bundle);
        self.phase = Phase::LamportReady;
        let peer_index = role_index(self.local_role.other());
        if !state.lamport_bundles[peer_index].is_empty() {
            self.accept_lamport_bundle(&state.lamport_bundles[peer_index])?;
        }
        if self.graph_summary.is_none() {
            if checkpoint_game_id != [0; 32]
                || checkpoint_graph_root != [0; 32]
                || state.phase != Phase::LamportReady
            {
                return Err("pre-graph CHAIN checkpoint has inconsistent graph binding".to_owned());
            }
            return Ok(());
        }
        let summary = self.graph_summary_ref()?;
        if summary.manifest().chain_game_id != checkpoint_game_id
            || summary.manifest().graph_root != checkpoint_graph_root
        {
            return Err("restored graph differs from the checkpoint binding".to_owned());
        }
        for commitment in state.root_commitments.iter().flatten() {
            self.accept_root_commitment(commitment)?;
        }
        for opening in state.root_openings.iter().flatten() {
            self.accept_root_opening(opening)?;
        }
        if state.local_preauth_nonce.is_some() != state.preauth_commitments[local_index].is_some() {
            return Err(
                "CHAIN checkpoint local preauthorization nonce and commitment disagree".to_owned(),
            );
        }
        if state.local_preauth_nonce == Some([0; 32]) {
            return Err("CHAIN checkpoint local preauthorization nonce is zero".to_owned());
        }
        if state.preauth_openings[local_index].is_some() {
            return Err(
                "CHAIN checkpoint redundantly contains its local preauthorization signatures"
                    .to_owned(),
            );
        }
        self.local_preauth_nonce = state.local_preauth_nonce;
        for commitment in state.preauth_commitments.iter().flatten() {
            self.accept_preauth_commitment(commitment)?;
        }
        for index in 0..2 {
            if !state.preauth_verified[index] {
                if state.preauth_openings[index].is_some()
                    || state.preauth_receipts[index].is_some()
                {
                    return Err(
                        "unverified CHAIN preauthorization has retained verification material"
                            .to_owned(),
                    );
                }
                continue;
            }
            let receipt_bytes = state.preauth_receipts[index].as_deref().ok_or_else(|| {
                "verified CHAIN preauthorization has no durable receipt".to_owned()
            })?;
            let expected_receipt = PreauthorizationVerifiedReceipt::decode_exact(receipt_bytes)
                .map_err(|error| error.to_string())?;
            let role = if index == 0 { Role::Alice } else { Role::Bob };
            let commitment = self.preauth_commitments[index].ok_or_else(|| {
                "verified CHAIN preauthorization has no authenticated commitment".to_owned()
            })?;
            let requests = self
                .setup_signature_requests
                .as_ref()
                .ok_or_else(|| "transient setup signature requests are unavailable".to_owned())?
                .preauthorizations(role);
            let request_count = u32::try_from(requests.len())
                .map_err(|_| "preauthorization count exceeds u32".to_owned())?;
            let verified_descriptor = self.verified_descriptor_value()?;
            verify_preauthorization_verified_receipt(
                &verified_descriptor,
                self.shared_config_hash,
                checkpoint_graph_root,
                &commitment,
                request_count,
                self.local_role,
                &expected_receipt,
            )
            .map_err(|error| error.to_string())?;
            if index != local_index {
                let opening_bytes = state.preauth_openings[index].as_deref().ok_or_else(|| {
                    "verified peer preauthorization signatures are unavailable".to_owned()
                })?;
                let opening = SignatureBundleOpening::decode_exact(opening_bytes)
                    .map_err(|error| error.to_string())?;
                verify_signature_bundle_binding(
                    &verified_descriptor,
                    checkpoint_graph_root,
                    &commitment,
                    &opening,
                    requests,
                )
                .map_err(|error| error.to_string())?;
                self.preauth_openings[index] = Some(opening);
            }
            self.preauth_verified[index] = true;
            self.preauth_receipts[index] = Some(expected_receipt);
        }
        if self.preauth_verified.into_iter().all(|verified| verified) {
            if state.phase < Phase::PreauthorizationsReady {
                return Err("verified checkpoint preauthorizations precede their phase".to_owned());
            }
            self.phase = Phase::PreauthorizationsReady;
            self.setup_signature_requests = None;
        }
        if state.inventory_verified {
            if state.phase < Phase::InventoryVerified {
                return Err("checkpoint inventory flag precedes its phase".to_owned());
            }
            let _ = self.attest_inventory()?;
            let attestation = state
                .inventory_attestation
                .ok_or_else(|| "verified checkpoint inventory has no attestation".to_owned())?;
            let summary = self.graph_summary_ref()?;
            let profile = self.profile.inventory(summary.descriptor().button);
            let (lamport_count, runtime_count) = match self.local_role {
                Role::Alice => (profile.alice_lamport_keys, profile.alice_runtime_signatures),
                Role::Bob => (profile.bob_lamport_keys, profile.bob_runtime_signatures),
            };
            self.verify_identity_signature(
                self.local_role,
                inventory_digest(
                    self.shared_config_hash,
                    summary.manifest().chain_game_id,
                    summary.manifest().graph_root,
                    self.local_role,
                    lamport_count,
                    runtime_count,
                ),
                attestation,
            )?;
            self.inventory_attestation = Some(attestation);
        } else if state.inventory_attestation.is_some() || state.phase >= Phase::InventoryVerified {
            return Err("checkpoint inventory state is inconsistent".to_owned());
        }
        for (index, ready) in state.inventory_ready.iter().enumerate() {
            if let Some(signature) = ready {
                let role = if index == 0 { Role::Alice } else { Role::Bob };
                let mut artifact = Vec::with_capacity(65);
                artifact.push(role.code());
                artifact.extend_from_slice(signature);
                self.accept_inventory_ready(&artifact)?;
            }
        }
        for confirmation in &state.confirmations {
            let (kind, confirmed_height, tip_height, transaction) = match confirmation {
                StoredConfirmation::Activation {
                    confirmed_height,
                    tip_height,
                    transaction,
                } => (0, *confirmed_height, *tip_height, transaction),
                StoredConfirmation::Child {
                    confirmed_height,
                    tip_height,
                    transaction,
                } => (1, *confirmed_height, *tip_height, transaction),
            };
            let mut writer = Writer::new();
            writer.write_u32(confirmed_height);
            writer.write_u32(tip_height);
            writer.write_byte_vector(transaction).map_err(codec)?;
            if kind == 0 {
                self.confirm_activation(&writer.into_bytes())?;
            } else {
                self.confirm_child(&writer.into_bytes())?;
            }
        }
        if DeterministicLamportInventory::packed_contains_issued(
            usize::from(state.lamport_key_count),
            &state.lamport_key_states,
        )? && state.authorization.is_none()
        {
            return Err("issued checkpoint Lamport key has no cached witness".to_owned());
        }
        if let Some(cache) = state.authorization {
            let active = self.active_node_id()?;
            if cache.node_id != active {
                return Err("checkpoint authorization cache is not for the active node".to_owned());
            }
            self.authorization_cache = Some(cache);
        }
        if let Some(erasure) = state.erasure {
            self.verify_identity_signature(
                self.local_role,
                erasure_digest(
                    self.shared_config_hash,
                    self.graph_summary_ref()?.manifest().chain_game_id,
                    erasure.parent_node_id,
                    erasure.child_txid,
                ),
                erasure.attestation,
            )?;
            self.last_erasure = Some(erasure);
        }
        if self.monitor.as_ref().map(ChainMonitor::state) != state.monitor_state {
            return Err("restored monitor state differs from the checkpoint".to_owned());
        }
        if self.phase != state.phase {
            return Err("restored CHAIN phase differs from the checkpoint".to_owned());
        }
        Ok(())
    }

    fn verify_identity_signature(
        &self,
        role: Role,
        digest: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), String> {
        let public = match role {
            Role::Alice => self.identities.alice(),
            Role::Bob => self.identities.bob(),
        };
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
            .map_err(|error| error.to_string())?;
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &Message::from_digest(digest), public)
            .map_err(|_| "identity signature is invalid".to_owned())
    }

    #[allow(clippy::too_many_lines)]
    fn checkpoint_body(&mut self, counter: u64) -> Result<Vec<u8>, String> {
        let (lamport_count, lamport_states) = match &self.lamport_inventory {
            Some(inventory) => (
                u16::try_from(inventory.len())
                    .map_err(|_| "too many Lamport keys in CHAIN checkpoint".to_owned())?,
                inventory.checkpoint_bytes(),
            ),
            None => (0, &[][..]),
        };
        let mut writer = Writer::new();
        writer.write_bytes(SNAPSHOT_BODY_MAGIC);
        writer.write_u64(counter);
        writer.write_u8(self.phase as u8);
        writer
            .write_byte_vector(
                &self
                    .descriptor_candidate
                    .as_ref()
                    .map(Encode::encode_to_vec)
                    .transpose()
                    .map_err(codec)?
                    .unwrap_or_default(),
            )
            .map_err(codec)?;
        write_optional_fixed(&mut writer, self.descriptor_signature.as_ref());
        writer
            .write_byte_vector(self.signed_descriptor_bytes.as_deref().unwrap_or_default())
            .map_err(codec)?;
        for role in [Role::Alice, Role::Bob] {
            let index = role_index(role);
            let encoded = self.lamport_bundle(role).map(LamportPublicBundle::encode);
            writer
                .write_byte_vector(if index == role_index(self.local_role) {
                    &[]
                } else {
                    encoded.as_deref().unwrap_or_default()
                })
                .map_err(codec)?;
        }
        for value in &self.root_commitments {
            write_optional_codec(&mut writer, value.as_ref())?;
        }
        for value in &self.root_openings {
            write_optional_codec(&mut writer, value.as_ref())?;
        }
        for value in &self.preauth_commitments {
            write_optional_codec(&mut writer, value.as_ref())?;
        }
        write_optional_fixed(&mut writer, self.local_preauth_nonce.as_ref());
        for verified in self.preauth_verified {
            writer.write_u8(u8::from(verified));
        }
        for (index, value) in self.preauth_openings.iter().enumerate() {
            if index == role_index(self.local_role) {
                write_optional_codec::<SignatureBundleOpening>(&mut writer, None)?;
            } else {
                write_optional_codec(&mut writer, value.as_ref())?;
            }
        }
        for receipt in &self.preauth_receipts {
            write_optional_codec(&mut writer, receipt.as_ref())?;
        }
        writer.write_u8(u8::from(self.inventory_verified));
        write_optional_fixed(&mut writer, self.inventory_attestation.as_ref());
        for ready in &self.inventory_ready {
            write_optional_fixed(&mut writer, ready.as_ref());
        }
        writer.write_u16(lamport_count);
        writer.write_byte_vector(lamport_states).map_err(codec)?;
        writer.write_u16(
            u16::try_from(self.confirmed_history.len())
                .map_err(|_| "too many confirmed records in CHAIN checkpoint".to_owned())?,
        );
        for record in &self.confirmed_history {
            match record {
                ConfirmedRecord::Activation {
                    confirmed_height,
                    tip_height,
                    transaction,
                } => {
                    writer.write_u8(0);
                    writer.write_u32(*confirmed_height);
                    writer.write_u32(*tip_height);
                    writer.write_byte_vector(transaction).map_err(codec)?;
                }
                ConfirmedRecord::Child {
                    confirmed_height,
                    tip_height,
                    transaction,
                } => {
                    writer.write_u8(1);
                    writer.write_u32(*confirmed_height);
                    writer.write_u32(*tip_height);
                    writer.write_byte_vector(transaction).map_err(codec)?;
                }
            }
        }
        if let Some(cache) = &self.authorization_cache {
            writer.write_u8(1);
            writer.write_bytes(&cache.node_id);
            writer.write_byte_vector(&cache.request).map_err(codec)?;
            writer.write_byte_vector(&cache.witness).map_err(codec)?;
        } else {
            writer.write_u8(0);
        }
        if let Some(erasure) = &self.last_erasure {
            writer.write_u8(1);
            writer.write_bytes(&erasure.parent_node_id);
            writer.write_bytes(&erasure.child_txid);
            writer.write_bytes(&erasure.attestation);
        } else {
            writer.write_u8(0);
        }
        write_monitor_state(&mut writer, self.monitor.as_ref().map(ChainMonitor::state));
        for signature in &self.descriptor_event_signatures {
            write_optional_fixed(&mut writer, signature.as_ref());
        }
        Ok(writer.into_bytes())
    }

    fn checkpoint_key(&self) -> [u8; 32] {
        let mut material = Zeroizing::new(Vec::with_capacity(193));
        material.extend_from_slice(self.snapshot_key.as_ref());
        material.extend_from_slice(&self.shared_config_hash);
        material.extend_from_slice(&self.network_id);
        material.push(bitcoin_network_code(self.bitcoin_network));
        material.extend_from_slice(&self.relay_room_id);
        material.extend_from_slice(&self.session_nonce);
        material.extend_from_slice(&self.verified_deal.as_deal().game_id);
        tagged_hash(SNAPSHOT_KEY_TAG, &material)
    }

    fn open_checkpoint(&self, bytes: &[u8]) -> Result<OpenedCheckpoint, String> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err("CHAIN checkpoint exceeds its fixed bound".to_owned());
        }
        let mut reader = Reader::new(bytes);
        if &reader.read_array::<8>().map_err(codec)? != SNAPSHOT_MAGIC {
            return Err("CHAIN checkpoint has the wrong magic".to_owned());
        }
        if reader.read_u16().map_err(codec)? != SNAPSHOT_VERSION {
            return Err("CHAIN checkpoint has an unsupported version".to_owned());
        }
        let counter = reader.read_u64().map_err(codec)?;
        if reader.read_array::<32>().map_err(codec)? != self.shared_config_hash
            || reader.read_array::<32>().map_err(codec)? != self.relay_room_id
            || reader.read_array::<32>().map_err(codec)? != self.session_nonce
            || reader.read_array::<36>().map_err(codec)? != self.origin_outpoint
            || reader.read_array::<32>().map_err(codec)? != self.verified_deal.as_deal().game_id
        {
            return Err("CHAIN checkpoint belongs to another session".to_owned());
        }
        let encoded_chain_game_id = reader.read_array::<32>().map_err(codec)?;
        let encoded_graph_root = reader.read_array::<32>().map_err(codec)?;
        if let Some(summary) = &self.graph_summary {
            if encoded_chain_game_id != summary.manifest().chain_game_id
                || encoded_graph_root != summary.manifest().graph_root
            {
                return Err("CHAIN checkpoint belongs to another graph".to_owned());
            }
        }
        if decode_role(reader.read_u8().map_err(codec)?)? != self.local_role {
            return Err("CHAIN checkpoint belongs to the other role".to_owned());
        }
        let nonce = reader.read_array::<24>().map_err(codec)?;
        let ciphertext_len = usize::try_from(reader.read_u32().map_err(codec)?)
            .map_err(|_| "CHAIN checkpoint length overflow".to_owned())?;
        let aad_len = bytes
            .len()
            .checked_sub(reader.remaining_len())
            .ok_or_else(|| "CHAIN checkpoint length underflow".to_owned())?;
        if ciphertext_len != reader.remaining_len() {
            return Err("CHAIN checkpoint ciphertext length is not canonical".to_owned());
        }
        let ciphertext = reader.read_bytes(ciphertext_len).map_err(codec)?;
        reader.finish().map_err(codec)?;
        let key_bytes = Zeroizing::new(self.checkpoint_key());
        let key = Key::try_from(key_bytes.as_ref())
            .map_err(|_| "CHAIN checkpoint key has the wrong length".to_owned())?;
        let nonce_value = XNonce::try_from(nonce.as_slice())
            .map_err(|_| "CHAIN checkpoint nonce has the wrong length".to_owned())?;
        let cipher = XChaCha20Poly1305::new(&key);
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: ciphertext,
                    aad: &bytes[..aad_len],
                },
            )
            .map_err(|_| "CHAIN checkpoint authentication failed".to_owned())?;
        Ok(OpenedCheckpoint {
            counter,
            chain_game_id: encoded_chain_game_id,
            graph_root: encoded_graph_root,
            nonce,
            body: Zeroizing::new(plaintext),
        })
    }

    fn derive_active_lamport_key(
        &self,
        purpose: LamportPurpose,
    ) -> Result<(usize, bp52_lamport::LamportSecretKey), String> {
        let expected_role = match purpose {
            LamportPurpose::AliceScore24Bit => Role::Alice,
            LamportPurpose::BobScore24Bit => Role::Bob,
        };
        if expected_role != self.local_role {
            return Err("active Lamport key belongs to the peer role".to_owned());
        }
        let node_id = self
            .monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?
            .confirmed_active_node(self.graph_ref()?)
            .map_err(|error| error.to_string())?
            .node_id();
        let graph = self.graph_ref()?;
        let index = graph
            .lamport_key_index(node_id, purpose)
            .ok_or_else(|| "active node has no local score-key index".to_owned())?;
        let public = graph
            .lamport_public_key(node_id, purpose)
            .ok_or_else(|| "active node has no local score public key".to_owned())?;
        let key_context_node_id = public.context().node_id;
        let game_id = graph.summary().manifest().chain_game_id;
        let key = self
            .lamport_inventory
            .as_ref()
            .ok_or_else(|| "Lamport inventory is unavailable".to_owned())?
            .derive_fresh_key(
                index,
                &self.snapshot_key,
                self.shared_config_hash,
                game_id,
                self.local_role,
                key_context_node_id,
                purpose,
                public,
            )?;
        Ok((index, key))
    }

    fn active_node_id(&self) -> Result<NodeId, String> {
        self.monitor
            .as_ref()
            .ok_or_else(|| "chain monitor is unavailable".to_owned())?
            .confirmed_active_node(self.graph_ref()?)
            .map(|active| active.node_id())
            .map_err(|error| error.to_string())
    }

    fn cached_authorization(&mut self, request: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let node_id = self.active_node_id()?;
        if let Some(cached) = &self.authorization_cache {
            if cached.node_id == node_id && cached.request == request {
                return Ok(Some(cached.witness.clone()));
            }
            return self.halt("a different runtime edge was already authorized at this node");
        }
        Ok(None)
    }

    fn retain_authorization(
        &mut self,
        node_id: NodeId,
        request: Vec<u8>,
        witness: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        if witness.len() > MAX_CACHED_WITNESS_BYTES {
            return self.halt("runtime witness exceeds the crash-safe cache bound");
        }
        self.authorization_cache = Some(AuthorizationCache {
            node_id,
            request,
            witness: witness.clone(),
        });
        Ok(witness)
    }

    fn sign_bip340(&mut self, digest: [u8; 32]) -> Result<[u8; 64], String> {
        let keypair = self.secret.keypair()?;
        let aux = self.random_array();
        Ok(Secp256k1::new()
            .sign_schnorr_with_aux_rand(&Message::from_digest(digest), &keypair, &aux)
            .serialize())
    }

    fn sign_default(&mut self, digest: [u8; 32]) -> Result<DefaultSighashSignature, String> {
        Ok(sign_sighash_default(
            &Secp256k1::new(),
            &self.secret.keypair()?,
            digest,
        ))
    }

    fn random_array(&mut self) -> [u8; 32] {
        let mut value = [0; 32];
        self.rng.fill_bytes(&mut value);
        value
    }

    fn random_nonzero(&mut self) -> Result<[u8; 32], String> {
        for _ in 0..8 {
            let value = self.random_array();
            if value != [0; 32] {
                return Ok(value);
            }
        }
        Err("CHAIN RNG repeatedly returned a zero commitment nonce".to_owned())
    }

    fn graph_ref(&self) -> Result<&MaterializedGraphWindow, String> {
        self.graph_window
            .as_ref()
            .ok_or_else(|| "active graph window is unavailable".to_owned())
    }

    fn graph_summary_ref(&self) -> Result<&CompiledGraphSummary, String> {
        self.graph_summary
            .as_ref()
            .ok_or_else(|| "compiled graph summary is unavailable".to_owned())
    }

    fn lamport_bundle(&self, role: Role) -> Option<&LamportPublicBundle> {
        self.lamport_bundles[role_index(role)].as_ref()
    }

    fn verified_descriptor_ref(
        &self,
    ) -> Result<&bp52_chain_types::VerifiedChainDescriptor, String> {
        self.verified_descriptor
            .as_ref()
            .ok_or_else(|| "verified descriptor is unavailable".to_owned())
    }

    fn verified_descriptor_value(
        &self,
    ) -> Result<bp52_chain_types::VerifiedChainDescriptor, String> {
        self.verified_descriptor_ref().copied()
    }

    fn halt<T>(&mut self, reason: &str) -> Result<T, String> {
        self.phase = Phase::Halted;
        Err(reason.to_owned())
    }
}

fn decode_tip_height(bytes: &[u8]) -> Result<u32, String> {
    let mut reader = Reader::new(bytes);
    let height = reader.read_u32().map_err(codec)?;
    reader.finish().map_err(codec)?;
    Ok(height)
}

struct LocalSigner<'a> {
    local_role: Role,
    secret: &'a IdentitySecret,
}

impl<'a> LocalSigner<'a> {
    const fn new(local_role: Role, secret: &'a IdentitySecret) -> Self {
        Self { local_role, secret }
    }
}

struct PackedPreauthorizationSource<'a> {
    graph: &'a MaterializedGraphWindow,
    local_role: Role,
    secret: &'a IdentitySecret,
    snapshot_key: &'a [u8; 32],
    shared_config_hash: [u8; 32],
    peer_opening: &'a SignatureBundleOpening,
}

impl PreauthorizationSource for PackedPreauthorizationSource<'_> {
    fn preauthorization(
        &self,
        parent_node_id: NodeId,
        child_node_id: NodeId,
        role: Role,
    ) -> Option<DefaultSighashSignature> {
        let (index, request) =
            self.graph
                .preauthorization_request(parent_node_id, child_node_id, role)?;
        if role == self.local_role {
            return deterministic_preauthorization_signature(
                self.secret,
                self.snapshot_key,
                self.shared_config_hash,
                self.graph.summary().manifest().chain_game_id,
                self.graph.summary().manifest().graph_root,
                role,
                &request,
            )
            .ok();
        }
        let bundle = self.peer_opening.bundle();
        if bundle.role() != role
            || bundle.graph_root() != self.graph.summary().manifest().graph_root
        {
            return None;
        }
        bundle
            .signatures()
            .get(index)
            .copied()
            .and_then(|signature| DefaultSighashSignature::from_bytes(signature).ok())
    }
}

#[allow(clippy::too_many_arguments)]
fn deterministic_preauthorization_signature(
    secret: &IdentitySecret,
    snapshot_key: &[u8; 32],
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    role: Role,
    request: &bp52_chain_compiler::SignatureRequest,
) -> Result<DefaultSighashSignature, String> {
    deterministic_preauthorization_signature_with(
        &Secp256k1::new(),
        &secret.keypair()?,
        snapshot_key,
        shared_config_hash,
        chain_game_id,
        graph_root,
        role,
        request,
    )
}

#[allow(clippy::too_many_arguments)]
fn deterministic_preauthorization_signature_with(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    keypair: &Keypair,
    snapshot_key: &[u8; 32],
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    role: Role,
    request: &bp52_chain_compiler::SignatureRequest,
) -> Result<DefaultSighashSignature, String> {
    let mut material = Zeroizing::new(Vec::with_capacity(226));
    material.extend_from_slice(snapshot_key);
    material.extend_from_slice(&shared_config_hash);
    material.extend_from_slice(&chain_game_id);
    material.extend_from_slice(&graph_root);
    material.push(role.code());
    material.extend_from_slice(&request.parent_node_id);
    material.extend_from_slice(&request.child_node_id);
    material.extend_from_slice(&request.sighash);
    let mut aux = tagged_hash(PREAUTH_SIGNATURE_AUX_TAG, &material);
    let signature =
        secp.sign_schnorr_with_aux_rand(&Message::from_digest(request.sighash), keypair, &aux);
    aux.zeroize();
    DefaultSighashSignature::from_bytes(signature.serialize()).map_err(|error| error.to_string())
}

impl BitcoinSigner for LocalSigner<'_> {
    fn sign_sighash_default(
        &self,
        role: Role,
        _node_id: NodeId,
        _child_node_id: NodeId,
        digest: [u8; 32],
    ) -> Result<DefaultSighashSignature, SignerError> {
        if role != self.local_role {
            return Err(SignerError::new("signer request names the peer role"));
        }
        let keypair = self
            .secret
            .keypair()
            .map_err(|_| SignerError::new("identity key unavailable"))?;
        Ok(sign_sighash_default(&Secp256k1::new(), &keypair, digest))
    }
}

struct LocalEraser<'a> {
    inventory: &'a mut DeterministicLamportInventory,
    key_index: Option<usize>,
    expected_game_id: [u8; 32],
    expected_node_id: NodeId,
}

impl SecretEraser for LocalEraser<'_> {
    fn erase_node_secrets(
        &mut self,
        chain_game_id: [u8; 32],
        node_id: NodeId,
    ) -> Result<(), RuntimeError> {
        if chain_game_id != self.expected_game_id {
            return Err(RuntimeError::WrongChainGame);
        }
        if node_id != self.expected_node_id {
            return Err(RuntimeError::SecretErasure {
                reason: "Lamport erasure names another node",
            });
        }
        if let Some(index) = self.key_index {
            self.inventory
                .erase_index(index)
                .map_err(|_| RuntimeError::SecretErasure {
                    reason: "Lamport lifecycle erasure failed",
                })?;
        }
        Ok(())
    }
}

fn verify_activation_signature(
    engine: &ChainEngine,
    role: Role,
    transaction: &Transaction,
    signature: &[u8],
) -> Result<(), String> {
    let Some((&sighash, der)) = signature.split_last() else {
        return Err("activation signature is empty".to_owned());
    };
    if sighash != EcdsaSighashType::All as u8 {
        return Err("activation signature is not SIGHASH_ALL".to_owned());
    }
    let signature =
        bitcoin::secp256k1::ecdsa::Signature::from_der(der).map_err(|error| error.to_string())?;
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err("activation signature is not low-S".to_owned());
    }
    let digest = SighashCache::new(transaction)
        .p2wsh_signature_hash(
            0,
            ScriptBuf::from_bytes(engine.origin_witness_script.to_vec()).as_script(),
            engine.origin_output.value,
            EcdsaSighashType::All,
        )
        .map_err(|error| error.to_string())?
        .to_byte_array();
    let offset = match role {
        Role::Alice => 35,
        Role::Bob => 70,
    };
    let key = PublicKey::from_slice(&engine.origin_witness_script[offset..offset + 33])
        .map_err(|error| error.to_string())?;
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &signature, &key)
        .map_err(|error| error.to_string())
}

fn verify_signed_activation(engine: &ChainEngine, transaction: &Transaction) -> Result<(), String> {
    let summary = engine.graph_summary_ref()?;
    let mut witness_free = transaction.clone();
    if witness_free.input.len() != 1 {
        return Err("activation must contain exactly one input".to_owned());
    }
    witness_free.input[0].witness = BitcoinWitness::new();
    if &witness_free != summary.activation_template().transaction() {
        return Err("confirmed activation differs from the compiled template".to_owned());
    }
    let witness = &transaction.input[0].witness;
    if witness.len() != 3 || witness.nth(2) != Some(engine.origin_witness_script.as_slice()) {
        return Err("activation witness has the wrong shape or script".to_owned());
    }
    verify_activation_signature(
        engine,
        Role::Alice,
        transaction,
        witness.nth(1).unwrap_or_default(),
    )?;
    verify_activation_signature(
        engine,
        Role::Bob,
        transaction,
        witness.nth(0).unwrap_or_default(),
    )
}

fn reveal_pattern_for_active(
    graph: &dyn bp52_chain_runtime::ChainBackend,
    node_id: NodeId,
) -> Result<RevealPattern, String> {
    let node = graph
        .node(node_id)
        .ok_or_else(|| "active node is unavailable".to_owned())?;
    let normal = node
        .child_node_ids
        .iter()
        .filter_map(|child| graph.edge(node_id, *child))
        .find(|edge| !edge.kind.is_timeout())
        .ok_or_else(|| "active reveal node has no normal child".to_owned())?;
    match normal.kind {
        EdgeKind::HoleCardReveal {
            revealer: Role::Bob,
        } => Ok(RevealPattern::DealAlice),
        EdgeKind::HoleCardReveal {
            revealer: Role::Alice,
        } => Ok(RevealPattern::DealBob),
        EdgeKind::CommunityReveal {
            street: Street::Flop,
            revealer,
        } => Ok(RevealPattern::Flop(revealer)),
        EdgeKind::CommunityReveal {
            street: Street::Turn,
            revealer,
        } => Ok(RevealPattern::Turn(revealer)),
        EdgeKind::CommunityReveal {
            street: Street::River,
            revealer,
        } => Ok(RevealPattern::River(revealer)),
        _ => Err("active node is not a reveal obligation".to_owned()),
    }
}

fn public_state_balances(state: &PlannedState) -> PublicStateBalances {
    match state {
        PlannedState::Terminal(terminal) => PublicStateBalances {
            alice_stack_sat: terminal.alice_output_sat,
            bob_stack_sat: terminal.bob_output_sat,
            pot_sat: 0,
        },
        state => {
            let amounts = state.amounts();
            PublicStateBalances {
                alice_stack_sat: amounts.alice_remaining,
                bob_stack_sat: amounts.bob_remaining,
                pot_sat: amounts.pot,
            }
        }
    }
}

fn logical_output(output: &TxOut) -> LogicalOutput {
    LogicalOutput {
        value_sat: output.value.to_sat(),
        script_pubkey: output.script_pubkey.as_bytes().to_vec(),
    }
}

fn consensus_outpoint_bytes(outpoint: bitcoin::OutPoint) -> [u8; 36] {
    let mut bytes = [0; 36];
    bytes[..32].copy_from_slice(&outpoint.txid.to_byte_array());
    bytes[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    bytes
}

fn active_state_outpoint(
    graph: &MaterializedGraphWindow,
    node_id: NodeId,
) -> Result<[u8; 36], String> {
    if node_id == graph.summary().root_node_id() {
        return Ok(consensus_outpoint_bytes(
            graph.summary().root_state_outpoint(),
        ));
    }
    let transaction = graph
        .node(node_id)
        .and_then(|node| node.transaction.as_ref())
        .ok_or_else(|| "active non-root node has no creating transaction".to_owned())?;
    let mut outpoint = [0; 36];
    outpoint[..32].copy_from_slice(&transaction.txid);
    Ok(outpoint)
}

fn policy() -> Result<&'static bp52_chain_bitcoin::ClassFeePolicy, String> {
    if let Some(value) = POLICY.get() {
        return Ok(value);
    }
    let value = HEADS_UP_FIXED_LIMIT_V1_PROFILE
        .fee_policy()
        .map_err(|error| error.to_string())?;
    let _ = POLICY.set(value);
    POLICY
        .get()
        .ok_or_else(|| "failed to retain the audited heads-up fee policy".to_owned())
}

fn audited_profile(code: u8) -> Result<HeadsUpProfile, String> {
    match code {
        PROFILE_HEADS_UP_FIXED_LIMIT_V1 => Ok(HEADS_UP_FIXED_LIMIT_V1_PROFILE),
        _ => Err("unsupported CHAIN protocol profile".to_owned()),
    }
}

fn validate_origin_script(
    script: &[u8; ORIGIN_SCRIPT_BYTES],
    identities: &CanonicalIdentities,
) -> Result<(), String> {
    if script[0] != 32
        || script[33] != 0x75
        || script[34] != 33
        || script[68] != 0xad
        || script[69] != 33
        || script[103] != 0xac
    {
        return Err("origin witness script has the wrong profile".to_owned());
    }
    let alice = PublicKey::from_slice(&script[35..68]).map_err(|error| error.to_string())?;
    let bob = PublicKey::from_slice(&script[70..103]).map_err(|error| error.to_string())?;
    if alice.x_only_public_key().0 != *identities.alice()
        || bob.x_only_public_key().0 != *identities.bob()
    {
        return Err("origin witness script identities differ from the DEAL identities".to_owned());
    }
    Ok(())
}

fn validate_origin_context(
    script: &[u8; ORIGIN_SCRIPT_BYTES],
    network_id: [u8; 32],
    room_id: [u8; 32],
    nonce: [u8; 32],
) -> Result<(), String> {
    let mut message = [0_u8; 96];
    message[..32].copy_from_slice(&network_id);
    message[32..64].copy_from_slice(&room_id);
    message[64..].copy_from_slice(&nonce);
    if script[1..33] != tagged_hash(b"BP52/origin-context/v1", &message) {
        return Err("origin witness script has the wrong session context".to_owned());
    }
    Ok(())
}

fn inventory_digest(
    shared_config_hash: [u8; 32],
    game_id: [u8; 32],
    graph_root: [u8; 32],
    role: Role,
    lamport_count: u32,
    runtime_signature_count: u32,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(105);
    bytes.extend_from_slice(&shared_config_hash);
    bytes.extend_from_slice(&game_id);
    bytes.extend_from_slice(&graph_root);
    bytes.push(role.code());
    bytes.extend_from_slice(&lamport_count.to_le_bytes());
    bytes.extend_from_slice(&runtime_signature_count.to_le_bytes());
    tagged_hash(INVENTORY_TAG, &bytes)
}

fn erasure_digest(
    shared_config_hash: [u8; 32],
    game_id: [u8; 32],
    node_id: NodeId,
    txid: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(&shared_config_hash);
    bytes.extend_from_slice(&game_id);
    bytes.extend_from_slice(&node_id);
    bytes.extend_from_slice(&txid);
    tagged_hash(ERASURE_TAG, &bytes)
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

fn card_from_preimages(a: &[u8], b: &[u8]) -> Result<u8, String> {
    let a = a
        .len()
        .checked_sub(16)
        .ok_or_else(|| "Alice preimage is shorter than 16 bytes".to_owned())?;
    let b = b
        .len()
        .checked_sub(16)
        .ok_or_else(|| "Bob preimage is shorter than 16 bytes".to_owned())?;
    let sum = a
        .checked_add(b)
        .ok_or_else(|| "card sum overflow".to_owned())?;
    u8::try_from(sum % 52).map_err(|_| "card identifier overflow".to_owned())
}

fn project_public_board(
    public: &PublicPreimageStore,
    mut verify: impl FnMut(CommunityStage, u8, &[u8], &[u8], u8) -> Result<u8, String>,
) -> Result<[u8; 5], String> {
    let mut board = [MISSING_CARD; 5];
    for (position, slot) in [4_u8, 5, 6, 7, 8].into_iter().enumerate() {
        let (Some(a), Some(b)) = (public.get(Role::Alice, slot), public.get(Role::Bob, slot))
        else {
            continue;
        };
        let stage = match slot {
            4..=6 => CommunityStage::Flop,
            7 => CommunityStage::Turn,
            8 => CommunityStage::River,
            _ => return Err("invalid community slot".to_owned()),
        };
        let claimed = card_from_preimages(a, b)?;
        board[position] = verify(stage, slot, a, b, claimed)?;
    }
    Ok(board)
}

fn complete_seven(hole: [u8; 2], board: [u8; 5]) -> Option<[u8; 7]> {
    if hole.iter().chain(&board).any(|card| *card == MISSING_CARD) {
        None
    } else {
        Some([
            hole[0], hole[1], board[0], board[1], board[2], board[3], board[4],
        ])
    }
}

fn best_hand(seven: [u8; 7]) -> Result<(u8, u32), String> {
    let mut best = None;
    for (index, subset) in SUBSETS_5_OF_7.iter().enumerate() {
        let cards = subset.map(|position| seven[usize::from(position)]);
        let score = evaluate_five_cards(cards).map_err(|error| error.to_string())?;
        if best.is_none_or(|(_, prior)| score > prior) {
            best = Some((
                u8::try_from(index).map_err(|_| "subset index overflow".to_owned())?,
                score,
            ));
        }
    }
    best.ok_or_else(|| "no five-card subset is available".to_owned())
}

fn write_optional_hand(writer: &mut Writer, hand: Option<(u8, u32)>) {
    if let Some((subset, score)) = hand {
        writer.write_u8(1);
        writer.write_u8(subset);
        writer.write_u32(score);
    } else {
        writer.write_u8(0);
        writer.write_u8(0);
        writer.write_u32(0);
    }
}

fn write_optional_fixed<const N: usize>(writer: &mut Writer, value: Option<&[u8; N]>) {
    if let Some(value) = value {
        writer.write_u8(1);
        writer.write_bytes(value);
    } else {
        writer.write_u8(0);
    }
}

fn write_optional_codec<T: Encode>(writer: &mut Writer, value: Option<&T>) -> Result<(), String> {
    if let Some(value) = value {
        writer.write_u8(1);
        let encoded = Zeroizing::new(value.encode_to_vec().map_err(codec)?);
        writer.write_byte_vector(&encoded).map_err(codec)?;
    } else {
        writer.write_u8(0);
    }
    Ok(())
}

fn write_monitor_state(writer: &mut Writer, state: Option<MonitorState>) {
    match state {
        None => writer.write_u8(0),
        Some(MonitorState::AwaitingFunding { root_node_id }) => {
            writer.write_u8(1);
            writer.write_bytes(&root_node_id);
        }
        Some(MonitorState::Active {
            node_id,
            confirmed_height,
            creating_txid,
        }) => {
            writer.write_u8(2);
            writer.write_bytes(&node_id);
            writer.write_u32(confirmed_height);
            write_optional_fixed(writer, creating_txid.as_ref());
        }
        Some(MonitorState::Terminal {
            node_id,
            confirmed_height,
            txid,
        }) => {
            writer.write_u8(3);
            writer.write_bytes(&node_id);
            writer.write_u32(confirmed_height);
            writer.write_bytes(&txid);
        }
        Some(MonitorState::Halted) => writer.write_u8(4),
    }
}

enum StoredConfirmation {
    Activation {
        confirmed_height: u32,
        tip_height: u32,
        transaction: Vec<u8>,
    },
    Child {
        confirmed_height: u32,
        tip_height: u32,
        transaction: Vec<u8>,
    },
}

struct CheckpointState {
    phase: Phase,
    descriptor_candidate: Vec<u8>,
    descriptor_signature: Option<[u8; 64]>,
    descriptor_event_signatures: [Option<[u8; 64]>; 2],
    signed_descriptor: Vec<u8>,
    lamport_bundles: [Vec<u8>; 2],
    root_commitments: [Option<Vec<u8>>; 2],
    root_openings: [Option<Vec<u8>>; 2],
    preauth_commitments: [Option<Vec<u8>>; 2],
    local_preauth_nonce: Option<[u8; 32]>,
    preauth_verified: [bool; 2],
    preauth_openings: [Option<Vec<u8>>; 2],
    preauth_receipts: [Option<Vec<u8>>; 2],
    inventory_verified: bool,
    inventory_attestation: Option<[u8; 64]>,
    inventory_ready: [Option<[u8; 64]>; 2],
    lamport_key_count: u16,
    lamport_key_states: Vec<u8>,
    confirmations: Vec<StoredConfirmation>,
    authorization: Option<AuthorizationCache>,
    erasure: Option<ErasureCache>,
    monitor_state: Option<MonitorState>,
}

#[allow(clippy::too_many_lines)]
fn decode_checkpoint_body(bytes: &[u8], expected_counter: u64) -> Result<CheckpointState, String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != SNAPSHOT_BODY_MAGIC {
        return Err("CHAIN checkpoint body has the wrong magic".to_owned());
    }
    if reader.read_u64().map_err(codec)? != expected_counter {
        return Err("CHAIN checkpoint body has the wrong counter".to_owned());
    }
    let phase = decode_phase(reader.read_u8().map_err(codec)?)?;
    let descriptor_candidate = reader.read_byte_vector(16 * 1024).map_err(codec)?;
    let descriptor_signature = read_optional_fixed::<64>(&mut reader)?;
    let signed_descriptor = reader.read_byte_vector(16 * 1024).map_err(codec)?;
    let lamport_bundles = [
        reader
            .read_byte_vector(MAX_LAMPORT_BUNDLE_BYTES)
            .map_err(codec)?,
        reader
            .read_byte_vector(MAX_LAMPORT_BUNDLE_BYTES)
            .map_err(codec)?,
    ];
    let root_commitments = [
        read_optional_artifact(&mut reader, 1_024)?,
        read_optional_artifact(&mut reader, 1_024)?,
    ];
    let root_openings = [
        read_optional_artifact(&mut reader, 1_024)?,
        read_optional_artifact(&mut reader, 1_024)?,
    ];
    let preauth_commitments = [
        read_optional_artifact(&mut reader, 1_024)?,
        read_optional_artifact(&mut reader, 1_024)?,
    ];
    let local_preauth_nonce = read_optional_fixed::<32>(&mut reader)?;
    let preauth_verified = [
        exact_boolean(reader.read_u8().map_err(codec)?)?,
        exact_boolean(reader.read_u8().map_err(codec)?)?,
    ];
    let preauth_openings = [
        read_optional_artifact(&mut reader, MAX_PREAUTHORIZATION_OPENING_BYTES)?,
        read_optional_artifact(&mut reader, MAX_PREAUTHORIZATION_OPENING_BYTES)?,
    ];
    let preauth_receipts = [
        read_optional_artifact(&mut reader, 512)?,
        read_optional_artifact(&mut reader, 512)?,
    ];
    let inventory_verified = exact_boolean(reader.read_u8().map_err(codec)?)?;
    let inventory_attestation = read_optional_fixed::<64>(&mut reader)?;
    let inventory_ready = [
        read_optional_fixed::<64>(&mut reader)?,
        read_optional_fixed::<64>(&mut reader)?,
    ];
    let lamport_count = reader.read_u16().map_err(codec)?;
    if lamport_count > MAX_LAMPORT_KEY_STATES {
        return Err("CHAIN checkpoint contains too many Lamport keys".to_owned());
    }
    let lamport_key_states = reader
        .read_byte_vector(MAX_LAMPORT_STATE_BYTES)
        .map_err(codec)?;
    DeterministicLamportInventory::validate_packed(
        usize::from(lamport_count),
        &lamport_key_states,
    )?;
    let confirmation_count = reader.read_u16().map_err(codec)?;
    if confirmation_count > MAX_CONFIRMATION_RECORDS {
        return Err("CHAIN checkpoint contains too many confirmations".to_owned());
    }
    let mut confirmations = Vec::with_capacity(usize::from(confirmation_count));
    for _ in 0..confirmation_count {
        let kind = reader.read_u8().map_err(codec)?;
        let confirmed_height = reader.read_u32().map_err(codec)?;
        let tip_height = reader.read_u32().map_err(codec)?;
        let transaction = reader.read_byte_vector(4 * 1024 * 1024).map_err(codec)?;
        let _: Transaction = deserialize(&transaction).map_err(|error| error.to_string())?;
        confirmations.push(match kind {
            0 => StoredConfirmation::Activation {
                confirmed_height,
                tip_height,
                transaction,
            },
            1 => StoredConfirmation::Child {
                confirmed_height,
                tip_height,
                transaction,
            },
            _ => return Err("CHAIN checkpoint contains an unknown confirmation kind".to_owned()),
        });
    }
    let authorization = if exact_boolean(reader.read_u8().map_err(codec)?)? {
        let node_id = reader.read_array::<32>().map_err(codec)?;
        let request = reader.read_byte_vector(1_024).map_err(codec)?;
        let witness = reader
            .read_byte_vector(MAX_CACHED_WITNESS_BYTES)
            .map_err(codec)?;
        let decoded =
            bp52_chain_runtime::Witness::decode(&witness).map_err(|error| error.to_string())?;
        if decoded.node_id() != node_id {
            return Err("cached CHAIN witness has the wrong node".to_owned());
        }
        Some(AuthorizationCache {
            node_id,
            request,
            witness,
        })
    } else {
        None
    };
    let erasure = if exact_boolean(reader.read_u8().map_err(codec)?)? {
        Some(ErasureCache {
            parent_node_id: reader.read_array::<32>().map_err(codec)?,
            child_txid: reader.read_array::<32>().map_err(codec)?,
            attestation: reader.read_array::<64>().map_err(codec)?,
        })
    } else {
        None
    };
    let monitor_state = match reader.read_u8().map_err(codec)? {
        0 => None,
        1 => Some(MonitorState::AwaitingFunding {
            root_node_id: reader.read_array::<32>().map_err(codec)?,
        }),
        2 => Some(MonitorState::Active {
            node_id: reader.read_array::<32>().map_err(codec)?,
            confirmed_height: reader.read_u32().map_err(codec)?,
            creating_txid: read_optional_fixed::<32>(&mut reader)?,
        }),
        3 => Some(MonitorState::Terminal {
            node_id: reader.read_array::<32>().map_err(codec)?,
            confirmed_height: reader.read_u32().map_err(codec)?,
            txid: reader.read_array::<32>().map_err(codec)?,
        }),
        4 => Some(MonitorState::Halted),
        _ => return Err("CHAIN checkpoint contains an unknown monitor state".to_owned()),
    };
    let descriptor_event_signatures = [
        read_optional_fixed::<64>(&mut reader)?,
        read_optional_fixed::<64>(&mut reader)?,
    ];
    reader.finish().map_err(codec)?;
    Ok(CheckpointState {
        phase,
        descriptor_candidate,
        descriptor_signature,
        descriptor_event_signatures,
        signed_descriptor,
        lamport_bundles,
        root_commitments,
        root_openings,
        preauth_commitments,
        local_preauth_nonce,
        preauth_verified,
        preauth_openings,
        preauth_receipts,
        inventory_verified,
        inventory_attestation,
        inventory_ready,
        lamport_key_count: lamport_count,
        lamport_key_states,
        confirmations,
        authorization,
        erasure,
        monitor_state,
    })
}

fn validate_checkpoint_body(bytes: &[u8], expected_counter: u64) -> Result<(), String> {
    let _ = decode_checkpoint_body(bytes, expected_counter)?;
    Ok(())
}

fn exact_boolean(value: u8) -> Result<bool, String> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("CHAIN checkpoint contains a non-canonical boolean".to_owned()),
    }
}

fn read_optional_fixed<const N: usize>(reader: &mut Reader<'_>) -> Result<Option<[u8; N]>, String> {
    if exact_boolean(reader.read_u8().map_err(codec)?)? {
        Ok(Some(reader.read_array().map_err(codec)?))
    } else {
        Ok(None)
    }
}

fn read_optional_artifact(
    reader: &mut Reader<'_>,
    maximum: usize,
) -> Result<Option<Vec<u8>>, String> {
    if exact_boolean(reader.read_u8().map_err(codec)?)? {
        Ok(Some(reader.read_byte_vector(maximum).map_err(codec)?))
    } else {
        Ok(None)
    }
}

fn decode_showdown_choice(bytes: &[u8]) -> Result<(u8, u32), String> {
    let mut reader = Reader::new(bytes);
    let subset = reader.read_u8().map_err(codec)?;
    let score = reader.read_u32().map_err(codec)?;
    reader.finish().map_err(codec)?;
    Ok((subset, score))
}

fn decode_outcome(value: u8) -> Result<ShowdownOutcome, String> {
    match value {
        0 => Ok(ShowdownOutcome::AliceWin),
        1 => Ok(ShowdownOutcome::BobWin),
        2 => Ok(ShowdownOutcome::Split),
        _ => Err("unknown showdown outcome".to_owned()),
    }
}

fn decode_role(value: u8) -> Result<Role, String> {
    match value {
        0 => Ok(Role::Alice),
        1 => Ok(Role::Bob),
        _ => Err("unknown player role".to_owned()),
    }
}

fn require_event_sender(sender: Role, artifact_role: Role) -> Result<(), String> {
    if sender == artifact_role {
        Ok(())
    } else {
        Err("authenticated relay sender differs from the setup artifact role".to_owned())
    }
}

fn decode_authenticated_session_event(bytes: &[u8]) -> Result<(Role, SessionEvent), String> {
    let Some((&sender, event_bytes)) = bytes.split_first() else {
        return Err("authenticated session event is empty".to_owned());
    };
    let sender = decode_role(sender)?;
    let event = SessionEvent::decode(event_bytes)
        .map_err(|error| format!("invalid canonical session event: {error}"))?;
    Ok((sender, event))
}

fn decode_setup_exchange(bytes: &[u8]) -> Result<(Role, SetupEventKind, Vec<u8>), String> {
    let mut reader = Reader::new(bytes);
    if reader.read_array::<8>().map_err(codec)? != *SETUP_EXCHANGE_MAGIC {
        return Err("setup exchange has the wrong magic".to_owned());
    }
    let sender = decode_role(reader.read_u8().map_err(codec)?)?;
    let kind = match reader.read_u8().map_err(codec)? {
        1 => SetupEventKind::LamportPublicBundle,
        2 => SetupEventKind::GraphRootCommitment,
        3 => SetupEventKind::GraphRootOpening,
        4 => SetupEventKind::PreauthorizationCommitment,
        5 => SetupEventKind::PreauthorizationOpening,
        _ => return Err("setup exchange has an unknown package kind".to_owned()),
    };
    let artifact = reader
        .read_byte_vector(MAX_LAMPORT_BUNDLE_BYTES)
        .map_err(codec)?;
    reader.finish().map_err(codec)?;
    Ok((sender, kind, artifact))
}

fn encode_setup_event_result(
    kind: SetupEventKind,
    status: SetupEventStatus,
    phase: Phase,
    local_lamport_bundle: &[u8],
) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.write_bytes(SESSION_EVENT_RESULT_MAGIC);
    writer.write_u8(kind as u8);
    writer.write_u8(status as u8);
    writer.write_u8(phase as u8);
    writer
        .write_byte_vector(local_lamport_bundle)
        .map_err(codec)?;
    Ok(writer.into_bytes())
}

fn encode_completed_preauthorization_plan(result: &[u8]) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.write_bytes(PREAUTHORIZATION_PLAN_MAGIC);
    writer.write_u8(0);
    writer.write_byte_vector(result).map_err(codec)?;
    Ok(writer.into_bytes())
}

fn encode_completed_lamport_generation_plan(artifact: &[u8]) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.write_bytes(LAMPORT_GENERATION_PLAN_MAGIC);
    writer.write_u8(0);
    writer.write_byte_vector(artifact).map_err(codec)?;
    Ok(writer.into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn encode_lamport_generation_plan(
    snapshot_key: &[u8; 32],
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    role: Role,
    expected: &[bp52_lamport::ExpectedLamportEntry],
    requested_workers: usize,
) -> Result<Vec<u8>, String> {
    if expected.is_empty() {
        return Err("Lamport generation plan is empty".to_owned());
    }
    let workers = requested_workers.min(expected.len());
    let mut writer = Writer::new();
    writer.write_bytes(LAMPORT_GENERATION_PLAN_MAGIC);
    writer.write_u8(1);
    writer.write_u32(
        u32::try_from(expected.len()).map_err(|_| "Lamport key count exceeds u32".to_owned())?,
    );
    writer
        .write_u8(u8::try_from(workers).map_err(|_| "Lamport worker count exceeds u8".to_owned())?);
    for worker in 0..workers {
        let start = worker * expected.len() / workers;
        let end = (worker + 1) * expected.len() / workers;
        let mut batch = Writer::new();
        batch.write_bytes(LAMPORT_GENERATION_BATCH_MAGIC);
        batch.write_u32(
            u32::try_from(start).map_err(|_| "Lamport batch offset exceeds u32".to_owned())?,
        );
        batch.write_bytes(snapshot_key);
        batch.write_bytes(&shared_config_hash);
        batch.write_bytes(&chain_game_id);
        batch.write_u8(role.code());
        batch.write_u32(
            u32::try_from(end - start).map_err(|_| "Lamport batch count exceeds u32".to_owned())?,
        );
        for entry in &expected[start..end] {
            batch.write_bytes(&entry.node_id);
            batch.write_u8(entry.purpose as u8);
        }
        writer.write_byte_vector(batch.as_bytes()).map_err(codec)?;
    }
    Ok(writer.into_bytes())
}

fn generate_lamport_batch(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != LAMPORT_GENERATION_BATCH_MAGIC {
        return Err("Lamport generation batch has the wrong magic".to_owned());
    }
    let start = reader.read_u32().map_err(codec)?;
    let snapshot_key = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
    let shared_config_hash = reader.read_array::<32>().map_err(codec)?;
    let chain_game_id = reader.read_array::<32>().map_err(codec)?;
    let role = decode_role(reader.read_u8().map_err(codec)?)?;
    let count = usize::try_from(reader.read_u32().map_err(codec)?)
        .map_err(|_| "Lamport generation batch count is invalid".to_owned())?;
    if count == 0 || count > usize::from(MAX_LAMPORT_KEY_STATES) {
        return Err("Lamport generation batch count is out of bounds".to_owned());
    }
    let mut public = Vec::with_capacity(count);
    for _ in 0..count {
        let node_id = reader.read_array::<32>().map_err(codec)?;
        let purpose = LamportPurpose::try_from(reader.read_u8().map_err(codec)?)
            .map_err(|error| error.to_string())?;
        let (_secret, public_key) = lamport_inventory::derive_key(
            &snapshot_key,
            shared_config_hash,
            chain_game_id,
            role,
            node_id,
            purpose,
        )?;
        public.push(public_key);
    }
    reader.finish().map_err(codec)?;
    let mut output = Writer::new();
    output.write_bytes(LAMPORT_GENERATION_SHARD_MAGIC);
    output.write_u32(start);
    output.write_u32(
        u32::try_from(public.len()).map_err(|_| "Lamport shard count exceeds u32".to_owned())?,
    );
    for key in public {
        for pair in key.public_hash_pairs() {
            output.write_bytes(&pair[0]);
            output.write_bytes(&pair[1]);
        }
    }
    Ok(output.into_bytes())
}

fn decode_lamport_generation_results(
    bytes: &[u8],
    chain_game_id: [u8; 32],
    expected: &[bp52_lamport::ExpectedLamportEntry],
) -> Result<Vec<LamportPublicKey>, String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != LAMPORT_GENERATION_RESULT_MAGIC {
        return Err("Lamport generation result has the wrong magic".to_owned());
    }
    let batch_count = usize::from(reader.read_u8().map_err(codec)?);
    if batch_count == 0 || batch_count > MAX_PREAUTHORIZATION_VERIFIERS {
        return Err("Lamport generation result has invalid batch count".to_owned());
    }
    let mut public = Vec::with_capacity(expected.len());
    for _ in 0..batch_count {
        let batch = reader
            .read_byte_vector(MAX_LAMPORT_BUNDLE_BYTES)
            .map_err(codec)?;
        let mut batch_reader = Reader::new(&batch);
        if &batch_reader.read_array::<8>().map_err(codec)? != LAMPORT_GENERATION_SHARD_MAGIC {
            return Err("Lamport generation shard has the wrong magic".to_owned());
        }
        let start = usize::try_from(batch_reader.read_u32().map_err(codec)?)
            .map_err(|_| "Lamport shard offset is invalid".to_owned())?;
        let count = usize::try_from(batch_reader.read_u32().map_err(codec)?)
            .map_err(|_| "Lamport shard count is invalid".to_owned())?;
        if start != public.len()
            || count == 0
            || start
                .checked_add(count)
                .is_none_or(|end| end > expected.len())
        {
            return Err("Lamport generation shards are not exact and contiguous".to_owned());
        }
        for entry in &expected[start..start + count] {
            let mut pairs = Vec::with_capacity(usize::from(entry.purpose.bit_width()));
            for _ in 0..entry.purpose.bit_width() {
                pairs.push([
                    batch_reader.read_array::<HASH_SIZE>().map_err(codec)?,
                    batch_reader.read_array::<HASH_SIZE>().map_err(codec)?,
                ]);
            }
            public.push(
                LamportPublicKey::from_parts(
                    KeyContext::new(chain_game_id, entry.node_id, entry.purpose),
                    pairs,
                )
                .map_err(|error| error.to_string())?,
            );
        }
        batch_reader.finish().map_err(codec)?;
    }
    reader.finish().map_err(codec)?;
    if public.len() != expected.len() {
        return Err("Lamport generation result is incomplete".to_owned());
    }
    Ok(public)
}

fn encode_completed_preauthorization_generation_plan(artifact: &[u8]) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.write_bytes(PREAUTHORIZATION_GENERATION_PLAN_MAGIC);
    writer.write_u8(0);
    writer.write_byte_vector(artifact).map_err(codec)?;
    Ok(writer.into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn encode_preauthorization_generation_plan(
    identity_secret: &[u8; 32],
    snapshot_key: &[u8; 32],
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    role: Role,
    requests: &[bp52_chain_compiler::SignatureRequest],
    requested_workers: usize,
) -> Result<Vec<u8>, String> {
    if requests.is_empty() {
        return Err("preauthorization generation plan is empty".to_owned());
    }
    let secret = IdentitySecret::new(*identity_secret)?;
    let identity_key = secret.keypair()?.x_only_public_key().0.serialize();
    let workers = requested_workers.min(requests.len());
    let mut writer = Writer::new();
    writer.write_bytes(PREAUTHORIZATION_GENERATION_PLAN_MAGIC);
    writer.write_u8(1);
    writer.write_u32(
        u32::try_from(requests.len())
            .map_err(|_| "preauthorization count exceeds u32".to_owned())?,
    );
    writer.write_u8(
        u8::try_from(workers).map_err(|_| "preauthorization worker count exceeds u8".to_owned())?,
    );
    for worker in 0..workers {
        let start = worker * requests.len() / workers;
        let end = (worker + 1) * requests.len() / workers;
        let mut batch = Writer::new();
        batch.write_bytes(PREAUTHORIZATION_SIGNING_BATCH_MAGIC);
        batch.write_u32(
            u32::try_from(start)
                .map_err(|_| "preauthorization batch offset exceeds u32".to_owned())?,
        );
        batch.write_bytes(identity_secret);
        batch.write_bytes(&identity_key);
        batch.write_bytes(snapshot_key);
        batch.write_bytes(&shared_config_hash);
        batch.write_bytes(&chain_game_id);
        batch.write_bytes(&graph_root);
        batch.write_u8(role.code());
        batch.write_u32(
            u32::try_from(end - start)
                .map_err(|_| "preauthorization batch count exceeds u32".to_owned())?,
        );
        for request in &requests[start..end] {
            batch.write_bytes(&request.parent_node_id);
            batch.write_bytes(&request.child_node_id);
            batch.write_bytes(&request.sighash);
        }
        writer.write_byte_vector(batch.as_bytes()).map_err(codec)?;
    }
    Ok(writer.into_bytes())
}

fn generate_preauthorization_batch(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != PREAUTHORIZATION_SIGNING_BATCH_MAGIC {
        return Err("preauthorization signing batch has the wrong magic".to_owned());
    }
    let start = reader.read_u32().map_err(codec)?;
    let identity_secret = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
    let expected_identity = reader.read_array::<32>().map_err(codec)?;
    let snapshot_key = Zeroizing::new(reader.read_array::<32>().map_err(codec)?);
    let shared_config_hash = reader.read_array::<32>().map_err(codec)?;
    let chain_game_id = reader.read_array::<32>().map_err(codec)?;
    let graph_root = reader.read_array::<32>().map_err(codec)?;
    let role = decode_role(reader.read_u8().map_err(codec)?)?;
    let count = usize::try_from(reader.read_u32().map_err(codec)?)
        .map_err(|_| "preauthorization signing batch count is invalid".to_owned())?;
    if count == 0 || count > bp52_chain_compiler::MAX_PREAUTHORIZATIONS_PER_ROLE {
        return Err("preauthorization signing batch count is out of bounds".to_owned());
    }
    let secret = IdentitySecret::new(*identity_secret)?;
    let secp = Secp256k1::new();
    let keypair = secret.keypair()?;
    if keypair.x_only_public_key().0.serialize() != expected_identity {
        return Err("preauthorization signing secret differs from its public identity".to_owned());
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        let request = bp52_chain_compiler::SignatureRequest {
            parent_node_id: reader.read_array::<32>().map_err(codec)?,
            child_node_id: reader.read_array::<32>().map_err(codec)?,
            signer: role,
            sighash: reader.read_array::<32>().map_err(codec)?,
        };
        signatures.push(
            deterministic_preauthorization_signature_with(
                &secp,
                &keypair,
                &snapshot_key,
                shared_config_hash,
                chain_game_id,
                graph_root,
                role,
                &request,
            )?
            .to_bytes(),
        );
    }
    reader.finish().map_err(codec)?;
    let mut output = Writer::new();
    output.write_bytes(PREAUTHORIZATION_SIGNING_RESULT_MAGIC);
    output.write_u32(start);
    output.write_u32(
        u32::try_from(signatures.len())
            .map_err(|_| "preauthorization signing result exceeds u32".to_owned())?,
    );
    for signature in signatures {
        output.write_bytes(&signature);
    }
    Ok(output.into_bytes())
}

fn decode_preauthorization_generation_results(
    bytes: &[u8],
    expected_count: usize,
) -> Result<Vec<[u8; 64]>, String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != PREAUTHORIZATION_GENERATION_RESULT_MAGIC {
        return Err("preauthorization generation result has the wrong magic".to_owned());
    }
    let batch_count = usize::from(reader.read_u8().map_err(codec)?);
    if batch_count == 0 || batch_count > MAX_PREAUTHORIZATION_VERIFIERS {
        return Err("preauthorization generation result has invalid batch count".to_owned());
    }
    let mut signatures = Vec::with_capacity(expected_count);
    for _ in 0..batch_count {
        let batch = reader
            .read_byte_vector(MAX_PREAUTHORIZATION_OPENING_BYTES)
            .map_err(codec)?;
        let mut batch_reader = Reader::new(&batch);
        if &batch_reader.read_array::<8>().map_err(codec)? != PREAUTHORIZATION_SIGNING_RESULT_MAGIC
        {
            return Err("preauthorization signing result has the wrong magic".to_owned());
        }
        let start = usize::try_from(batch_reader.read_u32().map_err(codec)?)
            .map_err(|_| "preauthorization signing result offset is invalid".to_owned())?;
        let count = usize::try_from(batch_reader.read_u32().map_err(codec)?)
            .map_err(|_| "preauthorization signing result count is invalid".to_owned())?;
        if start != signatures.len() || count == 0 || start.saturating_add(count) > expected_count {
            return Err(
                "preauthorization signing results are not exact contiguous shards".to_owned(),
            );
        }
        for _ in 0..count {
            let signature = batch_reader.read_array::<64>().map_err(codec)?;
            DefaultSighashSignature::from_bytes(signature).map_err(|error| error.to_string())?;
            signatures.push(signature);
        }
        batch_reader.finish().map_err(codec)?;
    }
    reader.finish().map_err(codec)?;
    if signatures.len() != expected_count {
        return Err("preauthorization signing results do not cover every request".to_owned());
    }
    Ok(signatures)
}

fn encode_preauthorization_verification_plan(
    identity_key: [u8; 32],
    requests: &[bp52_chain_compiler::SignatureRequest],
    signatures: &[[u8; 64]],
    requested_workers: usize,
) -> Result<Vec<u8>, String> {
    if requests.len() != signatures.len() || requests.is_empty() {
        return Err("preauthorization verification plan has inconsistent input".to_owned());
    }
    let workers = requested_workers.min(requests.len());
    let mut writer = Writer::new();
    writer.write_bytes(PREAUTHORIZATION_PLAN_MAGIC);
    writer.write_u8(1);
    writer.write_u32(
        u32::try_from(requests.len())
            .map_err(|_| "preauthorization count exceeds u32".to_owned())?,
    );
    writer.write_u8(
        u8::try_from(workers).map_err(|_| "preauthorization worker count exceeds u8".to_owned())?,
    );
    for worker in 0..workers {
        let start = worker * requests.len() / workers;
        let end = (worker + 1) * requests.len() / workers;
        let mut batch = Writer::new();
        batch.write_bytes(PREAUTHORIZATION_BATCH_MAGIC);
        batch.write_bytes(&identity_key);
        batch.write_u32(
            u32::try_from(end - start)
                .map_err(|_| "preauthorization batch count exceeds u32".to_owned())?,
        );
        for (request, signature) in requests[start..end].iter().zip(&signatures[start..end]) {
            batch.write_bytes(&request.sighash);
            batch.write_bytes(signature);
        }
        writer.write_byte_vector(batch.as_bytes()).map_err(codec)?;
    }
    Ok(writer.into_bytes())
}

fn verify_preauthorization_batch(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(bytes);
    if &reader.read_array::<8>().map_err(codec)? != PREAUTHORIZATION_BATCH_MAGIC {
        return Err("preauthorization batch has the wrong magic".to_owned());
    }
    let identity_key = reader.read_array::<32>().map_err(codec)?;
    let count = usize::try_from(reader.read_u32().map_err(codec)?)
        .map_err(|_| "preauthorization batch count is invalid".to_owned())?;
    if count == 0 || count > bp52_chain_compiler::MAX_PREAUTHORIZATIONS_PER_ROLE {
        return Err("preauthorization batch count is out of bounds".to_owned());
    }
    let secp = Secp256k1::verification_only();
    for _ in 0..count {
        let sighash = reader.read_array::<32>().map_err(codec)?;
        let signature =
            DefaultSighashSignature::from_bytes(reader.read_array::<64>().map_err(codec)?)
                .map_err(|error| error.to_string())?;
        bp52_chain_bitcoin::verify_sighash_default(&secp, identity_key, sighash, signature)
            .map_err(|error| error.to_string())?;
    }
    reader.finish().map_err(codec)?;
    let mut output = Writer::new();
    output.write_u32(
        u32::try_from(count).map_err(|_| "preauthorization batch count exceeds u32".to_owned())?,
    );
    Ok(output.into_bytes())
}

fn read_bitcoin_network(reader: &mut Reader<'_>) -> Result<Network, String> {
    match reader.read_u8().map_err(codec)? {
        0 => Ok(Network::Bitcoin),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Signet),
        3 => Ok(Network::Regtest),
        4 => Ok(Network::Testnet4),
        _ => Err("CHAIN initialization has an unknown Bitcoin network code".to_owned()),
    }
}

const fn bitcoin_network_code(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
        Network::Testnet4 => 4,
    }
}

fn decode_phase(value: u8) -> Result<Phase, String> {
    match value {
        0 => Ok(Phase::Empty),
        1 => Ok(Phase::AcceptedDeal),
        2 => Ok(Phase::DescriptorCandidate),
        3 => Ok(Phase::LamportReady),
        4 => Ok(Phase::GraphReady),
        5 => Ok(Phase::RootAgreed),
        6 => Ok(Phase::PreauthorizationsReady),
        7 => Ok(Phase::InventoryVerified),
        8 => Ok(Phase::Active),
        9 => Ok(Phase::Settled),
        10 => Ok(Phase::Halted),
        _ => Err("CHAIN checkpoint body has an unknown phase".to_owned()),
    }
}

fn exact_u8(bytes: &[u8]) -> Result<u8, String> {
    if let [value] = bytes {
        Ok(*value)
    } else {
        Err("operation requires exactly one byte".to_owned())
    }
}

fn authorization_request(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(payload.len() + 1);
    request.push(kind);
    request.extend_from_slice(payload);
    request
}

const fn role_index(role: Role) -> usize {
    match role {
        Role::Alice => 0,
        Role::Bob => 1,
    }
}

const fn to_lamport_role(role: Role) -> LamportRole {
    match role {
        Role::Alice => LamportRole::Alice,
        Role::Bob => LamportRole::Bob,
    }
}

const fn from_lamport_role(role: LamportRole) -> Role {
    match role {
        LamportRole::Alice => Role::Alice,
        LamportRole::Bob => Role::Bob,
    }
}

const fn to_deal_role(role: Role) -> bp52_protocol::Role {
    match role {
        Role::Alice => bp52_protocol::Role::Alice,
        Role::Bob => bp52_protocol::Role::Bob,
    }
}

fn codec(error: bp52_codec::CodecError) -> String {
    error.to_string()
}

fn with_engine(operation: impl FnOnce(&mut ChainEngine, &[u8]) -> Result<Vec<u8>, String>) -> i32 {
    let Ok(mut state) = MODULE.lock() else {
        return -90;
    };
    let input = core::mem::take(&mut state.input);
    let result = match state.engine.as_mut() {
        Some(engine) => operation(engine, &input),
        None => Err("CHAIN Worker is not initialized".to_owned()),
    };
    let mut input = input;
    input.zeroize();
    match result {
        Ok(output) if output.len() <= MAX_OUTPUT_BYTES => state.succeed(output),
        Ok(_) => state.fail(-4, "CHAIN output exceeds its fixed bound"),
        Err(error) => state.fail(-3, error),
    }
}

fn with_module_input(operation: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>) -> i32 {
    let Ok(mut state) = MODULE.lock() else {
        return -90;
    };
    let mut input = core::mem::take(&mut state.input);
    let result = operation(&input);
    input.zeroize();
    match result {
        Ok(output) if output.len() <= MAX_OUTPUT_BYTES => state.succeed(output),
        Ok(_) => state.fail(-4, "CHAIN output exceeds its fixed bound"),
        Err(error) => state.fail(-3, error),
    }
}

#[cfg(target_arch = "wasm32")]
mod abi {
    use super::*;

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_abi_version() -> u32 {
        ABI_VERSION
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_begin_input(length: u32) -> i32 {
        let Ok(length) = usize::try_from(length) else {
            return -1;
        };
        if length > MAX_INPUT_BYTES {
            return -2;
        }
        let Ok(mut state) = MODULE.lock() else {
            return -90;
        };
        state.input.zeroize();
        state.input = vec![0; length];
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_input_ptr() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|mut state| u32::try_from(state.input.as_mut_ptr() as usize).ok())
            .unwrap_or(0)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_init() -> i32 {
        let Ok(mut state) = MODULE.lock() else {
            return -90;
        };
        if state.permanently_cleared {
            return state.fail(-5, "cleared CHAIN Worker cannot be reused");
        }
        if state.engine.is_some() {
            return state.fail(-6, "CHAIN Worker is already initialized");
        }
        let mut input = core::mem::take(&mut state.input);
        let result = ChainEngine::initialize(&input);
        input.zeroize();
        match result {
            Ok(engine) => {
                state.engine = Some(engine);
                state.succeed(Vec::new())
            }
            Err(error) => state.fail(-3, error),
        }
    }

    macro_rules! op {
        ($name:ident, $method:ident) => {
            #[unsafe(no_mangle)]
            pub extern "C" fn $name() -> i32 {
                with_engine(|engine, input| engine.$method(input))
            }
        };
        ($name:ident, $method:ident, no_input) => {
            #[unsafe(no_mangle)]
            pub extern "C" fn $name() -> i32 {
                with_engine(|engine, _| engine.$method())
            }
        };
    }

    op!(bp52_chain_accept_session_event, accept_session_event);
    op!(bp52_chain_accept_setup_exchange, accept_setup_exchange);
    op!(bp52_chain_sign_descriptor, sign_descriptor);
    op!(
        bp52_chain_install_signed_descriptor,
        install_signed_descriptor
    );
    op!(bp52_chain_accept_lamport_bundle, accept_lamport_bundle);
    op!(
        bp52_chain_prepare_local_lamport_generation,
        prepare_local_lamport_generation
    );
    op!(
        bp52_chain_complete_local_lamport_generation,
        complete_local_lamport_generation
    );
    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_generate_lamport_batch() -> i32 {
        with_module_input(generate_lamport_batch)
    }
    op!(
        bp52_chain_make_root_commitment,
        make_root_commitment,
        no_input
    );
    op!(bp52_chain_accept_root_commitment, accept_root_commitment);
    op!(bp52_chain_open_root, open_root, no_input);
    op!(bp52_chain_accept_root_opening, accept_root_opening);
    op!(
        bp52_chain_make_preauthorization_commitment,
        make_preauthorization_commitment,
        no_input
    );
    op!(
        bp52_chain_prepare_local_preauthorization_generation,
        prepare_local_preauthorization_generation
    );
    op!(
        bp52_chain_complete_local_preauthorization_generation,
        complete_local_preauthorization_generation
    );
    op!(
        bp52_chain_accept_preauthorization_commitment,
        accept_preauth_commitment
    );
    op!(
        bp52_chain_open_preauthorizations,
        open_preauthorizations,
        no_input
    );
    op!(
        bp52_chain_accept_preauthorization_opening,
        accept_preauthorization_opening
    );
    op!(
        bp52_chain_prepare_peer_preauthorization_verification,
        prepare_peer_preauthorization_verification
    );
    op!(
        bp52_chain_complete_peer_preauthorization_verification,
        complete_peer_preauthorization_verification,
        no_input
    );

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_verify_preauthorization_batch() -> i32 {
        with_module_input(verify_preauthorization_batch)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_generate_preauthorization_batch() -> i32 {
        with_module_input(generate_preauthorization_batch)
    }
    op!(bp52_chain_attest_inventory, attest_inventory, no_input);
    op!(
        bp52_chain_graph_prepared_receipt,
        graph_prepared_receipt,
        no_input
    );
    op!(
        bp52_chain_make_inventory_ready,
        make_inventory_ready,
        no_input
    );
    op!(bp52_chain_accept_inventory_ready, accept_inventory_ready);
    op!(bp52_chain_sign_activation, sign_activation);
    op!(bp52_chain_assemble_activation, assemble_activation);
    op!(
        bp52_chain_activation_template,
        activation_template,
        no_input
    );
    op!(
        bp52_chain_verify_activation_artifact,
        verify_activation_artifact
    );
    op!(bp52_chain_confirm_activation, confirm_activation);
    op!(bp52_chain_observe_tip, observe_tip);
    op!(bp52_chain_build_action, build_action);
    op!(bp52_chain_build_advance, build_advance);
    op!(bp52_chain_build_reveal, build_reveal, no_input);
    op!(bp52_chain_build_alice_showdown, build_alice_showdown);
    op!(bp52_chain_build_bob_payout, build_bob_payout);
    op!(bp52_chain_build_timeout, build_timeout, no_input);
    op!(
        bp52_chain_runtime_authorization_receipt,
        runtime_authorization_receipt,
        no_input
    );
    op!(bp52_chain_confirm_child, confirm_child);
    op!(
        bp52_chain_confirmed_state_receipt,
        confirmed_state_receipt,
        no_input
    );
    op!(bp52_chain_public_context, public_context, no_input);
    op!(
        bp52_chain_public_runtime_status,
        public_runtime_status,
        no_input
    );
    op!(bp52_chain_seal_checkpoint, seal_checkpoint, no_input);
    op!(bp52_chain_verify_checkpoint, verify_checkpoint);
    op!(bp52_chain_restore_checkpoint, restore_checkpoint);

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_project_cards() -> i32 {
        with_engine(|engine, _| engine.card_projection())
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_phase() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|state| state.engine.as_ref().map(|engine| engine.phase as u32))
            .unwrap_or(Phase::Empty as u32)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_local_role() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .engine
                    .as_ref()
                    .map(|engine| engine.local_role.code().into())
            })
            .unwrap_or(u32::MAX)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_output_ptr() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|state| u32::try_from(state.output.as_ptr() as usize).ok())
            .unwrap_or(0)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_output_len() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|state| u32::try_from(state.output.len()).ok())
            .unwrap_or(0)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_last_error_ptr() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|state| u32::try_from(state.last_error.as_ptr() as usize).ok())
            .unwrap_or(0)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_last_error_len() -> u32 {
        MODULE
            .lock()
            .ok()
            .and_then(|state| u32::try_from(state.last_error.len()).ok())
            .unwrap_or(0)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_clear_output() {
        if let Ok(mut state) = MODULE.lock() {
            state.output.zeroize();
            state.output.clear();
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn bp52_chain_clear() {
        if let Ok(mut state) = MODULE.lock() {
            state.input.zeroize();
            state.input.clear();
            state.output.zeroize();
            state.output.clear();
            state.last_error.zeroize();
            state.last_error.clear();
            state.engine = None;
            state.permanently_cleared = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audited_profile_selector_is_exact() -> Result<(), String> {
        let current = audited_profile(PROFILE_HEADS_UP_FIXED_LIMIT_V1)?;
        assert_eq!(
            current.chain_protocol_version,
            bp52_chain_types::CHAIN_PROTOCOL_VERSION
        );
        assert_eq!(current.unit_sat, 100);
        assert_eq!(current.max_bets_per_street, 4);
        assert_eq!(current.stack_per_player_sat, 20_000);
        assert_eq!(current.fee_reserve_sat, 13_000);
        assert!(audited_profile(u8::MAX).is_err());
        Ok(())
    }

    #[test]
    fn card_selection_includes_wheel_and_high_ace_scores() -> Result<(), String> {
        // rank = card / 4; ace is rank 12.
        let wheel = [48, 0, 4, 8, 12, 20, 34];
        let broadway = [48, 44, 40, 36, 32, 20, 34];
        assert!(best_hand(broadway)?.1 > best_hand(wheel)?.1);
        Ok(())
    }

    #[test]
    fn public_board_projection_releases_only_completed_reveal_stages() -> Result<(), String> {
        fn preimage(role: Role, slot: usize, value: u8) -> Vec<u8> {
            let marker = match role {
                Role::Alice => 0x20,
                Role::Bob => 0x80,
            } + u8::try_from(slot).unwrap_or_default();
            vec![marker; 16 + usize::from(value)]
        }

        fn insert_pattern(
            store: &mut PublicPreimageStore,
            pattern: RevealPattern,
            alice: &[Vec<u8>; 9],
            bob: &[Vec<u8>; 9],
        ) -> Result<(), String> {
            let source = match pattern.revealer() {
                Role::Alice => alice,
                Role::Bob => bob,
            };
            let preimages = pattern
                .slots()
                .iter()
                .map(|slot| source[usize::from(*slot)].clone())
                .collect::<Vec<_>>();
            store
                .insert_reveal(pattern, &preimages)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }

        fn board(store: &PublicPreimageStore) -> Result<[u8; 5], String> {
            project_public_board(store, |stage, slot, _, _, claimed| {
                if !stage.contains(slot) {
                    return Err("projection assigned a card to the wrong street".to_owned());
                }
                Ok(claimed)
            })
        }

        // Alice contributes zero and Bob contributes the final card id.  The
        // five public cards match the live E2E deal used for this regression.
        let cards = [0, 4, 0, 9, 23, 35, 30, 50, 11];
        let alice = core::array::from_fn(|slot| preimage(Role::Alice, slot, 0));
        let bob = core::array::from_fn(|slot| preimage(Role::Bob, slot, cards[slot]));
        let deal = AcceptedDeal {
            protocol_version: bp52_protocol::PROTOCOL_VERSION,
            game_id: [0x31; 32],
            attempt: 0,
            hashes_a: core::array::from_fn(|slot| sha256::Hash::hash(&alice[slot]).to_byte_array()),
            hashes_b: core::array::from_fn(|slot| sha256::Hash::hash(&bob[slot]).to_byte_array()),
            verification_transcript_root: [0x32; 32],
            signature_a: [0x33; 64],
            signature_b: [0x34; 64],
        };
        let mut public = PublicPreimageStore::new([0x35; 32], deal);

        insert_pattern(&mut public, RevealPattern::DealAlice, &alice, &bob)?;
        insert_pattern(&mut public, RevealPattern::DealBob, &alice, &bob)?;
        assert_eq!(board(&public)?, [MISSING_CARD; 5]);

        insert_pattern(&mut public, RevealPattern::Flop(Role::Alice), &alice, &bob)?;
        assert_eq!(board(&public)?, [MISSING_CARD; 5]);
        insert_pattern(&mut public, RevealPattern::Flop(Role::Bob), &alice, &bob)?;
        assert_eq!(board(&public)?, [23, 35, 30, MISSING_CARD, MISSING_CARD]);

        insert_pattern(&mut public, RevealPattern::Turn(Role::Bob), &alice, &bob)?;
        assert_eq!(board(&public)?, [23, 35, 30, MISSING_CARD, MISSING_CARD]);
        insert_pattern(&mut public, RevealPattern::Turn(Role::Alice), &alice, &bob)?;
        assert_eq!(board(&public)?, [23, 35, 30, 50, MISSING_CARD]);

        insert_pattern(&mut public, RevealPattern::River(Role::Alice), &alice, &bob)?;
        assert_eq!(board(&public)?, [23, 35, 30, 50, MISSING_CARD]);
        insert_pattern(&mut public, RevealPattern::River(Role::Bob), &alice, &bob)?;
        assert_eq!(board(&public)?, [23, 35, 30, 50, 11]);
        Ok(())
    }

    #[test]
    fn inventory_and_erasure_domains_do_not_alias() {
        let inventory = inventory_digest([1; 32], [2; 32], [3; 32], Role::Alice, 1, 5);
        let erasure = erasure_digest([1; 32], [2; 32], [3; 32], [4; 32]);
        assert_ne!(inventory, erasure);
    }

    #[test]
    fn preauthorization_batches_partition_and_verify_exactly() -> Result<(), String> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7; 32]).map_err(|error| error.to_string())?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let identity_key = keypair.x_only_public_key().0.serialize();
        let requests = (0..7_u8)
            .map(|index| bp52_chain_compiler::SignatureRequest {
                parent_node_id: [index; 32],
                child_node_id: [index + 1; 32],
                signer: Role::Alice,
                sighash: [index + 2; 32],
            })
            .collect::<Vec<_>>();
        let signatures = requests
            .iter()
            .map(|request| sign_sighash_default(&secp, &keypair, request.sighash).to_bytes())
            .collect::<Vec<_>>();
        let plan =
            encode_preauthorization_verification_plan(identity_key, &requests, &signatures, 3)?;
        let mut reader = Reader::new(&plan);
        assert_eq!(
            reader.read_array::<8>().map_err(codec)?,
            *PREAUTHORIZATION_PLAN_MAGIC
        );
        assert_eq!(reader.read_u8().map_err(codec)?, 1);
        assert_eq!(reader.read_u32().map_err(codec)?, 7);
        assert_eq!(reader.read_u8().map_err(codec)?, 3);
        let mut verified = 0_u32;
        let mut first_batch = None;
        for index in 0..3 {
            let batch = reader
                .read_byte_vector(MAX_PREAUTHORIZATION_OPENING_BYTES)
                .map_err(codec)?;
            if index == 0 {
                first_batch = Some(batch.clone());
            }
            let count = verify_preauthorization_batch(&batch)?;
            verified += u32::from_le_bytes(
                count
                    .as_slice()
                    .try_into()
                    .map_err(|_| "verification count has the wrong length".to_owned())?,
            );
        }
        reader.finish().map_err(codec)?;
        assert_eq!(verified, 7);

        let mut tampered = first_batch.ok_or_else(|| "first batch is absent".to_owned())?;
        let last = tampered
            .last_mut()
            .ok_or_else(|| "first batch is empty".to_owned())?;
        *last ^= 1;
        assert!(verify_preauthorization_batch(&tampered).is_err());

        let generation_plan = encode_preauthorization_generation_plan(
            &[7; 32],
            &[8; 32],
            [9; 32],
            [10; 32],
            [11; 32],
            Role::Alice,
            &requests,
            3,
        )?;
        let mut generation_reader = Reader::new(&generation_plan);
        assert_eq!(
            generation_reader.read_array::<8>().map_err(codec)?,
            *PREAUTHORIZATION_GENERATION_PLAN_MAGIC
        );
        assert_eq!(generation_reader.read_u8().map_err(codec)?, 1);
        assert_eq!(generation_reader.read_u32().map_err(codec)?, 7);
        assert_eq!(generation_reader.read_u8().map_err(codec)?, 3);
        let mut results = Vec::new();
        for _ in 0..3 {
            let batch = generation_reader
                .read_byte_vector(MAX_PREAUTHORIZATION_OPENING_BYTES)
                .map_err(codec)?;
            results.push(generate_preauthorization_batch(&batch)?);
        }
        generation_reader.finish().map_err(codec)?;
        let mut combined = Writer::new();
        combined.write_bytes(PREAUTHORIZATION_GENERATION_RESULT_MAGIC);
        combined.write_u8(3);
        for result in &results {
            combined.write_byte_vector(result).map_err(codec)?;
        }
        let generated = decode_preauthorization_generation_results(combined.as_bytes(), 7)?;
        let expected = requests
            .iter()
            .map(|request| {
                deterministic_preauthorization_signature(
                    &IdentitySecret::new([7; 32])?,
                    &[8; 32],
                    [9; 32],
                    [10; 32],
                    [11; 32],
                    Role::Alice,
                    request,
                )
                .map(|signature| signature.to_bytes())
            })
            .collect::<Result<Vec<_>, String>>()?;
        assert_eq!(generated, expected);

        results.swap(0, 1);
        let mut reordered = Writer::new();
        reordered.write_bytes(PREAUTHORIZATION_GENERATION_RESULT_MAGIC);
        reordered.write_u8(3);
        for result in &results {
            reordered.write_byte_vector(result).map_err(codec)?;
        }
        assert!(decode_preauthorization_generation_results(reordered.as_bytes(), 7).is_err());
        Ok(())
    }

    #[test]
    fn lamport_batches_partition_and_reassemble_exactly() -> Result<(), String> {
        let expected = (0..7_u8)
            .map(|index| {
                bp52_lamport::ExpectedLamportEntry::new(
                    [index; 32],
                    if index % 2 == 0 {
                        LamportPurpose::AliceScore24Bit
                    } else {
                        LamportPurpose::BobScore24Bit
                    },
                )
            })
            .collect::<Vec<_>>();
        let plan =
            encode_lamport_generation_plan(&[4; 32], [5; 32], [6; 32], Role::Alice, &expected, 3)?;
        let mut reader = Reader::new(&plan);
        assert_eq!(
            reader.read_array::<8>().map_err(codec)?,
            *LAMPORT_GENERATION_PLAN_MAGIC
        );
        assert_eq!(reader.read_u8().map_err(codec)?, 1);
        assert_eq!(reader.read_u32().map_err(codec)?, 7);
        assert_eq!(reader.read_u8().map_err(codec)?, 3);
        let mut shards = Vec::new();
        for _ in 0..3 {
            let batch = reader
                .read_byte_vector(MAX_LAMPORT_BUNDLE_BYTES)
                .map_err(codec)?;
            shards.push(generate_lamport_batch(&batch)?);
        }
        reader.finish().map_err(codec)?;

        let mut combined = Writer::new();
        combined.write_bytes(LAMPORT_GENERATION_RESULT_MAGIC);
        combined.write_u8(3);
        for shard in &shards {
            combined.write_byte_vector(shard).map_err(codec)?;
        }
        let generated = decode_lamport_generation_results(combined.as_bytes(), [6; 32], &expected)?;
        let (_, sequential) = DeterministicLamportInventory::generate_public_keys(
            &[4; 32],
            [5; 32],
            [6; 32],
            Role::Alice,
            &expected,
        )?;
        assert_eq!(generated, sequential);

        shards.swap(0, 1);
        let mut reordered = Writer::new();
        reordered.write_bytes(LAMPORT_GENERATION_RESULT_MAGIC);
        reordered.write_u8(3);
        for shard in &shards {
            reordered.write_byte_vector(shard).map_err(codec)?;
        }
        assert!(
            decode_lamport_generation_results(reordered.as_bytes(), [6; 32], &expected).is_err()
        );
        Ok(())
    }

    #[test]
    fn local_preauthorization_is_byte_stable_and_domain_separated() -> Result<(), String> {
        let first_secret = IdentitySecret::new([7; 32])?;
        let restored_secret = IdentitySecret::new([7; 32])?;
        let request = bp52_chain_compiler::SignatureRequest {
            parent_node_id: [1; 32],
            child_node_id: [2; 32],
            signer: Role::Alice,
            sighash: [3; 32],
        };
        let sign = |secret: &IdentitySecret,
                    shared_config_hash,
                    chain_game_id,
                    graph_root,
                    role,
                    request| {
            deterministic_preauthorization_signature(
                secret,
                &[4; 32],
                shared_config_hash,
                chain_game_id,
                graph_root,
                role,
                request,
            )
        };
        let original = sign(
            &first_secret,
            [5; 32],
            [6; 32],
            [8; 32],
            Role::Alice,
            &request,
        )?;
        let restored = sign(
            &restored_secret,
            [5; 32],
            [6; 32],
            [8; 32],
            Role::Alice,
            &request,
        )?;
        assert_eq!(original, restored);

        let different_root = sign(
            &restored_secret,
            [5; 32],
            [6; 32],
            [9; 32],
            Role::Alice,
            &request,
        )?;
        let different_game = sign(
            &restored_secret,
            [5; 32],
            [7; 32],
            [8; 32],
            Role::Alice,
            &request,
        )?;
        let different_config = sign(
            &restored_secret,
            [10; 32],
            [6; 32],
            [8; 32],
            Role::Alice,
            &request,
        )?;
        assert_ne!(original, different_root);
        assert_ne!(original, different_game);
        assert_ne!(original, different_config);

        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&original.to_bytes())
            .map_err(|error| error.to_string())?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(request.sighash),
                &first_secret.keypair()?.x_only_public_key().0,
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn tip_wire_is_exactly_one_little_endian_u32() -> Result<(), String> {
        assert_eq!(
            decode_tip_height(&0x7856_3412_u32.to_le_bytes())?,
            0x7856_3412
        );
        assert!(decode_tip_height(&[]).is_err());
        assert!(decode_tip_height(&0_u64.to_le_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn setup_exchange_wire_is_private_bounded_and_exact() -> Result<(), String> {
        let descriptor = SessionEvent::DescriptorSignature {
            role: Role::Bob,
            descriptor: vec![7, 8, 9],
            signature: [10; 64],
        }
        .encode()
        .map_err(codec)?;
        let mut frame = vec![Role::Bob.code()];
        frame.extend_from_slice(&descriptor);
        let (sender, decoded) = decode_authenticated_session_event(&frame)?;
        assert_eq!(sender, Role::Bob);
        assert!(matches!(decoded, SessionEvent::DescriptorSignature { .. }));

        let mut setup = Writer::new();
        setup.write_bytes(SETUP_EXCHANGE_MAGIC);
        setup.write_u8(Role::Alice.code());
        setup.write_u8(SetupEventKind::GraphRootOpening as u8);
        setup.write_byte_vector(&[11, 12, 13]).map_err(codec)?;
        let setup = setup.into_bytes();
        let (sender, kind, artifact) = decode_setup_exchange(&setup)?;
        assert_eq!(sender, Role::Alice);
        assert_eq!(kind, SetupEventKind::GraphRootOpening);
        assert_eq!(artifact, [11, 12, 13]);

        // A non-setup receipt preserves the exact pre-dispatch phase and
        // carries no artifact, so routing it cannot advance CHAIN state.
        let receipt = encode_setup_event_result(
            SetupEventKind::NotApplicable,
            SetupEventStatus::NotApplicable,
            Phase::RootAgreed,
            &[],
        )?;
        let mut receipt_reader = Reader::new(&receipt);
        assert_eq!(
            receipt_reader.read_array::<8>().map_err(codec)?,
            *SESSION_EVENT_RESULT_MAGIC
        );
        assert_eq!(receipt_reader.read_u8().map_err(codec)?, u8::MAX);
        assert_eq!(receipt_reader.read_u8().map_err(codec)?, 2);
        assert_eq!(
            receipt_reader.read_u8().map_err(codec)?,
            Phase::RootAgreed as u8
        );
        assert!(
            receipt_reader
                .read_byte_vector(0)
                .map_err(codec)?
                .is_empty()
        );
        receipt_reader.finish().map_err(codec)?;

        assert!(decode_authenticated_session_event(&[]).is_err());
        let mut bad_role = frame.clone();
        bad_role[0] = 2;
        assert!(decode_authenticated_session_event(&bad_role).is_err());
        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_authenticated_session_event(&trailing).is_err());
        let mut trailing = setup;
        trailing.push(0);
        assert!(decode_setup_exchange(&trailing).is_err());
        assert!(require_event_sender(Role::Alice, Role::Bob).is_err());
        Ok(())
    }

    #[test]
    fn setup_event_result_has_a_strict_versioned_shape() -> Result<(), String> {
        let result = encode_setup_event_result(
            SetupEventKind::LamportPublicBundle,
            SetupEventStatus::Duplicate,
            Phase::GraphReady,
            &[1, 2, 3],
        )?;
        let mut reader = Reader::new(&result);
        assert_eq!(
            reader.read_array::<8>().map_err(codec)?,
            *SESSION_EVENT_RESULT_MAGIC
        );
        assert_eq!(reader.read_u8().map_err(codec)?, 1);
        assert_eq!(reader.read_u8().map_err(codec)?, 1);
        assert_eq!(reader.read_u8().map_err(codec)?, Phase::GraphReady as u8);
        assert_eq!(reader.read_byte_vector(3).map_err(codec)?, [1, 2, 3]);
        reader.finish().map_err(codec)?;
        Ok(())
    }

    #[test]
    fn accepted_deal_checkpoint_body_restores_exactly_and_rejects_rollback() -> Result<(), String> {
        fn make_body(counter: u64, confirmations: u16) -> Result<Vec<u8>, String> {
            let transaction = serialize(&Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: Vec::new(),
                output: Vec::new(),
            });
            let mut writer = Writer::new();
            writer.write_bytes(SNAPSHOT_BODY_MAGIC);
            writer.write_u64(counter);
            writer.write_u8(Phase::AcceptedDeal as u8);
            writer.write_byte_vector(&[]).map_err(codec)?;
            writer.write_u8(0);
            writer.write_byte_vector(&[]).map_err(codec)?;
            writer.write_byte_vector(&[]).map_err(codec)?;
            writer.write_byte_vector(&[]).map_err(codec)?;
            // Root commitments/openings and preauthorization commitments.
            for _ in 0..6 {
                writer.write_u8(0);
            }
            // Local preauthorization nonce, two verified flags, two peer/local
            // openings, and two compact verification receipts.
            writer.write_u8(0);
            writer.write_u8(0);
            writer.write_u8(0);
            for _ in 0..4 {
                writer.write_u8(0);
            }
            // Inventory flag, attestation, and two ready signatures.
            for _ in 0..4 {
                writer.write_u8(0);
            }
            writer.write_u16(0); // Lamport key count.
            writer.write_byte_vector(&[]).map_err(codec)?; // Packed two-bit states.
            writer.write_u16(confirmations);
            for index in 0..confirmations {
                writer.write_u8(u8::from(index != 0));
                writer.write_u32(u32::from(index) + 1);
                writer.write_u32(u32::from(index) + 1);
                writer.write_byte_vector(&transaction).map_err(codec)?;
            }
            // Cached authorization, erasure, and monitor.
            writer.write_u8(0);
            writer.write_u8(0);
            writer.write_u8(0);
            // Exact descriptor-event signatures; obsolete encodings are rejected.
            writer.write_u8(0);
            writer.write_u8(0);
            Ok(writer.into_bytes())
        }

        let counter = 9_u64;
        let body = make_body(counter, 0)?;

        let restored = decode_checkpoint_body(&body, counter)?;
        assert_eq!(restored.phase, Phase::AcceptedDeal);
        assert!(restored.descriptor_candidate.is_empty());
        assert_eq!(restored.descriptor_event_signatures, [None, None]);
        assert!(restored.confirmations.is_empty());
        assert!(restored.monitor_state.is_none());
        assert_eq!(restored.local_preauth_nonce, None);
        assert_eq!(restored.preauth_verified, [false; 2]);
        assert!(restored.preauth_openings.iter().all(Option::is_none));
        assert!(restored.preauth_receipts.iter().all(Option::is_none));
        assert!(decode_checkpoint_body(&body, counter - 1).is_err());
        let mut trailing = body;
        trailing.push(0);
        assert!(decode_checkpoint_body(&trailing, counter).is_err());
        assert_eq!(
            decode_checkpoint_body(&make_body(counter, MAX_CONFIRMATION_RECORDS)?, counter)?
                .confirmations
                .len(),
            usize::from(MAX_CONFIRMATION_RECORDS)
        );
        assert!(
            decode_checkpoint_body(&make_body(counter, MAX_CONFIRMATION_RECORDS + 1)?, counter)
                .is_err()
        );
        Ok(())
    }
}
