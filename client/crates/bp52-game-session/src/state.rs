//! Deterministic BP52 session reducer.

use std::num::NonZeroU16;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey, ecdsa, schnorr};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, Witness};
use bp52_chain_bitcoin::{FeePolicy, ensure_non_mainnet, validate_network_identity};
use bp52_chain_compiler::{
    ConfirmedStateReceipt, GraphPreparedReceipt, RuntimeAuthorizationReceipt,
    reference_compiler_id, verify_confirmed_state_receipt, verify_graph_prepared_receipt,
    verify_runtime_authorization_receipt,
};
use bp52_chain_types::{
    AcceptedDeal, AuthorizationPolicy, ChainGameDescriptor, EdgeKind, MIN_STARTING_STACK_UNITS,
    NodeId, NodeKind, RevealOrder, Role, SignedChainGameDescriptor, TimeoutSettlementPolicy,
    chain_game_id, descriptor_signature_digest, verify_signed_chain_descriptor,
};
use bp52_client_ports::{BlockRef, MAX_SESSION_SNAPSHOT_BYTES, OutPointRef};
use bp52_codec::{Decode, Encode, Reader, Writer};
use bp52_origin::OriginContext;
use bp52_protocol::archive::ArchiveProgress;
use bp52_protocol::attestation::{
    DealVerificationAttestation, DealVerificationResult, VerifiedDealVerification,
    verify_attested_accepted_deal, verify_deal_verification,
};
use bp52_protocol::auth::{
    CanonicalIdentities, derive_game_id, verify_accepted_deal_signature, verify_envelope,
};
use bp52_protocol::messages::{AcceptedDealBody, Envelope, PayloadType};
use bp52_protocol::retry::retry_digest;
use bp52_protocol::state::{expected_envelope, first_blinder};
use bp52_protocol::transcript::{advance, attempt_start};
use bp52_protocol::{PROTOCOL_VERSION, Role as DealRole};

use crate::codec::{JOURNAL_MAGIC, config_digest, shared_config_digest};
use crate::event::{ChainSpend, ConfirmedOrigin, EventRecord, SessionEvent, TipFact};
use crate::policy::{
    ConfirmationError, EventSource, SessionPhase, TipRelation, classify_tip, event_accepts_source,
    journal_link_is_contiguous, validate_confirmation,
};

const MAX_SCRIPT_BYTES: usize = 10_000;
/// Exact byte length of the prototype's context-bound two-party origin script.
pub const ORIGIN_WITNESS_SCRIPT_BYTES: usize = 104;
const OP_DROP: u8 = 0x75;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKSIG: u8 = 0xac;
const SIGHASH_ALL: u8 = 1;
const SNAPSHOT_HEADER_BYTES: usize = 8 + 32 + 4;
const EVENT_RECORD_OVERHEAD_BYTES: usize = 8 + 32 + 4 + 32;

const fn bitcoin_network_code(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
        Network::Testnet4 => 4,
    }
}

/// Descriptor terms agreed before cryptographic setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorTerms {
    /// Canonical chain descriptor wire version.
    pub chain_protocol_version: u16,
    /// Dealer/button role.
    pub button: Role,
    /// Small-blind unit.
    pub unit_sat: u64,
    /// Maximum total wagers on one street, including its opening bet.
    pub max_bets_per_street: u8,
    /// Alice's full poker stack.
    pub alice_starting_stack_sat: u64,
    /// Bob's full poker stack.
    pub bob_starting_stack_sat: u64,
    /// Dedicated maximum-path transaction-fee reserve.
    pub fee_reserve_sat: u64,
    /// Fee paid by the exact origin-to-gameplay-root activation.
    pub activation_fee_sat: u64,
    /// Betting-action CSV delay.
    pub action_csv: u16,
    /// Share-reveal CSV delay.
    pub reveal_csv: u16,
    /// Showdown CSV delay.
    pub showdown_csv: u16,
    /// Descriptor-bound community reveal order.
    pub reveal_order: RevealOrder,
    /// Recipient of an odd split satoshi.
    pub split_remainder_recipient: Role,
    /// Exact fee-policy identifier.
    pub fee_policy_id: [u8; 32],
    /// Exact compiler-profile identifier.
    pub compiler_id: [u8; 32],
}

/// Immutable session binding supplied by the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionConfig {
    /// Exact chain adapter profile identifier.
    pub profile_id: [u8; 32],
    /// Exact descriptor network identifier.
    pub network_id: [u8; 32],
    /// Bitcoin transaction/address parameter family selected by the deployment.
    pub bitcoin_network: Network,
    /// Shared origin outpoint in consensus byte order.
    pub origin_outpoint: OutPointRef,
    /// Exact value of the confirmed pre-activation origin output.
    pub origin_value_sat: u64,
    /// Relay room committed by the jointly agreed origin package.
    pub relay_room_id: [u8; 32],
    /// Exact 104-byte two-party origin witness script.
    pub origin_witness_script: [u8; ORIGIN_WITNESS_SCRIPT_BYTES],
    /// DEAL session nonce.
    pub deal_session_nonce: [u8; 32],
    /// Canonically ordered long-term identities.
    pub identities: CanonicalIdentities,
    /// Role controlled by this coordinator instance.
    pub local_role: Role,
    /// Confirmations required before DEAL begins.
    pub origin_confirmation_depth: NonZeroU16,
    /// Confirmations required before hole-card delivery begins.
    pub gameplay_confirmation_depth: NonZeroU16,
    /// Signed descriptor economics and timeout choices.
    pub terms: DescriptorTerms,
}

impl SessionConfig {
    /// Validate immutable network, identity, origin, and descriptor inputs.
    ///
    /// # Errors
    ///
    /// Rejects mainnet, contradictory network identity, zero identifiers, a
    /// null origin, or a fee-policy mismatch.
    pub fn validate(&self, fee_policy: &dyn FeePolicy) -> Result<(), SessionError> {
        validate_network_identity(self.network_id, self.bitcoin_network)
            .map_err(|error| artifact("network identity", error))?;
        ensure_non_mainnet(self.bitcoin_network)
            .map_err(|error| artifact("network policy", error))?;
        if self.profile_id != self.network_id {
            return Err(SessionError::InvalidConfig(
                "chain profile and descriptor network identifiers differ",
            ));
        }
        if self.origin_outpoint.txid == [0; 32] && self.origin_outpoint.vout == u32::MAX {
            return Err(SessionError::InvalidConfig("origin outpoint is null"));
        }
        if self.relay_room_id == [0; 32] {
            return Err(SessionError::InvalidConfig("relay room identifier is zero"));
        }
        if self.deal_session_nonce == [0; 32] {
            return Err(SessionError::InvalidConfig("deal session nonce is zero"));
        }
        if fee_policy.policy_id() != self.terms.fee_policy_id {
            return Err(SessionError::InvalidConfig(
                "fee-policy identifier mismatch",
            ));
        }
        if self.terms.unit_sat == 0 {
            return Err(SessionError::InvalidConfig("betting unit is zero"));
        }
        if self.terms.chain_protocol_version != bp52_chain_types::CHAIN_PROTOCOL_VERSION {
            return Err(SessionError::InvalidConfig(
                "chain protocol version is unsupported",
            ));
        }
        if self.terms.max_bets_per_street == 0
            || self.terms.max_bets_per_street > bp52_chain_types::MAX_BETS_PER_STREET
        {
            return Err(SessionError::InvalidConfig("betting cap is unsupported"));
        }
        let expected_compiler_id = reference_compiler_id();
        if self.terms.compiler_id != expected_compiler_id {
            return Err(SessionError::InvalidConfig(
                "compiler-profile identifier mismatch",
            ));
        }
        if self.terms.fee_reserve_sat == 0 {
            return Err(SessionError::InvalidConfig("fee reserve is zero"));
        }
        let minimum_stack = self
            .terms
            .unit_sat
            .checked_mul(MIN_STARTING_STACK_UNITS)
            .ok_or(SessionError::InvalidConfig("minimum stack overflows"))?;
        if self.terms.alice_starting_stack_sat < minimum_stack
            || self.terms.bob_starting_stack_sat < minimum_stack
        {
            return Err(SessionError::InvalidConfig("starting stack is too small"));
        }
        self.terms
            .alice_starting_stack_sat
            .checked_add(self.terms.bob_starting_stack_sat)
            .and_then(|value| value.checked_add(self.terms.fee_reserve_sat))
            .ok_or(SessionError::InvalidConfig("total locked value overflows"))?;
        if self.terms.action_csv == 0 || self.terms.reveal_csv == 0 || self.terms.showdown_csv == 0
        {
            return Err(SessionError::InvalidConfig("CSV timeout is zero"));
        }
        let gameplay_value = self
            .terms
            .alice_starting_stack_sat
            .checked_add(self.terms.bob_starting_stack_sat)
            .and_then(|value| value.checked_add(self.terms.fee_reserve_sat))
            .ok_or(SessionError::InvalidConfig("total locked value overflows"))?;
        if self.terms.activation_fee_sat == 0
            || gameplay_value
                .checked_add(self.terms.activation_fee_sat)
                .ok_or(SessionError::InvalidConfig("origin value overflows"))?
                != self.origin_value_sat
        {
            return Err(SessionError::InvalidConfig(
                "origin value does not equal gameplay value plus activation fee",
            ));
        }
        validate_configured_origin_script(self)?;
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_bytes(&self.profile_id);
        writer.write_bytes(&self.network_id);
        writer.write_u8(bitcoin_network_code(self.bitcoin_network));
        writer.write_bytes(&self.origin_outpoint.txid);
        writer.write_u32(self.origin_outpoint.vout);
        writer.write_u64(self.origin_value_sat);
        writer.write_bytes(&self.relay_room_id);
        writer.write_bytes(&self.origin_witness_script);
        writer.write_bytes(&self.deal_session_nonce);
        writer.write_bytes(&self.identities.alice().serialize());
        writer.write_bytes(&self.identities.bob().serialize());
        writer.write_u8(self.local_role.code());
        writer.write_u16(self.origin_confirmation_depth.get());
        writer.write_u16(self.gameplay_confirmation_depth.get());
        writer.write_u8(self.terms.button.code());
        writer.write_u16(self.terms.chain_protocol_version);
        writer.write_u8(self.terms.max_bets_per_street);
        writer.write_bytes(&self.terms.compiler_id);
        writer.write_u64(self.terms.unit_sat);
        writer.write_u64(self.terms.alice_starting_stack_sat);
        writer.write_u64(self.terms.bob_starting_stack_sat);
        writer.write_u64(self.terms.fee_reserve_sat);
        writer.write_u64(self.terms.activation_fee_sat);
        writer.write_u16(self.terms.action_csv);
        writer.write_u16(self.terms.reveal_csv);
        writer.write_u16(self.terms.showdown_csv);
        writer.write_u8(self.terms.reveal_order.flop_first.code());
        writer.write_u8(self.terms.reveal_order.turn_first.code());
        writer.write_u8(self.terms.reveal_order.river_first.code());
        writer.write_u8(self.terms.split_remainder_recipient.code());
        writer.write_bytes(&self.terms.fee_policy_id);
        writer.into_bytes()
    }

    /// Encode only fields that both participants must agree byte-for-byte.
    /// Local role and confirmation-depth policy deliberately remain outside
    /// this digest so both identities authorize the same DEAL retry message.
    fn encode_shared(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.write_bytes(&self.profile_id);
        writer.write_bytes(&self.network_id);
        writer.write_u8(bitcoin_network_code(self.bitcoin_network));
        writer.write_bytes(&self.origin_outpoint.txid);
        writer.write_u32(self.origin_outpoint.vout);
        writer.write_u64(self.origin_value_sat);
        writer.write_bytes(&self.relay_room_id);
        writer.write_bytes(&self.origin_witness_script);
        writer.write_bytes(&self.deal_session_nonce);
        writer.write_bytes(&self.identities.alice().serialize());
        writer.write_bytes(&self.identities.bob().serialize());
        writer.write_u8(self.terms.button.code());
        writer.write_u16(self.terms.chain_protocol_version);
        writer.write_u8(self.terms.max_bets_per_street);
        writer.write_bytes(&self.terms.compiler_id);
        writer.write_u64(self.terms.unit_sat);
        writer.write_u64(self.terms.alice_starting_stack_sat);
        writer.write_u64(self.terms.bob_starting_stack_sat);
        writer.write_u64(self.terms.fee_reserve_sat);
        writer.write_u64(self.terms.activation_fee_sat);
        writer.write_u16(self.terms.action_csv);
        writer.write_u16(self.terms.reveal_csv);
        writer.write_u16(self.terms.showdown_csv);
        writer.write_u8(self.terms.reveal_order.flop_first.code());
        writer.write_u8(self.terms.reveal_order.turn_first.code());
        writer.write_u8(self.terms.reveal_order.river_first.code());
        writer.write_u8(self.terms.split_remainder_recipient.code());
        writer.write_bytes(&self.terms.fee_policy_id);
        writer.into_bytes()
    }
}

/// Purpose attached to a transaction submission intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastPurpose {
    /// Origin-to-gameplay-root activation.
    Activation,
    /// Action, reveal, showdown, fold, payout, or timeout transition.
    Gameplay,
}

/// One exact graph edge available from the confirmed active node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeIntent {
    /// Fixed child state/terminal identifier.
    pub child_node_id: NodeId,
    /// Semantic choice.
    pub kind: EdgeKind,
    /// Signature/reveal authorization policy.
    pub authorization: AuthorizationPolicy,
    /// Exact BIP341 digest covered by transaction signatures.
    pub sighash: [u8; 32],
}

/// Explicit work requested from wallet, relay, chain, or secret-store adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionIntent {
    /// Poll the configured origin outpoint until sufficiently confirmed.
    ObserveOrigin {
        /// Exact shared origin to query.
        outpoint: OutPointRef,
    },
    /// Produce or await the exact next signed DEAL envelope.
    DealEnvelopeDue {
        /// Current attempt.
        attempt: u32,
        /// Global sequence in this attempt.
        sequence: u32,
        /// Protocol round.
        round: u16,
        /// Required sender.
        sender: Role,
        /// Required typed payload.
        payload_type: PayloadType,
        /// Required transcript predecessor.
        previous_message_hash: [u8; 32],
    },
    /// Both players must authenticate a neutral DEAL retry.
    ApproveDealRetry {
        /// Next attempt.
        next_attempt: u32,
        /// Exact BIP340 digest both identities sign.
        digest: [u8; 32],
    },
    /// Sign the semantic-verifier-derived accepted deal.
    SignAcceptedDeal {
        /// Exact body.
        body: Box<AcceptedDealBody>,
        /// Existing DEAL-defined signature digest.
        digest: [u8; 32],
    },
    /// Sign the deterministic chain descriptor.
    SignDescriptor {
        /// Canonical descriptor bytes.
        descriptor: Vec<u8>,
        /// Existing CHAIN-defined signature digest.
        digest: [u8; 32],
    },
    /// Await the local CHAIN worker's compact, signed setup receipt.
    PrepareGraph,
    /// Obtain both origin signatures over this exact activation template.
    AuthorizeActivation {
        /// Exact witness-free activation transaction to sign.
        unsigned_transaction: Vec<u8>,
    },
    /// Submit a fully validated transaction.
    BroadcastTransaction {
        /// Stable transaction identifier.
        txid: [u8; 32],
        /// Complete consensus transaction.
        transaction: Vec<u8>,
        /// Submission purpose.
        purpose: BroadcastPurpose,
    },
    /// Poll this exact live state outpoint and the best-chain tip.
    ObserveState {
        /// Exact current state outpoint to monitor for a spend.
        outpoint: OutPointRef,
    },
    /// Build one of the real runtime witnesses for the confirmed active node.
    ChooseRuntimeEdge {
        /// Confirmed active node.
        node_id: NodeId,
        /// Semantic node type.
        node_kind: NodeKind,
        /// Currently exercisable non-timeout branches.
        edges: Vec<EdgeIntent>,
        /// Timeout maturity when the active node has a timeout branch.
        timeout_matures_at: Option<u32>,
    },
    /// The terminal accounting transaction is confirmed.
    SettlementConfirmed {
        /// Confirmed terminal graph node.
        node_id: NodeId,
        /// Confirmed terminal transaction identifier.
        txid: [u8; 32],
    },
    /// No further signing or broadcast is permitted.
    Halted {
        /// Stable fail-closed reason suitable for diagnostics.
        reason: String,
    },
}

/// Public, copyable status suitable for UI rendering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionStatus {
    /// Current lifecycle phase.
    pub phase: SessionPhase,
    /// Current DEAL attempt.
    pub deal_attempt: u32,
    /// Number of accepted envelopes in the current attempt.
    pub deal_envelopes: u32,
    /// Chain game identifier once a descriptor exists.
    pub chain_game_id: Option<[u8; 32]>,
    /// Agreed graph root once both openings verify.
    pub graph_root: Option<[u8; 32]>,
    /// Authorized activation transaction id, retained after confirmation.
    pub activation_txid: Option<[u8; 32]>,
    /// Active or terminal node once activation confirms.
    pub node_id: Option<NodeId>,
    /// Rust-verified public poker balances for the current state.
    pub table_balances: TableBalances,
    /// Permanent halt reason.
    pub halt_reason: Option<String>,
}

/// Public poker balances derived from the immutable graph state.
///
/// Transaction-fee reserve is deliberately excluded: these are the chips at
/// the table, not an internal funding-accounting diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableBalances {
    /// Alice's chips not currently committed to the pot.
    pub alice_stack_sat: u64,
    /// Bob's chips not currently committed to the pot.
    pub bob_stack_sat: u64,
    /// Chips currently committed to the pot.
    pub pot_sat: u64,
}

/// Result of applying one input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    /// Whether the event was new (`false` means byte-identical idempotent replay).
    pub appended: bool,
    /// Complete currently actionable intent set.
    pub intents: Vec<SessionIntent>,
}

/// Coordinator construction, artifact, replay, or state error.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Invalid immutable configuration.
    #[error("invalid session configuration: {0}")]
    InvalidConfig(&'static str),
    /// Event is not valid in the current phase.
    #[error("unexpected session event: {0}")]
    UnexpectedEvent(&'static str),
    /// A canonical artifact failed verification.
    #[error("invalid {kind}: {reason}")]
    InvalidArtifact {
        /// Artifact class.
        kind: &'static str,
        /// Redacted deterministic reason.
        reason: String,
    },
    /// Canonical event or journal encoding failure.
    #[error(transparent)]
    Codec(#[from] bp52_codec::CodecError),
    /// Snapshot is structurally valid but belongs to another config or is not
    /// a contiguous hash chain.
    #[error("invalid session journal: {0}")]
    InvalidJournal(&'static str),
    /// Permanent fail-closed state.
    #[error("session halted: {0}")]
    Halted(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DealDisposition {
    Unique(Box<AcceptedDealBody>),
    Retry(ArchiveProgress),
}

#[derive(Clone, Debug)]
struct PendingSpend {
    fact: ChainSpend,
    child_node_id: NodeId,
}

enum ProcessResult {
    Appended,
    Duplicate,
}

/// In-memory projection of a canonical, replayable session journal.
pub struct GameSession<'policy> {
    config: SessionConfig,
    config_hash: [u8; 32],
    shared_config_hash: [u8; 32],
    fee_policy: &'policy dyn FeePolicy,
    journal: Vec<EventRecord>,
    snapshot_size: usize,
    phase: SessionPhase,
    halt_reason: Option<String>,
    origin: Option<ConfirmedOrigin>,
    deal_attempt: u32,
    deal_root: [u8; 32],
    deal_envelopes: Vec<Envelope>,
    deal_disposition: Option<DealDisposition>,
    deal_verification_attestation: Option<DealVerificationAttestation>,
    verified_deal_verification: Option<VerifiedDealVerification>,
    accepted_signatures: [Option<[u8; 64]>; 2],
    verified_deal: Option<bp52_protocol::VerifiedAcceptedDeal>,
    descriptor: Option<ChainGameDescriptor>,
    descriptor_signatures: [Option<[u8; 64]>; 2],
    verified_descriptor: Option<bp52_chain_types::VerifiedChainDescriptor>,
    graph_receipt: Option<GraphPreparedReceipt>,
    active_state_receipt: Option<ConfirmedStateReceipt>,
    activation_transaction: Option<Transaction>,
    pending_runtime_receipt: Option<RuntimeAuthorizationReceipt>,
    pending_spend: Option<PendingSpend>,
    last_tip: Option<BlockRef>,
}

impl<'policy> GameSession<'policy> {
    /// Construct an empty reducer bound to one deterministic configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration or fee-policy mismatch.
    pub fn new(
        config: SessionConfig,
        fee_policy: &'policy dyn FeePolicy,
    ) -> Result<Self, SessionError> {
        config.validate(fee_policy)?;
        let config_hash = config_digest(&config.encode());
        let shared_config_hash = shared_config_digest(&config.encode_shared());
        let funding_outpoint = consensus_outpoint(config.origin_outpoint);
        let game_id = derive_game_id(
            &config.network_id,
            &funding_outpoint,
            &config.identities,
            &config.deal_session_nonce,
        );
        Ok(Self {
            config,
            config_hash,
            shared_config_hash,
            fee_policy,
            journal: Vec::new(),
            snapshot_size: SNAPSHOT_HEADER_BYTES,
            phase: SessionPhase::AwaitingOrigin,
            halt_reason: None,
            origin: None,
            deal_attempt: 0,
            deal_root: attempt_start(&game_id, 0),
            deal_envelopes: Vec::new(),
            deal_disposition: None,
            deal_verification_attestation: None,
            verified_deal_verification: None,
            accepted_signatures: [None, None],
            verified_deal: None,
            descriptor: None,
            descriptor_signatures: [None, None],
            verified_descriptor: None,
            graph_receipt: None,
            active_state_receipt: None,
            activation_transaction: None,
            pending_runtime_receipt: None,
            pending_spend: None,
            last_tip: None,
        })
    }

    /// Apply one authenticated event transactionally and return current intents.
    ///
    /// # Errors
    ///
    /// Rejects an event from the wrong trust boundary, or invalid,
    /// out-of-order, or unbound input, without appending it.
    pub fn apply_from(
        &mut self,
        source: EventSource,
        event: &SessionEvent,
    ) -> Result<ApplyResult, SessionError> {
        if !event_accepts_source(event, source) {
            return Err(SessionError::UnexpectedEvent("event provenance mismatch"));
        }
        self.apply_trusted(event)
    }

    fn apply_trusted(&mut self, event: &SessionEvent) -> Result<ApplyResult, SessionError> {
        // Canonicalize before validation so accepted journal entries can always replay.
        let event_bytes = event.encode()?;
        let canonical = SessionEvent::decode(&event_bytes)?;
        if self.journal.iter().any(|record| record.event == canonical) {
            return Ok(ApplyResult {
                appended: false,
                intents: self.intents()?,
            });
        }
        if self.phase == SessionPhase::Halted {
            return Err(SessionError::Halted(
                self.halt_reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            ));
        }
        let sequence = u64::try_from(self.journal.len())
            .map_err(|_| SessionError::InvalidJournal("event count overflow"))?;
        let next_count = sequence
            .checked_add(1)
            .ok_or(SessionError::InvalidJournal("event count overflow"))?;
        u32::try_from(next_count)
            .map_err(|_| SessionError::InvalidJournal("event count overflow"))?;
        let previous_hash = self
            .journal
            .last()
            .map_or([0; 32], |record| record.record_hash);
        let record =
            EventRecord::new(self.config_hash, sequence, previous_hash, canonical.clone())?;
        let next_snapshot_size = self
            .snapshot_size
            .checked_add(EVENT_RECORD_OVERHEAD_BYTES)
            .and_then(|size| size.checked_add(event_bytes.len()))
            .ok_or(SessionError::InvalidJournal("snapshot size overflow"))?;
        if next_snapshot_size > MAX_SESSION_SNAPSHOT_BYTES {
            return Err(SessionError::InvalidJournal("snapshot exceeds storage cap"));
        }
        let result = match self.process(&canonical) {
            Ok(result) => result,
            Err(error) => {
                self.restore_projection_after_rejection()?;
                return Err(error);
            }
        };
        let appended = matches!(result, ProcessResult::Appended);
        let intents = match self.intents() {
            Ok(intents) => intents,
            Err(error) => {
                self.restore_projection_after_rejection()?;
                return Err(error);
            }
        };
        if appended {
            self.journal.push(record);
            self.snapshot_size = next_snapshot_size;
        }
        Ok(ApplyResult { appended, intents })
    }

    /// Current public status.
    #[must_use]
    pub fn status(&self) -> SessionStatus {
        let node_id = self
            .active_state_receipt
            .as_ref()
            .map(|receipt| receipt.state_record().node_id);
        let table_balances = self
            .active_state_receipt
            .as_ref()
            .map(|receipt| {
                let balances = receipt.balances();
                TableBalances {
                    alice_stack_sat: balances.alice_stack_sat,
                    bob_stack_sat: balances.bob_stack_sat,
                    pot_sat: balances.pot_sat,
                }
            })
            .unwrap_or(TableBalances {
                alice_stack_sat: self.config.terms.alice_starting_stack_sat,
                bob_stack_sat: self.config.terms.bob_starting_stack_sat,
                pot_sat: 0,
            });
        SessionStatus {
            phase: self.phase,
            deal_attempt: self.deal_attempt,
            deal_envelopes: u32::try_from(self.deal_envelopes.len()).unwrap_or(u32::MAX),
            chain_game_id: self
                .descriptor
                .as_ref()
                .and_then(|value| chain_game_id(value).ok()),
            graph_root: self
                .graph_receipt
                .as_ref()
                .map(|receipt| receipt.manifest().graph_root),
            activation_txid: self
                .activation_transaction
                .as_ref()
                .map(|transaction| transaction.compute_txid().to_byte_array()),
            node_id,
            table_balances,
            halt_reason: self.halt_reason.clone(),
        }
    }

    /// Accepted hash-chained journal records.
    #[must_use]
    pub fn event_log(&self) -> &[EventRecord] {
        &self.journal
    }

    /// Immutable configuration that binds every accepted event and artifact.
    #[must_use]
    pub const fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Local configuration digest used to bind this role's journal records
    /// and local-only runtime attestations.
    ///
    /// This value is not secret. It intentionally differs between Alice and
    /// Bob because the local role and local confirmation policy are part of
    /// the replay boundary.
    #[must_use]
    pub const fn config_hash(&self) -> [u8; 32] {
        self.config_hash
    }

    /// Role-independent configuration digest shared with the secret CHAIN
    /// runtime and bound into its verification receipts.
    #[must_use]
    pub const fn shared_config_hash(&self) -> [u8; 32] {
        self.shared_config_hash
    }

    /// Deterministic DEAL game identifier derived from the confirmed-origin
    /// binding and canonical identities.
    #[must_use]
    pub fn game_id(&self) -> [u8; 32] {
        self.deal_game_id()
    }

    /// Compact signed graph-setup receipt, once CHAIN completes verification.
    #[must_use]
    pub const fn graph_receipt(&self) -> Option<&GraphPreparedReceipt> {
        self.graph_receipt.as_ref()
    }

    /// Compact signed projection of the current confirmed public state.
    #[must_use]
    pub const fn active_state_receipt(&self) -> Option<&ConfirmedStateReceipt> {
        self.active_state_receipt.as_ref()
    }

    /// Descriptor evidence required by the CHAIN commit/open constructors.
    ///
    /// The opaque value exists only after both identity signatures and every
    /// descriptor invariant have verified.
    #[must_use]
    pub const fn verified_descriptor(&self) -> Option<&bp52_chain_types::VerifiedChainDescriptor> {
        self.verified_descriptor.as_ref()
    }

    /// Current complete intent projection.
    ///
    /// # Errors
    ///
    /// Returns a graph inconsistency rather than emitting unsafe work.
    pub fn intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        if self.phase == SessionPhase::Halted {
            return Ok(vec![SessionIntent::Halted {
                reason: self
                    .halt_reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            }]);
        }
        match self.phase {
            SessionPhase::AwaitingOrigin => Ok(vec![SessionIntent::ObserveOrigin {
                outpoint: self.config.origin_outpoint,
            }]),
            SessionPhase::Dealing => self.deal_intents(),
            SessionPhase::AcceptingDeal => self.acceptance_intents(),
            SessionPhase::SigningDescriptor => self.descriptor_intents(),
            SessionPhase::PreparingGraph => Ok(vec![SessionIntent::PrepareGraph]),
            SessionPhase::AuthorizingActivation => self.activation_authorization_intents(),
            SessionPhase::AwaitingActivation => self.awaiting_activation_intents(),
            SessionPhase::Active => self.active_intents(),
            SessionPhase::Settled => self.settlement_intents(),
            SessionPhase::Halted => unreachable!(),
        }
    }

    /// Canonically encode only the immutable config binding and accepted event
    /// journal. All derived state is reconstructed and reverified on load.
    ///
    /// # Errors
    ///
    /// Rejects a snapshot exceeding the client storage-port limit.
    pub fn snapshot(&self) -> Result<Vec<u8>, SessionError> {
        let mut writer = Writer::new();
        writer.write_bytes(JOURNAL_MAGIC);
        writer.write_bytes(&self.config_hash);
        let count = u32::try_from(self.journal.len())
            .map_err(|_| SessionError::InvalidJournal("event count overflow"))?;
        writer.write_u32(count);
        for record in &self.journal {
            record.encode_into(&mut writer)?;
        }
        let bytes = writer.into_bytes();
        if bytes.len() > MAX_SESSION_SNAPSHOT_BYTES {
            return Err(SessionError::InvalidJournal("snapshot exceeds storage cap"));
        }
        Ok(bytes)
    }

    /// Rebuild and reverify a complete session projection from canonical events.
    ///
    /// # Errors
    ///
    /// Rejects a config mismatch, broken hash chain, noncanonical event, or any
    /// event that no longer validates against the current protocol code.
    pub fn replay(
        config: SessionConfig,
        fee_policy: &'policy dyn FeePolicy,
        snapshot: &[u8],
    ) -> Result<Self, SessionError> {
        if snapshot.len() > MAX_SESSION_SNAPSHOT_BYTES {
            return Err(SessionError::InvalidJournal("snapshot exceeds storage cap"));
        }
        let mut session = Self::new(config, fee_policy)?;
        let mut reader = Reader::new(snapshot);
        if reader.read_array::<8>()? != *JOURNAL_MAGIC {
            return Err(SessionError::InvalidJournal("wrong magic"));
        }
        if reader.read_array::<32>()? != session.config_hash {
            return Err(SessionError::InvalidJournal(
                "configuration binding mismatch",
            ));
        }
        let count = usize::try_from(reader.read_u32()?)
            .map_err(|_| SessionError::InvalidJournal("event count overflow"))?;
        let mut previous_hash = [0; 32];
        for expected_sequence in 0..count {
            let record = EventRecord::decode_from(&mut reader, session.config_hash)?;
            if !journal_link_is_contiguous(
                expected_sequence,
                previous_hash,
                record.sequence,
                record.previous_hash,
            ) {
                return Err(SessionError::InvalidJournal("noncontiguous event chain"));
            }
            match session.process(&record.event)? {
                ProcessResult::Appended => {}
                ProcessResult::Duplicate => {
                    return Err(SessionError::InvalidJournal(
                        "journal contains duplicate event",
                    ));
                }
            }
            previous_hash = record.record_hash;
            session.journal.push(record);
        }
        reader.finish()?;
        session.snapshot_size = snapshot.len();
        Ok(session)
    }

    fn process(&mut self, event: &SessionEvent) -> Result<ProcessResult, SessionError> {
        if self.phase == SessionPhase::Halted {
            return Err(SessionError::Halted(
                self.halt_reason
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned()),
            ));
        }
        match event {
            SessionEvent::OriginConfirmed(fact) => self.accept_origin(fact),
            SessionEvent::DealEnvelope(bytes) => self.accept_deal_envelope(bytes),
            SessionEvent::DealVerificationAttested(bytes) => {
                self.accept_deal_verification_attestation(bytes)
            }
            SessionEvent::AcceptedDealSignature { role, signature } => {
                self.accept_deal_signature(*role, *signature)
            }
            SessionEvent::DealRetrySignature {
                next_attempt,
                role,
                signature,
            } => self.accept_retry_signature(*next_attempt, *role, *signature),
            SessionEvent::DescriptorSignature {
                role,
                descriptor,
                signature,
            } => self.accept_descriptor_signature(*role, descriptor, *signature),
            SessionEvent::GraphPrepared(bytes) => self.accept_graph_prepared(bytes),
            SessionEvent::ActivationAuthorized(bytes) => self.accept_activation(bytes),
            SessionEvent::TipObserved(fact) => self.accept_tip(*fact),
            SessionEvent::RuntimeAuthorized(bytes) => self.accept_runtime_authorization(bytes),
            SessionEvent::SpendConfirmed(fact) => self.accept_confirmed_spend(fact),
            SessionEvent::StateConfirmed(bytes) => self.accept_state_confirmation(bytes),
        }
    }

    fn restore_projection_after_rejection(&mut self) -> Result<(), SessionError> {
        // The snapshot contains only the untouched accepted journal, never
        // partially reduced state from the rejected event.
        let snapshot = self.snapshot()?;
        match Self::replay(self.config, self.fee_policy, &snapshot) {
            Ok(restored) => {
                *self = restored;
                Ok(())
            }
            Err(error) => {
                let reason = format!("accepted journal failed rollback replay: {error}");
                self.halt(reason.clone());
                Err(SessionError::Halted(reason))
            }
        }
    }

    fn accept_origin(&mut self, fact: &ConfirmedOrigin) -> Result<ProcessResult, SessionError> {
        if let Some(existing) = &self.origin {
            return Ok(self.identical_or_halt(existing == fact, "conflicting origin confirmation"));
        }
        if self.phase != SessionPhase::AwaitingOrigin {
            return Err(SessionError::UnexpectedEvent("origin confirmation"));
        }
        validate_origin(&self.config, fact)?;
        self.last_tip = Some(fact.observed_tip);
        self.origin = Some(fact.clone());
        self.phase = SessionPhase::Dealing;
        Ok(ProcessResult::Appended)
    }

    fn accept_deal_envelope(&mut self, bytes: &[u8]) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::Dealing {
            return Err(SessionError::UnexpectedEvent("DEAL envelope"));
        }
        if self.deal_disposition.is_some() {
            return Err(SessionError::UnexpectedEvent(
                "DEAL envelope after terminal verification",
            ));
        }
        let envelope =
            Envelope::decode_exact(bytes).map_err(|error| artifact("DEAL envelope", error))?;
        verify_envelope(
            &Secp256k1::verification_only(),
            &envelope,
            &self.config.identities,
        )
        .map_err(|error| artifact("DEAL envelope authentication", error))?;
        let sequence = u32::try_from(self.deal_envelopes.len())
            .map_err(|_| SessionError::UnexpectedEvent("DEAL sequence overflow"))?;
        let expected = expected_envelope(
            sequence,
            first_blinder(&self.deal_game_id(), self.deal_attempt),
        )
        .ok_or(SessionError::UnexpectedEvent("extra DEAL envelope"))?;
        if envelope.unsigned.protocol_version != PROTOCOL_VERSION
            || envelope.unsigned.game_id != self.deal_game_id()
            || envelope.unsigned.attempt != self.deal_attempt
            || envelope.unsigned.sequence != expected.sequence
            || envelope.unsigned.round != expected.round
            || envelope.unsigned.sender_role != expected.sender
            || envelope.unsigned.payload_type != expected.payload_type
            || envelope.unsigned.previous_message_hash != self.deal_root
        {
            return Err(SessionError::UnexpectedEvent("DEAL schedule mismatch"));
        }
        self.deal_root = advance(&self.deal_root, bytes);
        self.deal_envelopes.push(envelope);
        Ok(ProcessResult::Appended)
    }

    fn accept_deal_verification_attestation(
        &mut self,
        bytes: &[u8],
    ) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::Dealing {
            return Err(SessionError::UnexpectedEvent(
                "DEAL verification attestation",
            ));
        }
        let attestation = DealVerificationAttestation::decode_exact(bytes)
            .map_err(|error| artifact("DEAL verification attestation", error))?;
        if let Some(existing) = self.deal_verification_attestation {
            return Ok(self.identical_or_halt(
                existing == attestation,
                "conflicting DEAL verification attestation",
            ));
        }
        let verification = verify_deal_verification(
            &Secp256k1::verification_only(),
            &self.config.identities,
            to_deal_role(self.config.local_role),
            self.shared_config_hash,
            self.config.deal_session_nonce,
            self.deal_game_id(),
            self.deal_attempt,
            self.deal_root,
            &attestation,
        )
        .map_err(|error| artifact("DEAL verification attestation", error))?;
        let disposition = match verification.statement().result {
            DealVerificationResult::Accepted(body) => DealDisposition::Unique(Box::new(body)),
            DealVerificationResult::DegenerateRetry => {
                DealDisposition::Retry(ArchiveProgress::DegenerateRetry)
            }
            DealVerificationResult::CollisionRetry => {
                DealDisposition::Retry(ArchiveProgress::CollisionRetry)
            }
        };
        self.phase = if matches!(disposition, DealDisposition::Unique(_)) {
            SessionPhase::AcceptingDeal
        } else {
            SessionPhase::Dealing
        };
        self.deal_verification_attestation = Some(attestation);
        self.verified_deal_verification = Some(verification);
        self.deal_disposition = Some(disposition);
        // The attestation's transcript root now commits to the complete
        // semantically verified archive; long-lived GAME state needs no proof
        // objects after this boundary.
        self.deal_envelopes.clear();
        Ok(ProcessResult::Appended)
    }

    fn accept_deal_signature(
        &mut self,
        role: Role,
        signature: [u8; 64],
    ) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::AcceptingDeal {
            return Err(SessionError::UnexpectedEvent("accepted-deal signature"));
        }
        let DealDisposition::Unique(body) =
            self.deal_disposition
                .as_ref()
                .ok_or(SessionError::UnexpectedEvent(
                    "accepted-deal body unavailable",
                ))?
        else {
            return Err(SessionError::UnexpectedEvent("attempt requires retry"));
        };
        verify_accepted_deal_signature(
            &Secp256k1::verification_only(),
            body,
            to_deal_role(role),
            &signature,
            &self.config.identities,
        )
        .map_err(|error| artifact("accepted-deal signature", error))?;
        let index = role_index(role);
        if let Some(existing) = self.accepted_signatures[index] {
            return Ok(self
                .identical_or_halt(existing == signature, "conflicting accepted-deal signature"));
        }
        self.accepted_signatures[index] = Some(signature);
        if let [Some(signature_a), Some(signature_b)] = self.accepted_signatures {
            let deal = accepted_deal(body, signature_a, signature_b);
            let attested =
                self.verified_deal_verification
                    .as_ref()
                    .ok_or(SessionError::UnexpectedEvent(
                        "verified DEAL attestation unavailable",
                    ))?;
            let verified = match verify_attested_accepted_deal(
                &Secp256k1::verification_only(),
                &self.config.identities,
                attested,
                &deal,
            ) {
                Ok(verified) => verified,
                Err(error) => {
                    self.halt(format!(
                        "attested accepted DEAL failed authentication: {error}"
                    ));
                    return Ok(ProcessResult::Appended);
                }
            };
            self.verified_deal = Some(verified);
            self.phase = SessionPhase::SigningDescriptor;
        }
        Ok(ProcessResult::Appended)
    }

    fn accept_retry_signature(
        &mut self,
        next_attempt: u32,
        role: Role,
        signature: [u8; 64],
    ) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::Dealing
            || !matches!(
                self.deal_disposition.as_ref(),
                Some(DealDisposition::Retry(_))
            )
        {
            return Err(SessionError::UnexpectedEvent("DEAL retry approval"));
        }
        if next_attempt
            != self
                .deal_attempt
                .checked_add(1)
                .ok_or(SessionError::UnexpectedEvent("DEAL attempt overflow"))?
        {
            return Err(SessionError::UnexpectedEvent("noncontiguous DEAL retry"));
        }
        let digest = retry_digest(
            self.shared_config_hash,
            self.deal_attempt,
            self.deal_root,
            next_attempt,
        );
        verify_schnorr(
            self.chain_identity(role),
            digest,
            signature,
            "DEAL retry approval",
        )?;
        let index = role_index(role);
        if let Some(existing) = self.accepted_signatures[index] {
            return Ok(
                self.identical_or_halt(existing == signature, "conflicting DEAL retry signature")
            );
        }
        self.accepted_signatures[index] = Some(signature);
        if self.accepted_signatures.iter().any(Option::is_none) {
            return Ok(ProcessResult::Appended);
        }
        self.deal_attempt = next_attempt;
        self.deal_root = attempt_start(&self.deal_game_id(), next_attempt);
        self.deal_envelopes.clear();
        self.deal_disposition = None;
        self.deal_verification_attestation = None;
        self.verified_deal_verification = None;
        self.accepted_signatures = [None, None];
        Ok(ProcessResult::Appended)
    }

    fn accept_descriptor_signature(
        &mut self,
        role: Role,
        descriptor_bytes: &[u8],
        signature: [u8; 64],
    ) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::SigningDescriptor {
            return Err(SessionError::UnexpectedEvent("descriptor signature"));
        }
        let descriptor = ChainGameDescriptor::decode_exact(descriptor_bytes)
            .map_err(|error| artifact("chain descriptor", error))?;
        let expected = self.expected_descriptor()?;
        if descriptor != expected {
            return Err(SessionError::UnexpectedEvent(
                "descriptor differs from configured terms",
            ));
        }
        let digest = descriptor_signature_digest(&descriptor)
            .map_err(|error| artifact("descriptor digest", error))?;
        verify_schnorr(
            self.chain_identity(role),
            digest,
            signature,
            "descriptor signature",
        )?;
        if let Some(existing_descriptor) = self.descriptor {
            if existing_descriptor != descriptor {
                self.halt("conflicting signed descriptors".to_owned());
                return Ok(ProcessResult::Appended);
            }
        } else {
            self.descriptor = Some(descriptor);
        }
        let index = role_index(role);
        if let Some(existing) = self.descriptor_signatures[index] {
            return Ok(
                self.identical_or_halt(existing == signature, "conflicting descriptor signature")
            );
        }
        self.descriptor_signatures[index] = Some(signature);
        if let [Some(signature_a), Some(signature_b)] = self.descriptor_signatures {
            let signed = SignedChainGameDescriptor {
                descriptor,
                signature_a,
                signature_b,
            };
            let verified = match verify_signed_chain_descriptor(&signed) {
                Ok(verified) => verified,
                Err(error) => {
                    self.halt(format!(
                        "fully signed chain descriptor failed verification: {error}"
                    ));
                    return Ok(ProcessResult::Appended);
                }
            };
            self.verified_descriptor = Some(verified);
            self.phase = SessionPhase::PreparingGraph;
        }
        Ok(ProcessResult::Appended)
    }

    fn accept_graph_prepared(&mut self, bytes: &[u8]) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::PreparingGraph {
            return Err(SessionError::UnexpectedEvent("graph-prepared receipt"));
        }
        let receipt = GraphPreparedReceipt::decode_exact(bytes)
            .map_err(|error| artifact("graph-prepared receipt", error))?;
        let descriptor = self
            .verified_descriptor
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "verified descriptor unavailable",
            ))?
            .as_descriptor();
        verify_graph_prepared_receipt(
            descriptor,
            self.shared_config_hash,
            self.config.local_role,
            &receipt,
        )
        .map_err(|error| artifact("graph-prepared receipt", error))?;
        let profile = self.config.terms;
        if receipt.manifest().compiler_id != profile.compiler_id
            || receipt.manifest().fee_policy_id != profile.fee_policy_id
            || receipt.activation().fee_sat != profile.activation_fee_sat
        {
            return Err(SessionError::UnexpectedEvent(
                "graph receipt differs from configured profile",
            ));
        }
        if let Some(existing) = &self.graph_receipt {
            return Ok(
                self.identical_or_halt(existing == &receipt, "conflicting graph-prepared receipt")
            );
        }
        self.graph_receipt = Some(receipt);
        self.phase = SessionPhase::AuthorizingActivation;
        Ok(ProcessResult::Appended)
    }

    fn accept_activation(&mut self, bytes: &[u8]) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::AuthorizingActivation {
            return Err(SessionError::UnexpectedEvent("activation authorization"));
        }
        let receipt = self
            .graph_receipt
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "graph-prepared receipt unavailable",
            ))?;
        let transaction = decode_checked_transaction(bytes, None)?;
        verify_activation_transaction(&self.config, receipt, &transaction)?;
        if let Some(existing) = &self.activation_transaction {
            return Ok(self.identical_or_halt(
                existing == &transaction,
                "conflicting activation transaction",
            ));
        }
        self.activation_transaction = Some(transaction);
        self.phase = SessionPhase::AwaitingActivation;
        Ok(ProcessResult::Appended)
    }

    fn accept_tip(&mut self, fact: TipFact) -> Result<ProcessResult, SessionError> {
        if self.origin.is_none() {
            return Err(SessionError::UnexpectedEvent(
                "tip observed before confirmed origin",
            ));
        }
        if fact.profile_id != self.config.profile_id || fact.block.hash == [0; 32] {
            return Err(SessionError::UnexpectedEvent("tip profile/hash mismatch"));
        }
        match classify_tip(self.last_tip, fact.block) {
            TipRelation::Regression | TipRelation::SameHeightReplacement => {
                self.halt("best-chain regression or same-height replacement".to_owned());
                return Ok(ProcessResult::Appended);
            }
            TipRelation::Duplicate => return Ok(ProcessResult::Duplicate),
            TipRelation::First | TipRelation::Advance => {}
        }
        if self
            .active_state_receipt
            .as_ref()
            .is_some_and(|receipt| fact.block.height < receipt.confirmed_height())
        {
            self.halt("best-chain tip predates the confirmed poker state".to_owned());
            return Ok(ProcessResult::Appended);
        }
        self.last_tip = Some(fact.block);
        Ok(ProcessResult::Appended)
    }

    fn accept_runtime_authorization(
        &mut self,
        bytes: &[u8],
    ) -> Result<ProcessResult, SessionError> {
        if self.phase != SessionPhase::Active || self.pending_spend.is_some() {
            return Err(SessionError::UnexpectedEvent(
                "runtime authorization receipt",
            ));
        }
        let receipt = RuntimeAuthorizationReceipt::decode_exact(bytes)
            .map_err(|error| artifact("runtime authorization receipt", error))?;
        let descriptor = self
            .verified_descriptor
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "verified descriptor unavailable",
            ))?
            .as_descriptor();
        let graph = self
            .graph_receipt
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "graph-prepared receipt unavailable",
            ))?;
        verify_runtime_authorization_receipt(
            descriptor,
            self.shared_config_hash,
            graph.manifest().graph_root,
            self.config.local_role,
            &receipt,
        )
        .map_err(|error| artifact("runtime authorization receipt", error))?;
        let active = self
            .active_state_receipt
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "confirmed-state receipt unavailable",
            ))?;
        let advertised = active
            .edges()
            .iter()
            .find(|edge| edge.edge.child_node_id == receipt.child_node_id())
            .ok_or(SessionError::UnexpectedEvent(
                "runtime receipt selects an unavailable edge",
            ))?;
        if receipt.parent_node_id() != active.state_record().node_id
            || receipt.state_outpoint() != active.state_outpoint()
            || receipt.child_txid() != advertised.edge.transaction.txid
        {
            return Err(SessionError::UnexpectedEvent(
                "runtime receipt differs from the active state",
            ));
        }
        if let Some(existing) = &self.pending_runtime_receipt {
            return Ok(
                self.identical_or_halt(existing == &receipt, "conflicting runtime authorization")
            );
        }
        self.pending_runtime_receipt = Some(receipt);
        Ok(ProcessResult::Appended)
    }

    fn accept_confirmed_spend(&mut self, fact: &ChainSpend) -> Result<ProcessResult, SessionError> {
        validate_spend_fact(&self.config, fact)?;
        match classify_tip(self.last_tip, fact.observed_tip) {
            TipRelation::Regression => {
                return Err(SessionError::UnexpectedEvent(
                    "confirmed spend carries a stale best-chain tip",
                ));
            }
            TipRelation::SameHeightReplacement => {
                self.halt("confirmed spend conflicts with the accepted best-chain tip".to_owned());
                return Ok(ProcessResult::Appended);
            }
            TipRelation::First | TipRelation::Duplicate | TipRelation::Advance => {}
        }
        if let Some(existing) = &self.pending_spend {
            if &existing.fact == fact {
                return Ok(ProcessResult::Duplicate);
            }
            self.halt("conflicting confirmed spends of active outpoint".to_owned());
            return Ok(ProcessResult::Appended);
        }
        let transaction =
            decode_checked_transaction(&fact.spending_transaction, Some(fact.spending_txid))?;
        let child_node_id =
            match self.phase {
                SessionPhase::AwaitingActivation => {
                    if fact.spent_outpoint != self.config.origin_outpoint || fact.input_index != 0 {
                        return Err(SessionError::UnexpectedEvent(
                            "activation spends wrong origin/input",
                        ));
                    }
                    let expected = self.activation_transaction.as_ref().ok_or(
                        SessionError::UnexpectedEvent("authorized activation unavailable"),
                    )?;
                    if &transaction != expected {
                        return Err(SessionError::UnexpectedEvent(
                            "confirmed activation differs from authorization",
                        ));
                    }
                    self.graph_receipt
                        .as_ref()
                        .ok_or(SessionError::UnexpectedEvent(
                            "graph-prepared receipt unavailable",
                        ))?
                        .root_node_id()
                }
                SessionPhase::Active => {
                    let active =
                        self.active_state_receipt
                            .as_ref()
                            .ok_or(SessionError::UnexpectedEvent(
                                "confirmed-state receipt unavailable",
                            ))?;
                    if consensus_outpoint(fact.spent_outpoint) != active.state_outpoint()
                        || fact.input_index != 0
                    {
                        return Err(SessionError::UnexpectedEvent(
                            "confirmed child spends wrong state/input",
                        ));
                    }
                    let authorization = self.pending_runtime_receipt.as_ref().ok_or(
                        SessionError::UnexpectedEvent("confirmed child was not authorized"),
                    )?;
                    if authorization.transaction() != fact.spending_transaction
                        || authorization.child_txid() != fact.spending_txid
                    {
                        return Err(SessionError::UnexpectedEvent(
                            "confirmed child differs from runtime authorization",
                        ));
                    }
                    authorization.child_node_id()
                }
                _ => return Err(SessionError::UnexpectedEvent("confirmed spend")),
            };
        self.pending_spend = Some(PendingSpend {
            fact: fact.clone(),
            child_node_id,
        });
        self.last_tip = Some(fact.observed_tip);
        Ok(ProcessResult::Appended)
    }

    fn accept_state_confirmation(&mut self, bytes: &[u8]) -> Result<ProcessResult, SessionError> {
        if !matches!(
            self.phase,
            SessionPhase::AwaitingActivation | SessionPhase::Active
        ) {
            return Err(SessionError::UnexpectedEvent("confirmed-state receipt"));
        }
        let receipt = ConfirmedStateReceipt::decode_exact(bytes)
            .map_err(|error| artifact("confirmed-state receipt", error))?;
        let graph = self
            .graph_receipt
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "graph-prepared receipt unavailable",
            ))?;
        let descriptor = self
            .verified_descriptor
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "verified descriptor unavailable",
            ))?
            .as_descriptor();
        verify_confirmed_state_receipt(
            descriptor,
            self.shared_config_hash,
            graph.manifest().graph_root,
            self.config.local_role,
            &receipt,
        )
        .map_err(|error| artifact("confirmed-state receipt", error))?;
        let pending = self
            .pending_spend
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "no chain confirmation awaits a state receipt",
            ))?;
        if receipt.spent_outpoint() != consensus_outpoint(pending.fact.spent_outpoint)
            || receipt.state_outpoint()[..32] != pending.fact.spending_txid
            || receipt.confirmed_height() != pending.fact.confirmed_in.height
            || receipt.state_record().node_id != pending.child_node_id
        {
            return Err(SessionError::UnexpectedEvent(
                "state receipt differs from the confirmed spend",
            ));
        }
        let expected_parent = if self.phase == SessionPhase::AwaitingActivation {
            None
        } else {
            self.active_state_receipt
                .as_ref()
                .map(|active| active.state_record().node_id)
        };
        if receipt.spent_node_id() != expected_parent {
            return Err(SessionError::UnexpectedEvent(
                "state receipt has the wrong predecessor",
            ));
        }
        if let Some(existing) = &self.active_state_receipt {
            if existing == &receipt {
                return Ok(ProcessResult::Duplicate);
            }
        }
        let terminal = receipt.is_terminal();
        self.active_state_receipt = Some(receipt);
        self.pending_runtime_receipt = None;
        self.pending_spend = None;
        self.phase = if terminal {
            SessionPhase::Settled
        } else {
            SessionPhase::Active
        };
        Ok(ProcessResult::Appended)
    }

    fn identical_or_halt(&mut self, identical: bool, reason: &'static str) -> ProcessResult {
        if identical {
            ProcessResult::Duplicate
        } else {
            self.halt(reason.to_owned());
            ProcessResult::Appended
        }
    }

    fn halt(&mut self, reason: String) {
        self.phase = SessionPhase::Halted;
        self.halt_reason = Some(reason);
    }

    fn deal_game_id(&self) -> [u8; 32] {
        derive_game_id(
            &self.config.network_id,
            &consensus_outpoint(self.config.origin_outpoint),
            &self.config.identities,
            &self.config.deal_session_nonce,
        )
    }

    fn expected_descriptor(&self) -> Result<ChainGameDescriptor, SessionError> {
        let deal = self
            .verified_deal
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent("verified deal unavailable"))?
            .deal();
        let (alice, bob) = self.config.identities.serialized();
        Ok(ChainGameDescriptor {
            chain_protocol_version: self.config.terms.chain_protocol_version,
            deal,
            network_id: self.config.network_id,
            funding_outpoint: consensus_outpoint(self.config.origin_outpoint),
            deal_session_nonce: self.config.deal_session_nonce,
            alice_xonly_pk: alice,
            bob_xonly_pk: bob,
            button: self.config.terms.button,
            unit_sat: self.config.terms.unit_sat,
            max_bets_per_street: self.config.terms.max_bets_per_street,
            alice_starting_stack_sat: self.config.terms.alice_starting_stack_sat,
            bob_starting_stack_sat: self.config.terms.bob_starting_stack_sat,
            fee_reserve_sat: self.config.terms.fee_reserve_sat,
            action_csv: self.config.terms.action_csv,
            reveal_csv: self.config.terms.reveal_csv,
            showdown_csv: self.config.terms.showdown_csv,
            reveal_order: self.config.terms.reveal_order,
            timeout_policy: TimeoutSettlementPolicy::PotOnly,
            split_remainder_recipient: self.config.terms.split_remainder_recipient,
            fee_policy_id: self.config.terms.fee_policy_id,
            compiler_id: self.config.terms.compiler_id,
        })
    }

    fn chain_identity(&self, role: Role) -> &XOnlyPublicKey {
        match role {
            Role::Alice => self.config.identities.alice(),
            Role::Bob => self.config.identities.bob(),
        }
    }

    fn deal_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        if let Some(DealDisposition::Retry(_)) = self.deal_disposition.as_ref() {
            let next_attempt = self
                .deal_attempt
                .checked_add(1)
                .ok_or(SessionError::UnexpectedEvent("DEAL attempt overflow"))?;
            return Ok(
                if self.accepted_signatures[role_index(self.config.local_role)].is_none() {
                    vec![SessionIntent::ApproveDealRetry {
                        next_attempt,
                        digest: retry_digest(
                            self.shared_config_hash,
                            self.deal_attempt,
                            self.deal_root,
                            next_attempt,
                        ),
                    }]
                } else {
                    Vec::new()
                },
            );
        }
        let sequence = u32::try_from(self.deal_envelopes.len())
            .map_err(|_| SessionError::UnexpectedEvent("DEAL sequence overflow"))?;
        let Some(expected) = expected_envelope(
            sequence,
            first_blinder(&self.deal_game_id(), self.deal_attempt),
        ) else {
            // The disposable DEAL verifier supplies the terminal attestation
            // as a local-runtime event immediately after consuming this root.
            return Ok(Vec::new());
        };
        Ok(vec![SessionIntent::DealEnvelopeDue {
            attempt: self.deal_attempt,
            sequence,
            round: expected.round,
            sender: from_deal_role(expected.sender),
            payload_type: expected.payload_type,
            previous_message_hash: self.deal_root,
        }])
    }

    fn acceptance_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        let DealDisposition::Unique(body) =
            self.deal_disposition
                .as_ref()
                .ok_or(SessionError::UnexpectedEvent(
                    "accepted-deal body unavailable",
                ))?
        else {
            return Err(SessionError::UnexpectedEvent("attempt is not unique"));
        };
        if self.accepted_signatures[role_index(self.config.local_role)].is_some() {
            return Ok(Vec::new());
        }
        let digest = bp52_protocol::auth::accepted_deal_digest(body)
            .map_err(|error| artifact("accepted-deal digest", error))?;
        Ok(vec![SessionIntent::SignAcceptedDeal {
            body: body.clone(),
            digest,
        }])
    }

    fn descriptor_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        if self.descriptor_signatures[role_index(self.config.local_role)].is_some() {
            return Ok(Vec::new());
        }
        let descriptor = self.expected_descriptor()?;
        Ok(vec![SessionIntent::SignDescriptor {
            descriptor: descriptor.encode_to_vec()?,
            digest: descriptor_signature_digest(&descriptor)
                .map_err(|error| artifact("descriptor digest", error))?,
        }])
    }

    fn activation_authorization_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        let receipt = self
            .graph_receipt
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "graph-prepared receipt unavailable",
            ))?;
        Ok(vec![SessionIntent::AuthorizeActivation {
            unsigned_transaction: receipt.activation().non_witness_serialization.clone(),
        }])
    }

    fn awaiting_activation_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        let transaction =
            self.activation_transaction
                .as_ref()
                .ok_or(SessionError::UnexpectedEvent(
                    "authorized activation unavailable",
                ))?;
        Ok(vec![
            SessionIntent::BroadcastTransaction {
                txid: transaction.compute_txid().to_byte_array(),
                transaction: serialize(transaction),
                purpose: BroadcastPurpose::Activation,
            },
            SessionIntent::ObserveState {
                outpoint: self.config.origin_outpoint,
            },
        ])
    }

    fn active_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        let active = self
            .active_state_receipt
            .as_ref()
            .ok_or(SessionError::UnexpectedEvent(
                "confirmed-state receipt unavailable",
            ))?;
        let outpoint = outpoint_ref_from_consensus(active.state_outpoint());
        if self.pending_spend.is_some() {
            return Ok(vec![SessionIntent::ObserveState { outpoint }]);
        }
        let timeout_matures_at = active
            .state_record()
            .timeout
            .map(|timeout| {
                active
                    .confirmed_height()
                    .checked_add(u32::from(timeout.csv))
                    .ok_or(SessionError::UnexpectedEvent("timeout height overflow"))
            })
            .transpose()?;
        let current_height = self.last_tip.map(|tip| tip.height);
        let mut edges = Vec::new();
        for edge in active.edges() {
            if edge.edge.kind.is_timeout()
                && !timeout_matures_at
                    .is_some_and(|maturity| current_height.is_some_and(|height| height >= maturity))
            {
                continue;
            }
            edges.push(EdgeIntent {
                child_node_id: edge.edge.child_node_id,
                kind: edge.edge.kind,
                authorization: edge.edge.authorization,
                sighash: edge.sighash,
            });
        }
        let mut intents = Vec::new();
        if let Some(receipt) = &self.pending_runtime_receipt {
            intents.push(SessionIntent::BroadcastTransaction {
                txid: receipt.child_txid(),
                transaction: receipt.transaction().to_vec(),
                purpose: BroadcastPurpose::Gameplay,
            });
        } else {
            intents.push(SessionIntent::ChooseRuntimeEdge {
                node_id: active.state_record().node_id,
                node_kind: active.state_record().node_kind,
                edges,
                timeout_matures_at,
            });
        }
        intents.push(SessionIntent::ObserveState { outpoint });
        Ok(intents)
    }

    fn settlement_intents(&self) -> Result<Vec<SessionIntent>, SessionError> {
        let receipt = self
            .active_state_receipt
            .as_ref()
            .filter(|receipt| receipt.is_terminal())
            .ok_or(SessionError::UnexpectedEvent(
                "settled phase lacks a terminal state receipt",
            ))?;
        let outpoint = outpoint_ref_from_consensus(receipt.state_outpoint());
        Ok(vec![SessionIntent::SettlementConfirmed {
            node_id: receipt.state_record().node_id,
            txid: outpoint.txid,
        }])
    }
}

fn accepted_deal(
    body: &AcceptedDealBody,
    signature_a: [u8; 64],
    signature_b: [u8; 64],
) -> AcceptedDeal {
    AcceptedDeal {
        protocol_version: body.protocol_version,
        game_id: body.game_id,
        attempt: body.attempt,
        hashes_a: body.hashes_a,
        hashes_b: body.hashes_b,
        verification_transcript_root: body.verification_transcript_root,
        signature_a,
        signature_b,
    }
}

fn validate_origin(config: &SessionConfig, fact: &ConfirmedOrigin) -> Result<(), SessionError> {
    if fact.profile_id != config.profile_id || fact.outpoint != config.origin_outpoint {
        return Err(SessionError::UnexpectedEvent(
            "origin profile/outpoint mismatch",
        ));
    }
    if fact.script_pubkey.is_empty() || fact.script_pubkey.len() > MAX_SCRIPT_BYTES {
        return Err(SessionError::UnexpectedEvent("origin script length"));
    }
    match validate_confirmation(
        fact.confirmed_in,
        fact.observed_tip,
        config.origin_confirmation_depth,
    ) {
        Ok(_) => {}
        Err(ConfirmationError::InvalidBlockRelation) => {
            return Err(SessionError::UnexpectedEvent("origin confirmation block"));
        }
        Err(ConfirmationError::Overflow) => {
            return Err(SessionError::UnexpectedEvent(
                "origin confirmation overflow",
            ));
        }
        Err(ConfirmationError::InsufficientDepth) => {
            return Err(SessionError::UnexpectedEvent("origin confirmation depth"));
        }
    }
    let transaction =
        decode_checked_transaction(&fact.creating_transaction, Some(fact.creating_txid))?;
    let index = usize::try_from(fact.outpoint.vout)
        .map_err(|_| SessionError::UnexpectedEvent("origin output index"))?;
    let output = transaction
        .output
        .get(index)
        .ok_or(SessionError::UnexpectedEvent("origin output absent"))?;
    let expected_script_pubkey = configured_origin_script_pubkey(config);
    if fact.outpoint.txid != fact.creating_txid
        || output.value.to_sat() != fact.value_sat
        || fact.value_sat != config.origin_value_sat
        || output.script_pubkey.as_bytes() != fact.script_pubkey
        || fact.script_pubkey.as_slice() != expected_script_pubkey
    {
        return Err(SessionError::UnexpectedEvent("origin output fact mismatch"));
    }
    Ok(())
}

fn validate_spend_fact(config: &SessionConfig, fact: &ChainSpend) -> Result<(), SessionError> {
    if fact.profile_id != config.profile_id || fact.input_index != 0 {
        return Err(SessionError::UnexpectedEvent(
            "confirmed spend fact mismatch",
        ));
    }
    match validate_confirmation(
        fact.confirmed_in,
        fact.observed_tip,
        config.gameplay_confirmation_depth,
    ) {
        Ok(_) => {}
        Err(ConfirmationError::InvalidBlockRelation) => {
            return Err(SessionError::UnexpectedEvent(
                "confirmed spend fact mismatch",
            ));
        }
        Err(ConfirmationError::Overflow) => {
            return Err(SessionError::UnexpectedEvent("spend confirmation overflow"));
        }
        Err(ConfirmationError::InsufficientDepth) => {
            return Err(SessionError::UnexpectedEvent("spend confirmation depth"));
        }
    }
    let transaction =
        decode_checked_transaction(&fact.spending_transaction, Some(fact.spending_txid))?;
    let input = transaction
        .input
        .get(
            usize::try_from(fact.input_index)
                .map_err(|_| SessionError::UnexpectedEvent("spend input index"))?,
        )
        .ok_or(SessionError::UnexpectedEvent("spend input absent"))?;
    if outpoint_ref(input.previous_output) != fact.spent_outpoint {
        return Err(SessionError::UnexpectedEvent("spend prevout mismatch"));
    }
    Ok(())
}

fn verify_activation_transaction(
    config: &SessionConfig,
    receipt: &GraphPreparedReceipt,
    transaction: &Transaction,
) -> Result<(), SessionError> {
    if transaction.input.len() != 1 {
        return Err(SessionError::UnexpectedEvent("activation input count"));
    }
    let mut witness_free = transaction.clone();
    witness_free.input[0].witness = Witness::new();
    if serialize(&witness_free) != receipt.activation().non_witness_serialization {
        return Err(SessionError::UnexpectedEvent(
            "activation changed fixed template",
        ));
    }
    let witness = &transaction.input[0].witness;
    if witness.len() != 3 {
        return Err(SessionError::UnexpectedEvent("activation witness shape"));
    }
    let script = witness
        .nth(2)
        .ok_or(SessionError::UnexpectedEvent("activation witness script"))?;
    verify_origin_script(config, script)?;
    let expected_program = configured_origin_script_pubkey(config);
    let script_hash = sha256::Hash::hash(script).to_byte_array();
    if expected_program[0] != 0 || expected_program[1] != 32 || expected_program[2..] != script_hash
    {
        return Err(SessionError::UnexpectedEvent(
            "activation witness script does not spend origin",
        ));
    }
    let digest = SighashCache::new(transaction)
        .p2wsh_signature_hash(
            0,
            ScriptBuf::from_bytes(script.to_vec()).as_script(),
            Amount::from_sat(config.origin_value_sat),
            EcdsaSighashType::All,
        )
        .map_err(|error| artifact("activation sighash", error))?
        .to_byte_array();
    // Script consumes the top signature first, so witness item 1 belongs to
    // participant 0 and item 0 belongs to participant 1.
    verify_ecdsa_witness_signature(&script[35..68], digest, witness.nth(1).unwrap_or_default())?;
    verify_ecdsa_witness_signature(&script[70..103], digest, witness.nth(0).unwrap_or_default())?;
    Ok(())
}

fn verify_origin_script(config: &SessionConfig, script: &[u8]) -> Result<(), SessionError> {
    if script != config.origin_witness_script
        || script.len() != ORIGIN_WITNESS_SCRIPT_BYTES
        || script[0] != 32
        || script[33] != OP_DROP
        || script[34] != 33
        || script[68] != OP_CHECKSIGVERIFY
        || script[69] != 33
        || script[103] != OP_CHECKSIG
        || script[1..33].iter().all(|byte| *byte == 0)
    {
        return Err(SessionError::UnexpectedEvent(
            "origin witness script profile",
        ));
    }
    let first = PublicKey::from_slice(&script[35..68])
        .map_err(|error| artifact("origin participant key", error))?;
    let second = PublicKey::from_slice(&script[70..103])
        .map_err(|error| artifact("origin participant key", error))?;
    let (first_xonly, _) = first.x_only_public_key();
    let (second_xonly, _) = second.x_only_public_key();
    if first_xonly.serialize() != config.identities.alice().serialize()
        || second_xonly.serialize() != config.identities.bob().serialize()
    {
        return Err(SessionError::UnexpectedEvent(
            "origin participant keys differ from descriptor",
        ));
    }
    Ok(())
}

fn validate_configured_origin_script(config: &SessionConfig) -> Result<(), SessionError> {
    let script = &config.origin_witness_script;
    if script[0] != 32
        || script[33] != OP_DROP
        || script[34] != 33
        || script[68] != OP_CHECKSIGVERIFY
        || script[69] != 33
        || script[103] != OP_CHECKSIG
    {
        return Err(SessionError::InvalidConfig("origin witness script profile"));
    }
    let context = OriginContext::new(
        config.network_id,
        config.relay_room_id,
        config.deal_session_nonce,
    )
    .map_err(|error| artifact("origin context", error))?;
    if script[1..33] != context.commitment() {
        return Err(SessionError::InvalidConfig(
            "origin witness script has wrong context commitment",
        ));
    }
    let first = PublicKey::from_slice(&script[35..68])
        .map_err(|error| artifact("origin participant key", error))?;
    let second = PublicKey::from_slice(&script[70..103])
        .map_err(|error| artifact("origin participant key", error))?;
    let (first_xonly, _) = first.x_only_public_key();
    let (second_xonly, _) = second.x_only_public_key();
    if first_xonly.serialize() != config.identities.alice().serialize()
        || second_xonly.serialize() != config.identities.bob().serialize()
    {
        return Err(SessionError::InvalidConfig(
            "origin participant keys differ from canonical identities",
        ));
    }
    Ok(())
}

fn configured_origin_script_pubkey(config: &SessionConfig) -> [u8; 34] {
    let mut script_pubkey = [0_u8; 34];
    script_pubkey[1] = 32;
    script_pubkey[2..]
        .copy_from_slice(&sha256::Hash::hash(&config.origin_witness_script).to_byte_array());
    script_pubkey
}

fn verify_ecdsa_witness_signature(
    public_key: &[u8],
    digest: [u8; 32],
    signature: &[u8],
) -> Result<(), SessionError> {
    let Some((&sighash, der)) = signature.split_last() else {
        return Err(SessionError::UnexpectedEvent("empty activation signature"));
    };
    if sighash != SIGHASH_ALL {
        return Err(SessionError::UnexpectedEvent(
            "activation signature is not SIGHASH_ALL",
        ));
    }
    let signature = ecdsa::Signature::from_der(der)
        .map_err(|error| artifact("activation DER signature", error))?;
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(SessionError::UnexpectedEvent(
            "activation signature is not low-S",
        ));
    }
    let public_key = PublicKey::from_slice(public_key)
        .map_err(|error| artifact("activation public key", error))?;
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &signature, &public_key)
        .map_err(|error| artifact("activation signature", error))
}

fn decode_checked_transaction(
    bytes: &[u8],
    expected_txid: Option<[u8; 32]>,
) -> Result<Transaction, SessionError> {
    let transaction: Transaction =
        deserialize(bytes).map_err(|error| artifact("Bitcoin transaction", error))?;
    if serialize(&transaction) != bytes {
        return Err(SessionError::UnexpectedEvent(
            "noncanonical transaction serialization",
        ));
    }
    if expected_txid.is_some_and(|txid| transaction.compute_txid().to_byte_array() != txid) {
        return Err(SessionError::UnexpectedEvent(
            "transaction identifier mismatch",
        ));
    }
    Ok(transaction)
}

fn consensus_outpoint(outpoint: OutPointRef) -> [u8; 36] {
    let mut bytes = [0; 36];
    bytes[..32].copy_from_slice(&outpoint.txid);
    bytes[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    bytes
}

fn outpoint_ref_from_consensus(outpoint: [u8; 36]) -> OutPointRef {
    let mut txid = [0; 32];
    txid.copy_from_slice(&outpoint[..32]);
    let mut vout = [0; 4];
    vout.copy_from_slice(&outpoint[32..]);
    OutPointRef {
        txid,
        vout: u32::from_le_bytes(vout),
    }
}

fn outpoint_ref(outpoint: OutPoint) -> OutPointRef {
    OutPointRef {
        txid: outpoint.txid.to_byte_array(),
        vout: outpoint.vout,
    }
}

fn role_index(role: Role) -> usize {
    usize::from(role.code())
}

const fn to_deal_role(role: Role) -> DealRole {
    match role {
        Role::Alice => DealRole::Alice,
        Role::Bob => DealRole::Bob,
    }
}

const fn from_deal_role(role: DealRole) -> Role {
    match role {
        DealRole::Alice => Role::Alice,
        DealRole::Bob => Role::Bob,
    }
}

fn verify_schnorr(
    key: &XOnlyPublicKey,
    digest: [u8; 32],
    signature: [u8; 64],
    kind: &'static str,
) -> Result<(), SessionError> {
    let signature =
        schnorr::Signature::from_slice(&signature).map_err(|error| artifact(kind, error))?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &Message::from_digest(digest), key)
        .map_err(|error| artifact(kind, error))
}

fn artifact(kind: &'static str, error: impl std::fmt::Display) -> SessionError {
    SessionError::InvalidArtifact {
        kind,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;

    use bitcoin::absolute;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use bp52_chain_bitcoin::{FeePolicy, FixedFeePolicy, custom_signet_network_id};
    use bp52_codec::Encode;
    use bp52_protocol::auth::{CanonicalIdentities, sign_envelope};
    use bp52_protocol::messages::{PayloadType, UnsignedEnvelope};
    use bp52_protocol::payloads::{CommitmentPayload, ProtocolPayload};

    use super::*;

    struct Fixture {
        config: SessionConfig,
        origin: ConfirmedOrigin,
        alice: Keypair,
        bob: Keypair,
    }

    fn test_error(message: &'static str) -> io::Error {
        io::Error::other(message)
    }

    fn keypair(marker: u8) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[marker; 32])?;
        Ok(Keypair::from_secret_key(&secp, &secret))
    }

    fn fixture(fee_policy: &FixedFeePolicy) -> Result<Fixture, Box<dyn Error>> {
        let first = keypair(1)?;
        let second = keypair(2)?;
        let identities =
            CanonicalIdentities::new(first.x_only_public_key().0, second.x_only_public_key().0)?;
        let (alice, bob) = if first.x_only_public_key().0 == *identities.alice() {
            (first, second)
        } else {
            (second, first)
        };
        let network_id = custom_signet_network_id(ScriptBuf::from_bytes(vec![0x51]).as_script());
        let relay_room_id = [0x51; 32];
        let deal_session_nonce = [0x52; 32];
        let context = OriginContext::new(network_id, relay_room_id, deal_session_nonce)?;
        let mut origin_witness_script = [0_u8; ORIGIN_WITNESS_SCRIPT_BYTES];
        origin_witness_script[0] = 32;
        origin_witness_script[1..33].copy_from_slice(&context.commitment());
        origin_witness_script[33] = OP_DROP;
        origin_witness_script[34] = 33;
        origin_witness_script[35..68].copy_from_slice(&PublicKey::from_keypair(&alice).serialize());
        origin_witness_script[68] = OP_CHECKSIGVERIFY;
        origin_witness_script[69] = 33;
        origin_witness_script[70..103].copy_from_slice(&PublicKey::from_keypair(&bob).serialize());
        origin_witness_script[103] = OP_CHECKSIG;
        let mut script_pubkey_bytes = vec![0, 32];
        script_pubkey_bytes
            .extend_from_slice(&sha256::Hash::hash(&origin_witness_script).to_byte_array());
        let script_pubkey = ScriptBuf::from_bytes(script_pubkey_bytes);
        let creating_transaction = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0x31; 32]), 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_500),
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let creating_txid = creating_transaction.compute_txid().to_byte_array();
        let origin_outpoint = OutPointRef {
            txid: creating_txid,
            vout: 0,
        };
        let config = SessionConfig {
            profile_id: network_id,
            network_id,
            bitcoin_network: Network::Signet,
            origin_outpoint,
            origin_value_sat: 10_500,
            relay_room_id,
            origin_witness_script,
            deal_session_nonce,
            identities,
            local_role: Role::Alice,
            origin_confirmation_depth: NonZeroU16::MIN,
            gameplay_confirmation_depth: NonZeroU16::MIN,
            terms: DescriptorTerms {
                chain_protocol_version: bp52_chain_types::CHAIN_PROTOCOL_VERSION,
                button: Role::Alice,
                unit_sat: 100,
                max_bets_per_street: bp52_chain_types::MAX_BETS_PER_STREET,
                alice_starting_stack_sat: 4_000,
                bob_starting_stack_sat: 4_000,
                fee_reserve_sat: 2_000,
                activation_fee_sat: 500,
                action_csv: 6,
                reveal_csv: 6,
                showdown_csv: 6,
                reveal_order: RevealOrder {
                    flop_first: Role::Alice,
                    turn_first: Role::Bob,
                    river_first: Role::Alice,
                },
                split_remainder_recipient: Role::Alice,
                fee_policy_id: fee_policy.policy_id(),
                compiler_id: reference_compiler_id(),
            },
        };
        let block = BlockRef {
            height: 100,
            hash: [0x61; 32],
        };
        let origin = ConfirmedOrigin {
            profile_id: network_id,
            outpoint: origin_outpoint,
            value_sat: 10_500,
            script_pubkey: script_pubkey.into_bytes(),
            creating_txid,
            creating_transaction: serialize(&creating_transaction),
            confirmed_in: block,
            observed_tip: block,
        };
        Ok(Fixture {
            config,
            origin,
            alice,
            bob,
        })
    }

    fn next_commitment_envelope(
        session: &GameSession<'_>,
        fixture: &Fixture,
        wrong_predecessor: bool,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let intent = session
            .intents()?
            .into_iter()
            .next()
            .ok_or_else(|| test_error("missing DEAL intent"))?;
        let SessionIntent::DealEnvelopeDue {
            attempt,
            sequence,
            round,
            sender,
            payload_type,
            previous_message_hash,
        } = intent
        else {
            return Err(test_error("next intent is not a DEAL envelope").into());
        };
        if payload_type != PayloadType::KeyCommit {
            return Err(test_error("test expected an initial key commitment").into());
        }
        let payload = ProtocolPayload::KeyCommit(CommitmentPayload {
            commitment: [0x71_u8.wrapping_add(u8::try_from(sequence)?); 32],
        })
        .encode_body()?;
        let unsigned = UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: session.game_id(),
            attempt,
            round,
            sender_role: to_deal_role(sender),
            sequence,
            previous_message_hash: if wrong_predecessor {
                [0x99; 32]
            } else {
                previous_message_hash
            },
            payload_type,
            payload,
        };
        let signer = match sender {
            Role::Alice => &fixture.alice,
            Role::Bob => &fixture.bob,
        };
        Ok(sign_envelope(
            &Secp256k1::new(),
            &unsigned,
            signer,
            &fixture.config.identities,
            &[0x81; 32],
        )?
        .encode_to_vec()?)
    }

    #[test]
    fn config_binds_origin_context_and_retry_digest_is_shared() -> Result<(), Box<dyn Error>> {
        let fee_policy = FixedFeePolicy::new(1, 1)?;
        let fixture = fixture(&fee_policy)?;

        let mut wrong_value = fixture.config;
        wrong_value.origin_value_sat = 10_000;
        assert!(GameSession::new(wrong_value, &fee_policy).is_err());

        let mut wrong_context = fixture.config;
        wrong_context.origin_witness_script[1] ^= 1;
        assert!(GameSession::new(wrong_context, &fee_policy).is_err());

        let alice_session = GameSession::new(fixture.config, &fee_policy)?;
        let mut bob_config = fixture.config;
        bob_config.local_role = Role::Bob;
        bob_config.origin_confirmation_depth =
            NonZeroU16::new(2).ok_or_else(|| test_error("zero"))?;
        bob_config.gameplay_confirmation_depth =
            NonZeroU16::new(3).ok_or_else(|| test_error("zero"))?;
        let bob_session = GameSession::new(bob_config, &fee_policy)?;
        assert_ne!(alice_session.config_hash, bob_session.config_hash);
        assert_eq!(
            alice_session.shared_config_hash,
            bob_session.shared_config_hash
        );

        let mut bad_fact = fixture.origin.clone();
        bad_fact.script_pubkey[2] ^= 1;
        let mut session = GameSession::new(fixture.config, &fee_policy)?;
        assert!(
            session
                .apply_from(
                    EventSource::Exchange,
                    &SessionEvent::OriginConfirmed(fixture.origin.clone()),
                )
                .is_err()
        );
        assert!(
            session
                .apply_from(EventSource::Chain, &SessionEvent::OriginConfirmed(bad_fact))
                .is_err()
        );
        assert_eq!(session.status().phase, SessionPhase::AwaitingOrigin);
        assert!(session.event_log().is_empty());
        Ok(())
    }

    #[test]
    fn status_retains_the_authorized_activation_txid() -> Result<(), Box<dyn Error>> {
        let fee_policy = FixedFeePolicy::new(1, 1)?;
        let fixture = fixture(&fee_policy)?;
        let mut session = GameSession::new(fixture.config, &fee_policy)?;
        assert_eq!(session.status().activation_txid, None);

        let activation: Transaction = deserialize(&fixture.origin.creating_transaction)?;
        let activation_txid = activation.compute_txid().to_byte_array();
        session.activation_transaction = Some(activation);
        assert_eq!(session.status().activation_txid, Some(activation_txid));
        Ok(())
    }

    #[test]
    fn verified_retry_advances_only_after_both_role_signatures() -> Result<(), Box<dyn Error>> {
        let fee_policy = FixedFeePolicy::new(1, 1)?;
        let fixture = fixture(&fee_policy)?;
        let mut session = GameSession::new(fixture.config, &fee_policy)?;
        session.phase = SessionPhase::Dealing;
        session.deal_root = [0x91; 32];
        session.deal_disposition = Some(DealDisposition::Retry(ArchiveProgress::CollisionRetry));
        let digest = retry_digest(session.shared_config_hash, 0, session.deal_root, 1);
        let secp = Secp256k1::new();
        let signature_a = *secp
            .sign_schnorr_with_aux_rand(&Message::from_digest(digest), &fixture.alice, &[3; 32])
            .as_ref();
        let signature_b = *secp
            .sign_schnorr_with_aux_rand(&Message::from_digest(digest), &fixture.bob, &[4; 32])
            .as_ref();

        let first = SessionEvent::DealRetrySignature {
            next_attempt: 1,
            role: Role::Alice,
            signature: signature_a,
        };
        session.apply_from(EventSource::Exchange, &first)?;
        assert_eq!(session.status().deal_attempt, 0);
        assert!(session.intents()?.is_empty());

        let second = SessionEvent::DealRetrySignature {
            next_attempt: 1,
            role: Role::Bob,
            signature: signature_b,
        };
        session.apply_from(EventSource::Exchange, &second)?;
        assert_eq!(session.status().deal_attempt, 1);
        assert!(matches!(
            session.intents()?.first(),
            Some(SessionIntent::DealEnvelopeDue { sequence: 0, .. })
        ));
        Ok(())
    }

    #[test]
    fn confirmed_origin_and_deal_prefix_replay_canonically() -> Result<(), Box<dyn Error>> {
        let fee_policy = FixedFeePolicy::new(1, 1)?;
        let fixture = fixture(&fee_policy)?;
        let mut session = GameSession::new(fixture.config, &fee_policy)?;
        assert_eq!(session.status().phase, SessionPhase::AwaitingOrigin);

        let mut incorrect_origin = fixture.origin.clone();
        incorrect_origin.value_sat -= 1;
        assert!(
            session
                .apply_from(
                    EventSource::Chain,
                    &SessionEvent::OriginConfirmed(incorrect_origin),
                )
                .is_err()
        );
        assert_eq!(session.status().phase, SessionPhase::AwaitingOrigin);
        assert!(session.event_log().is_empty());

        let origin_event = SessionEvent::OriginConfirmed(fixture.origin.clone());
        assert!(
            session
                .apply_from(EventSource::Chain, &origin_event)?
                .appended
        );
        assert_eq!(session.status().phase, SessionPhase::Dealing);

        let first_envelope = next_commitment_envelope(&session, &fixture, false)?;
        assert!(
            session
                .apply_from(
                    EventSource::Exchange,
                    &SessionEvent::DealEnvelope(first_envelope.clone()),
                )?
                .appended
        );
        assert_eq!(session.status().deal_envelopes, 1);
        let accepted_snapshot = session.snapshot()?;

        let wrong_second = next_commitment_envelope(&session, &fixture, true)?;
        assert!(
            session
                .apply_from(
                    EventSource::Exchange,
                    &SessionEvent::DealEnvelope(wrong_second),
                )
                .is_err()
        );
        assert_eq!(session.snapshot()?, accepted_snapshot);
        assert_eq!(session.status().deal_envelopes, 1);

        assert!(
            !session
                .apply_from(EventSource::Chain, &origin_event)?
                .appended
        );
        assert!(
            !session
                .apply_from(
                    EventSource::Exchange,
                    &SessionEvent::DealEnvelope(first_envelope),
                )?
                .appended
        );

        let replayed = GameSession::replay(fixture.config, &fee_policy, &accepted_snapshot)?;
        assert_eq!(replayed.status(), session.status());
        assert_eq!(replayed.intents()?, session.intents()?);
        assert_eq!(replayed.event_log(), session.event_log());

        let mut tampered = accepted_snapshot.clone();
        let last = tampered
            .last_mut()
            .ok_or_else(|| test_error("snapshot cannot be empty"))?;
        *last ^= 1;
        assert!(GameSession::replay(fixture.config, &fee_policy, &tampered,).is_err());

        let mut different_config = fixture.config;
        different_config.deal_session_nonce = [0x53; 32];
        assert!(GameSession::replay(different_config, &fee_policy, &accepted_snapshot,).is_err());
        Ok(())
    }
}
