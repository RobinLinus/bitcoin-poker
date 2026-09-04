//! Compact identity-signed receipts crossing the CHAIN/GAME boundary.
//!
//! The secret CHAIN worker is the sole owner of Lamport material, packed
//! preauthorizations, and materialized graph pages. GAME receives only these
//! canonical public facts and verifies the local identity signature before
//! advancing its replayable projection.

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use bp52_chain_types::node::MAX_NODE_CHILDREN;
use bp52_chain_types::{
    ChainGameDescriptor, LogicalEdge, LogicalNodeRecord, LogicalOutput, LogicalTransaction, NodeId,
    Role, VerifiedChainDescriptor, chain_game_id,
};
use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use sha2::{Digest, Sha256};

use crate::{CompiledGraphSummary, CompilerError, GraphManifest};

const GRAPH_PREPARED_TAG: &[u8] = b"BP52/graph-prepared-receipt/v1";
const CONFIRMED_STATE_TAG: &[u8] = b"BP52/confirmed-state-receipt/v1";
const RUNTIME_AUTHORIZATION_TAG: &[u8] = b"BP52/runtime-authorization-receipt/v1";
const RECEIPT_VERSION: u16 = 1;
const MAX_RUNTIME_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;

/// Public chip accounting for one confirmed graph state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicStateBalances {
    /// Alice's uncommitted table stack.
    pub alice_stack_sat: u64,
    /// Bob's uncommitted table stack.
    pub bob_stack_sat: u64,
    /// Chips committed to the pot.
    pub pot_sat: u64,
}

impl PublicStateBalances {
    fn total(self) -> Result<u64, CompilerError> {
        self.alice_stack_sat
            .checked_add(self.bob_stack_sat)
            .and_then(|value| value.checked_add(self.pot_sat))
            .ok_or_else(|| invalid("public state balances overflow"))
    }
}

impl Encode for PublicStateBalances {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.alice_stack_sat.encode(writer)?;
        self.bob_stack_sat.encode(writer)?;
        self.pot_sat.encode(writer)
    }
}

impl Decode for PublicStateBalances {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            alice_stack_sat: Decode::decode(reader)?,
            bob_stack_sat: Decode::decode(reader)?,
            pot_sat: Decode::decode(reader)?,
        })
    }
}

/// One public outgoing edge advertised for a confirmed active state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicEdgeReceipt {
    /// Canonical logical edge, including its fixed witness-free transaction.
    pub edge: LogicalEdge,
    /// Exact BIP341 digest authorized by runtime signatures for this edge.
    pub sighash: [u8; 32],
}

impl Encode for PublicEdgeReceipt {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.edge.encode(writer)?;
        self.sighash.encode(writer)
    }
}

impl Decode for PublicEdgeReceipt {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            edge: Decode::decode(reader)?,
            sighash: Decode::decode(reader)?,
        };
        if value.sighash == [0; 32] {
            return Err(CodecError::NonCanonical);
        }
        Ok(value)
    }
}

/// Small setup checkpoint proving that CHAIN audited the complete graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphPreparedReceipt {
    version: u16,
    shared_config_hash: [u8; 32],
    manifest: GraphManifest,
    root_node_id: NodeId,
    activation: LogicalTransaction,
    preauthorization_counts: [u32; 2],
    runtime_signature_counts: [u32; 2],
    lamport_counts: [u32; 2],
    verifier_role: Role,
    verifier_signature: [u8; 64],
}

impl GraphPreparedReceipt {
    /// Role-local configuration digest shared by GAME and CHAIN.
    #[must_use]
    pub const fn shared_config_hash(&self) -> [u8; 32] {
        self.shared_config_hash
    }

    /// Audited graph manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GraphManifest {
        &self.manifest
    }

    /// Gameplay-root node identifier.
    #[must_use]
    pub const fn root_node_id(&self) -> NodeId {
        self.root_node_id
    }

    /// Witness-free origin-to-root transaction.
    #[must_use]
    pub const fn activation(&self) -> &LogicalTransaction {
        &self.activation
    }

    /// Role that performed the graph audit and signed the receipt.
    #[must_use]
    pub const fn verifier_role(&self) -> Role {
        self.verifier_role
    }

    /// Number of fixed preauthorizations required from one role.
    #[must_use]
    pub const fn preauthorization_count(&self, role: Role) -> u32 {
        self.preauthorization_counts[role_index(role)]
    }

    /// Number of live runtime signing opportunities for one role.
    #[must_use]
    pub const fn runtime_signature_count(&self, role: Role) -> u32 {
        self.runtime_signature_counts[role_index(role)]
    }

    /// Number of deterministic Lamport keys for one role.
    #[must_use]
    pub const fn lamport_count(&self, role: Role) -> u32 {
        self.lamport_counts[role_index(role)]
    }
}

impl Encode for GraphPreparedReceipt {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        encode_graph_prepared_unsigned(self, writer)?;
        self.verifier_signature.encode(writer)
    }
}

impl Decode for GraphPreparedReceipt {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            version: Decode::decode(reader)?,
            shared_config_hash: Decode::decode(reader)?,
            manifest: decode_manifest(reader)?,
            root_node_id: Decode::decode(reader)?,
            activation: Decode::decode(reader)?,
            preauthorization_counts: [Decode::decode(reader)?, Decode::decode(reader)?],
            runtime_signature_counts: [Decode::decode(reader)?, Decode::decode(reader)?],
            lamport_counts: [Decode::decode(reader)?, Decode::decode(reader)?],
            verifier_role: Decode::decode(reader)?,
            verifier_signature: Decode::decode(reader)?,
        };
        validate_graph_prepared_shape(&value).map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

/// Signed public projection for one confirmed active or terminal state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedStateReceipt {
    version: u16,
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    spent_node_id: Option<NodeId>,
    spent_outpoint: [u8; 36],
    state_outpoint: [u8; 36],
    state_output: Option<LogicalOutput>,
    state_record: LogicalNodeRecord,
    balances: PublicStateBalances,
    confirmed_height: u32,
    edges: Vec<PublicEdgeReceipt>,
    verifier_role: Role,
    verifier_signature: [u8; 64],
}

impl ConfirmedStateReceipt {
    /// Role-independent GAME/CHAIN configuration binding.
    #[must_use]
    pub const fn shared_config_hash(&self) -> [u8; 32] {
        self.shared_config_hash
    }

    /// Descriptor-bound chain game identifier.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Audited graph root.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }

    /// Node consumed by the confirmation, absent for activation.
    #[must_use]
    pub const fn spent_node_id(&self) -> Option<NodeId> {
        self.spent_node_id
    }

    /// Exact outpoint consumed by the confirmed transaction.
    #[must_use]
    pub const fn spent_outpoint(&self) -> [u8; 36] {
        self.spent_outpoint
    }

    /// Exact newly confirmed state outpoint.
    #[must_use]
    pub const fn state_outpoint(&self) -> [u8; 36] {
        self.state_outpoint
    }

    /// Exact newly confirmed state output.
    #[must_use]
    pub const fn state_output(&self) -> Option<&LogicalOutput> {
        self.state_output.as_ref()
    }

    /// Canonical committed record for the new state.
    #[must_use]
    pub const fn state_record(&self) -> &LogicalNodeRecord {
        &self.state_record
    }

    /// Public table stacks and pot.
    #[must_use]
    pub const fn balances(&self) -> PublicStateBalances {
        self.balances
    }

    /// Block height confirming the state-creating transaction.
    #[must_use]
    pub const fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }

    /// Exact currently available outgoing edges.
    #[must_use]
    pub fn edges(&self) -> &[PublicEdgeReceipt] {
        &self.edges
    }

    /// Whether this receipt describes a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state_record.node_kind.is_terminal()
    }

    /// Role that verified chain semantics and signed the receipt.
    #[must_use]
    pub const fn verifier_role(&self) -> Role {
        self.verifier_role
    }
}

impl Encode for ConfirmedStateReceipt {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        encode_confirmed_state_unsigned(self, writer)?;
        self.verifier_signature.encode(writer)
    }
}

impl Decode for ConfirmedStateReceipt {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            version: Decode::decode(reader)?,
            shared_config_hash: Decode::decode(reader)?,
            chain_game_id: Decode::decode(reader)?,
            graph_root: Decode::decode(reader)?,
            spent_node_id: decode_optional_node(reader)?,
            spent_outpoint: Decode::decode(reader)?,
            state_outpoint: Decode::decode(reader)?,
            state_output: decode_optional_output(reader)?,
            state_record: Decode::decode(reader)?,
            balances: Decode::decode(reader)?,
            confirmed_height: Decode::decode(reader)?,
            edges: decode_edges(reader)?,
            verifier_role: Decode::decode(reader)?,
            verifier_signature: Decode::decode(reader)?,
        };
        validate_confirmed_state_shape(&value).map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

/// Local CHAIN proof that one active edge was fully authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAuthorizationReceipt {
    version: u16,
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    parent_node_id: NodeId,
    child_node_id: NodeId,
    state_outpoint: [u8; 36],
    child_txid: [u8; 32],
    transaction: Vec<u8>,
    verifier_role: Role,
    verifier_signature: [u8; 64],
}

impl RuntimeAuthorizationReceipt {
    /// Construct a zero-signature receipt for
    /// [`issue_runtime_authorization_receipt`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn unsigned(
        shared_config_hash: [u8; 32],
        chain_game_id: [u8; 32],
        graph_root: [u8; 32],
        parent_node_id: NodeId,
        child_node_id: NodeId,
        state_outpoint: [u8; 36],
        child_txid: [u8; 32],
        transaction: Vec<u8>,
        verifier_role: Role,
    ) -> Self {
        Self {
            version: RECEIPT_VERSION,
            shared_config_hash,
            chain_game_id,
            graph_root,
            parent_node_id,
            child_node_id,
            state_outpoint,
            child_txid,
            transaction,
            verifier_role,
            verifier_signature: [0; 64],
        }
    }

    /// Active parent authorized by this receipt.
    #[must_use]
    pub const fn parent_node_id(&self) -> NodeId {
        self.parent_node_id
    }

    /// Selected child authorized by this receipt.
    #[must_use]
    pub const fn child_node_id(&self) -> NodeId {
        self.child_node_id
    }

    /// Exact active outpoint consumed by the transaction.
    #[must_use]
    pub const fn state_outpoint(&self) -> [u8; 36] {
        self.state_outpoint
    }

    /// Stable witness-independent child transaction identifier.
    #[must_use]
    pub const fn child_txid(&self) -> [u8; 32] {
        self.child_txid
    }

    /// Complete witness-bearing transaction authorized for broadcast.
    #[must_use]
    pub fn transaction(&self) -> &[u8] {
        &self.transaction
    }

    /// Role-local configuration digest.
    #[must_use]
    pub const fn shared_config_hash(&self) -> [u8; 32] {
        self.shared_config_hash
    }

    /// Descriptor-bound game identifier.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Audited graph root.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }

    /// CHAIN identity authenticating local verification.
    #[must_use]
    pub const fn verifier_role(&self) -> Role {
        self.verifier_role
    }
}

impl Encode for RuntimeAuthorizationReceipt {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        encode_runtime_authorization_unsigned(self, writer)?;
        self.verifier_signature.encode(writer)
    }
}

impl Decode for RuntimeAuthorizationReceipt {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            version: Decode::decode(reader)?,
            shared_config_hash: Decode::decode(reader)?,
            chain_game_id: Decode::decode(reader)?,
            graph_root: Decode::decode(reader)?,
            parent_node_id: Decode::decode(reader)?,
            child_node_id: Decode::decode(reader)?,
            state_outpoint: Decode::decode(reader)?,
            child_txid: Decode::decode(reader)?,
            transaction: reader.read_byte_vector(MAX_RUNTIME_TRANSACTION_BYTES)?,
            verifier_role: Decode::decode(reader)?,
            verifier_signature: Decode::decode(reader)?,
        };
        validate_runtime_authorization_shape(&value).map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

/// Issue a compact signed receipt from one completed streaming graph audit.
///
/// # Errors
///
/// Rejects an internally inconsistent graph summary or invalid signature.
pub fn issue_graph_prepared_receipt<F>(
    summary: &CompiledGraphSummary,
    shared_config_hash: [u8; 32],
    verifier_role: Role,
    sign_digest: F,
) -> Result<GraphPreparedReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    let mut receipt = GraphPreparedReceipt {
        version: RECEIPT_VERSION,
        shared_config_hash,
        manifest: summary.manifest().clone(),
        root_node_id: summary.root_node_id(),
        activation: summary.activation_template().to_logical_transaction(),
        preauthorization_counts: [
            summary.preauthorization_count(Role::Alice),
            summary.preauthorization_count(Role::Bob),
        ],
        runtime_signature_counts: [
            summary.runtime_signature_count(Role::Alice),
            summary.runtime_signature_count(Role::Bob),
        ],
        lamport_counts: [
            summary.lamport_count(Role::Alice),
            summary.lamport_count(Role::Bob),
        ],
        verifier_role,
        verifier_signature: [0; 64],
    };
    validate_graph_prepared_shape(&receipt)?;
    receipt.verifier_signature = sign_digest(graph_prepared_digest(&receipt)?);
    verify_graph_prepared_receipt(
        // A summary is created only from an already verified descriptor. This
        // local check still verifies all descriptor-bound fields and signature.
        summary.descriptor(),
        shared_config_hash,
        verifier_role,
        &receipt,
    )?;
    Ok(receipt)
}

/// Verify a graph receipt against the exact signed descriptor binding.
///
/// # Errors
///
/// Rejects substituted configuration, descriptor, manifest, activation, role,
/// or identity signature fields.
pub fn verify_graph_prepared_receipt(
    descriptor: &ChainGameDescriptor,
    shared_config_hash: [u8; 32],
    expected_verifier_role: Role,
    receipt: &GraphPreparedReceipt,
) -> Result<(), CompilerError> {
    validate_graph_prepared_shape(receipt)?;
    let expected_game_id = chain_game_id(descriptor)?;
    if receipt.shared_config_hash != shared_config_hash
        || receipt.manifest.chain_game_id != expected_game_id
        || receipt.manifest.compiler_id != descriptor.compiler_id
        || receipt.manifest.fee_policy_id != descriptor.fee_policy_id
        || receipt.verifier_role != expected_verifier_role
        || receipt.activation.input_outpoint != descriptor.funding_outpoint
        || receipt.activation.outputs.len() != 1
    {
        return Err(invalid("graph receipt binding differs from the descriptor"));
    }
    verify_receipt_signature(
        descriptor,
        receipt.verifier_role,
        graph_prepared_digest(receipt)?,
        receipt.verifier_signature,
    )
}

/// Issue a compact signed active-state projection.
///
/// `receipt` must carry a zeroed signature; the callback signs its canonical
/// unsigned digest. Keeping construction explicit makes the caller prove every
/// field came from the same already-verified CHAIN transition.
pub fn issue_confirmed_state_receipt<F>(
    descriptor: &VerifiedChainDescriptor,
    mut receipt: ConfirmedStateReceipt,
    sign_digest: F,
) -> Result<ConfirmedStateReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    if receipt.verifier_signature != [0; 64] {
        return Err(invalid("new confirmed-state receipt contains a signature"));
    }
    validate_confirmed_state_shape(&receipt)?;
    receipt.verifier_signature = sign_digest(confirmed_state_digest(&receipt)?);
    verify_confirmed_state_receipt(
        descriptor.as_descriptor(),
        receipt.shared_config_hash,
        receipt.graph_root,
        receipt.verifier_role,
        &receipt,
    )?;
    Ok(receipt)
}

/// Verify a compact active-state receipt without materializing any graph.
///
/// # Errors
///
/// Rejects malformed state/edge facts, graph or config substitution, or an
/// invalid local identity signature.
pub fn verify_confirmed_state_receipt(
    descriptor: &ChainGameDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    expected_verifier_role: Role,
    receipt: &ConfirmedStateReceipt,
) -> Result<(), CompilerError> {
    validate_confirmed_state_shape(receipt)?;
    if receipt.shared_config_hash != shared_config_hash
        || receipt.chain_game_id != chain_game_id(descriptor)?
        || receipt.graph_root != expected_graph_root
        || receipt.verifier_role != expected_verifier_role
    {
        return Err(invalid(
            "confirmed-state receipt binding differs from the session",
        ));
    }
    verify_receipt_signature(
        descriptor,
        receipt.verifier_role,
        confirmed_state_digest(receipt)?,
        receipt.verifier_signature,
    )
}

/// Sign one CHAIN-verified, witness-bearing active-edge transaction.
///
/// # Errors
///
/// Rejects malformed transaction bindings or an invalid generated signature.
pub fn issue_runtime_authorization_receipt<F>(
    descriptor: &VerifiedChainDescriptor,
    mut receipt: RuntimeAuthorizationReceipt,
    sign_digest: F,
) -> Result<RuntimeAuthorizationReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    if receipt.verifier_signature != [0; 64] {
        return Err(invalid("new runtime receipt contains a signature"));
    }
    validate_runtime_authorization_shape(&receipt)?;
    receipt.verifier_signature = sign_digest(runtime_authorization_digest(&receipt)?);
    verify_runtime_authorization_receipt(
        descriptor.as_descriptor(),
        receipt.shared_config_hash,
        receipt.graph_root,
        receipt.verifier_role,
        &receipt,
    )?;
    Ok(receipt)
}

/// Verify an authorized-edge receipt without materializing a graph page.
///
/// # Errors
///
/// Rejects a substituted config/game/graph, transaction, or identity signature.
pub fn verify_runtime_authorization_receipt(
    descriptor: &ChainGameDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    expected_verifier_role: Role,
    receipt: &RuntimeAuthorizationReceipt,
) -> Result<(), CompilerError> {
    validate_runtime_authorization_shape(receipt)?;
    if receipt.shared_config_hash != shared_config_hash
        || receipt.chain_game_id != chain_game_id(descriptor)?
        || receipt.graph_root != expected_graph_root
        || receipt.verifier_role != expected_verifier_role
    {
        return Err(invalid("runtime receipt binding differs from the session"));
    }
    verify_receipt_signature(
        descriptor,
        receipt.verifier_role,
        runtime_authorization_digest(receipt)?,
        receipt.verifier_signature,
    )
}

impl ConfirmedStateReceipt {
    /// Construct an unsigned receipt for [`issue_confirmed_state_receipt`].
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn unsigned(
        shared_config_hash: [u8; 32],
        chain_game_id: [u8; 32],
        graph_root: [u8; 32],
        spent_node_id: Option<NodeId>,
        spent_outpoint: [u8; 36],
        state_outpoint: [u8; 36],
        state_output: Option<LogicalOutput>,
        state_record: LogicalNodeRecord,
        balances: PublicStateBalances,
        confirmed_height: u32,
        edges: Vec<PublicEdgeReceipt>,
        verifier_role: Role,
    ) -> Self {
        Self {
            version: RECEIPT_VERSION,
            shared_config_hash,
            chain_game_id,
            graph_root,
            spent_node_id,
            spent_outpoint,
            state_outpoint,
            state_output,
            state_record,
            balances,
            confirmed_height,
            edges,
            verifier_role,
            verifier_signature: [0; 64],
        }
    }
}

fn validate_graph_prepared_shape(receipt: &GraphPreparedReceipt) -> Result<(), CompilerError> {
    receipt.activation.validate()?;
    if receipt.version != RECEIPT_VERSION
        || receipt.shared_config_hash == [0; 32]
        || receipt.manifest.chain_game_id == [0; 32]
        || receipt.manifest.graph_root == [0; 32]
        || receipt.manifest.alice_lamport_bundle_root == [0; 32]
        || receipt.manifest.bob_lamport_bundle_root == [0; 32]
        || receipt.root_node_id == [0; 32]
        || receipt.manifest.node_count == 0
        || receipt.manifest.transaction_count.checked_add(1) != Some(receipt.manifest.node_count)
        || receipt.manifest.maximum_path_length == 0
        || receipt.activation.outputs.len() != 1
        || receipt.activation.txid == [0; 32]
        || receipt.preauthorization_counts.contains(&0)
        || receipt.runtime_signature_counts.contains(&0)
        || receipt.lamport_counts.contains(&0)
    {
        return Err(invalid("graph receipt has noncanonical or empty fields"));
    }
    if receipt.verifier_signature != [0; 64]
        && Signature::from_slice(&receipt.verifier_signature).is_err()
    {
        return Err(invalid("graph receipt signature is not canonical BIP340"));
    }
    Ok(())
}

fn validate_confirmed_state_shape(receipt: &ConfirmedStateReceipt) -> Result<(), CompilerError> {
    receipt.state_record.validate()?;
    if receipt.version != RECEIPT_VERSION
        || receipt.shared_config_hash == [0; 32]
        || receipt.chain_game_id == [0; 32]
        || receipt.graph_root == [0; 32]
        || receipt.spent_outpoint == [0; 36]
        || receipt.state_outpoint == [0; 36]
        || receipt.state_record.node_id == [0; 32]
        || receipt.edges.len() > MAX_NODE_CHILDREN
    {
        return Err(invalid("confirmed-state receipt has invalid public fields"));
    }
    let state_txid = &receipt.state_outpoint[..32];
    if receipt.state_outpoint[32..] != 0_u32.to_le_bytes()
        || receipt.state_record.child_node_ids.len() != receipt.edges.len()
        || receipt.state_record.node_kind.is_terminal() != receipt.edges.is_empty()
    {
        return Err(invalid(
            "confirmed-state receipt has an invalid state shape",
        ));
    }
    match (
        &receipt.state_output,
        receipt.state_record.node_kind.is_terminal(),
    ) {
        (Some(output), false) if receipt.balances.total()? <= output.value_sat => {}
        (None, true) => {}
        _ => {
            return Err(invalid(
                "confirmed-state receipt output differs from terminal status",
            ));
        }
    }
    if let Some(transaction) = &receipt.state_record.transaction {
        if transaction.txid.as_slice() != state_txid {
            return Err(invalid("confirmed state outpoint differs from its record"));
        }
    } else if receipt.spent_node_id.is_some() {
        return Err(invalid(
            "non-activation state omits its creating transaction",
        ));
    }
    for (index, advertised) in receipt.edges.iter().enumerate() {
        advertised.edge.validate()?;
        if advertised.edge.parent_node_id != receipt.state_record.node_id
            || advertised.edge.child_node_id != receipt.state_record.child_node_ids[index]
            || advertised.edge.transaction.input_outpoint != receipt.state_outpoint
            || advertised.sighash == [0; 32]
        {
            return Err(invalid(
                "confirmed-state edge differs from its active record",
            ));
        }
    }
    if receipt.verifier_signature != [0; 64]
        && Signature::from_slice(&receipt.verifier_signature).is_err()
    {
        return Err(invalid("confirmed-state signature is not canonical BIP340"));
    }
    Ok(())
}

fn validate_runtime_authorization_shape(
    receipt: &RuntimeAuthorizationReceipt,
) -> Result<(), CompilerError> {
    if receipt.version != RECEIPT_VERSION
        || receipt.shared_config_hash == [0; 32]
        || receipt.chain_game_id == [0; 32]
        || receipt.graph_root == [0; 32]
        || receipt.parent_node_id == [0; 32]
        || receipt.child_node_id == [0; 32]
        || receipt.parent_node_id == receipt.child_node_id
        || receipt.state_outpoint == [0; 36]
        || receipt.child_txid == [0; 32]
        || receipt.transaction.is_empty()
        || receipt.transaction.len() > MAX_RUNTIME_TRANSACTION_BYTES
    {
        return Err(invalid("runtime receipt has invalid or empty fields"));
    }
    let transaction: bitcoin::Transaction = deserialize(&receipt.transaction)
        .map_err(|_| invalid("runtime receipt transaction is not Bitcoin consensus data"))?;
    if serialize(&transaction) != receipt.transaction
        || transaction.input.len() != 1
        || consensus_outpoint(transaction.input[0].previous_output) != receipt.state_outpoint
        || transaction.compute_txid().to_byte_array() != receipt.child_txid
        || transaction.input[0].witness.is_empty()
    {
        return Err(invalid("runtime receipt transaction binding is invalid"));
    }
    if receipt.verifier_signature != [0; 64]
        && Signature::from_slice(&receipt.verifier_signature).is_err()
    {
        return Err(invalid("runtime receipt signature is not canonical BIP340"));
    }
    Ok(())
}

fn encode_graph_prepared_unsigned(
    receipt: &GraphPreparedReceipt,
    writer: &mut Writer,
) -> Result<(), CodecError> {
    receipt.version.encode(writer)?;
    receipt.shared_config_hash.encode(writer)?;
    receipt.manifest.encode(writer)?;
    receipt.root_node_id.encode(writer)?;
    receipt.activation.encode(writer)?;
    receipt.preauthorization_counts[0].encode(writer)?;
    receipt.preauthorization_counts[1].encode(writer)?;
    receipt.runtime_signature_counts[0].encode(writer)?;
    receipt.runtime_signature_counts[1].encode(writer)?;
    receipt.lamport_counts[0].encode(writer)?;
    receipt.lamport_counts[1].encode(writer)?;
    receipt.verifier_role.encode(writer)
}

fn encode_confirmed_state_unsigned(
    receipt: &ConfirmedStateReceipt,
    writer: &mut Writer,
) -> Result<(), CodecError> {
    receipt.version.encode(writer)?;
    receipt.shared_config_hash.encode(writer)?;
    receipt.chain_game_id.encode(writer)?;
    receipt.graph_root.encode(writer)?;
    encode_optional_node(receipt.spent_node_id, writer)?;
    receipt.spent_outpoint.encode(writer)?;
    receipt.state_outpoint.encode(writer)?;
    encode_optional_output(receipt.state_output.as_ref(), writer)?;
    receipt.state_record.encode(writer)?;
    receipt.balances.encode(writer)?;
    receipt.confirmed_height.encode(writer)?;
    encode_edges(&receipt.edges, writer)?;
    receipt.verifier_role.encode(writer)
}

fn encode_runtime_authorization_unsigned(
    receipt: &RuntimeAuthorizationReceipt,
    writer: &mut Writer,
) -> Result<(), CodecError> {
    receipt.version.encode(writer)?;
    receipt.shared_config_hash.encode(writer)?;
    receipt.chain_game_id.encode(writer)?;
    receipt.graph_root.encode(writer)?;
    receipt.parent_node_id.encode(writer)?;
    receipt.child_node_id.encode(writer)?;
    receipt.state_outpoint.encode(writer)?;
    receipt.child_txid.encode(writer)?;
    writer.write_byte_vector(&receipt.transaction)?;
    receipt.verifier_role.encode(writer)
}

fn graph_prepared_digest(receipt: &GraphPreparedReceipt) -> Result<[u8; 32], CompilerError> {
    let mut writer = Writer::new();
    encode_graph_prepared_unsigned(receipt, &mut writer)?;
    Ok(tagged_hash(GRAPH_PREPARED_TAG, writer.as_bytes()))
}

fn confirmed_state_digest(receipt: &ConfirmedStateReceipt) -> Result<[u8; 32], CompilerError> {
    let mut writer = Writer::new();
    encode_confirmed_state_unsigned(receipt, &mut writer)?;
    Ok(tagged_hash(CONFIRMED_STATE_TAG, writer.as_bytes()))
}

fn runtime_authorization_digest(
    receipt: &RuntimeAuthorizationReceipt,
) -> Result<[u8; 32], CompilerError> {
    let mut writer = Writer::new();
    encode_runtime_authorization_unsigned(receipt, &mut writer)?;
    Ok(tagged_hash(RUNTIME_AUTHORIZATION_TAG, writer.as_bytes()))
}

fn verify_receipt_signature(
    descriptor: &ChainGameDescriptor,
    role: Role,
    digest: [u8; 32],
    signature: [u8; 64],
) -> Result<(), CompilerError> {
    let public = XOnlyPublicKey::from_slice(descriptor.identity_key(role))
        .map_err(|_| invalid("receipt verifier identity is not a canonical x-only public key"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| invalid("receipt signature is not canonical BIP340"))?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &Message::from_digest(digest), &public)
        .map_err(|_| invalid("receipt identity signature is invalid"))
}

fn decode_manifest(reader: &mut Reader<'_>) -> Result<GraphManifest, CodecError> {
    Ok(GraphManifest {
        chain_game_id: Decode::decode(reader)?,
        graph_root: Decode::decode(reader)?,
        alice_lamport_bundle_root: Decode::decode(reader)?,
        bob_lamport_bundle_root: Decode::decode(reader)?,
        compiler_id: Decode::decode(reader)?,
        fee_policy_id: Decode::decode(reader)?,
        node_count: Decode::decode(reader)?,
        transaction_count: Decode::decode(reader)?,
        maximum_path_length: Decode::decode(reader)?,
    })
}

fn encode_edges(edges: &[PublicEdgeReceipt], writer: &mut Writer) -> Result<(), CodecError> {
    let len = u8::try_from(edges.len()).map_err(|_| CodecError::LengthOverflow)?;
    len.encode(writer)?;
    for edge in edges {
        edge.encode(writer)?;
    }
    Ok(())
}

fn decode_edges(reader: &mut Reader<'_>) -> Result<Vec<PublicEdgeReceipt>, CodecError> {
    let len = usize::from(u8::decode(reader)?);
    if len > MAX_NODE_CHILDREN {
        return Err(CodecError::LengthLimitExceeded);
    }
    (0..len).map(|_| Decode::decode(reader)).collect()
}

fn encode_optional_node(value: Option<NodeId>, writer: &mut Writer) -> Result<(), CodecError> {
    match value {
        None => 0_u8.encode(writer),
        Some(node_id) => {
            1_u8.encode(writer)?;
            node_id.encode(writer)
        }
    }
}

fn decode_optional_node(reader: &mut Reader<'_>) -> Result<Option<NodeId>, CodecError> {
    match u8::decode(reader)? {
        0 => Ok(None),
        1 => Ok(Some(Decode::decode(reader)?)),
        _ => Err(CodecError::NonCanonical),
    }
}

fn encode_optional_output(
    value: Option<&LogicalOutput>,
    writer: &mut Writer,
) -> Result<(), CodecError> {
    match value {
        None => 0_u8.encode(writer),
        Some(output) => {
            1_u8.encode(writer)?;
            output.encode(writer)
        }
    }
}

fn decode_optional_output(reader: &mut Reader<'_>) -> Result<Option<LogicalOutput>, CodecError> {
    match u8::decode(reader)? {
        0 => Ok(None),
        1 => Ok(Some(Decode::decode(reader)?)),
        _ => Err(CodecError::NonCanonical),
    }
}

fn consensus_outpoint(outpoint: bitcoin::OutPoint) -> [u8; 36] {
    let mut value = [0; 36];
    value[..32].copy_from_slice(&outpoint.txid.to_byte_array());
    value[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    value
}

const fn role_index(role: Role) -> usize {
    match role {
        Role::Alice => 0,
        Role::Bob => 1,
    }
}

fn tagged_hash(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(bytes);
    hash.finalize().into()
}

const fn invalid(reason: &'static str) -> CompilerError {
    CompilerError::InvalidGraphReceipt { reason }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use bp52_chain_types::{
        AuthorizationPolicy, EdgeKind, LogicalNodeRecord, LogicalOutput, LogicalTransaction,
        NodeKind, Phase, Role,
    };
    use bp52_codec::{Decode, Encode};

    use super::{
        ConfirmedStateReceipt, PublicEdgeReceipt, PublicStateBalances, confirmed_state_digest,
        issue_confirmed_state_receipt, verify_confirmed_state_receipt,
    };
    use crate::test_support::verified_descriptor_fixture;

    fn keypair_for(
        role: Role,
        descriptor: &bp52_chain_types::ChainGameDescriptor,
    ) -> Result<Keypair, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        for value in [1_u8, 2] {
            let mut secret = [0; 32];
            secret[31] = value;
            let Ok(keypair) = Keypair::from_seckey_slice(&secp, &secret) else {
                continue;
            };
            if keypair.x_only_public_key().0.serialize() == *descriptor.identity_key(role) {
                return Ok(keypair);
            }
        }
        Err("fixture identity has no matching keypair".into())
    }

    #[test]
    fn confirmed_receipt_is_canonical_bound_and_tamper_evident()
    -> Result<(), Box<dyn std::error::Error>> {
        let verified = verified_descriptor_fixture()?;
        let descriptor = verified.as_descriptor();
        let game = bp52_chain_types::chain_game_id(descriptor)?;
        let parent = [7; 32];
        let child = [8; 32];
        let state_outpoint = {
            let mut value = [0; 36];
            value[..32].copy_from_slice(&[9; 32]);
            value
        };
        let child_transaction = LogicalTransaction {
            version: 2,
            lock_time: 0,
            input_outpoint: state_outpoint,
            sequence: u32::MAX,
            outputs: vec![LogicalOutput {
                value_sat: 100,
                script_pubkey: vec![0x51],
            }],
            fee_sat: 1,
            txid: [10; 32],
            non_witness_serialization: vec![1],
        };
        let record = LogicalNodeRecord {
            node_id: parent,
            parent_node_id: None,
            node_kind: NodeKind::Funded,
            logical_state_digest: [11; 32],
            transaction: None,
            required_predicate_id: [12; 32],
            timeout: None,
            child_node_ids: vec![child],
        };
        let edge = bp52_chain_types::LogicalEdge {
            parent_node_id: parent,
            child_node_id: child,
            kind: EdgeKind::Advance {
                phase: Phase::DealAlice,
            },
            transaction: child_transaction,
            authorization: AuthorizationPolicy::BothPresigned,
            timeout: None,
        };
        let mut spent = [0; 36];
        spent[..32].copy_from_slice(&[13; 32]);
        let unsigned = ConfirmedStateReceipt::unsigned(
            [14; 32],
            game,
            [15; 32],
            None,
            spent,
            state_outpoint,
            Some(LogicalOutput {
                value_sat: 1_000,
                script_pubkey: vec![0x51],
            }),
            record,
            PublicStateBalances {
                alice_stack_sat: 400,
                bob_stack_sat: 400,
                pot_sat: 200,
            },
            100,
            vec![PublicEdgeReceipt {
                edge,
                sighash: [16; 32],
            }],
            Role::Alice,
        );
        let keypair = keypair_for(Role::Alice, descriptor)?;
        let secp = Secp256k1::new();
        let receipt = issue_confirmed_state_receipt(&verified, unsigned, |digest| {
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                .serialize()
        })?;
        verify_confirmed_state_receipt(descriptor, [14; 32], [15; 32], Role::Alice, &receipt)?;
        let encoded = receipt.encode_to_vec()?;
        assert_eq!(ConfirmedStateReceipt::decode_exact(&encoded)?, receipt);

        let mut changed = receipt.clone();
        changed.confirmed_height += 1;
        assert_ne!(
            confirmed_state_digest(&changed)?,
            confirmed_state_digest(&receipt)?
        );
        assert!(
            verify_confirmed_state_receipt(descriptor, [14; 32], [15; 32], Role::Alice, &changed)
                .is_err()
        );
        Ok(())
    }
}
