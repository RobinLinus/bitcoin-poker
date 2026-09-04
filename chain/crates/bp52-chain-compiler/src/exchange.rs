//! Commit-then-open exchange for graph roots and preauthorization bundles.

use std::{collections::HashSet, fmt};

use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use bp52_chain_bitcoin::{DefaultSighashSignature, verify_sighash_default};
use bp52_chain_types::{
    ChainError, ChainGameDescriptor, NodeId, Role, VerifiedChainDescriptor, chain_game_id,
    tagged_sha256,
};
use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CompilerError, readiness::RuntimeSignatureKind};

const GRAPH_ROOT_COMMIT_TAG: &str = "BP52/chain-graph-root-commit/v1";
const SIGNATURE_BUNDLE_COMMIT_TAG: &str = "BP52/chain-signature-bundle-commit/v1";
const COMMITMENT_SIGNATURE_TAG: &str = "BP52/chain-commitment-signature/v1";
const SIGNED_COMMITMENT_DIGEST_TAG: &str = "BP52/chain-signed-commitment/v1";
const PREAUTHORIZATION_RECEIPT_TAG: &str = "BP52/preauthorization-verified-receipt/v1";

/// Canonical version of a compact verified-opening receipt.
pub const PREAUTHORIZATION_RECEIPT_VERSION: u16 = 1;
/// Exact encoded length of a compact verified-opening receipt.
pub const PREAUTHORIZATION_RECEIPT_BYTES: usize = 232;

/// Maximum signatures accepted in one participant's bundle.
///
/// Category-specific showdown leaves require 155,641 signatures in the
/// largest fixed-limit role inventory. Keep a power-of-two defensive ceiling
/// above that audited profile while still bounding allocations and decoding.
pub const MAX_PREAUTHORIZATIONS_PER_ROLE: usize = 262_144;

/// Opaque evidence that both identity-authenticated graph-root openings were
/// valid for the same signed descriptor and opened the same value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgreedGraphRoot {
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
}

impl AgreedGraphRoot {
    /// Return the descriptor-bound chain game identifier.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Return the graph root opened identically by both participants.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }
}

/// Domain of one signed commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CommitmentPurpose {
    /// Commitment to the independently compiled canonical graph root.
    GraphRoot = 0,
    /// Commitment to one role's complete preauthorization bundle.
    PreauthorizationBundle = 1,
}

impl CommitmentPurpose {
    const fn code(self) -> u8 {
        self as u8
    }
}

impl Encode for CommitmentPurpose {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.code().encode(writer)
    }
}

impl Decode for CommitmentPurpose {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match u8::decode(reader)? {
            0 => Ok(Self::GraphRoot),
            1 => Ok(Self::PreauthorizationBundle),
            _ => Err(CodecError::NonCanonical),
        }
    }
}

/// Long-term-authenticated commitment sent before an opening is disclosed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedCommitment {
    chain_game_id: [u8; 32],
    role: Role,
    purpose: CommitmentPurpose,
    commitment: [u8; 32],
    signature: [u8; 64],
}

impl SignedCommitment {
    /// Return the committed chain game.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Return the authenticated participant.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Return the commitment domain.
    #[must_use]
    pub const fn purpose(&self) -> CommitmentPurpose {
        self.purpose
    }

    /// Return the hiding commitment digest.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Return the BIP340 identity signature.
    #[must_use]
    pub const fn signature(&self) -> [u8; 64] {
        self.signature
    }
}

impl Encode for SignedCommitment {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.chain_game_id.encode(writer)?;
        self.role.encode(writer)?;
        self.purpose.encode(writer)?;
        self.commitment.encode(writer)?;
        self.signature.encode(writer)
    }
}

impl Decode for SignedCommitment {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            chain_game_id: <[u8; 32]>::decode(reader)?,
            role: Role::decode(reader)?,
            purpose: CommitmentPurpose::decode(reader)?,
            commitment: <[u8; 32]>::decode(reader)?,
            signature: <[u8; 64]>::decode(reader)?,
        })
    }
}

/// Opening for one participant's graph-root commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphRootOpening {
    chain_game_id: [u8; 32],
    role: Role,
    nonce: [u8; 32],
    graph_root: [u8; 32],
}

impl GraphRootOpening {
    /// Construct a role- and game-bound opening.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero nonce, which is not a valid fresh commitment nonce.
    pub fn new(
        chain_game_id: [u8; 32],
        role: Role,
        nonce: [u8; 32],
        graph_root: [u8; 32],
    ) -> Result<Self, CompilerError> {
        require_fresh_nonce(nonce)?;
        Ok(Self {
            chain_game_id,
            role,
            nonce,
            graph_root,
        })
    }

    /// Return the opened graph root.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }

    /// Return the committing role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
}

impl Encode for GraphRootOpening {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.chain_game_id.encode(writer)?;
        self.role.encode(writer)?;
        self.nonce.encode(writer)?;
        self.graph_root.encode(writer)
    }
}

impl Decode for GraphRootOpening {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let opening = Self {
            chain_game_id: <[u8; 32]>::decode(reader)?,
            role: Role::decode(reader)?,
            nonce: <[u8; 32]>::decode(reader)?,
            graph_root: <[u8; 32]>::decode(reader)?,
        };
        if opening.nonce == [0; 32] {
            return Err(CodecError::NonCanonical);
        }
        Ok(opening)
    }
}

/// One fixed transaction signature requested from a named participant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SignatureRequest {
    /// State output being spent.
    pub parent_node_id: NodeId,
    /// Exact branch transaction being authorized.
    pub child_node_id: NodeId,
    /// Participant whose signature is requested.
    pub signer: Role,
    /// Exact BIP341 `SIGHASH_DEFAULT` digest, with ALL commitment semantics.
    pub sighash: [u8; 32],
}

impl Encode for SignatureRequest {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.parent_node_id.encode(writer)?;
        self.child_node_id.encode(writer)?;
        self.signer.encode(writer)?;
        self.sighash.encode(writer)
    }
}

impl Decode for SignatureRequest {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            parent_node_id: <[u8; 32]>::decode(reader)?,
            child_node_id: <[u8; 32]>::decode(reader)?,
            signer: Role::decode(reader)?,
            sighash: <[u8; 32]>::decode(reader)?,
        })
    }
}

/// One graph-derived Bitcoin signature request deliberately retained locally.
///
/// These requests are never part of the counterparty preauthorization
/// exchange. They cover Bob's live terminal-payout choice and each role's
/// own CSV-timeout branches. Betting actions are not retained requests: the
/// actor signs only the selected transaction through the runtime signer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuntimeSignatureRequest {
    /// Exact graph transaction digest and signer.
    pub request: SignatureRequest,
    /// Reason this signature remains private until the branch is exercised.
    pub kind: RuntimeSignatureKind,
}

/// One locally retained response to an exact runtime signature request.
///
/// The response intentionally does not implement `Clone` or `Debug`. Its
/// signature bytes are erased when the value is dropped.
pub struct RuntimeSignatureResponse {
    request: RuntimeSignatureRequest,
    signature: [u8; 64],
}

impl RuntimeSignatureResponse {
    /// Construct one canonical implicit-`SIGHASH_DEFAULT` response.
    ///
    /// Graph membership and cryptographic validity are checked by
    /// [`crate::CompiledGraph::verify_private_runtime_signature_bundle`].
    ///
    /// # Errors
    ///
    /// Rejects bytes that are not a canonical BIP340 signature encoding.
    pub fn new(
        request: RuntimeSignatureRequest,
        mut signature: [u8; 64],
    ) -> Result<Self, CompilerError> {
        if let Err(error) = DefaultSighashSignature::from_bytes(signature) {
            signature.zeroize();
            return Err(error.into());
        }
        Ok(Self { request, signature })
    }

    /// Return the exact request answered by this response.
    #[must_use]
    pub const fn request(&self) -> RuntimeSignatureRequest {
        self.request
    }

    pub(crate) const fn signature_bytes(&self) -> [u8; 64] {
        self.signature
    }
}

impl Drop for RuntimeSignatureResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for RuntimeSignatureResponse {
    fn zeroize(&mut self) {
        self.signature.zeroize();
    }
}

impl ZeroizeOnDrop for RuntimeSignatureResponse {}

/// Opaque, graph-verified collection of locally retained runtime signatures.
///
/// This owner intentionally implements neither `Clone` nor `Debug`. All
/// contained signatures are erased when it is dropped.
pub struct PrivateRuntimeSignatureBundle {
    pub(crate) chain_game_id: [u8; 32],
    pub(crate) graph_root: [u8; 32],
    pub(crate) role: Role,
    entries: Vec<RuntimeSignatureResponse>,
}

impl PrivateRuntimeSignatureBundle {
    pub(crate) const fn verified(
        chain_game_id: [u8; 32],
        graph_root: [u8; 32],
        role: Role,
        entries: Vec<RuntimeSignatureResponse>,
    ) -> Self {
        Self {
            chain_game_id,
            graph_root,
            role,
            entries,
        }
    }

    /// Return the role controlling every signature in this bundle.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Return the exact number of retained runtime signatures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether this graph requires no private signatures from the role.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return one verified signature for an exact graph request.
    ///
    /// The returned signature is a public witness value; the bundle retains
    /// and erases its owned copy until the caller drops the inventory token.
    #[must_use]
    pub fn signature(&self, request: RuntimeSignatureRequest) -> Option<DefaultSighashSignature> {
        self.entries
            .iter()
            .find(|entry| entry.request() == request)
            .and_then(|entry| DefaultSighashSignature::from_bytes(entry.signature_bytes()).ok())
    }
}

impl Drop for PrivateRuntimeSignatureBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for PrivateRuntimeSignatureBundle {
    fn zeroize(&mut self) {
        self.chain_game_id.zeroize();
        self.graph_root.zeroize();
        for entry in &mut self.entries {
            entry.zeroize();
        }
    }
}

impl ZeroizeOnDrop for PrivateRuntimeSignatureBundle {}

/// One implicit-`SIGHASH_DEFAULT` response to a canonical signature request.
#[derive(Eq, PartialEq)]
pub struct Preauthorization {
    /// Exact request whose digest is signed.
    pub request: SignatureRequest,
    /// Canonical 64-byte Schnorr signature with no explicit sighash byte.
    pub signature: [u8; 64],
}

impl fmt::Debug for Preauthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preauthorization")
            .field("request", &self.request)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for Preauthorization {
    fn zeroize(&mut self) {
        self.signature.zeroize();
    }
}

impl Drop for Preauthorization {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Preauthorization {}

impl Encode for Preauthorization {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.request.encode(writer)?;
        self.signature.encode(writer)
    }
}

impl Decode for Preauthorization {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            request: SignatureRequest::decode(reader)?,
            signature: <[u8; 64]>::decode(reader)?,
        };
        DefaultSighashSignature::from_bytes(value.signature)
            .map_err(|_| CodecError::NonCanonical)?;
        Ok(value)
    }
}

/// Complete signatures for one role in canonical graph-request order.
///
/// Requests are deterministic graph data and are deliberately not serialized
/// in the bundle. A decoder retains only one 64-byte signature per request;
/// verification zips these signatures with the locally re-derived request
/// list and fails closed on a count, role, or signature mismatch.
#[derive(Eq, PartialEq)]
pub struct PreauthorizationBundle {
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    role: Role,
    signatures: Vec<[u8; 64]>,
}

impl fmt::Debug for PreauthorizationBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreauthorizationBundle")
            .field("chain_game_id", &self.chain_game_id)
            .field("graph_root", &self.graph_root)
            .field("role", &self.role)
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

impl Zeroize for PreauthorizationBundle {
    fn zeroize(&mut self) {
        self.chain_game_id.zeroize();
        self.graph_root.zeroize();
        self.signatures.zeroize();
    }
}

impl Drop for PreauthorizationBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PreauthorizationBundle {}

impl PreauthorizationBundle {
    /// Construct a canonical bundle.
    ///
    /// # Errors
    ///
    /// Rejects oversized, unsorted, duplicate, or wrong-role entries.
    pub fn new(
        chain_game_id: [u8; 32],
        graph_root: [u8; 32],
        role: Role,
        entries: Vec<Preauthorization>,
    ) -> Result<Self, CompilerError> {
        if graph_root == [0; 32] {
            return Err(CompilerError::ExchangeGraphMismatch);
        }
        validate_preauthorizations(role, &entries)?;
        Ok(Self {
            chain_game_id,
            graph_root,
            role,
            signatures: entries.into_iter().map(|entry| entry.signature).collect(),
        })
    }

    /// Return the bundle owner/signer.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Return the exact deterministic graph authorized by every signature.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }

    /// Return all signatures in canonical graph-request order.
    #[must_use]
    pub fn signatures(&self) -> &[[u8; 64]] {
        &self.signatures
    }

    /// Return the number of graph-derived requests answered by this bundle.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Return whether this bundle answers no requests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

impl Encode for PreauthorizationBundle {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.chain_game_id.encode(writer)?;
        self.graph_root.encode(writer)?;
        self.role.encode(writer)?;
        let count = u32::try_from(self.signatures.len()).map_err(|_| CodecError::LengthOverflow)?;
        count.encode(writer)?;
        for signature in &self.signatures {
            signature.encode(writer)?;
        }
        Ok(())
    }
}

impl Decode for PreauthorizationBundle {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let chain_game_id = <[u8; 32]>::decode(reader)?;
        let graph_root = <[u8; 32]>::decode(reader)?;
        if graph_root == [0; 32] {
            return Err(CodecError::NonCanonical);
        }
        let role = Role::decode(reader)?;
        let count =
            usize::try_from(u32::decode(reader)?).map_err(|_| CodecError::LengthOverflow)?;
        if count > MAX_PREAUTHORIZATIONS_PER_ROLE {
            return Err(CodecError::LengthLimitExceeded);
        }
        let mut signatures = zeroize::Zeroizing::new(Vec::with_capacity(count));
        for _ in 0..count {
            let signature = <[u8; 64]>::decode(reader)?;
            DefaultSighashSignature::from_bytes(signature).map_err(|_| CodecError::NonCanonical)?;
            signatures.push(signature);
        }
        Ok(Self {
            chain_game_id,
            graph_root,
            role,
            signatures: std::mem::take(&mut *signatures),
        })
    }
}

/// Opening for one role's complete preauthorization bundle commitment.
#[derive(Eq, PartialEq)]
pub struct SignatureBundleOpening {
    nonce: [u8; 32],
    bundle: PreauthorizationBundle,
}

impl fmt::Debug for SignatureBundleOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignatureBundleOpening")
            .field("nonce", &"[REDACTED]")
            .field("bundle", &self.bundle)
            .finish()
    }
}

impl Zeroize for SignatureBundleOpening {
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.bundle.zeroize();
    }
}

impl Drop for SignatureBundleOpening {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SignatureBundleOpening {}

impl SignatureBundleOpening {
    /// Construct a one-time bundle opening.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero nonce.
    pub fn new(nonce: [u8; 32], bundle: PreauthorizationBundle) -> Result<Self, CompilerError> {
        require_fresh_nonce(nonce)?;
        Ok(Self { nonce, bundle })
    }

    /// Return the opened bundle.
    #[must_use]
    pub const fn bundle(&self) -> &PreauthorizationBundle {
        &self.bundle
    }

    /// Return the one-time commitment nonce.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
}

impl Encode for SignatureBundleOpening {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.nonce.encode(writer)?;
        self.bundle.encode(writer)
    }
}

impl Decode for SignatureBundleOpening {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let nonce = <[u8; 32]>::decode(reader)?;
        if nonce == [0; 32] {
            return Err(CodecError::NonCanonical);
        }
        Ok(Self {
            nonce,
            bundle: PreauthorizationBundle::decode(reader)?,
        })
    }
}

/// Compact identity-authenticated proof that one opening was fully verified.
///
/// The receipt contains no transaction signatures or graph requests. It lets
/// the game reducer advance from a previously accepted signed commitment while
/// the CHAIN worker remains the sole owner of the peer's packed signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreauthorizationVerifiedReceipt {
    version: u16,
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    graph_root: [u8; 32],
    subject_role: Role,
    signed_commitment_digest: [u8; 32],
    opening_digest: [u8; 32],
    signature_count: u32,
    verifier_role: Role,
    verifier_signature: [u8; 64],
}

impl PreauthorizationVerifiedReceipt {
    /// Return the role whose packed preauthorizations were verified.
    #[must_use]
    pub const fn subject_role(&self) -> Role {
        self.subject_role
    }

    /// Return the role that performed and authenticated verification.
    #[must_use]
    pub const fn verifier_role(&self) -> Role {
        self.verifier_role
    }

    /// Return the role-independent session/deployment binding.
    #[must_use]
    pub const fn shared_config_hash(&self) -> [u8; 32] {
        self.shared_config_hash
    }

    /// Return the descriptor-bound chain game identifier.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Return the exact graph whose requests were verified.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }

    /// Return the digest of the complete subject-authenticated commitment.
    #[must_use]
    pub const fn signed_commitment_digest(&self) -> [u8; 32] {
        self.signed_commitment_digest
    }

    /// Return the commitment value opening the packed bundle.
    #[must_use]
    pub const fn opening_digest(&self) -> [u8; 32] {
        self.opening_digest
    }

    /// Return the exact number of graph requests verified.
    #[must_use]
    pub const fn signature_count(&self) -> u32 {
        self.signature_count
    }
}

impl Encode for PreauthorizationVerifiedReceipt {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.version.encode(writer)?;
        self.shared_config_hash.encode(writer)?;
        self.chain_game_id.encode(writer)?;
        self.graph_root.encode(writer)?;
        self.subject_role.encode(writer)?;
        self.signed_commitment_digest.encode(writer)?;
        self.opening_digest.encode(writer)?;
        self.signature_count.encode(writer)?;
        self.verifier_role.encode(writer)?;
        self.verifier_signature.encode(writer)
    }
}

impl Decode for PreauthorizationVerifiedReceipt {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let value = Self {
            version: u16::decode(reader)?,
            shared_config_hash: <[u8; 32]>::decode(reader)?,
            chain_game_id: <[u8; 32]>::decode(reader)?,
            graph_root: <[u8; 32]>::decode(reader)?,
            subject_role: Role::decode(reader)?,
            signed_commitment_digest: <[u8; 32]>::decode(reader)?,
            opening_digest: <[u8; 32]>::decode(reader)?,
            signature_count: u32::decode(reader)?,
            verifier_role: Role::decode(reader)?,
            verifier_signature: <[u8; 64]>::decode(reader)?,
        };
        if value.version != PREAUTHORIZATION_RECEIPT_VERSION
            || value.shared_config_hash == [0; 32]
            || value.chain_game_id == [0; 32]
            || value.graph_root == [0; 32]
            || value.signed_commitment_digest == [0; 32]
            || value.opening_digest == [0; 32]
            || value.signature_count == 0
            || Signature::from_slice(&value.verifier_signature).is_err()
        {
            return Err(CodecError::NonCanonical);
        }
        Ok(value)
    }
}

/// Verify a raw opening and issue its compact, deterministic receipt.
///
/// The callback receives the receipt's exact tagged digest and must sign with
/// `verifier_role`'s descriptor identity key. Deterministic BIP340 signing
/// makes retries return byte-identical receipt bytes.
///
/// # Errors
///
/// Rejects a wrong config/game/root/role/commitment/request set, an invalid
/// transaction signature, or an invalid verifier signature.
#[allow(clippy::too_many_arguments)]
pub fn issue_preauthorization_verified_receipt<F>(
    verified_descriptor: &VerifiedChainDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
    verifier_role: Role,
    sign_digest: F,
) -> Result<PreauthorizationVerifiedReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    verify_signature_bundle(
        verified_descriptor,
        expected_graph_root,
        signed,
        opening,
        expected_requests,
    )?;
    issue_bound_preauthorization_receipt(
        verified_descriptor,
        shared_config_hash,
        expected_graph_root,
        signed,
        opening,
        expected_requests.len(),
        verifier_role,
        sign_digest,
    )
}

/// Issue a compact receipt for a bundle generated by the verifier itself.
///
/// This is the local-echo fast path. It verifies the complete authenticated
/// game/graph/role/count/opening binding but deliberately does not repeat the
/// per-signature checks: the caller must pass only the exact bundle it created
/// with its own signer. Requiring the verifier and bundle roles to match keeps
/// this API from being used to trust an opponent's signatures.
///
/// # Errors
///
/// Rejects a peer-owned bundle or any wrong config/game/root/role/commitment/
/// request-count binding.
#[allow(clippy::too_many_arguments)]
pub fn issue_locally_generated_preauthorization_receipt<F>(
    verified_descriptor: &VerifiedChainDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
    verifier_role: Role,
    sign_digest: F,
) -> Result<PreauthorizationVerifiedReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    if opening.bundle.role != verifier_role {
        return Err(invalid_receipt(
            "only the bundle owner may trust locally generated signatures",
        ));
    }
    verify_signature_bundle_binding(
        verified_descriptor,
        expected_graph_root,
        signed,
        opening,
        expected_requests,
    )?;
    issue_bound_preauthorization_receipt(
        verified_descriptor,
        shared_config_hash,
        expected_graph_root,
        signed,
        opening,
        expected_requests.len(),
        verifier_role,
        sign_digest,
    )
}

/// Issue a compact receipt after independent workers verified every signature.
///
/// The caller must have verified the exact bound opening against every
/// `expected_requests` entry before calling this function. This function
/// repeats the inexpensive authenticated binding checks and requires the
/// verifier to be the opposite participant, preventing this path from being
/// confused with the locally-generated fast path.
///
/// # Errors
///
/// Rejects a self-owned bundle or any wrong config/game/root/role/commitment/
/// request-count binding.
#[allow(clippy::too_many_arguments)]
pub fn issue_externally_verified_preauthorization_receipt<F>(
    verified_descriptor: &VerifiedChainDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
    verifier_role: Role,
    sign_digest: F,
) -> Result<PreauthorizationVerifiedReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    if opening.bundle.role == verifier_role {
        return Err(invalid_receipt(
            "external verification is reserved for the opponent's signatures",
        ));
    }
    verify_signature_bundle_binding(
        verified_descriptor,
        expected_graph_root,
        signed,
        opening,
        expected_requests,
    )?;
    issue_bound_preauthorization_receipt(
        verified_descriptor,
        shared_config_hash,
        expected_graph_root,
        signed,
        opening,
        expected_requests.len(),
        verifier_role,
        sign_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_bound_preauthorization_receipt<F>(
    verified_descriptor: &VerifiedChainDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_request_count: usize,
    verifier_role: Role,
    sign_digest: F,
) -> Result<PreauthorizationVerifiedReceipt, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    if shared_config_hash == [0; 32] {
        return Err(invalid_receipt("shared config hash is invalid"));
    }
    let signature_count = u32::try_from(expected_request_count)
        .map_err(|_| invalid_receipt("signature count exceeds u32"))?;
    if signature_count == 0 {
        return Err(invalid_receipt("empty bundles do not produce receipts"));
    }
    let mut receipt = PreauthorizationVerifiedReceipt {
        version: PREAUTHORIZATION_RECEIPT_VERSION,
        shared_config_hash,
        chain_game_id: chain_game_id(verified_descriptor.as_descriptor())?,
        graph_root: expected_graph_root,
        subject_role: opening.bundle.role,
        signed_commitment_digest: signed_commitment_digest(signed)?,
        opening_digest: signed.commitment,
        signature_count,
        verifier_role,
        verifier_signature: [0; 64],
    };
    receipt.verifier_signature = sign_digest(receipt_signature_digest(&receipt)?);
    verify_preauthorization_verified_receipt(
        verified_descriptor,
        shared_config_hash,
        expected_graph_root,
        signed,
        signature_count,
        verifier_role,
        &receipt,
    )?;
    Ok(receipt)
}

/// Verify a compact opening receipt without retaining the raw opening.
///
/// # Errors
///
/// Rejects any substituted config, game, graph, role, commitment, count, or
/// verifier signature.
pub fn verify_preauthorization_verified_receipt(
    verified_descriptor: &VerifiedChainDescriptor,
    shared_config_hash: [u8; 32],
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    expected_signature_count: u32,
    expected_verifier_role: Role,
    receipt: &PreauthorizationVerifiedReceipt,
) -> Result<(), CompilerError> {
    let descriptor = verified_descriptor.as_descriptor();
    let expected_game_id = chain_game_id(descriptor)?;
    if receipt.version != PREAUTHORIZATION_RECEIPT_VERSION
        || receipt.shared_config_hash != shared_config_hash
        || receipt.chain_game_id != expected_game_id
        || receipt.graph_root != expected_graph_root
        || receipt.subject_role != signed.role
        || receipt.verifier_role != expected_verifier_role
        || receipt.signed_commitment_digest != signed_commitment_digest(signed)?
        || receipt.opening_digest != signed.commitment
        || receipt.signature_count != expected_signature_count
        || expected_signature_count == 0
    {
        return Err(invalid_receipt(
            "receipt binding differs from expected state",
        ));
    }
    verify_signed_commitment(
        descriptor,
        signed,
        expected_game_id,
        receipt.subject_role,
        CommitmentPurpose::PreauthorizationBundle,
    )?;
    let public_key = XOnlyPublicKey::from_slice(descriptor.identity_key(receipt.verifier_role))
        .map_err(|_| ChainError::InvalidIdentityKey {
            role: receipt.verifier_role,
        })?;
    let signature = Signature::from_slice(&receipt.verifier_signature)
        .map_err(|_| invalid_receipt("verifier signature is not canonical BIP340"))?;
    let message = Message::from_digest(receipt_signature_digest(receipt)?);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| invalid_receipt("verifier signature is invalid"))
}

/// Create and authenticate one graph-root commitment.
///
/// The signing callback receives the exact tagged digest and must use the
/// descriptor identity key for `role`.
///
/// # Errors
///
/// Rejects descriptor/context errors, zero nonces, or a callback signature
/// that does not verify under the claimed identity.
pub fn commit_graph_root<F>(
    verified_descriptor: &VerifiedChainDescriptor,
    role: Role,
    graph_root: [u8; 32],
    nonce: [u8; 32],
    sign_digest: F,
) -> Result<(SignedCommitment, GraphRootOpening), CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    let descriptor = verified_descriptor.as_descriptor();
    let game_id = chain_game_id(descriptor)?;
    let opening = GraphRootOpening::new(game_id, role, nonce, graph_root)?;
    let commitment = graph_root_commitment(&opening)?;
    let authenticated = authenticate_commitment(
        descriptor,
        game_id,
        role,
        CommitmentPurpose::GraphRoot,
        commitment,
        sign_digest,
    )?;
    Ok((authenticated, opening))
}

/// Verify a graph-root commitment/opening pair.
///
/// # Errors
///
/// Rejects wrong games, roles, domains, signatures, or opening digests.
pub fn verify_graph_root_opening(
    verified_descriptor: &VerifiedChainDescriptor,
    signed: &SignedCommitment,
    opening: &GraphRootOpening,
) -> Result<(), CompilerError> {
    verify_graph_root_opening_descriptor(verified_descriptor.as_descriptor(), signed, opening)
}

fn verify_graph_root_opening_descriptor(
    descriptor: &ChainGameDescriptor,
    signed: &SignedCommitment,
    opening: &GraphRootOpening,
) -> Result<(), CompilerError> {
    verify_signed_commitment(
        descriptor,
        signed,
        opening.chain_game_id,
        opening.role,
        CommitmentPurpose::GraphRoot,
    )?;
    if graph_root_commitment(opening)? != signed.commitment {
        return Err(CompilerError::CommitmentMismatch {
            purpose: "graph root",
        });
    }
    Ok(())
}

/// Verify both parties' openings and return their agreed graph root.
///
/// # Errors
///
/// Rejects wrong role placement, either invalid opening, or unequal roots.
pub fn verify_matching_graph_roots(
    verified_descriptor: &VerifiedChainDescriptor,
    alice: (&SignedCommitment, &GraphRootOpening),
    bob: (&SignedCommitment, &GraphRootOpening),
) -> Result<AgreedGraphRoot, CompilerError> {
    let descriptor = verified_descriptor.as_descriptor();
    if alice.1.role != Role::Alice || bob.1.role != Role::Bob {
        return Err(CompilerError::ExchangeRoleMismatch);
    }
    verify_graph_root_opening_descriptor(descriptor, alice.0, alice.1)?;
    verify_graph_root_opening_descriptor(descriptor, bob.0, bob.1)?;
    if alice.1.graph_root != bob.1.graph_root {
        return Err(CompilerError::GraphRootDisagreement);
    }
    Ok(AgreedGraphRoot {
        chain_game_id: chain_game_id(descriptor)?,
        graph_root: alice.1.graph_root,
    })
}

/// Create and authenticate a complete signature-bundle commitment.
///
/// # Errors
///
/// Rejects wrong game/role, zero nonces, malformed bundles, or a callback
/// identity signature that does not verify.
pub fn commit_signature_bundle<F>(
    verified_descriptor: &VerifiedChainDescriptor,
    nonce: [u8; 32],
    bundle: PreauthorizationBundle,
    sign_digest: F,
) -> Result<(SignedCommitment, SignatureBundleOpening), CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    let descriptor = verified_descriptor.as_descriptor();
    require_fresh_nonce(nonce)?;
    let game_id = chain_game_id(descriptor)?;
    if bundle.chain_game_id != game_id {
        return Err(CompilerError::ExchangeGameMismatch);
    }
    if bundle.graph_root == [0; 32] {
        return Err(CompilerError::ExchangeGraphMismatch);
    }
    for signature in &bundle.signatures {
        DefaultSighashSignature::from_bytes(*signature)?;
    }
    let opening = SignatureBundleOpening { nonce, bundle };
    let commitment = signature_bundle_opening_digest(&opening)?;
    let authenticated = authenticate_commitment(
        descriptor,
        game_id,
        opening.bundle.role,
        CommitmentPurpose::PreauthorizationBundle,
        commitment,
        sign_digest,
    )?;
    Ok((authenticated, opening))
}

/// Verify an opened bundle, its outer commitment, exact request membership,
/// and every transaction signature.
///
/// # Errors
///
/// Rejects any context, commitment, membership, ordering, or signature error.
pub fn verify_signature_bundle(
    verified_descriptor: &VerifiedChainDescriptor,
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
) -> Result<(), CompilerError> {
    verify_signature_bundle_descriptor(
        verified_descriptor.as_descriptor(),
        expected_graph_root,
        signed,
        opening,
        expected_requests,
    )
}

pub(crate) fn verify_signature_bundle_descriptor(
    descriptor: &ChainGameDescriptor,
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
) -> Result<(), CompilerError> {
    verify_signature_bundle_binding_descriptor(
        descriptor,
        expected_graph_root,
        signed,
        opening,
        expected_requests,
    )?;
    let bundle = &opening.bundle;
    let secp = Secp256k1::verification_only();
    let key = *descriptor.identity_key(bundle.role);
    for (request, signature) in expected_requests.iter().zip(&bundle.signatures) {
        verify_sighash_default(
            &secp,
            key,
            request.sighash,
            DefaultSighashSignature::from_bytes(*signature)?,
        )?;
    }
    Ok(())
}

/// Verify all public binding and membership properties without repeating the
/// transaction-signature checks.
///
/// This is useful only when signature validity is already established by a
/// trusted local generation path or by independent verification workers.
///
/// # Errors
///
/// Rejects any wrong game, graph, role, commitment, count, or signer set.
pub fn verify_signature_bundle_binding(
    verified_descriptor: &VerifiedChainDescriptor,
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
) -> Result<(), CompilerError> {
    verify_signature_bundle_binding_descriptor(
        verified_descriptor.as_descriptor(),
        expected_graph_root,
        signed,
        opening,
        expected_requests,
    )
}

pub(crate) fn verify_signature_bundle_binding_descriptor(
    descriptor: &ChainGameDescriptor,
    expected_graph_root: [u8; 32],
    signed: &SignedCommitment,
    opening: &SignatureBundleOpening,
    expected_requests: &[SignatureRequest],
) -> Result<(), CompilerError> {
    let bundle = &opening.bundle;
    if bundle.graph_root != expected_graph_root || expected_graph_root == [0; 32] {
        return Err(CompilerError::ExchangeGraphMismatch);
    }
    verify_signed_commitment(
        descriptor,
        signed,
        bundle.chain_game_id,
        bundle.role,
        CommitmentPurpose::PreauthorizationBundle,
    )?;
    if signature_bundle_opening_digest(opening)? != signed.commitment {
        return Err(CompilerError::CommitmentMismatch {
            purpose: "preauthorization bundle",
        });
    }
    if expected_requests.len() != bundle.signatures.len()
        || expected_requests
            .iter()
            .any(|request| request.signer != bundle.role)
    {
        return Err(CompilerError::SignatureBundleMembershipMismatch);
    }
    Ok(())
}

fn authenticate_commitment<F>(
    descriptor: &ChainGameDescriptor,
    game_id: [u8; 32],
    role: Role,
    purpose: CommitmentPurpose,
    commitment: [u8; 32],
    sign_digest: F,
) -> Result<SignedCommitment, CompilerError>
where
    F: FnOnce([u8; 32]) -> [u8; 64],
{
    let mut authenticated = SignedCommitment {
        chain_game_id: game_id,
        role,
        purpose,
        commitment,
        signature: [0; 64],
    };
    authenticated.signature = sign_digest(commitment_signature_digest(&authenticated)?);
    verify_signed_commitment(descriptor, &authenticated, game_id, role, purpose)?;
    Ok(authenticated)
}

fn verify_signed_commitment(
    descriptor: &ChainGameDescriptor,
    signed: &SignedCommitment,
    expected_game_id: [u8; 32],
    expected_role: Role,
    expected_purpose: CommitmentPurpose,
) -> Result<(), CompilerError> {
    let descriptor_game_id = chain_game_id(descriptor)?;
    if signed.chain_game_id != descriptor_game_id || signed.chain_game_id != expected_game_id {
        return Err(CompilerError::ExchangeGameMismatch);
    }
    if signed.role != expected_role || signed.purpose != expected_purpose {
        return Err(CompilerError::ExchangeRoleMismatch);
    }
    let public_key = XOnlyPublicKey::from_slice(descriptor.identity_key(signed.role))
        .map_err(|_| ChainError::InvalidIdentityKey { role: signed.role })?;
    let signature =
        Signature::from_slice(&signed.signature).map_err(|_| ChainError::InvalidSignature {
            role: signed.role,
            object: "chain commitment",
        })?;
    let message = Message::from_digest(commitment_signature_digest(signed)?);
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| ChainError::InvalidSignature {
            role: signed.role,
            object: "chain commitment",
        })?;
    Ok(())
}

fn graph_root_commitment(opening: &GraphRootOpening) -> Result<[u8; 32], CompilerError> {
    Ok(tagged_sha256(
        GRAPH_ROOT_COMMIT_TAG,
        &opening.encode_to_vec()?,
    ))
}

/// Return the canonical commitment digest of one packed opening.
pub fn signature_bundle_opening_digest(
    opening: &SignatureBundleOpening,
) -> Result<[u8; 32], CompilerError> {
    Ok(tagged_sha256(
        SIGNATURE_BUNDLE_COMMIT_TAG,
        &opening.encode_to_vec()?,
    ))
}

/// Return the canonical digest of a complete authenticated commitment.
///
/// Compact verification receipts bind this value so reducers never need to
/// retain the corresponding raw signature opening.
pub fn signed_commitment_digest(signed: &SignedCommitment) -> Result<[u8; 32], CompilerError> {
    Ok(tagged_sha256(
        SIGNED_COMMITMENT_DIGEST_TAG,
        &signed.encode_to_vec()?,
    ))
}

fn receipt_signature_digest(
    receipt: &PreauthorizationVerifiedReceipt,
) -> Result<[u8; 32], CompilerError> {
    let mut writer = Writer::with_capacity(PREAUTHORIZATION_RECEIPT_BYTES - 64);
    receipt.version.encode(&mut writer)?;
    receipt.shared_config_hash.encode(&mut writer)?;
    receipt.chain_game_id.encode(&mut writer)?;
    receipt.graph_root.encode(&mut writer)?;
    receipt.subject_role.encode(&mut writer)?;
    receipt.signed_commitment_digest.encode(&mut writer)?;
    receipt.opening_digest.encode(&mut writer)?;
    receipt.signature_count.encode(&mut writer)?;
    receipt.verifier_role.encode(&mut writer)?;
    Ok(tagged_sha256(
        PREAUTHORIZATION_RECEIPT_TAG,
        writer.as_bytes(),
    ))
}

const fn invalid_receipt(reason: &'static str) -> CompilerError {
    CompilerError::InvalidPreauthorizationReceipt { reason }
}

fn commitment_signature_digest(signed: &SignedCommitment) -> Result<[u8; 32], CompilerError> {
    let mut writer = Writer::with_capacity(98);
    signed.chain_game_id.encode(&mut writer)?;
    signed.role.encode(&mut writer)?;
    signed.purpose.encode(&mut writer)?;
    signed.commitment.encode(&mut writer)?;
    Ok(tagged_sha256(COMMITMENT_SIGNATURE_TAG, writer.as_bytes()))
}

fn validate_preauthorizations(
    role: Role,
    entries: &[Preauthorization],
) -> Result<(), CompilerError> {
    if entries.len() > MAX_PREAUTHORIZATIONS_PER_ROLE {
        return Err(CompilerError::SignatureBundleTooLarge {
            actual: entries.len(),
            maximum: MAX_PREAUTHORIZATIONS_PER_ROLE,
        });
    }
    let mut seen = HashSet::with_capacity(entries.len());
    let mut previous = None;
    for entry in entries {
        DefaultSighashSignature::from_bytes(entry.signature)?;
        if entry.request.signer != role {
            return Err(CompilerError::ExchangeRoleMismatch);
        }
        let key = (
            entry.request.parent_node_id,
            entry.request.child_node_id,
            entry.request.sighash,
        );
        if previous.is_some_and(|prior| prior >= key) || !seen.insert(key) {
            return Err(CompilerError::NonCanonicalSignatureBundle);
        }
        previous = Some(key);
    }
    Ok(())
}

fn require_fresh_nonce(nonce: [u8; 32]) -> Result<(), CompilerError> {
    if nonce == [0; 32] {
        Err(CompilerError::InvalidCommitmentNonce)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use bp52_codec::{Decode, Encode, Writer};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        CommitmentPurpose, GraphRootOpening, PREAUTHORIZATION_RECEIPT_BYTES, Preauthorization,
        PreauthorizationBundle, PreauthorizationVerifiedReceipt, PrivateRuntimeSignatureBundle,
        RuntimeSignatureResponse, SignatureBundleOpening, SignatureRequest, SignedCommitment,
        commit_graph_root, commit_signature_bundle,
        issue_externally_verified_preauthorization_receipt,
        issue_locally_generated_preauthorization_receipt, issue_preauthorization_verified_receipt,
        verify_matching_graph_roots, verify_preauthorization_verified_receipt,
        verify_signature_bundle,
    };
    use crate::{CompilerError, test_support::verified_descriptor_fixture};

    fn keypair_for(descriptor_key: [u8; 32]) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        for number in [1_u8, 2] {
            let mut secret = [0_u8; 32];
            secret[31] = number;
            let candidate = Keypair::from_seckey_slice(&secp, &secret)?;
            if candidate.x_only_public_key().0.serialize() == descriptor_key {
                return Ok(candidate);
            }
        }
        Keypair::from_seckey_slice(&secp, &[1; 32])
    }

    #[test]
    fn private_runtime_signature_owners_are_explicitly_zeroizing() {
        fn require_zeroizing<T: Zeroize + ZeroizeOnDrop>() {}

        require_zeroizing::<RuntimeSignatureResponse>();
        require_zeroizing::<PrivateRuntimeSignatureBundle>();
        require_zeroizing::<Preauthorization>();
        require_zeroizing::<PreauthorizationBundle>();
        require_zeroizing::<super::SignatureBundleOpening>();
    }

    #[test]
    fn graph_commit_open_is_authenticated_and_equal() -> Result<(), Box<dyn std::error::Error>> {
        let verified_descriptor = verified_descriptor_fixture()?;
        let descriptor = verified_descriptor.as_descriptor();
        let alice_key = keypair_for(*descriptor.identity_key(bp52_chain_types::Role::Alice))?;
        let bob_key = keypair_for(*descriptor.identity_key(bp52_chain_types::Role::Bob))?;
        let root = [0xa5; 32];
        let (commit_a, open_a) = commit_graph_root(
            &verified_descriptor,
            bp52_chain_types::Role::Alice,
            root,
            [1; 32],
            |digest| {
                Secp256k1::new()
                    .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &alice_key)
                    .serialize()
            },
        )?;
        let (commit_b, open_b) = commit_graph_root(
            &verified_descriptor,
            bp52_chain_types::Role::Bob,
            root,
            [2; 32],
            |digest| {
                Secp256k1::new()
                    .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &bob_key)
                    .serialize()
            },
        )?;
        assert_eq!(
            verify_matching_graph_roots(
                &verified_descriptor,
                (&commit_a, &open_a),
                (&commit_b, &open_b),
            )?
            .graph_root(),
            root
        );
        assert_eq!(
            SignedCommitment::decode_exact(&commit_a.encode_to_vec()?)?,
            commit_a
        );
        assert_eq!(
            GraphRootOpening::decode_exact(&open_a.encode_to_vec()?)?,
            open_a
        );
        assert_eq!(commit_a.purpose(), CommitmentPurpose::GraphRoot);

        let mut wrong = open_b;
        wrong.graph_root[0] ^= 1;
        assert!(matches!(
            verify_matching_graph_roots(
                &verified_descriptor,
                (&commit_a, &open_a),
                (&commit_b, &wrong),
            ),
            Err(CompilerError::CommitmentMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn signature_bundle_requires_exact_membership_and_valid_signatures()
    -> Result<(), Box<dyn std::error::Error>> {
        let verified_descriptor = verified_descriptor_fixture()?;
        let descriptor = verified_descriptor.as_descriptor();
        let secp = Secp256k1::new();
        let role = bp52_chain_types::Role::Alice;
        let keypair = keypair_for(*descriptor.identity_key(role))?;
        let requests = [
            SignatureRequest {
                parent_node_id: [1; 32],
                child_node_id: [2; 32],
                signer: role,
                sighash: [3; 32],
            },
            SignatureRequest {
                // A distinct tapscript leaf can authorize the same graph edge
                // with a different BIP341 digest.
                parent_node_id: [1; 32],
                child_node_id: [2; 32],
                signer: role,
                sighash: [4; 32],
            },
        ];
        let entries = requests
            .iter()
            .map(|request| Preauthorization {
                request: *request,
                signature: bp52_chain_bitcoin::sign_sighash_default(
                    &secp,
                    &keypair,
                    request.sighash,
                )
                .to_bytes(),
            })
            .collect();
        let bundle = PreauthorizationBundle::new(
            bp52_chain_types::chain_game_id(descriptor)?,
            [0x77; 32],
            role,
            entries,
        )?;
        let (commitment, opening) =
            commit_signature_bundle(&verified_descriptor, [9; 32], bundle, |digest| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                    .serialize()
            })?;
        verify_signature_bundle(
            &verified_descriptor,
            [0x77; 32],
            &commitment,
            &opening,
            &requests,
        )?;
        assert!(matches!(
            verify_signature_bundle(
                &verified_descriptor,
                [0x77; 32],
                &commitment,
                &opening,
                &requests[..1],
            ),
            Err(CompilerError::SignatureBundleMembershipMismatch)
        ));

        let encoded_opening = opening.encode_to_vec()?;
        assert_eq!(encoded_opening.len(), 32 + 32 + 32 + 1 + 4 + 2 * 64);
        assert_eq!(
            SignatureBundleOpening::decode_exact(&encoded_opening)?,
            opening
        );
        assert!(matches!(
            verify_signature_bundle(
                &verified_descriptor,
                [0x78; 32],
                &commitment,
                &opening,
                &requests,
            ),
            Err(CompilerError::ExchangeGraphMismatch)
        ));

        let mut reversed = requests;
        reversed.reverse();
        assert!(
            verify_signature_bundle(
                &verified_descriptor,
                [0x77; 32],
                &commitment,
                &opening,
                &reversed,
            )
            .is_err()
        );

        let receipt = issue_preauthorization_verified_receipt(
            &verified_descriptor,
            [0x55; 32],
            [0x77; 32],
            &commitment,
            &opening,
            &requests,
            role,
            |digest| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                    .serialize()
            },
        )?;
        let repeated_receipt = issue_preauthorization_verified_receipt(
            &verified_descriptor,
            [0x55; 32],
            [0x77; 32],
            &commitment,
            &opening,
            &requests,
            role,
            |digest| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                    .serialize()
            },
        )?;
        assert_eq!(receipt, repeated_receipt);
        let local_receipt = issue_locally_generated_preauthorization_receipt(
            &verified_descriptor,
            [0x55; 32],
            [0x77; 32],
            &commitment,
            &opening,
            &requests,
            role,
            |digest| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
                    .serialize()
            },
        )?;
        assert_eq!(receipt, local_receipt);
        let verifier_role = role.other();
        let verifier_keypair = keypair_for(*descriptor.identity_key(verifier_role))?;
        let external_receipt = issue_externally_verified_preauthorization_receipt(
            &verified_descriptor,
            [0x55; 32],
            [0x77; 32],
            &commitment,
            &opening,
            &requests,
            verifier_role,
            |digest| {
                secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &verifier_keypair)
                    .serialize()
            },
        )?;
        verify_preauthorization_verified_receipt(
            &verified_descriptor,
            [0x55; 32],
            [0x77; 32],
            &commitment,
            2,
            verifier_role,
            &external_receipt,
        )?;
        assert!(
            issue_externally_verified_preauthorization_receipt(
                &verified_descriptor,
                [0x55; 32],
                [0x77; 32],
                &commitment,
                &opening,
                &requests,
                role,
                |_| [1; 64],
            )
            .is_err()
        );
        assert!(
            issue_locally_generated_preauthorization_receipt(
                &verified_descriptor,
                [0x55; 32],
                [0x77; 32],
                &commitment,
                &opening,
                &requests,
                role.other(),
                |_| [1; 64],
            )
            .is_err()
        );
        let mut tampered_opening = SignatureBundleOpening::decode_exact(&encoded_opening)?;
        tampered_opening.bundle.signatures[0][0] ^= 1;
        assert!(
            issue_locally_generated_preauthorization_receipt(
                &verified_descriptor,
                [0x55; 32],
                [0x77; 32],
                &commitment,
                &tampered_opening,
                &requests,
                role,
                |_| [1; 64],
            )
            .is_err()
        );
        let receipt_bytes = receipt.encode_to_vec()?;
        assert_eq!(receipt_bytes.len(), PREAUTHORIZATION_RECEIPT_BYTES);
        assert_eq!(
            PreauthorizationVerifiedReceipt::decode_exact(&receipt_bytes)?,
            receipt
        );
        verify_preauthorization_verified_receipt(
            &verified_descriptor,
            [0x55; 32],
            [0x77; 32],
            &commitment,
            2,
            role,
            &receipt,
        )?;
        for mut corrupted in [
            {
                let mut value = receipt;
                value.shared_config_hash[0] ^= 1;
                value
            },
            {
                let mut value = receipt;
                value.graph_root[0] ^= 1;
                value
            },
            {
                let mut value = receipt;
                value.opening_digest[0] ^= 1;
                value
            },
            {
                let mut value = receipt;
                value.signature_count += 1;
                value
            },
            {
                let mut value = receipt;
                value.verifier_signature[0] ^= 1;
                value
            },
        ] {
            assert!(
                verify_preauthorization_verified_receipt(
                    &verified_descriptor,
                    [0x55; 32],
                    [0x77; 32],
                    &commitment,
                    2,
                    role,
                    &corrupted,
                )
                .is_err()
            );
            corrupted.verifier_signature.zeroize();
        }

        let mut oversized = Writer::new();
        [1_u8; 32].encode(&mut oversized)?;
        [2_u8; 32].encode(&mut oversized)?;
        role.encode(&mut oversized)?;
        (u32::try_from(super::MAX_PREAUTHORIZATIONS_PER_ROLE)? + 1).encode(&mut oversized)?;
        assert!(PreauthorizationBundle::decode_exact(oversized.as_bytes()).is_err());
        Ok(())
    }
}
