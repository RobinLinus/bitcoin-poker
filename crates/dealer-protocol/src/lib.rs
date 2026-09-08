#![forbid(unsafe_code)]
//! Typed construction and validation boundaries for DLOG52 setup objects.

mod certificate;
mod reveal;
mod session;
mod local;

pub use certificate::{Envelope, SetupCertificate, verify_setup_certificate};
pub use reveal::{
    SignedShareReveal, VerifiedShareReveal, create_share_reveal, verify_share_reveal,
};
pub use session::{LiveParticipant, ParticipantSnapshot};

use dealer_codec::{Encode, put_u16, put_u32};
use dealer_group::{
    N_SLOTS, SlotPublic, create_slot, encode_point, protocol_parameters, random_contribution,
    random_nonzero_scalar, random_scalar,
};
use dealer_proofs::{
    KeyPop, LinkProofRecord, Range52Proof, RangeWitness, prove_key_pop, prove_links, prove_range52,
    verify_key_pop, verify_links, verify_range52,
};
use dealer_transcript::tagged_hash;
use dealer_uniqueness::{UniquenessError, VerifiedCatalogue, derive_candidate_catalogue};
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Group, sec1::ToEncodedPoint},
    schnorr::{Signature, VerifyingKey},
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

/// DLOG52 wire version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum authenticated envelope size.
pub const MAX_ENVELOPE_BYTES: usize = 32_768;
/// Maximum public certificate size.
pub const MAX_SETUP_CERT_BYTES: usize = 131_072;

/// Authenticated party role.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    /// Lexicographically smaller identity.
    A = 0,
    /// Other identity.
    B = 1,
}

impl Role {
    /// Return the canonical wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Agreed game/session configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GameConfig {
    /// Consensus-serialized network genesis hash.
    pub network_genesis: [u8; 32],
    /// Opaque pre-deal application session identifier.
    pub session_anchor: [u8; 32],
    /// Lexicographically smaller BIP340 identity.
    pub identity_a: [u8; 32],
    /// Second BIP340 identity.
    pub identity_b: [u8; 32],
    /// Fresh public application nonce.
    pub session_nonce: [u8; 32],
    /// External reveal-policy identifier.
    pub rules_hash: [u8; 32],
}

impl Encode for GameConfig {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.network_genesis);
        out.extend_from_slice(&self.session_anchor);
        out.extend_from_slice(&self.identity_a);
        out.extend_from_slice(&self.identity_b);
        out.extend_from_slice(&self.session_nonce);
        out.extend_from_slice(&self.rules_hash);
    }
}

/// Protocol-layer validation failure.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Identity keys are equal, out of order, or do not lift to curve points.
    #[error("invalid identity configuration")]
    Identity,
    /// The two threshold keys cancel.
    #[error("joint threshold key is identity")]
    JointKey,
    /// A proof did not validate.
    #[error("proof validation failed")]
    Proof,
    /// A commitment or ciphertext was degenerate.
    #[error("degenerate slot data")]
    Degenerate,
    /// Candidate screening failed.
    #[error("candidate catalogue screening failed: {0}")]
    Catalogue(#[from] UniquenessError),
    /// An accepted descriptor disagrees with the fully verified attempt.
    #[error("accepted deal descriptor mismatch")]
    AcceptedDescriptor,
    /// One of the detached accepted-deal identity signatures is invalid.
    #[error("invalid accepted deal signature")]
    AcceptedSignature,
    /// Canonical wire decoding or a bounded-size check failed.
    #[error("invalid canonical protocol encoding")]
    Wire,
    /// An authenticated message violated the stage machine.
    #[error("invalid authenticated protocol stage")]
    Stage,
    /// A committed opening did not match its earlier commitment.
    #[error("commitment opening mismatch")]
    Commitment,
    /// The uniqueness result requires a new attempt rather than acceptance.
    #[error("deal contains a card collision")]
    Collision,
    /// A selective opening was malformed, unauthorized, or incorrectly signed.
    #[error("invalid or unauthorized share reveal")]
    Reveal,
    /// An off-chain state commitment was malformed or incorrectly signed.
    #[error("invalid off-chain state commitment")]
    OffchainCommitment,
}

/// Domain-separated BIP340 digest for one application-level off-chain state.
///
/// The DLOG participant only signs a 32-byte canonical commitment produced by
/// the public game reducer. Binding that commitment to the accepted DLOG game
/// id prevents signatures from being replayed into another table or protocol.
#[must_use]
pub fn offchain_commitment_digest(game_id: &[u8; 32], commitment_hash: &[u8; 32]) -> [u8; 32] {
    let mut body = [0_u8; 64];
    body[..32].copy_from_slice(game_id);
    body[32..].copy_from_slice(commitment_hash);
    tagged_hash("BP52/offchain-state/v1", &body)
}

/// Validate identities and derive the game identifier.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn derive_game_id(config: &GameConfig) -> Result<[u8; 32], ProtocolError> {
    if config.identity_a >= config.identity_b
        || k256::schnorr::VerifyingKey::from_bytes(&config.identity_a).is_err()
        || k256::schnorr::VerifyingKey::from_bytes(&config.identity_b).is_err()
    {
        return Err(ProtocolError::Identity);
    }
    let mut body = Vec::with_capacity(32 + 192);
    body.extend_from_slice(&protocol_parameters().params_id);
    config.encode(&mut body);
    Ok(tagged_hash("DLOG52/game/v1", &body))
}

/// Frozen context supplied to one proof family by the state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofContext {
    /// Game identifier.
    pub game_id: [u8; 32],
    /// Attempt number.
    pub attempt: u32,
    /// Exact proof stage.
    pub proof_stage: u16,
    /// Prover role.
    pub prover_role: Role,
    /// Transcript root before the corresponding commit stage.
    pub frozen_anchor: [u8; 32],
}

impl Encode for ProofContext {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&protocol_parameters().params_id);
        out.extend_from_slice(&self.game_id);
        put_u32(out, self.attempt);
        put_u16(out, self.proof_stage);
        out.push(self.prover_role.as_u8());
        out.extend_from_slice(&self.frozen_anchor);
    }
}

/// Public joint-key statement.
#[derive(Clone)]
pub struct JointPublic {
    /// A's threshold public key.
    pub pk_a: ProjectivePoint,
    /// B's threshold public key.
    pub pk_b: ProjectivePoint,
    /// Checked sum of both keys.
    pub y: ProjectivePoint,
}

impl JointPublic {
    /// Validate and construct the exact joint statement.
    ///
    /// # Errors
    ///
    /// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
    pub fn new(pk_a: ProjectivePoint, pk_b: ProjectivePoint) -> Result<Self, ProtocolError> {
        if bool::from(pk_a.is_identity()) || bool::from(pk_b.is_identity()) {
            return Err(ProtocolError::Degenerate);
        }
        let y = pk_a + pk_b;
        if bool::from(y.is_identity()) {
            return Err(ProtocolError::JointKey);
        }
        Ok(Self { pk_a, pk_b, y })
    }
}

impl Encode for JointPublic {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_point(&self.pk_a, out);
        encode_point(&self.pk_b, out);
        encode_point(&self.y, out);
    }
}

/// Public key-open body.
#[derive(Clone)]
pub struct KeyOpenBody {
    /// Per-attempt threshold public key.
    pub public_key: ProjectivePoint,
    /// Proof of possession.
    pub proof: KeyPop,
}

/// Non-cloneable per-attempt secret threshold share.
pub struct SecretKeyShare(Scalar);

impl SecretKeyShare {
    /// Borrow the scalar inside secret-owning protocol code.
    #[must_use]
    pub fn expose_for_protocol(&self) -> &Scalar {
        &self.0
    }
}

impl Drop for SecretKeyShare {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Generate a threshold key and proof against a frozen context.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn generate_key_open(
    context: &ProofContext,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(KeyOpenBody, SecretKeyShare), ProtocolError> {
    let secret = random_nonzero_scalar(rng);
    let public_key = protocol_parameters().g * secret;
    let proof =
        prove_key_pop(&context.to_bytes(), &secret, rng).map_err(|_| ProtocolError::Proof)?;
    Ok((KeyOpenBody { public_key, proof }, SecretKeyShare(secret)))
}

/// Verify a key-open proof.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn verify_key_open(context: &ProofContext, body: &KeyOpenBody) -> Result<(), ProtocolError> {
    verify_key_pop(&context.to_bytes(), &body.public_key, &body.proof)
        .map_err(|_| ProtocolError::Proof)
}

/// Complete public player bundle.
#[derive(Clone)]
pub struct PlayerBundle {
    /// Claimed sender role.
    pub role: Role,
    /// Exact nine public slots.
    pub slots: [SlotPublic; N_SLOTS],
    /// Exact range proof.
    pub range_proof: Range52Proof,
    /// Exact encryption-link proof.
    pub link_proof: [LinkProofRecord; N_SLOTS],
}

impl Encode for PlayerBundle {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.role.as_u8());
        for slot in &self.slots {
            slot.encode(out);
        }
        self.range_proof.encode(out);
        for record in &self.link_proof {
            record.encode(out);
        }
    }
}

/// Long-lived opening for one accepted contribution.
pub struct ContributionSecret {
    value: u8,
    gamma: Scalar,
}

impl ContributionSecret {
    /// Contribution value for an authorized local opening action.
    #[must_use]
    pub const fn value(&self) -> u8 {
        self.value
    }
    /// Commitment blinder for an authorized local opening action.
    #[must_use]
    pub fn gamma(&self) -> &Scalar {
        &self.gamma
    }
}

impl Drop for ContributionSecret {
    fn drop(&mut self) {
        self.value.zeroize();
        self.gamma.zeroize();
    }
}

/// All secret material retained by one setup instance until acceptance/retry.
pub struct SetupSecrets {
    /// Long-lived commitment openings.
    pub openings: [ContributionSecret; N_SLOTS],
    encryption_randomness: [Scalar; N_SLOTS],
}

impl Drop for SetupSecrets {
    fn drop(&mut self) {
        self.encryption_randomness.zeroize();
    }
}

fn bundle_statement(
    context: &ProofContext,
    joint: &JointPublic,
    slots: &[SlotPublic; N_SLOTS],
) -> Vec<u8> {
    let mut bytes = context.to_bytes();
    joint.encode(&mut bytes);
    for slot in slots {
        slot.encode(&mut bytes);
    }
    bytes
}

/// Generate nine contributions and both exact bundle proofs.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn generate_player_bundle(
    context: &ProofContext,
    joint: &JointPublic,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(PlayerBundle, SetupSecrets), ProtocolError> {
    if context.prover_role != Role::A && context.prover_role != Role::B {
        return Err(ProtocolError::Identity);
    }
    let openings: [ContributionSecret; N_SLOTS] = std::array::from_fn(|_| ContributionSecret {
        value: random_contribution(rng),
        gamma: random_scalar(rng),
    });
    let encryption_randomness: [Scalar; N_SLOTS] =
        std::array::from_fn(|_| random_nonzero_scalar(rng));
    let mut maybe_slots = Vec::with_capacity(N_SLOTS);
    for i in 0..N_SLOTS {
        maybe_slots.push(
            create_slot(
                openings[i].value,
                &openings[i].gamma,
                &encryption_randomness[i],
                &joint.y,
            )
            .map_err(|_| ProtocolError::Degenerate)?,
        );
    }
    let slots: [SlotPublic; N_SLOTS] = maybe_slots
        .try_into()
        .map_err(|_| ProtocolError::Degenerate)?;
    let witnesses: [RangeWitness; N_SLOTS] = std::array::from_fn(|i| RangeWitness {
        value: openings[i].value,
        gamma: openings[i].gamma,
    });
    let statement = bundle_statement(context, joint, &slots);
    let range_proof =
        prove_range52(&statement, &slots, &witnesses, rng).map_err(|_| ProtocolError::Proof)?;
    let link_proof = prove_links(
        &statement,
        &range_proof,
        &witnesses,
        &encryption_randomness,
        &joint.y,
        rng,
    )
    .map_err(|_| ProtocolError::Proof)?;
    let bundle = PlayerBundle {
        role: context.prover_role,
        slots,
        range_proof,
        link_proof,
    };
    debug_assert_eq!(bundle.to_bytes().len(), 16_611);
    Ok((
        bundle,
        SetupSecrets {
            openings,
            encryption_randomness,
        },
    ))
}

/// Bundle which has crossed all local proof-validation boundaries.
pub struct VerifiedBundle(PlayerBundle);

impl VerifiedBundle {
    /// Borrow the verified bundle.
    #[must_use]
    pub const fn as_bundle(&self) -> &PlayerBundle {
        &self.0
    }
}

/// Verify both proof families against the same slots and frozen statement.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn verify_player_bundle(
    context: &ProofContext,
    joint: &JointPublic,
    bundle: &PlayerBundle,
) -> Result<VerifiedBundle, ProtocolError> {
    if bundle.role != context.prover_role {
        return Err(ProtocolError::Identity);
    }
    let statement = bundle_statement(context, joint, &bundle.slots);
    verify_range52(&statement, &bundle.slots, &bundle.range_proof)
        .map_err(|_| ProtocolError::Proof)?;
    verify_links(
        &statement,
        &bundle.range_proof,
        &bundle.slots,
        &joint.y,
        &bundle.link_proof,
    )
    .map_err(|_| ProtocolError::Proof)?;
    Ok(VerifiedBundle(bundle.clone()))
}

/// Derive and screen a catalogue from two independently verified bundles.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn derive_candidate_keys(
    game_id: &[u8; 32],
    attempt: u32,
    identities: (&[u8; 32], &[u8; 32]),
    a: &VerifiedBundle,
    b: &VerifiedBundle,
) -> Result<VerifiedCatalogue, ProtocolError> {
    derive_candidate_catalogue(
        &protocol_parameters().params_id,
        game_id,
        attempt,
        &a.0.slots,
        &b.0.slots,
        identities.0,
        identities.1,
    )
    .map_err(ProtocolError::from)
}

/// Signed accepted public body (signatures are carried separately).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedDealBody {
    /// Wire version.
    pub version: u16,
    /// Fixed parameter identifier.
    pub params_id: [u8; 32],
    /// Game identifier.
    pub game_id: [u8; 32],
    /// Successful attempt number.
    pub attempt: u32,
    /// A's accepted commitments.
    pub commitments_a: [ProjectivePoint; N_SLOTS],
    /// B's accepted commitments.
    pub commitments_b: [ProjectivePoint; N_SLOTS],
    /// Screened catalogue hash.
    pub catalogue_hash: [u8; 32],
    /// Frozen T8 root.
    pub verification_root: [u8; 32],
}

impl Encode for AcceptedDealBody {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.version);
        out.extend_from_slice(&self.params_id);
        out.extend_from_slice(&self.game_id);
        put_u32(out, self.attempt);
        for point in &self.commitments_a {
            encode_point(point, out);
        }
        for point in &self.commitments_b {
            encode_point(point, out);
        }
        out.extend_from_slice(&self.catalogue_hash);
        out.extend_from_slice(&self.verification_root);
    }
}

/// Hash signed by both identities after successful verification.
#[must_use]
pub fn accepted_body_hash(body: &AcceptedDealBody) -> [u8; 32] {
    tagged_hash("DLOG52/accepted/v1", &body.to_bytes())
}

/// Accepted deal plus detached BIP340 signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedDeal {
    /// Verified public body.
    pub body: AcceptedDealBody,
    /// A's signature.
    pub signature_a: [u8; 64],
    /// B's signature.
    pub signature_b: [u8; 64],
}

/// Sealed accepted-deal type. Full certificate replay will be added at M3.
pub struct VerifiedAcceptedDeal {
    deal: AcceptedDeal,
    catalogue: VerifiedCatalogue,
    game_config: GameConfig,
}

impl VerifiedAcceptedDeal {
    /// Borrow the accepted descriptor.
    #[must_use]
    pub const fn as_deal(&self) -> &AcceptedDeal {
        &self.deal
    }
    /// Borrow the screened candidate catalogue.
    #[must_use]
    pub const fn catalogue(&self) -> &VerifiedCatalogue {
        &self.catalogue
    }
    /// Borrow the game configuration authenticated by certificate replay.
    #[must_use]
    pub const fn game_config(&self) -> &GameConfig {
        &self.game_config
    }
}

/// Finish an already verified live attempt and cross the chain-authoritative
/// accepted-deal boundary.
///
/// The caller supplies bundles that have already crossed
/// [`verify_player_bundle`] and the exact stage-8 transcript root produced by
/// the live state machine. This function independently re-derives the game id,
/// candidate catalogue, descriptor commitments, and both BIP340 signatures.
/// Public certificate decoding must replay the same checks before calling this
/// boundary; detached acceptance signatures alone are deliberately
/// insufficient.
///
/// # Errors
///
/// Returns an error if the identities, proof-verified bundle roles,
/// descriptor fields, re-derived catalogue, transcript root, or either BIP340
/// signature disagree.
pub fn finalize_verified_attempt(
    config: &GameConfig,
    bundle_a: &VerifiedBundle,
    bundle_b: &VerifiedBundle,
    verification_root: [u8; 32],
    deal: AcceptedDeal,
) -> Result<VerifiedAcceptedDeal, ProtocolError> {
    let game_id = derive_game_id(config)?;
    let a = bundle_a.as_bundle();
    let b = bundle_b.as_bundle();
    if a.role != Role::A || b.role != Role::B {
        return Err(ProtocolError::Identity);
    }
    let catalogue = derive_candidate_keys(
        &game_id,
        deal.body.attempt,
        (&config.identity_a, &config.identity_b),
        bundle_a,
        bundle_b,
    )?;
    let commitments_a = std::array::from_fn(|index| a.slots[index].commitment);
    let commitments_b = std::array::from_fn(|index| b.slots[index].commitment);
    if deal.body.version != PROTOCOL_VERSION
        || deal.body.params_id != protocol_parameters().params_id
        || deal.body.game_id != game_id
        || deal.body.commitments_a != commitments_a
        || deal.body.commitments_b != commitments_b
        || deal.body.catalogue_hash != catalogue.hash
        || deal.body.verification_root != verification_root
    {
        return Err(ProtocolError::AcceptedDescriptor);
    }
    let digest = accepted_body_hash(&deal.body);
    verify_accepted_signature(&config.identity_a, &digest, &deal.signature_a)?;
    verify_accepted_signature(&config.identity_b, &digest, &deal.signature_b)?;
    Ok(VerifiedAcceptedDeal {
        deal,
        catalogue,
        game_config: config.clone(),
    })
}

fn verify_accepted_signature(
    identity: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    let key = VerifyingKey::from_bytes(identity).map_err(|_| ProtocolError::Identity)?;
    let signature =
        Signature::try_from(signature.as_slice()).map_err(|_| ProtocolError::AcceptedSignature)?;
    key.verify_raw(digest, &signature)
        .map_err(|_| ProtocolError::AcceptedSignature)
}

/// Return an x-only encoding for a nonidentity full point.
///
/// # Errors
///
/// Rejects invalid protocol inputs, authentication failures, or inconsistent session state.
pub fn point_xonly(point: &ProjectivePoint) -> Result<[u8; 32], ProtocolError> {
    if bool::from(point.is_identity()) {
        return Err(ProtocolError::Degenerate);
    }
    let encoded = point.to_affine().to_encoded_point(true);
    let x = encoded.x().ok_or(ProtocolError::Degenerate)?;
    let mut out = [0_u8; 32];
    out.copy_from_slice(x);
    Ok(out)
}
