//! Backend-neutral construction of the BP52 prototype origin package.
//!
//! The package consumes two native P2WSH staging outputs controlled by scripts
//! of the form `<compressed-pubkey> OP_CHECKSIG`. Each participant contributes
//! exactly 27,000 satoshis. The funding transaction pays a fixed 500-satoshi
//! fee, returns every excess satoshi as deterministic change, and creates a
//! context-bound two-party P2WSH origin. Before funding is broadcast, both
//! participants can sign a 144-block fair-refund transaction. Once the
//! deterministic gameplay-root script is known, the same origin package also
//! derives and verifies the exact two-party activation transaction. Funding
//! authorization is intentionally independent. Every caller must persist a
//! complete signed refund before releasing a staging-input signature. A flow
//! that already knows the gameplay root must persist the complete activation
//! too; the browser origin-first prototype instead completes DEAL/graph
//! setup after origin confirmation while remaining recoverable through the
//! signed delayed refund.
//!
//! Production code is pure Rust (`sha2` and `k256`) and has no wallet, relay,
//! chain-backend, or `rust-bitcoin` dependency. Tests independently decode and
//! re-hash every vector with `rust-bitcoin`.
//!
//! This crate performs no I/O, broadcasting, chain observation, or game
//! activation. Producing a signed transaction is not evidence that it was
//! accepted by a backend or confirmed by Bitcoin.

#![forbid(unsafe_code)]

use core::fmt;

use k256::PublicKey;
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Amount contributed by each staging input.
pub const CONTRIBUTION_SAT: u64 = 27_000;
/// Fee paid by the funding transaction.
pub const FUNDING_FEE_SAT: u64 = 500;
/// Value locked in the shared origin output.
pub const ORIGIN_VALUE_SAT: u64 = CONTRIBUTION_SAT * 2 - FUNDING_FEE_SAT;
/// Relative block delay on the fair-refund transaction.
pub const REFUND_DELAY_BLOCKS: u16 = 144;
/// Amount returned to each participant by the fair refund.
pub const REFUND_VALUE_PER_PARTICIPANT_SAT: u64 = 26_500;
/// Fee paid by the fair-refund transaction.
pub const REFUND_FEE_SAT: u64 = ORIGIN_VALUE_SAT - REFUND_VALUE_PER_PARTICIPANT_SAT * 2;
/// Fee paid by the origin-to-gameplay-root activation transaction.
pub const ACTIVATION_FEE_SAT: u64 = 500;
/// Exact value of the first gameplay state output.
pub const GAMEPLAY_ROOT_VALUE_SAT: u64 = ORIGIN_VALUE_SAT - ACTIVATION_FEE_SAT;
/// Default-relay minimum non-dust value for a native P2WSH output.
pub const P2WSH_MIN_NON_DUST_SAT: u64 = 330;
/// Bitcoin's consensus money range in satoshis.
pub const MAX_MONEY_SAT: u64 = 2_100_000_000_000_000;
/// Worst-case virtual size of a signed funding transaction with two change
/// outputs and two 72-byte DER signatures plus sighash bytes.
pub const MAX_SIGNED_FUNDING_VBYTES: u64 = 277;
/// Worst-case virtual size of the signed fair-refund transaction with two
/// 72-byte DER signatures plus sighash bytes.
pub const MAX_SIGNED_REFUND_VBYTES: u64 = 201;

const CONTEXT_TAG: &[u8] = b"BP52/origin-context/v1";
const PACKAGE_TAG: &[u8] = b"BP52/origin-package/v1";
const ACTIVATION_TAG: &[u8] = b"BP52/origin-activation/v1";
const NONCE_SHARE_COMMITMENT_TAG: &[u8] = b"BP52/client/session-nonce-commit/v1";
const SESSION_NONCE_TAG: &[u8] = b"BP52/client/session-nonce/v1";
const SIGHASH_ALL_BYTE: u8 = 1;
const SIGHASH_ALL_U32: u32 = 1;
const VERSION_TWO: u32 = 2;
const FINAL_SEQUENCE: u32 = u32::MAX;
const LOCK_TIME_ZERO: u32 = 0;
const OP_DROP: u8 = 0x75;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKSIG: u8 = 0xac;
const OP_PUSHNUM_1: u8 = 0x51;

/// A transaction identifier stored in conventional block-explorer display
/// byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Txid([u8; 32]);

impl Txid {
    /// Creates an identifier from conventional display-order bytes.
    #[must_use]
    pub const fn from_display_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns conventional display-order bytes.
    #[must_use]
    pub const fn to_display_bytes(self) -> [u8; 32] {
        self.0
    }

    fn from_consensus_digest(mut digest: [u8; 32]) -> Self {
        digest.reverse();
        Self(digest)
    }

    fn encode_consensus(self, encoded: &mut Vec<u8>) {
        encoded.extend(self.0.iter().rev());
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A typed Bitcoin transaction outpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutPoint {
    txid: Txid,
    vout: u32,
}

impl OutPoint {
    /// Creates an outpoint.
    #[must_use]
    pub const fn new(txid: Txid, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Creating transaction identifier.
    #[must_use]
    pub const fn txid(self) -> Txid {
        self.txid
    }

    /// Creating transaction output index.
    #[must_use]
    pub const fn vout(self) -> u32 {
        self.vout
    }

    /// Whether this is the reserved coinbase-style null outpoint.
    #[must_use]
    pub const fn is_null(self) -> bool {
        is_all_zero(&self.txid.0) && self.vout == u32::MAX
    }

    fn encode(self, encoded: &mut Vec<u8>) {
        self.txid.encode_consensus(encoded);
        encoded.extend_from_slice(&self.vout.to_le_bytes());
    }
}

/// Session identifiers committed by the origin output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginContext {
    network_id: [u8; 32],
    room_id: [u8; 32],
    session_nonce: [u8; 32],
}

/// Canonical participant position in the two-party session-nonce ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceSeat {
    /// First/canonical Alice share.
    Alice,
    /// Second/canonical Bob share.
    Bob,
}

impl NonceSeat {
    const fn code(self) -> u8 {
        match self {
            Self::Alice => 0,
            Self::Bob => 1,
        }
    }
}

/// Commit to one participant's session-nonce share.
///
/// This is the sole owner of the domain tag and canonical field order used by
/// the browser commitment/reveal ceremony.
#[must_use]
pub fn commit_session_nonce_share(room_id: [u8; 32], seat: NonceSeat, share: [u8; 32]) -> [u8; 32] {
    let mut message = [0_u8; 65];
    message[..32].copy_from_slice(&room_id);
    message[32] = seat.code();
    message[33..].copy_from_slice(&share);
    tagged_hash(NONCE_SHARE_COMMITMENT_TAG, &message)
}

/// Derive the joint session nonce from canonically ordered participant shares.
///
/// The caller supplies Alice's share first and Bob's share second regardless
/// of which local browser performs the derivation.
#[must_use]
pub fn derive_session_nonce(
    room_id: [u8; 32],
    alice_share: [u8; 32],
    bob_share: [u8; 32],
) -> [u8; 32] {
    let mut message = [0_u8; 96];
    message[..32].copy_from_slice(&room_id);
    message[32..64].copy_from_slice(&alice_share);
    message[64..].copy_from_slice(&bob_share);
    tagged_hash(SESSION_NONCE_TAG, &message)
}

impl OriginContext {
    /// Validates and creates an immutable origin context.
    ///
    /// # Errors
    ///
    /// Rejects an all-zero network identifier, room identifier, or session
    /// nonce. Reserving zero prevents an absent/uninitialized binding from
    /// becoming a valid package context.
    pub const fn new(
        network_id: [u8; 32],
        room_id: [u8; 32],
        session_nonce: [u8; 32],
    ) -> Result<Self, OriginError> {
        if is_all_zero(&network_id) {
            return Err(OriginError::ZeroNetworkId);
        }
        if is_all_zero(&room_id) {
            return Err(OriginError::ZeroRoomId);
        }
        if is_all_zero(&session_nonce) {
            return Err(OriginError::ZeroSessionNonce);
        }
        Ok(Self {
            network_id,
            room_id,
            session_nonce,
        })
    }

    /// Network/profile identifier.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Relay room identifier.
    #[must_use]
    pub const fn room_id(&self) -> [u8; 32] {
        self.room_id
    }

    /// Joint session nonce.
    #[must_use]
    pub const fn session_nonce(&self) -> [u8; 32] {
        self.session_nonce
    }

    /// BIP340-style tagged commitment embedded in the origin witness script.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut message = [0_u8; 96];
        message[..32].copy_from_slice(&self.network_id);
        message[32..64].copy_from_slice(&self.room_id);
        message[64..].copy_from_slice(&self.session_nonce);
        tagged_hash(CONTEXT_TAG, &message)
    }
}

/// Canonical participant identifier: the x coordinate of a valid public key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParticipantId([u8; 32]);

impl ParticipantId {
    /// Parses a canonical x-only public key.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::InvalidXOnlyPublicKey`] when the bytes are not a
    /// curve point x coordinate.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, OriginError> {
        let mut compressed = [0_u8; 33];
        compressed[0] = 2;
        compressed[1..].copy_from_slice(&bytes);
        PublicKey::from_sec1_bytes(&compressed).map_err(|_| OriginError::InvalidXOnlyPublicKey)?;
        Ok(Self(bytes))
    }

    /// Derives an identifier from a compressed ECDSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`OriginError::InvalidPublicKey`] for a malformed key.
    pub fn from_compressed_public_key(bytes: [u8; 33]) -> Result<Self, OriginError> {
        validate_compressed_public_key(bytes)?;
        Ok(Self(x_only_bytes(bytes)))
    }

    /// Serialized x-only key bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One confirmed staging output and the key controlling it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingInput {
    outpoint: OutPoint,
    value_sat: u64,
    compressed_public_key: [u8; 33],
    participant_id: ParticipantId,
}

impl StagingInput {
    /// Validates one staging input.
    ///
    /// # Errors
    ///
    /// Rejects malformed compressed public keys, null outpoints, values below
    /// the fixed contribution, values above Bitcoin's money range, and nonzero
    /// change below the default-relay native-P2WSH dust threshold.
    pub fn new(
        outpoint: OutPoint,
        value_sat: u64,
        compressed_public_key: [u8; 33],
    ) -> Result<Self, OriginError> {
        validate_compressed_public_key(compressed_public_key)?;
        if outpoint.is_null() {
            return Err(OriginError::NullOutpoint);
        }
        if value_sat < CONTRIBUTION_SAT {
            return Err(OriginError::StagingValueTooSmall { value_sat });
        }
        if value_sat > MAX_MONEY_SAT {
            return Err(OriginError::StagingValueOutOfRange { value_sat });
        }
        let change_sat = value_sat - CONTRIBUTION_SAT;
        if change_sat != 0 && change_sat < P2WSH_MIN_NON_DUST_SAT {
            return Err(OriginError::DustChange {
                value_sat: change_sat,
                minimum_sat: P2WSH_MIN_NON_DUST_SAT,
            });
        }
        Ok(Self {
            outpoint,
            value_sat,
            compressed_public_key,
            participant_id: ParticipantId(x_only_bytes(compressed_public_key)),
        })
    }

    /// Validates an input whose transaction id bytes use conventional display
    /// order (the order emitted by hex-formatted block explorers).
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::new`].
    pub fn from_display_txid_bytes(
        display_txid: [u8; 32],
        vout: u32,
        value_sat: u64,
        compressed_public_key: [u8; 33],
    ) -> Result<Self, OriginError> {
        Self::new(
            OutPoint::new(Txid::from_display_bytes(display_txid), vout),
            value_sat,
            compressed_public_key,
        )
    }

    /// Exact staging outpoint.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Confirmed staging value in satoshis.
    #[must_use]
    pub const fn value_sat(&self) -> u64 {
        self.value_sat
    }

    /// Canonical participant identifier.
    #[must_use]
    pub const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Compressed ECDSA public key.
    #[must_use]
    pub const fn compressed_public_key(&self) -> [u8; 33] {
        self.compressed_public_key
    }

    /// Witness script controlling this staging output.
    #[must_use]
    pub fn staging_witness_script(&self) -> [u8; 35] {
        one_key_witness_script(self.compressed_public_key)
    }

    /// Expected native P2WSH script pubkey for this staging output.
    #[must_use]
    pub fn staging_script_pubkey(&self) -> [u8; 34] {
        p2wsh_script_pubkey(&self.staging_witness_script())
    }

    /// Change returned by the funding transaction.
    #[must_use]
    pub const fn change_sat(&self) -> u64 {
        self.value_sat - CONTRIBUTION_SAT
    }
}

/// A parsed, canonical, low-S compact ECDSA signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactSignature([u8; 64]);

impl CompactSignature {
    /// Parses a compact ECDSA signature and rejects high-S encodings.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid scalar encodings or high-S signatures.
    pub fn new(bytes: [u8; 64]) -> Result<Self, OriginError> {
        let signature =
            Signature::from_slice(&bytes).map_err(|_| OriginError::InvalidCompactSignature)?;
        if signature.normalize_s().is_some() {
            return Err(OriginError::HighSSignature);
        }
        Ok(Self(bytes))
    }

    /// Compact signature bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    fn parse(self) -> Result<Signature, OriginError> {
        Signature::from_slice(&self.0).map_err(|_| OriginError::InvalidCompactSignature)
    }
}

/// One participant-attributed compact signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureShare {
    signer: ParticipantId,
    signature: CompactSignature,
}

impl SignatureShare {
    /// Associates a compact signature with its signer.
    #[must_use]
    pub const fn new(signer: ParticipantId, signature: CompactSignature) -> Self {
        Self { signer, signature }
    }

    /// Claimed signer.
    #[must_use]
    pub const fn signer(&self) -> ParticipantId {
        self.signer
    }

    /// Canonical compact signature.
    #[must_use]
    pub const fn signature(&self) -> CompactSignature {
        self.signature
    }
}

/// Complete consensus bytes of an assembled witness transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTransaction {
    consensus_bytes: Vec<u8>,
    txid: Txid,
}

impl SignedTransaction {
    /// Full `SegWit` consensus serialization, including witnesses.
    #[must_use]
    pub fn consensus_bytes(&self) -> &[u8] {
        &self.consensus_bytes
    }

    /// Consumes the value and returns its full consensus bytes.
    #[must_use]
    pub fn into_consensus_bytes(self) -> Vec<u8> {
        self.consensus_bytes
    }

    /// Witness-independent transaction identifier.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputTemplate {
    outpoint: OutPoint,
    sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OutputTemplate {
    value_sat: u64,
    script_pubkey: Vec<u8>,
}

/// Fully deterministic unsigned funding and fair-refund transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginPackage {
    context: OriginContext,
    participants: [StagingInput; 2],
    origin_witness_script: Vec<u8>,
    origin_script_pubkey: [u8; 34],
    funding_inputs: [InputTemplate; 2],
    funding_outputs: Vec<OutputTemplate>,
    refund_input: InputTemplate,
    refund_outputs: [OutputTemplate; 2],
    unsigned_funding: Vec<u8>,
    unsigned_refund: Vec<u8>,
    funding_txid: Txid,
    refund_txid: Txid,
    funding_sighashes: [[u8; 32]; 2],
    refund_sighash: [u8; 32],
    package_id: [u8; 32],
}

impl OriginPackage {
    /// Constructs and canonicalizes an origin package.
    ///
    /// Participants and transaction inputs are ordered lexicographically by
    /// their x-only public key bytes. Funding output zero is always the shared
    /// origin. Nonzero change outputs follow in participant order.
    ///
    /// # Errors
    ///
    /// Rejects the same x-only participant or exact outpoint appearing twice,
    /// aggregate value above Bitcoin's money range, plus any internal
    /// serialization/signature-hash construction failure.
    pub fn new(
        context: OriginContext,
        first: StagingInput,
        second: StagingInput,
    ) -> Result<Self, OriginError> {
        if first.participant_id == second.participant_id {
            return Err(OriginError::DuplicateParticipant);
        }
        if first.outpoint == second.outpoint {
            return Err(OriginError::DuplicateOutpoint);
        }
        let aggregate_value_sat = first
            .value_sat
            .checked_add(second.value_sat)
            .ok_or(OriginError::AggregateStagingValueOutOfRange)?;
        if aggregate_value_sat > MAX_MONEY_SAT {
            return Err(OriginError::AggregateStagingValueOutOfRange);
        }

        let mut participants = [first, second];
        participants.sort_unstable_by_key(StagingInput::participant_id);
        let origin_witness_script = origin_witness_script(&context, &participants).to_vec();
        let origin_script_pubkey = p2wsh_script_pubkey(&origin_witness_script);
        let funding_inputs = participants.clone().map(|participant| InputTemplate {
            outpoint: participant.outpoint,
            sequence: FINAL_SEQUENCE,
        });
        let mut funding_outputs = vec![OutputTemplate {
            value_sat: ORIGIN_VALUE_SAT,
            script_pubkey: origin_script_pubkey.to_vec(),
        }];
        for participant in &participants {
            if participant.change_sat() != 0 {
                funding_outputs.push(OutputTemplate {
                    value_sat: participant.change_sat(),
                    script_pubkey: participant.staging_script_pubkey().to_vec(),
                });
            }
        }
        let unsigned_funding = serialize_transaction(&funding_inputs, &funding_outputs, None)?;
        let funding_txid = transaction_id(&unsigned_funding);
        let refund_input = InputTemplate {
            outpoint: OutPoint::new(funding_txid, 0),
            sequence: u32::from(REFUND_DELAY_BLOCKS),
        };
        let refund_outputs = participants.clone().map(|participant| OutputTemplate {
            value_sat: REFUND_VALUE_PER_PARTICIPANT_SAT,
            script_pubkey: participant.staging_script_pubkey().to_vec(),
        });
        let unsigned_refund =
            serialize_transaction(core::slice::from_ref(&refund_input), &refund_outputs, None)?;
        let refund_txid = transaction_id(&unsigned_refund);

        let funding_sighashes = [
            bip143_sighash(
                &funding_inputs,
                &funding_outputs,
                0,
                &participants[0].staging_witness_script(),
                participants[0].value_sat,
            )?,
            bip143_sighash(
                &funding_inputs,
                &funding_outputs,
                1,
                &participants[1].staging_witness_script(),
                participants[1].value_sat,
            )?,
        ];
        let refund_sighash = bip143_sighash(
            core::slice::from_ref(&refund_input),
            &refund_outputs,
            0,
            &origin_witness_script,
            ORIGIN_VALUE_SAT,
        )?;
        let package_id = package_id(&context, &unsigned_funding, &unsigned_refund);

        Ok(Self {
            context,
            participants,
            origin_witness_script,
            origin_script_pubkey,
            funding_inputs,
            funding_outputs,
            refund_input,
            refund_outputs,
            unsigned_funding,
            unsigned_refund,
            funding_txid,
            refund_txid,
            funding_sighashes,
            refund_sighash,
            package_id,
        })
    }

    /// Bound context.
    #[must_use]
    pub const fn context(&self) -> OriginContext {
        self.context
    }

    /// Participants in lexicographic x-only key order.
    #[must_use]
    pub const fn participants(&self) -> &[StagingInput; 2] {
        &self.participants
    }

    /// Returns the canonical index for a participant.
    #[must_use]
    pub fn participant_index(&self, participant: ParticipantId) -> Option<usize> {
        self.participants
            .iter()
            .position(|candidate| candidate.participant_id == participant)
    }

    /// Context-bound package identifier.
    #[must_use]
    pub const fn package_id(&self) -> [u8; 32] {
        self.package_id
    }

    /// Context-bound origin witness script.
    #[must_use]
    pub fn origin_witness_script(&self) -> &[u8] {
        &self.origin_witness_script
    }

    /// Native P2WSH origin script pubkey.
    #[must_use]
    pub const fn origin_script_pubkey(&self) -> [u8; 34] {
        self.origin_script_pubkey
    }

    /// Consensus serialization of the unsigned funding transaction.
    #[must_use]
    pub fn unsigned_funding_bytes(&self) -> Vec<u8> {
        self.unsigned_funding.clone()
    }

    /// Witness-independent funding transaction id.
    #[must_use]
    pub const fn funding_txid(&self) -> Txid {
        self.funding_txid
    }

    /// Shared origin outpoint, always funding output zero.
    #[must_use]
    pub const fn origin_outpoint(&self) -> OutPoint {
        OutPoint::new(self.funding_txid, 0)
    }

    /// Derives the exact origin-to-gameplay-root activation transaction.
    ///
    /// The caller supplies only the independently compiled Taproot root
    /// scriptPubKey. The input, output value, fee, sequence, version, and lock
    /// time are fixed by this prototype profile.
    ///
    /// # Errors
    ///
    /// Rejects anything other than a canonical 34-byte P2TR scriptPubKey or
    /// an internal serialization/signature-hash invariant failure.
    pub fn activation(
        &self,
        gameplay_root_script_pubkey: [u8; 34],
    ) -> Result<ActivationPackage, OriginError> {
        if gameplay_root_script_pubkey[0] != OP_PUSHNUM_1 || gameplay_root_script_pubkey[1] != 32 {
            return Err(OriginError::InvalidGameplayRootScript);
        }
        let input = InputTemplate {
            outpoint: self.origin_outpoint(),
            sequence: FINAL_SEQUENCE,
        };
        let output = OutputTemplate {
            value_sat: GAMEPLAY_ROOT_VALUE_SAT,
            script_pubkey: gameplay_root_script_pubkey.to_vec(),
        };
        let unsigned_transaction = serialize_transaction(
            core::slice::from_ref(&input),
            core::slice::from_ref(&output),
            None,
        )?;
        let txid = transaction_id(&unsigned_transaction);
        let sighash = bip143_sighash(
            core::slice::from_ref(&input),
            core::slice::from_ref(&output),
            0,
            &self.origin_witness_script,
            ORIGIN_VALUE_SAT,
        )?;
        let mut binding = Vec::with_capacity(32 + unsigned_transaction.len());
        binding.extend_from_slice(&self.package_id);
        binding.extend_from_slice(&unsigned_transaction);
        let activation_id = tagged_hash(ACTIVATION_TAG, &binding);
        Ok(ActivationPackage {
            origin_package_id: self.package_id,
            participants: self.participants.clone(),
            origin_witness_script: self.origin_witness_script.clone(),
            gameplay_root_script_pubkey,
            input,
            output,
            unsigned_transaction,
            txid,
            sighash,
            activation_id,
        })
    }

    /// Consensus serialization of the unsigned fair-refund transaction.
    #[must_use]
    pub fn unsigned_refund_bytes(&self) -> Vec<u8> {
        self.unsigned_refund.clone()
    }

    /// Witness-independent fair-refund transaction id.
    #[must_use]
    pub const fn refund_txid(&self) -> Txid {
        self.refund_txid
    }

    /// Funding BIP143 `SIGHASH_ALL` digests in participant/input order.
    #[must_use]
    pub const fn funding_sighashes(&self) -> [[u8; 32]; 2] {
        self.funding_sighashes
    }

    /// Funding digest for one participant.
    ///
    /// # Errors
    ///
    /// Rejects a signer not present in this package.
    pub fn funding_sighash(&self, participant: ParticipantId) -> Result<[u8; 32], OriginError> {
        let index = self
            .participant_index(participant)
            .ok_or(OriginError::UnknownSigner)?;
        Ok(self.funding_sighashes[index])
    }

    /// Shared refund BIP143 `SIGHASH_ALL` digest.
    #[must_use]
    pub const fn refund_sighash(&self) -> [u8; 32] {
        self.refund_sighash
    }

    /// Verifies one funding signature against its participant-specific digest.
    ///
    /// # Errors
    ///
    /// Rejects unknown signers and invalid signatures.
    pub fn verify_funding_signature(&self, share: SignatureShare) -> Result<(), OriginError> {
        let index = self
            .participant_index(share.signer)
            .ok_or(OriginError::UnknownSigner)?;
        verify_signature(
            self.participants[index].compressed_public_key,
            self.funding_sighashes[index],
            share.signature,
        )
    }

    /// Verifies one refund signature against the shared refund digest.
    ///
    /// # Errors
    ///
    /// Rejects unknown signers and invalid signatures.
    pub fn verify_refund_signature(&self, share: SignatureShare) -> Result<(), OriginError> {
        let index = self
            .participant_index(share.signer)
            .ok_or(OriginError::UnknownSigner)?;
        verify_signature(
            self.participants[index].compressed_public_key,
            self.refund_sighash,
            share.signature,
        )
    }

    /// Verifies both shares and assembles staging P2WSH witnesses.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, unknown signers, invalid signatures, and internal
    /// serialization failure.
    pub fn assemble_signed_funding(
        &self,
        shares: [SignatureShare; 2],
    ) -> Result<SignedTransaction, OriginError> {
        let ordered = self.verify_and_order(shares, SignatureTarget::Funding)?;
        let witnesses = [
            vec![
                signature_with_sighash_byte(ordered[0].signature)?,
                self.participants[0].staging_witness_script().to_vec(),
            ],
            vec![
                signature_with_sighash_byte(ordered[1].signature)?,
                self.participants[1].staging_witness_script().to_vec(),
            ],
        ];
        Ok(SignedTransaction {
            consensus_bytes: serialize_transaction(
                &self.funding_inputs,
                &self.funding_outputs,
                Some(&witnesses),
            )?,
            txid: self.funding_txid,
        })
    }

    /// Verifies both shares and assembles the context-bound origin witness.
    ///
    /// The script checks canonical participant zero first. Because Bitcoin
    /// consumes the top stack element first, the witness order is precisely
    /// `[signature_for_participant_1, signature_for_participant_0, script]`.
    /// No historical `CHECKMULTISIG` dummy element is present.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, unknown signers, invalid signatures, and internal
    /// serialization failure.
    pub fn assemble_signed_refund(
        &self,
        shares: [SignatureShare; 2],
    ) -> Result<SignedTransaction, OriginError> {
        let ordered = self.verify_and_order(shares, SignatureTarget::Refund)?;
        let witnesses = [vec![
            signature_with_sighash_byte(ordered[1].signature)?,
            signature_with_sighash_byte(ordered[0].signature)?,
            self.origin_witness_script.clone(),
        ]];
        Ok(SignedTransaction {
            consensus_bytes: serialize_transaction(
                core::slice::from_ref(&self.refund_input),
                &self.refund_outputs,
                Some(&witnesses),
            )?,
            txid: self.refund_txid,
        })
    }

    fn verify_and_order(
        &self,
        shares: [SignatureShare; 2],
        target: SignatureTarget,
    ) -> Result<[SignatureShare; 2], OriginError> {
        if shares[0].signer == shares[1].signer {
            return Err(OriginError::DuplicateSignature);
        }
        let mut ordered: [Option<SignatureShare>; 2] = [None, None];
        for share in shares {
            let index = self
                .participant_index(share.signer)
                .ok_or(OriginError::UnknownSigner)?;
            match target {
                SignatureTarget::Funding => self.verify_funding_signature(share)?,
                SignatureTarget::Refund => self.verify_refund_signature(share)?,
            }
            ordered[index] = Some(share);
        }
        match ordered {
            [Some(first), Some(second)] => Ok([first, second]),
            _ => Err(OriginError::MissingSignature),
        }
    }
}

/// Exact two-party transaction that activates the first gameplay state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationPackage {
    origin_package_id: [u8; 32],
    participants: [StagingInput; 2],
    origin_witness_script: Vec<u8>,
    gameplay_root_script_pubkey: [u8; 34],
    input: InputTemplate,
    output: OutputTemplate,
    unsigned_transaction: Vec<u8>,
    txid: Txid,
    sighash: [u8; 32],
    activation_id: [u8; 32],
}

impl ActivationPackage {
    /// Identifier of the origin/refund package this activation spends.
    #[must_use]
    pub const fn origin_package_id(&self) -> [u8; 32] {
        self.origin_package_id
    }

    /// Context- and root-bound activation identifier.
    #[must_use]
    pub const fn activation_id(&self) -> [u8; 32] {
        self.activation_id
    }

    /// Canonical P2TR gameplay-root scriptPubKey.
    #[must_use]
    pub const fn gameplay_root_script_pubkey(&self) -> [u8; 34] {
        self.gameplay_root_script_pubkey
    }

    /// Consensus serialization without witnesses.
    #[must_use]
    pub fn unsigned_transaction_bytes(&self) -> &[u8] {
        &self.unsigned_transaction
    }

    /// Witness-independent activation transaction identifier.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// Shared BIP143 `SIGHASH_ALL` digest signed by both participants.
    #[must_use]
    pub const fn sighash(&self) -> [u8; 32] {
        self.sighash
    }

    /// Verifies a participant's activation signature.
    ///
    /// # Errors
    ///
    /// Rejects an unknown participant or invalid signature.
    pub fn verify_signature(&self, share: SignatureShare) -> Result<(), OriginError> {
        let index = self
            .participants
            .iter()
            .position(|participant| participant.participant_id == share.signer)
            .ok_or(OriginError::UnknownSigner)?;
        verify_signature(
            self.participants[index].compressed_public_key,
            self.sighash,
            share.signature,
        )
    }

    /// Verifies both participants and assembles the complete activation.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, missing, unknown, or invalid signatures and any
    /// internal serialization invariant failure.
    pub fn assemble_signed(
        &self,
        shares: [SignatureShare; 2],
    ) -> Result<SignedTransaction, OriginError> {
        if shares[0].signer == shares[1].signer {
            return Err(OriginError::DuplicateSignature);
        }
        let mut ordered: [Option<SignatureShare>; 2] = [None, None];
        for share in shares {
            let index = self
                .participants
                .iter()
                .position(|participant| participant.participant_id == share.signer)
                .ok_or(OriginError::UnknownSigner)?;
            self.verify_signature(share)?;
            ordered[index] = Some(share);
        }
        let [Some(first), Some(second)] = ordered else {
            return Err(OriginError::MissingSignature);
        };
        let witnesses = [vec![
            signature_with_sighash_byte(second.signature)?,
            signature_with_sighash_byte(first.signature)?,
            self.origin_witness_script.clone(),
        ]];
        Ok(SignedTransaction {
            consensus_bytes: serialize_transaction(
                core::slice::from_ref(&self.input),
                core::slice::from_ref(&self.output),
                Some(&witnesses),
            )?,
            txid: self.txid,
        })
    }
}

#[derive(Clone, Copy)]
enum SignatureTarget {
    Funding,
    Refund,
}

/// Origin-package validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OriginError {
    /// The network/profile binding is absent.
    #[error("network identifier must not be all zero")]
    ZeroNetworkId,
    /// The room binding is absent.
    #[error("room identifier must not be all zero")]
    ZeroRoomId,
    /// The jointly derived nonce is absent.
    #[error("session nonce must not be all zero")]
    ZeroSessionNonce,
    /// Compressed public key parsing failed.
    #[error("invalid compressed public key")]
    InvalidPublicKey,
    /// X-only participant key parsing failed.
    #[error("invalid x-only public key")]
    InvalidXOnlyPublicKey,
    /// The same x-only key was supplied for both participants.
    #[error("duplicate participant")]
    DuplicateParticipant,
    /// The same transaction outpoint was supplied twice.
    #[error("duplicate staging outpoint")]
    DuplicateOutpoint,
    /// A coinbase-style null outpoint cannot be a staging output.
    #[error("staging outpoint must not be null")]
    NullOutpoint,
    /// A staging output cannot cover the fixed contribution.
    #[error("staging value {value_sat} is below the {CONTRIBUTION_SAT}-sat contribution")]
    StagingValueTooSmall {
        /// Invalid staging value.
        value_sat: u64,
    },
    /// A staging value exceeds Bitcoin's money range.
    #[error("staging value {value_sat} exceeds Bitcoin's money range")]
    StagingValueOutOfRange {
        /// Invalid staging value.
        value_sat: u64,
    },
    /// The pair's aggregate staging value exceeds Bitcoin's money range.
    #[error("aggregate staging value exceeds Bitcoin's money range")]
    AggregateStagingValueOutOfRange,
    /// Exact change would create a dust output.
    #[error("change value {value_sat} is below the {minimum_sat}-sat dust threshold")]
    DustChange {
        /// Proposed exact change.
        value_sat: u64,
        /// Default-relay minimum for the change script.
        minimum_sat: u64,
    },
    /// Transaction serialization or BIP143 construction hit an invariant.
    #[error("origin transaction construction invariant failed")]
    ConstructionInvariant,
    /// Gameplay root is not a canonical P2TR scriptPubKey.
    #[error("gameplay root must be a canonical 34-byte P2TR scriptPubKey")]
    InvalidGameplayRootScript,
    /// Compact ECDSA scalar encoding is invalid.
    #[error("invalid compact ECDSA signature")]
    InvalidCompactSignature,
    /// Compact ECDSA signature is not in low-S form.
    #[error("high-S ECDSA signature rejected")]
    HighSSignature,
    /// Signature names a participant not in the package.
    #[error("signature is from an unknown participant")]
    UnknownSigner,
    /// Both shares name the same signer.
    #[error("duplicate signature share")]
    DuplicateSignature,
    /// One canonical participant's share is absent.
    #[error("missing participant signature")]
    MissingSignature,
    /// Cryptographic verification failed.
    #[error("ECDSA signature does not authorize the exact transaction")]
    InvalidSignature,
}

fn validate_compressed_public_key(bytes: [u8; 33]) -> Result<(), OriginError> {
    if !matches!(bytes[0], 2 | 3) {
        return Err(OriginError::InvalidPublicKey);
    }
    let public_key =
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| OriginError::InvalidPublicKey)?;
    if public_key.to_encoded_point(true).as_bytes() != bytes {
        return Err(OriginError::InvalidPublicKey);
    }
    Ok(())
}

fn x_only_bytes(compressed_public_key: [u8; 33]) -> [u8; 32] {
    let mut x_only = [0_u8; 32];
    x_only.copy_from_slice(&compressed_public_key[1..]);
    x_only
}

fn one_key_witness_script(compressed_public_key: [u8; 33]) -> [u8; 35] {
    let mut script = [0_u8; 35];
    script[0] = 33;
    script[1..34].copy_from_slice(&compressed_public_key);
    script[34] = OP_CHECKSIG;
    script
}

fn origin_witness_script(context: &OriginContext, participants: &[StagingInput; 2]) -> [u8; 104] {
    let mut script = [0_u8; 104];
    script[0] = 32;
    script[1..33].copy_from_slice(&context.commitment());
    script[33] = OP_DROP;
    script[34] = 33;
    script[35..68].copy_from_slice(&participants[0].compressed_public_key);
    script[68] = OP_CHECKSIGVERIFY;
    script[69] = 33;
    script[70..103].copy_from_slice(&participants[1].compressed_public_key);
    script[103] = OP_CHECKSIG;
    script
}

fn p2wsh_script_pubkey(witness_script: &[u8]) -> [u8; 34] {
    let mut script_pubkey = [0_u8; 34];
    script_pubkey[1] = 32;
    script_pubkey[2..].copy_from_slice(&Sha256::digest(witness_script));
    script_pubkey
}

fn verify_signature(
    compressed_public_key: [u8; 33],
    sighash: [u8; 32],
    compact: CompactSignature,
) -> Result<(), OriginError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(&compressed_public_key)
        .map_err(|_| OriginError::InvalidPublicKey)?;
    verifying_key
        .verify_prehash(&sighash, &compact.parse()?)
        .map_err(|_| OriginError::InvalidSignature)
}

fn signature_with_sighash_byte(compact: CompactSignature) -> Result<Vec<u8>, OriginError> {
    let mut encoded = compact.parse()?.to_der().as_bytes().to_vec();
    encoded.push(SIGHASH_ALL_BYTE);
    Ok(encoded)
}

fn serialize_transaction(
    inputs: &[InputTemplate],
    outputs: &[OutputTemplate],
    witnesses: Option<&[Vec<Vec<u8>>]>,
) -> Result<Vec<u8>, OriginError> {
    if inputs.is_empty() || outputs.is_empty() {
        return Err(OriginError::ConstructionInvariant);
    }
    if witnesses.is_some_and(|stacks| stacks.len() != inputs.len()) {
        return Err(OriginError::ConstructionInvariant);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&VERSION_TWO.to_le_bytes());
    if witnesses.is_some() {
        encoded.extend_from_slice(&[0, 1]);
    }
    encode_compact_size(inputs.len(), &mut encoded)?;
    for input in inputs {
        input.outpoint.encode(&mut encoded);
        encoded.push(0);
        encoded.extend_from_slice(&input.sequence.to_le_bytes());
    }
    encode_compact_size(outputs.len(), &mut encoded)?;
    for output in outputs {
        encode_output(output, &mut encoded)?;
    }
    if let Some(stacks) = witnesses {
        for stack in stacks {
            encode_compact_size(stack.len(), &mut encoded)?;
            for element in stack {
                encode_compact_size(element.len(), &mut encoded)?;
                encoded.extend_from_slice(element);
            }
        }
    }
    encoded.extend_from_slice(&LOCK_TIME_ZERO.to_le_bytes());
    Ok(encoded)
}

fn encode_output(output: &OutputTemplate, encoded: &mut Vec<u8>) -> Result<(), OriginError> {
    encoded.extend_from_slice(&output.value_sat.to_le_bytes());
    encode_compact_size(output.script_pubkey.len(), encoded)?;
    encoded.extend_from_slice(&output.script_pubkey);
    Ok(())
}

fn encode_compact_size(value: usize, encoded: &mut Vec<u8>) -> Result<(), OriginError> {
    let value = u64::try_from(value).map_err(|_| OriginError::ConstructionInvariant)?;
    match value {
        0..=0xfc => {
            encoded.push(u8::try_from(value).map_err(|_| OriginError::ConstructionInvariant)?);
        }
        0xfd..=0xffff => {
            encoded.push(0xfd);
            encoded.extend_from_slice(
                &u16::try_from(value)
                    .map_err(|_| OriginError::ConstructionInvariant)?
                    .to_le_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            encoded.push(0xfe);
            encoded.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| OriginError::ConstructionInvariant)?
                    .to_le_bytes(),
            );
        }
        _ => {
            encoded.push(0xff);
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

fn bip143_sighash(
    inputs: &[InputTemplate],
    outputs: &[OutputTemplate],
    input_index: usize,
    witness_script: &[u8],
    value_sat: u64,
) -> Result<[u8; 32], OriginError> {
    let input = inputs
        .get(input_index)
        .ok_or(OriginError::ConstructionInvariant)?;
    let mut previous_outputs = Vec::with_capacity(inputs.len() * 36);
    let mut sequences = Vec::with_capacity(inputs.len() * 4);
    for candidate in inputs {
        candidate.outpoint.encode(&mut previous_outputs);
        sequences.extend_from_slice(&candidate.sequence.to_le_bytes());
    }
    let mut serialized_outputs = Vec::new();
    for output in outputs {
        encode_output(output, &mut serialized_outputs)?;
    }

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&VERSION_TWO.to_le_bytes());
    preimage.extend_from_slice(&double_sha256(&previous_outputs));
    preimage.extend_from_slice(&double_sha256(&sequences));
    input.outpoint.encode(&mut preimage);
    encode_compact_size(witness_script.len(), &mut preimage)?;
    preimage.extend_from_slice(witness_script);
    preimage.extend_from_slice(&value_sat.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&double_sha256(&serialized_outputs));
    preimage.extend_from_slice(&LOCK_TIME_ZERO.to_le_bytes());
    preimage.extend_from_slice(&SIGHASH_ALL_U32.to_le_bytes());
    Ok(double_sha256(&preimage))
}

fn transaction_id(unsigned_transaction: &[u8]) -> Txid {
    Txid::from_consensus_digest(double_sha256(unsigned_transaction))
}

fn package_id(
    context: &OriginContext,
    unsigned_funding: &[u8],
    unsigned_refund: &[u8],
) -> [u8; 32] {
    let mut message = Vec::with_capacity(
        32_usize
            .saturating_add(unsigned_funding.len())
            .saturating_add(unsigned_refund.len()),
    );
    message.extend_from_slice(&context.commitment());
    message.extend_from_slice(unsigned_funding);
    message.extend_from_slice(unsigned_refund);
    tagged_hash(PACKAGE_TAG, &message)
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

fn double_sha256(message: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(message)).into()
}

const fn is_all_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::{Amount, ScriptBuf, Transaction};
    use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

    use super::{
        ACTIVATION_FEE_SAT, CONTRIBUTION_SAT, CompactSignature, FUNDING_FEE_SAT,
        GAMEPLAY_ROOT_VALUE_SAT, MAX_MONEY_SAT, MAX_SIGNED_FUNDING_VBYTES,
        MAX_SIGNED_REFUND_VBYTES, NonceSeat, ORIGIN_VALUE_SAT, OriginContext, OriginError,
        OriginPackage, OutPoint, ParticipantId, REFUND_DELAY_BLOCKS, REFUND_FEE_SAT,
        REFUND_VALUE_PER_PARTICIPANT_SAT, SignatureShare, StagingInput, Txid,
        commit_session_nonce_share, derive_session_nonce,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn signing_key(byte: u8) -> Result<SigningKey, OriginError> {
        SigningKey::from_slice(&[byte; 32]).map_err(|_| OriginError::ConstructionInvariant)
    }

    fn public(key: &SigningKey) -> [u8; 33] {
        let encoded = key.verifying_key().to_encoded_point(true);
        let mut public_key = [0_u8; 33];
        public_key.copy_from_slice(encoded.as_bytes());
        public_key
    }

    fn context(nonce: u8) -> Result<OriginContext, OriginError> {
        OriginContext::new([0x51; 32], [0x52; 32], [nonce; 32])
    }

    fn staging(
        txid_byte: u8,
        vout: u32,
        value_sat: u64,
        key: &SigningKey,
    ) -> Result<StagingInput, OriginError> {
        StagingInput::new(
            OutPoint::new(Txid::from_display_bytes([txid_byte; 32]), vout),
            value_sat,
            public(key),
        )
    }

    fn fixture() -> Result<(OriginPackage, SigningKey, SigningKey), Box<dyn std::error::Error>> {
        let first_key = signing_key(1)?;
        let second_key = signing_key(2)?;
        let package = OriginPackage::new(
            context(0x53)?,
            staging(0x11, 1, 500_000, &first_key)?,
            staging(0x22, 2, CONTRIBUTION_SAT, &second_key)?,
        )?;
        Ok((package, first_key, second_key))
    }

    fn sign(key: &SigningKey, digest: [u8; 32]) -> Result<SignatureShare, OriginError> {
        let signature: Signature = key
            .sign_prehash(&digest)
            .map_err(|_| OriginError::InvalidSignature)?;
        Ok(SignatureShare::new(
            ParticipantId::from_compressed_public_key(public(key))?,
            CompactSignature::new(signature.to_bytes().into())?,
        ))
    }

    fn package_shares(
        package: &OriginPackage,
        first_key: &SigningKey,
        second_key: &SigningKey,
        refund: bool,
    ) -> Result<[SignatureShare; 2], OriginError> {
        let first_id = ParticipantId::from_compressed_public_key(public(first_key))?;
        let second_id = ParticipantId::from_compressed_public_key(public(second_key))?;
        let first_digest = if refund {
            package.refund_sighash()
        } else {
            package.funding_sighash(first_id)?
        };
        let second_digest = if refund {
            package.refund_sighash()
        } else {
            package.funding_sighash(second_id)?
        };
        Ok([
            sign(first_key, first_digest)?,
            sign(second_key, second_digest)?,
        ])
    }

    fn decode(bytes: &[u8]) -> Result<Transaction, bitcoin::consensus::encode::Error> {
        deserialize(bytes)
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[test]
    fn fixed_policy_and_worst_case_vsize() {
        assert_eq!(ORIGIN_VALUE_SAT, 53_500);
        assert_eq!(REFUND_VALUE_PER_PARTICIPANT_SAT, 26_500);
        assert_eq!(FUNDING_FEE_SAT, 500);
        assert_eq!(REFUND_FEE_SAT, 500);
        assert_eq!(ACTIVATION_FEE_SAT, 500);
        assert_eq!(GAMEPLAY_ROOT_VALUE_SAT, 53_000);
        assert_eq!(REFUND_DELAY_BLOCKS, 144);
        // 221 stripped bytes and 224 witness bytes with two changes.
        assert_eq!((221_u64 * 4 + 224).div_ceil(4), MAX_SIGNED_FUNDING_VBYTES);
        // 137 stripped bytes and 256 witness bytes.
        assert_eq!((137_u64 * 4 + 256).div_ceil(4), MAX_SIGNED_REFUND_VBYTES);
    }

    #[test]
    fn activation_is_exact_root_bound_and_fully_authorized() -> TestResult {
        let (package, first_key, second_key) = fixture()?;
        let mut root_script = [0x42; 34];
        root_script[0] = 0x51;
        root_script[1] = 32;
        let activation = package.activation(root_script)?;
        let transaction = decode(activation.unsigned_transaction_bytes())?;
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 1);
        assert_eq!(transaction.input[0].previous_output.vout, 0);
        assert_eq!(
            transaction.input[0].previous_output.txid.to_string(),
            package.funding_txid().to_string()
        );
        assert_eq!(transaction.input[0].sequence.to_consensus_u32(), u32::MAX);
        assert_eq!(
            transaction.output[0].value.to_sat(),
            GAMEPLAY_ROOT_VALUE_SAT
        );
        assert_eq!(transaction.output[0].script_pubkey.as_bytes(), root_script);
        assert_eq!(ORIGIN_VALUE_SAT - transaction.output[0].value.to_sat(), 500);
        assert_eq!(
            transaction.compute_txid().to_string(),
            activation.txid().to_string()
        );

        let expected = SighashCache::new(&transaction).p2wsh_signature_hash(
            0,
            &ScriptBuf::from_bytes(package.origin_witness_script().to_vec()),
            Amount::from_sat(ORIGIN_VALUE_SAT),
            EcdsaSighashType::All,
        )?;
        assert_eq!(expected.to_byte_array(), activation.sighash());

        let signed = activation.assemble_signed([
            sign(&first_key, activation.sighash())?,
            sign(&second_key, activation.sighash())?,
        ])?;
        let signed_transaction = decode(signed.consensus_bytes())?;
        assert_eq!(
            signed_transaction.compute_txid().to_string(),
            activation.txid().to_string()
        );
        assert_eq!(signed_transaction.input[0].witness.len(), 3);
        assert_eq!(
            signed_transaction.input[0].witness.nth(2),
            Some(package.origin_witness_script())
        );

        let mut different_root = root_script;
        different_root[2] ^= 1;
        let substituted = package.activation(different_root)?;
        assert_ne!(activation.activation_id(), substituted.activation_id());
        assert_ne!(activation.txid(), substituted.txid());
        assert_ne!(activation.sighash(), substituted.sighash());
        assert_eq!(
            substituted.verify_signature(sign(&first_key, activation.sighash())?),
            Err(OriginError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn activation_rejects_non_taproot_output() -> TestResult {
        let (package, _, _) = fixture()?;
        assert_eq!(
            package.activation([0; 34]),
            Err(OriginError::InvalidGameplayRootScript)
        );
        let mut wrong_version = [0x11; 34];
        wrong_version[1] = 32;
        assert_eq!(
            package.activation(wrong_version),
            Err(OriginError::InvalidGameplayRootScript)
        );
        Ok(())
    }

    #[test]
    fn canonical_order_is_independent_of_argument_order() -> TestResult {
        let first_key = signing_key(1)?;
        let second_key = signing_key(2)?;
        let first = staging(0x11, 1, 500_000, &first_key)?;
        let second = staging(0x22, 2, CONTRIBUTION_SAT, &second_key)?;
        let forward = OriginPackage::new(context(0x53)?, first.clone(), second.clone())?;
        let reverse = OriginPackage::new(context(0x53)?, second, first)?;
        assert_eq!(forward, reverse);
        assert!(
            forward.participants()[0].participant_id() < forward.participants()[1].participant_id()
        );
        Ok(())
    }

    #[test]
    fn rust_bitcoin_cross_checks_transactions_fees_and_sighashes() -> TestResult {
        let (package, _, _) = fixture()?;
        let funding = decode(&package.unsigned_funding_bytes())?;
        let refund = decode(&package.unsigned_refund_bytes())?;
        assert_eq!(
            funding.compute_txid().to_string(),
            package.funding_txid().to_string()
        );
        assert_eq!(
            refund.compute_txid().to_string(),
            package.refund_txid().to_string()
        );
        assert_eq!(funding.input.len(), 2);
        assert_eq!(funding.output.len(), 2);
        assert_eq!(funding.output[0].value.to_sat(), ORIGIN_VALUE_SAT);
        assert_eq!(
            funding.output[0].script_pubkey.as_bytes(),
            package.origin_script_pubkey()
        );
        assert_eq!(funding.output[1].value.to_sat(), 473_000);
        let input_sum = package
            .participants()
            .iter()
            .map(StagingInput::value_sat)
            .sum::<u64>();
        let output_sum = funding
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .sum::<u64>();
        assert_eq!(input_sum - output_sum, FUNDING_FEE_SAT);
        assert_eq!(
            refund.input[0].sequence.to_consensus_u32(),
            u32::from(REFUND_DELAY_BLOCKS)
        );
        assert!(
            refund
                .output
                .iter()
                .all(|output| output.value.to_sat() == REFUND_VALUE_PER_PARTICIPANT_SAT)
        );
        assert_eq!(
            ORIGIN_VALUE_SAT
                - refund
                    .output
                    .iter()
                    .map(|output| output.value.to_sat())
                    .sum::<u64>(),
            REFUND_FEE_SAT
        );

        let mut funding_cache = SighashCache::new(&funding);
        for (index, participant) in package.participants().iter().enumerate() {
            let expected = funding_cache.p2wsh_signature_hash(
                index,
                &ScriptBuf::from_bytes(participant.staging_witness_script().to_vec()),
                Amount::from_sat(participant.value_sat()),
                EcdsaSighashType::All,
            )?;
            assert_eq!(expected.to_byte_array(), package.funding_sighashes()[index]);
        }
        let expected_refund = SighashCache::new(&refund).p2wsh_signature_hash(
            0,
            &ScriptBuf::from_bytes(package.origin_witness_script().to_vec()),
            Amount::from_sat(ORIGIN_VALUE_SAT),
            EcdsaSighashType::All,
        )?;
        assert_eq!(expected_refund.to_byte_array(), package.refund_sighash());
        Ok(())
    }

    #[test]
    fn verifies_and_assembles_consensus_transactions() -> TestResult {
        let (package, first_key, second_key) = fixture()?;
        let signed_funding = package.assemble_signed_funding(package_shares(
            &package,
            &first_key,
            &second_key,
            false,
        )?)?;
        let funding = decode(signed_funding.consensus_bytes())?;
        assert_eq!(
            funding.compute_txid().to_string(),
            signed_funding.txid().to_string()
        );
        assert!(funding.input.iter().all(|input| input.witness.len() == 2));
        for (index, input) in funding.input.iter().enumerate() {
            assert_eq!(
                input.witness.last(),
                Some(
                    package.participants()[index]
                        .staging_witness_script()
                        .as_slice()
                )
            );
        }

        let signed_refund = package.assemble_signed_refund(package_shares(
            &package,
            &first_key,
            &second_key,
            true,
        )?)?;
        let refund = decode(signed_refund.consensus_bytes())?;
        assert_eq!(
            refund.compute_txid().to_string(),
            signed_refund.txid().to_string()
        );
        let witness = &refund.input[0].witness;
        assert_eq!(witness.len(), 3);
        assert_eq!(witness.nth(2), Some(package.origin_witness_script()));
        assert!(
            witness
                .nth(0)
                .is_some_and(|signature| signature.last() == Some(&1))
        );
        assert!(
            witness
                .nth(1)
                .is_some_and(|signature| signature.last() == Some(&1))
        );
        Ok(())
    }

    #[test]
    fn signatures_cannot_replay_across_contexts() -> TestResult {
        let (first_package, first_key, second_key) = fixture()?;
        let second_package = OriginPackage::new(
            context(0x54)?,
            first_package.participants()[0].clone(),
            first_package.participants()[1].clone(),
        )?;
        assert_ne!(first_package.package_id(), second_package.package_id());
        assert_ne!(first_package.funding_txid(), second_package.funding_txid());
        for share in package_shares(&first_package, &first_key, &second_key, false)? {
            assert_eq!(
                second_package.verify_funding_signature(share),
                Err(OriginError::InvalidSignature)
            );
        }
        for share in package_shares(&first_package, &first_key, &second_key, true)? {
            assert_eq!(
                second_package.verify_refund_signature(share),
                Err(OriginError::InvalidSignature)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_context_inputs_and_signature_sets() -> TestResult {
        assert_eq!(
            OriginContext::new([0; 32], [1; 32], [2; 32]),
            Err(OriginError::ZeroNetworkId)
        );
        assert_eq!(
            OriginContext::new([1; 32], [0; 32], [2; 32]),
            Err(OriginError::ZeroRoomId)
        );
        assert_eq!(
            OriginContext::new([1; 32], [2; 32], [0; 32]),
            Err(OriginError::ZeroSessionNonce)
        );
        let first_key = signing_key(1)?;
        let second_key = signing_key(2)?;
        let first = staging(0x11, 1, CONTRIBUTION_SAT, &first_key)?;
        let same_outpoint =
            StagingInput::new(first.outpoint(), CONTRIBUTION_SAT, public(&second_key))?;
        assert_eq!(
            OriginPackage::new(context(3)?, first.clone(), same_outpoint),
            Err(OriginError::DuplicateOutpoint)
        );
        assert_eq!(
            OriginPackage::new(
                context(3)?,
                first,
                staging(0x22, 2, CONTRIBUTION_SAT, &first_key)?,
            ),
            Err(OriginError::DuplicateParticipant)
        );
        assert_eq!(
            staging(1, 0, CONTRIBUTION_SAT - 1, &first_key),
            Err(OriginError::StagingValueTooSmall {
                value_sat: CONTRIBUTION_SAT - 1,
            })
        );
        assert!(matches!(
            staging(1, 0, CONTRIBUTION_SAT + 1, &first_key),
            Err(OriginError::DustChange { value_sat: 1, .. })
        ));
        assert_eq!(
            StagingInput::new(
                OutPoint::new(Txid::from_display_bytes([0; 32]), u32::MAX),
                CONTRIBUTION_SAT,
                public(&first_key),
            ),
            Err(OriginError::NullOutpoint)
        );
        assert_eq!(
            OriginPackage::new(
                context(3)?,
                staging(0x31, 0, MAX_MONEY_SAT, &first_key)?,
                staging(0x32, 0, CONTRIBUTION_SAT, &second_key)?,
            ),
            Err(OriginError::AggregateStagingValueOutOfRange)
        );
        let (package, first_key, _) = fixture()?;
        let first_id = ParticipantId::from_compressed_public_key(public(&first_key))?;
        let share = sign(&first_key, package.funding_sighash(first_id)?)?;
        assert_eq!(
            package.assemble_signed_funding([share, share]),
            Err(OriginError::DuplicateSignature)
        );
        let wrong = sign(&first_key, package.refund_sighash())?;
        assert_eq!(
            package.verify_funding_signature(wrong),
            Err(OriginError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn rejects_high_s_compact_signature() {
        let mut high_s = [0_u8; 64];
        high_s[31] = 1;
        high_s[32..].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ]);
        assert_eq!(
            CompactSignature::new(high_s),
            Err(OriginError::HighSSignature)
        );
    }

    #[test]
    fn fixed_serialization_vector() -> TestResult {
        let (package, _, _) = fixture()?;
        assert_eq!(
            hex(&package.unsigned_funding_bytes()),
            "020000000211111111111111111111111111111111111111111111111111111111111111110100000000ffffffff22222222222222222222222222222222222222222222222222222222222222220200000000ffffffff02fcd000000000000022002063cd3a810e1406dc5a637df078bf8bb5827b698e91facc11bf43f5413fec1a59a8370700000000002200207a0f34ce0c30967eed1c5a2021b1e9321cd9949db04625c94580040b85c7433800000000"
        );
        assert_eq!(
            hex(&package.unsigned_refund_bytes()),
            "02000000011cd96704b781058f53084886c87005daf04c72fa512570a81e13c39e88db91ed0000000000900000000284670000000000002200207a0f34ce0c30967eed1c5a2021b1e9321cd9949db04625c94580040b85c743388467000000000000220020c8e67b034888874e4b80835ce8c50e310740fcd70aa85297c5dca4b786a6905b00000000"
        );
        assert_eq!(
            hex(package.origin_witness_script()),
            "207f1c586fbd5e683682bc9a7efbbed617b485e0f2f17869f5fb981df6f924ad4a7521031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fad21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac"
        );
        assert_eq!(
            package.funding_sighashes().map(|digest| hex(&digest)),
            [
                "8e5d802047f98e2da3f80423ec70d03e47c8260eb8f5ba63c9e18dd58064400d",
                "317246293a621a17b750047f4a66d22d3cc75b9ccac4ccf353831f9242b60f5e",
            ]
        );
        assert_eq!(
            hex(&package.refund_sighash()),
            "b6f38b31d776a321948f7c3ba3fea55bcabcd8acebe5f34d44933521232fd102"
        );
        assert_eq!(
            hex(&package.package_id()),
            "db676113235fadc1ca1a7d55c7ca1f28012c5b74d5c7b3dff78f85779d091ea8"
        );
        assert_eq!(
            serialize(&decode(&package.unsigned_funding_bytes())?),
            package.unsigned_funding_bytes()
        );
        assert_eq!(
            serialize(&decode(&package.unsigned_refund_bytes())?),
            package.unsigned_refund_bytes()
        );
        Ok(())
    }

    #[test]
    fn session_nonce_ceremony_has_fixed_domain_vectors() {
        let room_id = [0x11; 32];
        let alice_share = [0x22; 32];
        let bob_share = [0x33; 32];
        assert_eq!(
            hex(&commit_session_nonce_share(
                room_id,
                NonceSeat::Alice,
                alice_share,
            )),
            "5b766e9ead7ed7172f61dc3ac12beee824cc892cf7e0f3229776b3ec83c03d20",
        );
        assert_eq!(
            hex(&commit_session_nonce_share(
                room_id,
                NonceSeat::Bob,
                bob_share,
            )),
            "be489912dad579821d4681481b80f482e4a515f417a41a373d8cb1b3aa9ce9ca",
        );
        assert_eq!(
            hex(&derive_session_nonce(room_id, alice_share, bob_share)),
            "4c2910d24a30bdc8eecd041b277ef4396bbf478ee4ce52c7303e3e191b3bbef4",
        );
    }
}
