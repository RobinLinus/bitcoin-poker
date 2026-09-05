//! Backend-neutral construction of the BP52 prototype origin package.
//!
//! The package consumes two native P2WSH staging outputs controlled by scripts
//! of the form `<compressed-pubkey> OP_CHECKSIG`. Each participant contributes
//! according to explicit validated funding terms. The funding transaction
//! pays the selected fee, returns every excess satoshi as deterministic change, and creates a
//! context-bound two-party P2WSH origin. Before funding is broadcast, both
//! participants can sign a delayed fair-refund transaction. Once the
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
const COOPERATIVE_CLOSE_TAG: &[u8] = b"BP52/origin-cooperative-close/v1";
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
pub struct DisplayTxid([u8; 32]);

impl DisplayTxid {
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

impl fmt::Display for DisplayTxid {
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
    txid: DisplayTxid,
    vout: u32,
}

impl OutPoint {
    /// Creates an outpoint.
    #[must_use]
    pub const fn new(txid: DisplayTxid, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Creating transaction identifier.
    #[must_use]
    pub const fn txid(self) -> DisplayTxid {
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
pub struct FundingContext {
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

impl FundingContext {
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
    ) -> Result<Self, FundingError> {
        if is_all_zero(&network_id) {
            return Err(FundingError::ZeroNetworkId);
        }
        if is_all_zero(&room_id) {
            return Err(FundingError::ZeroRoomId);
        }
        if is_all_zero(&session_nonce) {
            return Err(FundingError::ZeroSessionNonce);
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
    /// Returns [`FundingError::InvalidXOnlyPublicKey`] when the bytes are not a
    /// curve point x coordinate.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, FundingError> {
        let mut compressed = [0_u8; 33];
        compressed[0] = 2;
        compressed[1..].copy_from_slice(&bytes);
        PublicKey::from_sec1_bytes(&compressed).map_err(|_| FundingError::InvalidXOnlyPublicKey)?;
        Ok(Self(bytes))
    }

    /// Derives an identifier from a compressed ECDSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`FundingError::InvalidPublicKey`] for a malformed key.
    pub fn from_compressed_public_key(bytes: [u8; 33]) -> Result<Self, FundingError> {
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
pub struct PlayerFundingInput {
    terms: FundingTerms,
    outpoint: OutPoint,
    value_sat: u64,
    compressed_public_key: [u8; 33],
    participant_id: ParticipantId,
}

impl PlayerFundingInput {
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
        terms: FundingTerms,
    ) -> Result<Self, FundingError> {
        validate_compressed_public_key(compressed_public_key)?;
        if outpoint.is_null() {
            return Err(FundingError::NullOutpoint);
        }
        if value_sat < terms.contribution_sat() {
            return Err(FundingError::StagingValueTooSmall { value_sat });
        }
        if value_sat > MAX_MONEY_SAT {
            return Err(FundingError::StagingValueOutOfRange { value_sat });
        }
        let change_sat = value_sat - terms.contribution_sat();
        if change_sat != 0 && change_sat < P2WSH_MIN_NON_DUST_SAT {
            return Err(FundingError::DustChange {
                value_sat: change_sat,
                minimum_sat: P2WSH_MIN_NON_DUST_SAT,
            });
        }
        Ok(Self {
            terms,
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
        terms: FundingTerms,
    ) -> Result<Self, FundingError> {
        Self::new(
            OutPoint::new(DisplayTxid::from_display_bytes(display_txid), vout),
            value_sat,
            compressed_public_key,
            terms,
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
        self.value_sat - self.terms.contribution_sat()
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
    pub fn new(bytes: [u8; 64]) -> Result<Self, FundingError> {
        let signature =
            Signature::from_slice(&bytes).map_err(|_| FundingError::InvalidCompactSignature)?;
        if signature.normalize_s().is_some() {
            return Err(FundingError::HighSSignature);
        }
        Ok(Self(bytes))
    }

    /// Compact signature bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }

    fn parse(self) -> Result<Signature, FundingError> {
        Signature::from_slice(&self.0).map_err(|_| FundingError::InvalidCompactSignature)
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
    txid: DisplayTxid,
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
    pub const fn txid(&self) -> DisplayTxid {
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
pub struct EscrowFundingPackage {
    terms: FundingTerms,
    context: FundingContext,
    participants: [PlayerFundingInput; 2],
    origin_witness_script: Vec<u8>,
    origin_script_pubkey: [u8; 34],
    funding_inputs: [InputTemplate; 2],
    funding_outputs: Vec<OutputTemplate>,
    refund_input: InputTemplate,
    refund_outputs: [OutputTemplate; 2],
    unsigned_funding: Vec<u8>,
    unsigned_refund: Vec<u8>,
    funding_txid: DisplayTxid,
    refund_txid: DisplayTxid,
    funding_sighashes: [[u8; 32]; 2],
    refund_sighash: [u8; 32],
    package_id: [u8; 32],
}

impl EscrowFundingPackage {
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
        context: FundingContext,
        first: PlayerFundingInput,
        second: PlayerFundingInput,
    ) -> Result<Self, FundingError> {
        let terms = first.terms;
        if terms != second.terms {
            return Err(FundingError::InvalidFundingTerms);
        }
        if first.participant_id == second.participant_id {
            return Err(FundingError::DuplicateParticipant);
        }
        if first.outpoint == second.outpoint {
            return Err(FundingError::DuplicateOutpoint);
        }
        let aggregate_value_sat = first
            .value_sat
            .checked_add(second.value_sat)
            .ok_or(FundingError::AggregateStagingValueOutOfRange)?;
        if aggregate_value_sat > MAX_MONEY_SAT {
            return Err(FundingError::AggregateStagingValueOutOfRange);
        }

        let mut participants = [first, second];
        participants.sort_unstable_by_key(PlayerFundingInput::participant_id);
        let origin_witness_script = origin_witness_script(&context, &participants).to_vec();
        let origin_script_pubkey = p2wsh_script_pubkey(&origin_witness_script);
        let funding_inputs = participants.clone().map(|participant| InputTemplate {
            outpoint: participant.outpoint,
            sequence: FINAL_SEQUENCE,
        });
        let mut funding_outputs = vec![OutputTemplate {
            value_sat: terms.origin_value_sat(),
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
            sequence: u32::from(terms.refund_delay_blocks()),
        };
        let refund_outputs = participants.clone().map(|participant| OutputTemplate {
            value_sat: terms.refund_value_sat(),
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
            terms.origin_value_sat(),
        )?;
        let package_id = package_id(&context, &unsigned_funding, &unsigned_refund);

        Ok(Self {
            terms,
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
    pub const fn context(&self) -> FundingContext {
        self.context
    }

    /// Participants in lexicographic x-only key order.
    #[must_use]
    pub const fn participants(&self) -> &[PlayerFundingInput; 2] {
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
    pub const fn funding_txid(&self) -> DisplayTxid {
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
    ) -> Result<ActivationPackage, FundingError> {
        if gameplay_root_script_pubkey[0] != OP_PUSHNUM_1 || gameplay_root_script_pubkey[1] != 32 {
            return Err(FundingError::InvalidGameplayRootScript);
        }
        let input = InputTemplate {
            outpoint: self.origin_outpoint(),
            sequence: FINAL_SEQUENCE,
        };
        let output = OutputTemplate {
            value_sat: self.terms.gameplay_value_sat(),
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
            self.terms.origin_value_sat(),
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

    /// Build a cooperative settlement that spends the still-unpublished
    /// origin directly to the two participant staging scripts.
    ///
    /// Payouts are supplied in canonical participant order and must consume
    /// exactly the origin value less the fixed cooperative-close fee. This
    /// path is intended for a mutually agreed terminal off-chain state: it
    /// avoids publishing the activation and descendant gameplay graph.
    ///
    /// # Errors
    ///
    /// Rejects dust outputs, an overflowing or incorrect payout total, or an
    /// internal serialization/signature-hash invariant failure.
    pub fn cooperative_close(
        &self,
        payouts_sat: [u64; 2],
    ) -> Result<CooperativeClosePackage, FundingError> {
        let total = payouts_sat[0]
            .checked_add(payouts_sat[1])
            .ok_or(FundingError::InvalidCooperativeClosePayouts)?;
        if total != self.terms.origin_value_sat() - self.terms.cooperative_close_fee_sat()
            || payouts_sat
                .iter()
                .any(|value| *value < P2WSH_MIN_NON_DUST_SAT)
        {
            return Err(FundingError::InvalidCooperativeClosePayouts);
        }
        let input = InputTemplate {
            outpoint: self.origin_outpoint(),
            sequence: FINAL_SEQUENCE,
        };
        let outputs = core::array::from_fn(|index| OutputTemplate {
            value_sat: payouts_sat[index],
            script_pubkey: self.participants[index].staging_script_pubkey().to_vec(),
        });
        let unsigned_transaction =
            serialize_transaction(core::slice::from_ref(&input), &outputs, None)?;
        let txid = transaction_id(&unsigned_transaction);
        let sighash = bip143_sighash(
            core::slice::from_ref(&input),
            &outputs,
            0,
            &self.origin_witness_script,
            self.terms.origin_value_sat(),
        )?;
        let mut binding = Vec::with_capacity(32 + unsigned_transaction.len());
        binding.extend_from_slice(&self.package_id);
        binding.extend_from_slice(&unsigned_transaction);
        let close_id = tagged_hash(COOPERATIVE_CLOSE_TAG, &binding);
        Ok(CooperativeClosePackage {
            origin_package_id: self.package_id,
            participants: self.participants.clone(),
            origin_witness_script: self.origin_witness_script.clone(),
            input,
            outputs,
            unsigned_transaction,
            txid,
            sighash,
            close_id,
        })
    }

    /// Consensus serialization of the unsigned fair-refund transaction.
    #[must_use]
    pub fn unsigned_refund_bytes(&self) -> Vec<u8> {
        self.unsigned_refund.clone()
    }

    /// Witness-independent fair-refund transaction id.
    #[must_use]
    pub const fn refund_txid(&self) -> DisplayTxid {
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
    pub fn funding_sighash(&self, participant: ParticipantId) -> Result<[u8; 32], FundingError> {
        let index = self
            .participant_index(participant)
            .ok_or(FundingError::UnknownSigner)?;
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
    pub fn verify_funding_signature(&self, share: SignatureShare) -> Result<(), FundingError> {
        let index = self
            .participant_index(share.signer)
            .ok_or(FundingError::UnknownSigner)?;
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
    pub fn verify_refund_signature(&self, share: SignatureShare) -> Result<(), FundingError> {
        let index = self
            .participant_index(share.signer)
            .ok_or(FundingError::UnknownSigner)?;
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
    ) -> Result<SignedTransaction, FundingError> {
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
    ) -> Result<SignedTransaction, FundingError> {
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
    ) -> Result<[SignatureShare; 2], FundingError> {
        if shares[0].signer == shares[1].signer {
            return Err(FundingError::DuplicateSignature);
        }
        let mut ordered: [Option<SignatureShare>; 2] = [None, None];
        for share in shares {
            let index = self
                .participant_index(share.signer)
                .ok_or(FundingError::UnknownSigner)?;
            match target {
                SignatureTarget::Funding => self.verify_funding_signature(share)?,
                SignatureTarget::Refund => self.verify_refund_signature(share)?,
            }
            ordered[index] = Some(share);
        }
        match ordered {
            [Some(first), Some(second)] => Ok([first, second]),
            _ => Err(FundingError::MissingSignature),
        }
    }
}

#[derive(Clone, Copy)]
enum SignatureTarget {
    Funding,
    Refund,
}

/// Origin-package validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FundingError {
    /// Funding amounts, fees, or refund delay are inconsistent.
    #[error("invalid or mismatched funding terms")]
    InvalidFundingTerms,
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
    #[error("staging value {value_sat} is below the selected contribution")]
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
    /// Cooperative payouts are dusty or do not consume the exact close value.
    #[error(
        "cooperative-close payouts must be non-dust and sum to the exact origin value less fee"
    )]
    InvalidCooperativeClosePayouts,
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

fn validate_compressed_public_key(bytes: [u8; 33]) -> Result<(), FundingError> {
    if !matches!(bytes[0], 2 | 3) {
        return Err(FundingError::InvalidPublicKey);
    }
    let public_key =
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| FundingError::InvalidPublicKey)?;
    if public_key.to_encoded_point(true).as_bytes() != bytes {
        return Err(FundingError::InvalidPublicKey);
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

fn origin_witness_script(
    context: &FundingContext,
    participants: &[PlayerFundingInput; 2],
) -> [u8; 104] {
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
) -> Result<(), FundingError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(&compressed_public_key)
        .map_err(|_| FundingError::InvalidPublicKey)?;
    verifying_key
        .verify_prehash(&sighash, &compact.parse()?)
        .map_err(|_| FundingError::InvalidSignature)
}

fn signature_with_sighash_byte(compact: CompactSignature) -> Result<Vec<u8>, FundingError> {
    let mut encoded = compact.parse()?.to_der().as_bytes().to_vec();
    encoded.push(SIGHASH_ALL_BYTE);
    Ok(encoded)
}

fn package_id(
    context: &FundingContext,
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
mod tests;

mod transactions;
use transactions::{bip143_sighash, serialize_transaction, transaction_id};

pub mod activation;
pub use activation::*;

pub mod cooperative;
pub use cooperative::*;

/// Validated funding economics.
pub mod terms;
pub use terms::FundingTerms;
/// Fixed funding test vectors, separate from deployment configuration.
pub mod diagnostic;
