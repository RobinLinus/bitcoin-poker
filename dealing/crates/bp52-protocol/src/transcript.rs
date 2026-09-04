//! Hash-chain and Merlin transcript contexts.
//!
//! The protocol transcript has two layers. Signed wire envelopes form a
//! tagged-SHA-256 hash chain, while each zero-knowledge proof starts a Merlin
//! transcript at a phase-specific snapshot of that chain. This module keeps
//! the shared framing in one place so prover and verifier cannot silently
//! disagree about field order or integer encoding.

use bp52_group::{GroupError, JointPublicKey, ProtocolGenerators, hash::TaggedHash};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::{N_SLOTS, PROTOCOL_VERSION, Role};

/// Fixed protocol identifier bound into every proof transcript.
pub const PROTOCOL_ID: &[u8] = b"BP52-DEAL-v1";

/// Tagged-hash domain for an attempt's initial transcript root.
pub const TRANSCRIPT_START_TAG: &[u8] = b"BP52/transcript-start/v1";
/// Tagged-hash domain for every accepted full envelope.
pub const TRANSCRIPT_MESSAGE_TAG: &[u8] = b"BP52/transcript-msg/v1";

/// Merlin label for the common protocol identifier field.
pub const MERLIN_PROTOCOL_ID_LABEL: &[u8] = b"protocol-id";
/// Merlin label for the common protocol-version field.
pub const MERLIN_PROTOCOL_VERSION_LABEL: &[u8] = b"protocol-version";
/// Merlin label for the common game identifier field.
pub const MERLIN_GAME_ID_LABEL: &[u8] = b"game-id";
/// Merlin label for the common attempt number field.
pub const MERLIN_ATTEMPT_LABEL: &[u8] = b"attempt";
/// Merlin label for the common prover role field.
pub const MERLIN_ROLE_LABEL: &[u8] = b"role";
/// Merlin label for the preceding wire-transcript root.
pub const MERLIN_PRIOR_TRANSCRIPT_LABEL: &[u8] = b"prior-transcript";
/// Merlin label for Alice's x-only Bitcoin identity key.
pub const MERLIN_ALICE_IDENTITY_LABEL: &[u8] = b"alice-identity";
/// Merlin label for Bob's x-only Bitcoin identity key.
pub const MERLIN_BOB_IDENTITY_LABEL: &[u8] = b"bob-identity";
/// Merlin label for the threshold joint public key.
pub const MERLIN_JOINT_KEY_LABEL: &[u8] = b"joint-key";
/// Merlin label for the fixed circuit identifier.
pub const MERLIN_CIRCUIT_ID_LABEL: &[u8] = b"circuit-id";
/// Merlin label for the standard Ristretto blinding generator.
pub const MERLIN_BLINDING_GENERATOR_LABEL: &[u8] = b"G";
/// Merlin label for the independently derived message generator.
pub const MERLIN_MESSAGE_GENERATOR_LABEL: &[u8] = b"M";
/// Merlin label for the fixed number of card slots.
pub const MERLIN_SLOT_COUNT_LABEL: &[u8] = b"slot-count";
/// Merlin label used to extract every generalized-Schnorr challenge.
pub const MERLIN_CHALLENGE_LABEL: &[u8] = b"challenge";

const CHALLENGE_LENGTH: usize = 64;

/// A tagged-SHA-256 root in the authenticated envelope chain.
pub type TranscriptHash = [u8; 32];

/// Errors raised while constructing a proof transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TranscriptError {
    /// Alice's identity must sort strictly before Bob's identity.
    #[error("identity keys are not in canonical Alice/Bob order")]
    NonCanonicalIdentityOrder,
    /// The fixed Ristretto generators did not pass their invariant checks.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// A role-specific proof domain was paired with the other role.
    #[error("proof domain does not match the prover role")]
    DomainRoleMismatch,
    /// A Merlin challenge reduced to zero and must not be used.
    #[error("Merlin challenge reduced to zero")]
    ZeroChallenge,
}

/// The hash-chain state bound into proofs for one protocol attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptContext {
    /// Identifier of the surrounding funded game.
    pub game_id: [u8; 32],
    /// Zero-based attempt number.
    pub attempt: u32,
    /// Current `T_n`, before the next envelope is accepted.
    pub prior_transcript: TranscriptHash,
}

impl AttemptContext {
    /// Starts an attempt at `T_0`.
    #[must_use]
    pub fn new(game_id: [u8; 32], attempt: u32) -> Self {
        Self {
            game_id,
            attempt,
            prior_transcript: attempt_start(&game_id, attempt),
        }
    }

    /// Reconstructs a context at an already authenticated transcript root.
    ///
    /// Callers must obtain `prior_transcript` by validating and hashing the
    /// canonical full envelopes that precede this context.
    #[must_use]
    pub const fn with_prior_transcript(
        game_id: [u8; 32],
        attempt: u32,
        prior_transcript: TranscriptHash,
    ) -> Self {
        Self {
            game_id,
            attempt,
            prior_transcript,
        }
    }

    /// Advances to the hash of one fully validated, canonically encoded
    /// envelope and returns the new root.
    ///
    /// Authentication, schedule, predecessor, and canonical-encoding checks
    /// must happen before calling this method.
    pub fn advance(&mut self, encoded_full_envelope: &[u8]) -> TranscriptHash {
        self.prior_transcript = advance(&self.prior_transcript, encoded_full_envelope);
        self.prior_transcript
    }

    /// Labels the current root as the shared snapshot for `phase`.
    #[must_use]
    pub const fn phase_root(&self, phase: ProofPhase) -> PhaseRoot {
        PhaseRoot {
            phase,
            hash: self.prior_transcript,
        }
    }
}

/// Computes `T_0` for an attempt.
#[must_use]
pub fn attempt_start(game_id: &[u8; 32], attempt: u32) -> TranscriptHash {
    let mut hash = TaggedHash::new(TRANSCRIPT_START_TAG);
    hash.update(game_id);
    hash.update(attempt.to_le_bytes());
    hash.finalize()
}

/// Computes the next root from `T_n` and a canonical full envelope.
///
/// Under the ADR schedule, the envelope at sequence `n` carries `T_n` as its
/// predecessor and this function returns `T_(n+1)`.
#[must_use]
pub fn advance(previous: &TranscriptHash, encoded_full_envelope: &[u8]) -> TranscriptHash {
    let mut hash = TaggedHash::new(TRANSCRIPT_MESSAGE_TAG);
    hash.update(previous);
    hash.update(encoded_full_envelope);
    hash.finalize()
}

/// Proof flights and the authenticated snapshot each one must bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofPhase {
    /// Both key proofs bind `T_4`, after both key openings.
    KeyProof,
    /// Both player-bundle proofs bind `T_6`, after both key proofs.
    PlayerBundle,
    /// The selected first blinder's scale proof binds `T_10`.
    ScaleFirst,
    /// The other party's scale proof binds `T_11`.
    ScaleSecond,
    /// Both partial-decryption proofs bind `T_12`.
    PartialDecrypt,
}

impl ProofPhase {
    /// Number of accepted envelopes preceding this proof snapshot.
    #[must_use]
    pub const fn transcript_height(self) -> u32 {
        match self {
            Self::KeyProof => 4,
            Self::PlayerBundle => 6,
            Self::ScaleFirst => 10,
            Self::ScaleSecond => 11,
            Self::PartialDecrypt => 12,
        }
    }
}

/// A transcript root annotated with its proof flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseRoot {
    phase: ProofPhase,
    hash: TranscriptHash,
}

impl PhaseRoot {
    /// Constructs an explicitly labeled phase root.
    #[must_use]
    pub const fn new(phase: ProofPhase, hash: TranscriptHash) -> Self {
        Self { phase, hash }
    }

    /// Returns the proof flight associated with this root.
    #[must_use]
    pub const fn phase(self) -> ProofPhase {
        self.phase
    }

    /// Returns the tagged-SHA-256 transcript root.
    #[must_use]
    pub const fn hash(self) -> TranscriptHash {
        self.hash
    }
}

/// Exact Merlin domain separators assigned by protocol version 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofDomain {
    /// Threshold-key Schnorr proof of possession.
    KeyPop,
    /// Aggregated nine-slot SHA-256/preimage-length proof.
    HashLength,
    /// Batched Pedersen-to-ElGamal link proof.
    EncryptionLink,
    /// First uniqueness blinding layer.
    ScaleFirst,
    /// Second uniqueness blinding layer.
    ScaleSecond,
    /// Alice's batched partial-decryption proof.
    PartialDecryptAlice,
    /// Bob's batched partial-decryption proof.
    PartialDecryptBob,
}

impl ProofDomain {
    /// Returns the exact domain label passed to [`Transcript::new`].
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::KeyPop => b"BP52/key-pop/v1",
            Self::HashLength => b"BP52/hash-length/v1",
            Self::EncryptionLink => b"BP52/encryption-link/v1",
            Self::ScaleFirst => b"BP52/scale-first/v1",
            Self::ScaleSecond => b"BP52/scale-second/v1",
            Self::PartialDecryptAlice => b"BP52/partial-decrypt-A/v1",
            Self::PartialDecryptBob => b"BP52/partial-decrypt-B/v1",
        }
    }

    /// Selects the role-specific partial-decryption domain.
    #[must_use]
    pub const fn partial_decrypt(role: Role) -> Self {
        match role {
            Role::Alice => Self::PartialDecryptAlice,
            Role::Bob => Self::PartialDecryptBob,
        }
    }

    const fn accepts_role(self, role: Role) -> bool {
        !matches!(
            (self, role),
            (Self::PartialDecryptAlice, Role::Bob) | (Self::PartialDecryptBob, Role::Alice)
        )
    }
}

/// Public values shared by every proof transcript in an attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofCommonFrame {
    alice_identity: [u8; 32],
    bob_identity: [u8; 32],
    joint_key: [u8; 32],
    circuit_id: [u8; 32],
}

impl ProofCommonFrame {
    /// Constructs a frame and enforces canonical identity-role assignment.
    ///
    /// # Errors
    ///
    /// Returns [`TranscriptError::NonCanonicalIdentityOrder`] unless Alice's
    /// key is lexicographically smaller than Bob's key.
    pub fn new(
        alice_identity: [u8; 32],
        bob_identity: [u8; 32],
        joint_key: &JointPublicKey,
        circuit_id: [u8; 32],
    ) -> Result<Self, TranscriptError> {
        if alice_identity >= bob_identity {
            return Err(TranscriptError::NonCanonicalIdentityOrder);
        }

        Ok(Self {
            alice_identity,
            bob_identity,
            joint_key: joint_key.to_bytes(),
            circuit_id,
        })
    }

    /// Returns Alice's canonical x-only identity key.
    #[must_use]
    pub const fn alice_identity(&self) -> &[u8; 32] {
        &self.alice_identity
    }

    /// Returns Bob's canonical x-only identity key.
    #[must_use]
    pub const fn bob_identity(&self) -> &[u8; 32] {
        &self.bob_identity
    }

    /// Returns the compressed threshold joint public key.
    #[must_use]
    pub const fn joint_key(&self) -> &[u8; 32] {
        &self.joint_key
    }

    /// Returns the fixed hash-length circuit identifier.
    #[must_use]
    pub const fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }
}

/// Starts a proof transcript and appends the common v1 frame in normative
/// order.
///
/// # Errors
///
/// Returns an error if a role-specific domain is paired with the wrong role,
/// or if derivation of the fixed protocol generators fails.
pub fn proof_transcript(
    domain: ProofDomain,
    context: &AttemptContext,
    role: Role,
    common: &ProofCommonFrame,
) -> Result<Transcript, TranscriptError> {
    if !domain.accepts_role(role) {
        return Err(TranscriptError::DomainRoleMismatch);
    }
    let mut transcript = Transcript::new(domain.label());
    append_proof_common_frame(&mut transcript, context, role, common)?;
    Ok(transcript)
}

/// Appends the common v1 frame to an already domain-separated Merlin
/// transcript.
///
/// Prefer [`proof_transcript`] when starting a new proof. This lower-level
/// helper exists for proof backends that own transcript construction.
///
/// # Errors
///
/// Returns an error if derivation of the fixed protocol generators fails.
pub fn append_proof_common_frame(
    transcript: &mut Transcript,
    context: &AttemptContext,
    role: Role,
    common: &ProofCommonFrame,
) -> Result<(), TranscriptError> {
    let generators = ProtocolGenerators::derive()?;
    let blinding_generator = generators.blinding().compress().to_bytes();
    let message_generator = generators.message().compress().to_bytes();
    let protocol_version = PROTOCOL_VERSION.to_le_bytes();
    let attempt = context.attempt.to_le_bytes();
    let role = [role_byte(role)];
    let slot_count = u16::try_from(N_SLOTS)
        .map_err(|_| TranscriptError::Group(GroupError::InvalidGenerator))?
        .to_le_bytes();

    transcript.append_message(MERLIN_PROTOCOL_ID_LABEL, PROTOCOL_ID);
    transcript.append_message(MERLIN_PROTOCOL_VERSION_LABEL, &protocol_version);
    transcript.append_message(MERLIN_GAME_ID_LABEL, &context.game_id);
    transcript.append_message(MERLIN_ATTEMPT_LABEL, &attempt);
    transcript.append_message(MERLIN_ROLE_LABEL, &role);
    transcript.append_message(MERLIN_PRIOR_TRANSCRIPT_LABEL, &context.prior_transcript);
    transcript.append_message(MERLIN_ALICE_IDENTITY_LABEL, &common.alice_identity);
    transcript.append_message(MERLIN_BOB_IDENTITY_LABEL, &common.bob_identity);
    transcript.append_message(MERLIN_JOINT_KEY_LABEL, &common.joint_key);
    transcript.append_message(MERLIN_CIRCUIT_ID_LABEL, &common.circuit_id);
    transcript.append_message(MERLIN_BLINDING_GENERATOR_LABEL, &blinding_generator);
    transcript.append_message(MERLIN_MESSAGE_GENERATOR_LABEL, &message_generator);
    transcript.append_message(MERLIN_SLOT_COUNT_LABEL, &slot_count);
    Ok(())
}

/// Extracts and reduces the common 64-byte Merlin challenge.
///
/// A zero result is invalid under the v1 profile. Provers must retry with a
/// fresh proof nonce; verifiers must reject the proof.
///
/// # Errors
///
/// Returns [`TranscriptError::ZeroChallenge`] if reduction modulo the scalar
/// field produces zero.
pub fn challenge_scalar(transcript: &mut Transcript) -> Result<Scalar, TranscriptError> {
    let mut wide = [0_u8; CHALLENGE_LENGTH];
    transcript.challenge_bytes(MERLIN_CHALLENGE_LABEL, &mut wide);
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);
    if challenge == Scalar::ZERO {
        Err(TranscriptError::ZeroChallenge)
    } else {
        Ok(challenge)
    }
}

const fn role_byte(role: Role) -> u8 {
    match role {
        Role::Alice => 0,
        Role::Bob => 1,
    }
}

#[cfg(test)]
mod tests {
    use bp52_group::JointPublicKey;
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};

    use super::{
        AttemptContext, PhaseRoot, ProofCommonFrame, ProofDomain, ProofPhase, TranscriptError,
        advance, attempt_start, challenge_scalar, proof_transcript,
    };
    use crate::Role;

    fn fixed_common_frame() -> Result<ProofCommonFrame, TranscriptError> {
        let joint_key = JointPublicKey::new(Scalar::from(7_u64) * RISTRETTO_BASEPOINT_POINT)?;
        ProofCommonFrame::new([0x11; 32], [0x22; 32], &joint_key, [0x44; 32])
    }

    #[test]
    fn attempt_hash_chain_matches_fixed_vectors() {
        let game_id = core::array::from_fn(|index| u8::try_from(index).unwrap_or(0));
        let start = attempt_start(&game_id, 0x7856_3412);
        assert_eq!(
            start,
            [
                184, 110, 37, 24, 218, 105, 55, 253, 49, 9, 79, 226, 229, 57, 128, 203, 208, 216,
                2, 196, 4, 160, 184, 177, 254, 64, 55, 118, 159, 173, 229, 44,
            ]
        );

        let envelope = b"canonical full envelope including signature";
        let next = advance(&start, envelope);
        assert_eq!(
            next,
            [
                1, 48, 199, 205, 27, 77, 229, 150, 172, 92, 208, 133, 145, 247, 48, 216, 88, 169,
                245, 152, 44, 247, 142, 186, 204, 98, 245, 126, 153, 45, 242, 38,
            ]
        );

        let mut context = AttemptContext::new(game_id, 0x7856_3412);
        assert_eq!(context.prior_transcript, start);
        assert_eq!(context.advance(envelope), next);
    }

    #[test]
    fn merlin_common_frame_matches_fixed_vector() -> Result<(), TranscriptError> {
        let context = AttemptContext::with_prior_transcript([0x33; 32], 0x0403_0201, [0x55; 32]);
        let common = fixed_common_frame()?;
        let mut transcript =
            proof_transcript(ProofDomain::EncryptionLink, &context, Role::Bob, &common)?;
        let challenge = challenge_scalar(&mut transcript)?;
        assert_eq!(
            challenge.to_bytes(),
            [
                196, 168, 124, 46, 173, 105, 213, 165, 243, 90, 98, 228, 120, 147, 26, 212, 227,
                26, 40, 131, 7, 233, 16, 105, 188, 115, 195, 134, 83, 212, 222, 1,
            ]
        );
        Ok(())
    }

    #[test]
    fn proof_domains_are_exact() {
        assert_eq!(ProofDomain::KeyPop.label(), b"BP52/key-pop/v1");
        assert_eq!(ProofDomain::HashLength.label(), b"BP52/hash-length/v1");
        assert_eq!(
            ProofDomain::EncryptionLink.label(),
            b"BP52/encryption-link/v1"
        );
        assert_eq!(ProofDomain::ScaleFirst.label(), b"BP52/scale-first/v1");
        assert_eq!(ProofDomain::ScaleSecond.label(), b"BP52/scale-second/v1");
        assert_eq!(
            ProofDomain::partial_decrypt(Role::Alice).label(),
            b"BP52/partial-decrypt-A/v1"
        );
        assert_eq!(
            ProofDomain::partial_decrypt(Role::Bob).label(),
            b"BP52/partial-decrypt-B/v1"
        );
    }

    #[test]
    fn partial_decrypt_domain_must_match_role() -> Result<(), TranscriptError> {
        let context = AttemptContext::with_prior_transcript([0x33; 32], 0, [0x55; 32]);
        let common = fixed_common_frame()?;
        assert!(
            proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &context,
                Role::Alice,
                &common,
            )
            .is_ok()
        );
        assert_eq!(
            proof_transcript(
                ProofDomain::PartialDecryptAlice,
                &context,
                Role::Bob,
                &common,
            )
            .err(),
            Some(TranscriptError::DomainRoleMismatch)
        );
        Ok(())
    }

    #[test]
    fn phase_heights_match_the_canonical_schedule() {
        assert_eq!(ProofPhase::KeyProof.transcript_height(), 4);
        assert_eq!(ProofPhase::PlayerBundle.transcript_height(), 6);
        assert_eq!(ProofPhase::ScaleFirst.transcript_height(), 10);
        assert_eq!(ProofPhase::ScaleSecond.transcript_height(), 11);
        assert_eq!(ProofPhase::PartialDecrypt.transcript_height(), 12);

        let root = PhaseRoot::new(ProofPhase::ScaleSecond, [0xaa; 32]);
        assert_eq!(root.phase(), ProofPhase::ScaleSecond);
        assert_eq!(root.hash(), [0xaa; 32]);
    }

    #[test]
    fn common_frame_rejects_noncanonical_identity_order() -> Result<(), TranscriptError> {
        let joint_key = JointPublicKey::new(Scalar::from(7_u64) * RISTRETTO_BASEPOINT_POINT)?;
        assert_eq!(
            ProofCommonFrame::new([0x22; 32], [0x11; 32], &joint_key, [0x44; 32]),
            Err(TranscriptError::NonCanonicalIdentityOrder)
        );
        assert_eq!(
            ProofCommonFrame::new([0x11; 32], [0x11; 32], &joint_key, [0x44; 32]),
            Err(TranscriptError::NonCanonicalIdentityOrder)
        );
        Ok(())
    }
}
