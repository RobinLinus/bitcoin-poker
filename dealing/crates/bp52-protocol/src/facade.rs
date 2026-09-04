//! Stable, fixed-parameter compatibility facade for the section 23 API.
//!
//! The lower-level modules retain their more explicit transcript-frame and
//! validated-key types for the authenticated state machine. This facade keeps
//! the compact specification API without permitting a caller to select
//! generators, circuit shape, slot count, deck size, or preimage bounds.
//!
//! Native share/card opening functions intentionally remain in the sibling
//! `bp52-bitcoin` crate. Keeping that direction avoids a protocol-to-Bitcoin
//! dependency cycle; applications may import both facade families directly.

use std::sync::{Arc, Mutex, OnceLock};

use bp52_circuit::hash_length::{HashLengthParameters, HashLengthProofError};
use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, GroupError, JointPublicKey, ProtocolGenerators,
};
use bp52_sigma::SigmaError;
use bp52_uniqueness::UniquenessError;
use curve25519_dalek::RistrettoPoint;
use rand_core::{CryptoRng, RngCore};

use crate::{
    N_SLOTS, Role,
    auth::CanonicalIdentities,
    bundle::{
        BundleError, generate_player_bundle as generate_player_bundle_inner,
        verify_player_bundle as verify_player_bundle_inner,
    },
    contribution::{ContributionError, SecretContribution},
    messages::{Ciphertext, PlayerBundle, ZERO_TEST_COUNT},
    outcome::ProtocolError,
    transcript::{AttemptContext, ProofCommonFrame},
    uniqueness::{
        JointKeyPublic, UniquenessTranscript, UniquenessTranscriptError,
        verify_uniqueness_transcript as verify_uniqueness_transcript_inner,
    },
};

/// Fixed version-one proof parameters and canonical Bitcoin identity roles.
///
/// Fields are private so a caller cannot substitute another circuit backend or
/// change the identities bound into every proof transcript. The large,
/// deterministic Bulletproof generator allocation is initialized at most once
/// per process and shared immutably by all instances.
#[derive(Clone)]
pub struct ProtocolParams {
    hash_length: Arc<HashLengthParameters>,
    circuit_id: [u8; 32],
    identities: CanonicalIdentities,
}

static HASH_LENGTH_PARAMETERS: SharedCache<HashLengthParameters> = SharedCache::new();

impl ProtocolParams {
    /// Obtains the only accepted version-one proof parameters.
    ///
    /// The first successful call constructs the expensive fixed generator
    /// vectors. Later calls, including calls for different games or identity
    /// pairs, reuse that immutable process-wide allocation.
    ///
    /// `identities` must have been produced by [`CanonicalIdentities::new`] (or
    /// [`crate::auth::derive_roles`]), which fixes Alice and Bob by x-only key
    /// ordering before any proof transcript is built.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed [`ProtocolError`] if fixed generator derivation,
    /// manifest construction, or backend parameter allocation fails.
    pub fn new(identities: CanonicalIdentities) -> Result<Self, ProtocolError> {
        let hash_length = HASH_LENGTH_PARAMETERS
            .get_or_try_init(HashLengthParameters::new)
            .map_err(map_shared_parameter_error)?;
        let circuit_id = hash_length.circuit_id();
        Ok(Self {
            hash_length,
            circuit_id,
            identities,
        })
    }

    /// Returns the immutable circuit identifier compiled into version one.
    #[must_use]
    pub const fn circuit_id(&self) -> [u8; 32] {
        self.circuit_id
    }

    /// Returns the canonical identity-to-role assignment bound into proofs.
    #[must_use]
    pub const fn identities(&self) -> &CanonicalIdentities {
        &self.identities
    }

    /// Borrows the fixed proof parameters used by the authenticated attempt
    /// lifecycle.
    ///
    /// This accessor does not expose mutable generator or circuit choices;
    /// [`HashLengthParameters`] itself has only the fixed v1 constructor.
    #[must_use]
    pub fn hash_length_parameters(&self) -> &HashLengthParameters {
        self.hash_length.as_ref()
    }
}

/// Generates one fresh nine-slot player bundle under fixed version-one
/// parameters.
///
/// The compatibility signature accepts the Ristretto point shown in the
/// specification. The point is first validated as a nonidentity joint key,
/// then the full proof frame is reconstructed from `params`; no transcript
/// field or generator is caller-selectable.
///
/// # Errors
///
/// Returns a conservative [`ProtocolError`] for invalid joint-key input,
/// randomness failure, inconsistent local witness generation, or proof-system
/// failure. Secret openings remain in the private, zeroizing
/// [`SecretContribution`] container.
pub fn generate_player_bundle<R>(
    params: &ProtocolParams,
    context: &AttemptContext,
    role: Role,
    joint_key: &RistrettoPoint,
    rng: &mut R,
) -> Result<(PlayerBundle, SecretContribution), ProtocolError>
where
    R: CryptoRng + RngCore,
{
    let joint_key = validate_joint_key(joint_key)?;
    let common = proof_common_frame(params, &joint_key)?;
    generate_player_bundle_inner(
        params.hash_length.as_ref(),
        context,
        &common,
        role,
        &joint_key,
        rng,
    )
    .map_err(map_bundle_error)
}

/// Verifies one self-describing player bundle under fixed version-one
/// parameters.
///
/// This wrapper binds the proof to the bundle's encoded role, both canonical
/// Bitcoin identities, the validated joint key, the fixed circuit identifier,
/// and the complete [`AttemptContext`]. Authenticated protocol processing
/// should continue to use [`crate::driver::AttemptVerifier`], which additionally
/// enforces the scheduled sender role.
///
/// # Errors
///
/// Returns a conservative [`ProtocolError`] for malformed public values,
/// context disagreement, or either failed bundle proof.
pub fn verify_player_bundle(
    params: &ProtocolParams,
    context: &AttemptContext,
    joint_key: &RistrettoPoint,
    bundle: &PlayerBundle,
) -> Result<(), ProtocolError> {
    let joint_key = validate_joint_key(joint_key)?;
    let common = proof_common_frame(params, &joint_key)?;
    verify_player_bundle_inner(
        params.hash_length.as_ref(),
        context,
        &common,
        bundle.role,
        &joint_key,
        bundle,
    )
    .map_err(map_bundle_error)
}

/// Derives the 108 fixed-order zero-test ciphertexts from two public bundles.
///
/// Alice and Bob roles are checked before decoding, both original ciphertext
/// `R` components must be nonidentity, and the message generator is always the
/// fixed locally derived version-one generator. This operation derives public
/// statements only; callers must separately verify both bundle proofs.
///
/// # Errors
///
/// Returns [`ProtocolError::UnexpectedMessage`] if the bundles are not in
/// Alice-then-Bob order, a canonical point error for malformed ciphertexts, or
/// [`ProtocolError::UnexpectedIdentity`] for a neutral derived-`R`
/// cancellation that requires a fresh attempt.
pub fn derive_zero_test_ciphertexts(
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
) -> Result<[Ciphertext; ZERO_TEST_COUNT], ProtocolError> {
    if bundle_a.role != Role::Alice || bundle_b.role != Role::Bob {
        return Err(ProtocolError::UnexpectedMessage);
    }

    let contributions_a = decode_bundle_ciphertexts(bundle_a)?;
    let contributions_b = decode_bundle_ciphertexts(bundle_b)?;
    let generators = ProtocolGenerators::derive().map_err(map_group_error)?;
    let differences = bp52_uniqueness::derive_zero_test_ciphertexts(
        &contributions_a,
        &contributions_b,
        &generators,
    )
    .map_err(|error| map_uniqueness_error(error, ProtocolError::InvalidScaleProof))?;
    Ok(differences.map(|ciphertext| ciphertext.to_bytes().into()))
}

/// Verifies the complete public uniqueness transcript and returns whether all
/// nine cards are distinct.
///
/// The richer [`crate::uniqueness::verify_uniqueness_transcript_detailed`]
/// remains available to protocol-state code that must distinguish a neutral
/// derived-point retry from an attributable proof failure.
///
/// # Errors
///
/// Returns a fail-closed [`ProtocolError`] for context, bundle, point, ordering,
/// scaling-proof, or partial-decryption-proof failure.
pub fn verify_uniqueness_transcript(
    context: &AttemptContext,
    key_setup: &JointKeyPublic,
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
    transcript: &UniquenessTranscript,
) -> Result<bool, ProtocolError> {
    verify_uniqueness_transcript_inner(context, key_setup, bundle_a, bundle_b, transcript)
        .map_err(map_uniqueness_transcript_error)
}

fn validate_joint_key(point: &RistrettoPoint) -> Result<JointPublicKey, ProtocolError> {
    JointPublicKey::new(*point).map_err(map_group_error)
}

fn proof_common_frame(
    params: &ProtocolParams,
    joint_key: &JointPublicKey,
) -> Result<ProofCommonFrame, ProtocolError> {
    ProofCommonFrame::new(
        params.identities.alice().serialize(),
        params.identities.bob().serialize(),
        joint_key,
        params.circuit_id,
    )
    .map_err(|_| ProtocolError::TranscriptMismatch)
}

#[derive(Debug)]
enum SharedCacheError<E> {
    Initialization(E),
    Poisoned,
}

struct SharedCache<T> {
    value: OnceLock<Arc<T>>,
    initialization: Mutex<()>,
}

impl<T> SharedCache<T> {
    const fn new() -> Self {
        Self {
            value: OnceLock::new(),
            initialization: Mutex::new(()),
        }
    }

    fn get_or_try_init<E>(
        &self,
        initialize: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, SharedCacheError<E>> {
        if let Some(value) = self.value.get() {
            return Ok(Arc::clone(value));
        }

        let _initialization_guard = self
            .initialization
            .lock()
            .map_err(|_| SharedCacheError::Poisoned)?;
        if let Some(value) = self.value.get() {
            return Ok(Arc::clone(value));
        }

        let value = Arc::new(initialize().map_err(SharedCacheError::Initialization)?);
        if self.value.set(Arc::clone(&value)).is_ok() {
            return Ok(value);
        }

        // `value` is private and every initializer is serialized by the mutex,
        // so this branch is defensive rather than an expected race path.
        self.value
            .get()
            .map(Arc::clone)
            .ok_or(SharedCacheError::Poisoned)
    }
}

fn map_shared_parameter_error(error: SharedCacheError<HashLengthProofError>) -> ProtocolError {
    match error {
        SharedCacheError::Initialization(error) => map_hash_length_error(&error),
        SharedCacheError::Poisoned => ProtocolError::InvalidHashLengthProof,
    }
}

fn decode_bundle_ciphertexts(
    bundle: &PlayerBundle,
) -> Result<[ElGamalCiphertext; N_SLOTS], ProtocolError> {
    let mut decoded = Vec::with_capacity(N_SLOTS);
    for slot in &bundle.slots {
        let ciphertext = CiphertextBytes::from(slot.ciphertext)
            .decompress_contribution()
            .map_err(map_group_error)?;
        decoded.push(ciphertext);
    }
    decoded
        .try_into()
        .map_err(|_| ProtocolError::MalformedEncoding)
}

fn map_bundle_error(error: BundleError) -> ProtocolError {
    match error {
        BundleError::Contribution(error) => map_contribution_error(error),
        BundleError::Group(error) => map_group_error(error),
        BundleError::HashLengthProof(error) => map_hash_length_error(&error),
        BundleError::EncryptionLinkProof(error) => {
            map_sigma_error(&error, ProtocolError::InvalidEncryptionLinkProof)
        }
        BundleError::Codec(_) => ProtocolError::MalformedEncoding,
        BundleError::Transcript(_)
        | BundleError::ContextJointKeyMismatch
        | BundleError::ContextCircuitMismatch => ProtocolError::TranscriptMismatch,
        BundleError::RoleMismatch { .. } => ProtocolError::UnexpectedMessage,
        BundleError::BundleCircuitMismatch
        | BundleError::HashWitness(_)
        | BundleError::SecretOpeningMismatch { .. }
        | BundleError::InternalShape => ProtocolError::InvalidHashLengthProof,
        BundleError::HashLengthProofSize { .. } | BundleError::EncryptionLinkProofSize { .. } => {
            ProtocolError::MalformedEncoding
        }
    }
}

fn map_contribution_error(error: ContributionError) -> ProtocolError {
    match error {
        ContributionError::Group(error)
        | ContributionError::InvalidValueCommitment { source: error, .. }
        | ContributionError::InvalidCiphertext { source: error, .. } => map_group_error(error),
        ContributionError::PreimageRandomnessUnavailable
        | ContributionError::BlindingSamplingFailed => ProtocolError::RngFailure,
        ContributionError::DuplicateHash { .. } => ProtocolError::DuplicateHash,
    }
}

fn map_hash_length_error(error: &HashLengthProofError) -> ProtocolError {
    match error {
        HashLengthProofError::Group(error) => map_group_error(*error),
        HashLengthProofError::Circuit(_)
        | HashLengthProofError::Backend(_)
        | HashLengthProofError::Manifest(_)
        | HashLengthProofError::CommitmentMismatch
        | HashLengthProofError::ZeroBlinding
        | HashLengthProofError::MetricsMismatch
        | HashLengthProofError::VerificationFailed => ProtocolError::InvalidHashLengthProof,
    }
}

fn map_sigma_error(error: &SigmaError, proof_error: ProtocolError) -> ProtocolError {
    match error {
        SigmaError::Group(error) => map_group_error(*error),
        SigmaError::WrongProofLength => ProtocolError::MalformedEncoding,
        SigmaError::ZeroChallenge | SigmaError::VerificationFailed => proof_error,
    }
}

fn map_uniqueness_error(error: UniquenessError, proof_error: ProtocolError) -> ProtocolError {
    match error {
        UniquenessError::DegenerateIdentity { .. } => ProtocolError::UnexpectedIdentity,
        UniquenessError::Group(error) => map_group_error(error),
        UniquenessError::Sigma(error) => map_sigma_error(&error, proof_error),
        UniquenessError::InternalLength => ProtocolError::MalformedEncoding,
    }
}

fn map_uniqueness_transcript_error(error: UniquenessTranscriptError) -> ProtocolError {
    match error {
        UniquenessTranscriptError::FirstPhaseRootMismatch
        | UniquenessTranscriptError::Transcript(_) => ProtocolError::TranscriptMismatch,
        UniquenessTranscriptError::BundleRoleMismatch => ProtocolError::UnexpectedMessage,
        UniquenessTranscriptError::CircuitMismatch => ProtocolError::InvalidHashLengthProof,
        UniquenessTranscriptError::InternalShape => ProtocolError::MalformedEncoding,
        UniquenessTranscriptError::Contribution(error) => map_contribution_error(error),
        UniquenessTranscriptError::Group(error) => map_group_error(error),
        // The lower-level aggregate error intentionally hides whether a Sigma
        // failure occurred during scaling or partial decryption. Classifying
        // it as a uniqueness scaling failure is fail-closed; callers needing
        // phase-precise diagnostics should use the detailed verifier directly.
        UniquenessTranscriptError::Uniqueness(error) => {
            map_uniqueness_error(error, ProtocolError::InvalidScaleProof)
        }
    }
}

const fn map_group_error(error: GroupError) -> ProtocolError {
    match error {
        GroupError::InvalidPoint => ProtocolError::NonCanonicalPoint,
        GroupError::NonCanonicalScalar => ProtocolError::NonCanonicalScalar,
        GroupError::UnexpectedIdentity
        | GroupError::JointKeyIdentity
        | GroupError::DuplicateKeyShare
        | GroupError::InvalidGenerator => ProtocolError::UnexpectedIdentity,
        GroupError::ZeroScalar => ProtocolError::ZeroScaleFactor,
        GroupError::RngFailure => ProtocolError::RngFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use curve25519_dalek::RistrettoPoint;
    use curve25519_dalek::traits::Identity;
    use rand_core::OsRng;

    use crate::{
        AttemptContext, CanonicalIdentities, Ciphertext, JointKeyPublic, PlayerBundle,
        ProtocolError, ProtocolParams, Role, SecretContribution, UniquenessTranscript,
        ZERO_TEST_COUNT, derive_zero_test_ciphertexts, generate_player_bundle,
        verify_player_bundle, verify_uniqueness_transcript,
    };

    use super::{SharedCache, SharedCacheError};

    #[test]
    fn section_23_function_signatures_typecheck_without_parameter_allocation() {
        type Construct = fn(CanonicalIdentities) -> Result<ProtocolParams, ProtocolError>;
        type Generate = fn(
            &ProtocolParams,
            &AttemptContext,
            Role,
            &RistrettoPoint,
            &mut OsRng,
        ) -> Result<(PlayerBundle, SecretContribution), ProtocolError>;
        type Verify = fn(
            &ProtocolParams,
            &AttemptContext,
            &RistrettoPoint,
            &PlayerBundle,
        ) -> Result<(), ProtocolError>;
        type Derive = fn(
            &PlayerBundle,
            &PlayerBundle,
        ) -> Result<[Ciphertext; ZERO_TEST_COUNT], ProtocolError>;
        type VerifyUniqueness = fn(
            &AttemptContext,
            &JointKeyPublic,
            &PlayerBundle,
            &PlayerBundle,
            &UniquenessTranscript,
        ) -> Result<bool, ProtocolError>;

        let _: Construct = ProtocolParams::new;
        let _: Generate = generate_player_bundle::<OsRng>;
        let _: Verify = verify_player_bundle;
        let _: Derive = derive_zero_test_ciphertexts;
        let _: VerifyUniqueness = verify_uniqueness_transcript;
    }

    #[test]
    fn facade_rejects_identity_joint_key_without_parameter_allocation() {
        assert!(matches!(
            super::validate_joint_key(&RistrettoPoint::identity()),
            Err(ProtocolError::UnexpectedIdentity)
        ));
    }

    #[test]
    fn shared_cache_initializes_once_across_threads() -> Result<(), Box<dyn std::error::Error>> {
        const WORKERS: usize = 8;

        let cache = Arc::new(SharedCache::new());
        let barrier = Arc::new(Barrier::new(WORKERS));
        let initialization_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(WORKERS);

        for _ in 0..WORKERS {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            let initialization_count = Arc::clone(&initialization_count);
            handles.push(thread::spawn(move || {
                barrier.wait();
                cache.get_or_try_init(|| {
                    initialization_count.fetch_add(1, Ordering::SeqCst);
                    Ok::<usize, &'static str>(52)
                })
            }));
        }

        let mut values = Vec::with_capacity(WORKERS);
        for handle in handles {
            let result = handle
                .join()
                .map_err(|_| io::Error::other("shared-cache worker panicked"))?;
            let value =
                result.map_err(|_| io::Error::other("shared-cache initialization failed"))?;
            values.push(value);
        }

        assert_eq!(initialization_count.load(Ordering::SeqCst), 1);
        let first = values
            .first()
            .ok_or_else(|| io::Error::other("shared-cache test produced no values"))?;
        assert_eq!(**first, 52);
        assert!(values.iter().all(|value| Arc::ptr_eq(first, value)));
        Ok(())
    }

    #[test]
    fn failed_shared_cache_initialization_can_be_retried() -> Result<(), Box<dyn std::error::Error>>
    {
        let cache = SharedCache::new();
        let failed = cache.get_or_try_init(|| Err::<usize, _>("expected failure"));
        assert!(matches!(
            failed,
            Err(SharedCacheError::Initialization("expected failure"))
        ));

        let initialized = cache
            .get_or_try_init(|| Ok::<usize, &'static str>(7))
            .map_err(|_| io::Error::other("shared-cache retry failed"))?;
        let reused = cache
            .get_or_try_init(|| Ok::<usize, &'static str>(99))
            .map_err(|_| io::Error::other("shared-cache reuse failed"))?;

        assert_eq!(*initialized, 7);
        assert!(Arc::ptr_eq(&initialized, &reused));
        Ok(())
    }
}
