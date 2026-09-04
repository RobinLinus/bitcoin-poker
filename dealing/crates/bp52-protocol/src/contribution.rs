//! Secret contribution generation and public-slot prevalidation.
//!
//! Proof construction deliberately lives outside this module.  Generation
//! stops at the nine public hash/commitment/ciphertext statements and retains
//! their openings in a zeroizing container.

use bp52_group::{
    CiphertextBytes, ElGamalCiphertext, GroupError, JointPublicKey, NonZeroScalar,
    ProtocolGenerators, commit, decode_point, sample_card_value,
};
use curve25519_dalek::{RistrettoPoint, Scalar, traits::IsIdentity};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    N_SLOTS, PREIMAGE_BASE_LEN, PREIMAGE_MAX_LEN, Role,
    messages::{AcceptedDeal, Ciphertext, PlayerBundle, SlotPublic},
    preimage_storage::StorageContext,
};

pub use crate::preimage_storage::{
    PreimageStorageError, PreimageStorageKey, SealedRetainedPreimages,
};

/// Maximum number of attempts made when a blinding candidate is rejected.
const MAX_BLINDING_REJECTION_ATTEMPTS: usize = 128;

/// Contribution-generation and public prevalidation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContributionError {
    /// A group operation or a bounded group sampler failed.
    #[error(transparent)]
    Group(#[from] GroupError),
    /// The random source reported a failure while filling a share preimage.
    #[error("random source failed while filling a share preimage")]
    PreimageRandomnessUnavailable,
    /// Every bounded Pedersen-blinding candidate was zero or produced identity.
    #[error("random source failed bounded Pedersen-blinding rejection sampling")]
    BlindingSamplingFailed,
    /// A public value commitment was noncanonical or the identity.
    #[error("slot {slot} has an invalid original value commitment: {source}")]
    InvalidValueCommitment {
        /// Zero-based slot containing the invalid commitment.
        slot: usize,
        /// Exact group-decoding failure.
        source: GroupError,
    },
    /// An original ciphertext was noncanonical or had an identity `R` component.
    #[error("slot {slot} has an invalid original ciphertext: {source}")]
    InvalidCiphertext {
        /// Zero-based slot containing the invalid ciphertext.
        slot: usize,
        /// Exact group-decoding failure.
        source: GroupError,
    },
    /// Two hash locks in the Alice-then-Bob 18-slot ordering are equal.
    #[error("duplicate hash locks at global indices {first} and {second}")]
    DuplicateHash {
        /// First global index in Alice-then-Bob order.
        first: usize,
        /// Second global index in Alice-then-Bob order.
        second: usize,
    },
}

/// The nine secret openings retained by one contributor.
///
/// The fields intentionally remain private, and this type intentionally does
/// not implement `Clone`, `Debug`, or serialization.  It zeroizes both when
/// explicitly requested and when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretContribution {
    preimages: [Vec<u8>; N_SLOTS],
    values: [u8; N_SLOTS],
    encryption_randomness: [Scalar; N_SLOTS],
    commitment_blindings: [Scalar; N_SLOTS],
}

/// The nine share preimages retained after an accepted deal.
///
/// This value is intentionally non-cloneable, non-debuggable, and
/// non-serializable. It erases its in-memory buffers on drop. Applications
/// persist it only through [`RetainedPreimages::seal_at_rest`]; this crate
/// deliberately provides no plaintext persistence API.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RetainedPreimages {
    preimages: [Vec<u8>; N_SLOTS],
}

impl RetainedPreimages {
    /// Borrows one accepted share preimage.
    #[must_use]
    pub fn get(&self, slot: usize) -> Option<&[u8]> {
        self.preimages.get(slot).map(Vec::as_slice)
    }

    /// Returns the fixed number of retained share preimages.
    #[must_use]
    pub const fn len(&self) -> usize {
        N_SLOTS
    }

    /// The accepted container is never empty under protocol version one.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Authenticates and encrypts these accepted preimages for persistence,
    /// then erases their live plaintext allocations.
    ///
    /// `accepted_deal` must be the verified certificate that retained these
    /// local share preimages, and `role` must identify their contributor. All
    /// nine lengths and hash locks are checked before encryption. The operation
    /// is atomic with respect to this owner: validation, RNG, or AEAD failure
    /// leaves the live preimages untouched, while success erases `self`.
    ///
    /// # Errors
    ///
    /// Returns a storage-context, preimage-validation, RNG, or AEAD error.
    pub fn seal_at_rest<R>(
        &mut self,
        accepted_deal: &AcceptedDeal,
        role: Role,
        storage_key: &mut PreimageStorageKey,
        rng: &mut R,
    ) -> Result<SealedRetainedPreimages, PreimageStorageError>
    where
        R: CryptoRng + RngCore,
    {
        self.validate_against(accepted_deal, role)?;
        let context = StorageContext::from_deal(accepted_deal, role)?;
        let plaintext_size = self
            .preimages
            .iter()
            .map(|preimage| 1 + preimage.len())
            .sum();
        let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(plaintext_size));
        for (slot, preimage) in self.preimages.iter().enumerate() {
            let length = u8::try_from(preimage.len()).map_err(|_| {
                PreimageStorageError::InvalidPreimageLength {
                    slot,
                    length: preimage.len(),
                }
            })?;
            plaintext.push(length);
            plaintext.extend_from_slice(preimage);
        }
        let sealed = SealedRetainedPreimages::seal(context, &plaintext, storage_key, rng)?;
        self.zeroize();
        Ok(sealed)
    }

    fn validate_against(
        &self,
        accepted_deal: &AcceptedDeal,
        role: Role,
    ) -> Result<(), PreimageStorageError> {
        let expected_hashes = match role {
            Role::Alice => &accepted_deal.hashes_a,
            Role::Bob => &accepted_deal.hashes_b,
        };
        for (slot, (preimage, expected_hash)) in
            self.preimages.iter().zip(expected_hashes).enumerate()
        {
            if !(PREIMAGE_BASE_LEN..=PREIMAGE_MAX_LEN).contains(&preimage.len()) {
                return Err(PreimageStorageError::InvalidPreimageLength {
                    slot,
                    length: preimage.len(),
                });
            }
            let actual_hash: [u8; 32] = Sha256::digest(preimage).into();
            if &actual_hash != expected_hash {
                return Err(PreimageStorageError::PreimageMismatch { slot });
            }
        }
        Ok(())
    }
}

impl SealedRetainedPreimages {
    /// Authenticates this stored owner and verifies all nine accepted hash
    /// locks without releasing live share preimages.
    ///
    /// This is intended for pre-funding inventory checks. The ciphertext owner
    /// remains sealed and can later be consumed by [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns a context, authentication, canonical-plaintext, length, or
    /// accepted hash-lock mismatch.
    pub fn verify(
        &self,
        accepted_deal: &AcceptedDeal,
        role: Role,
        storage_key: &PreimageStorageKey,
    ) -> Result<(), PreimageStorageError> {
        let retained = self.reconstruct(accepted_deal, role, storage_key)?;
        drop(retained);
        Ok(())
    }

    /// Authenticates and consumes this encrypted owner, returning the nine
    /// preimages only after exact parsing and accepted hash-lock validation.
    ///
    /// The caller must supply the same verified accepted deal and local role
    /// used when sealing. No partially parsed secret owner is returned on
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns a context, authentication, canonical-plaintext, length, or
    /// accepted hash-lock mismatch.
    pub fn open(
        self,
        accepted_deal: &AcceptedDeal,
        role: Role,
        storage_key: &PreimageStorageKey,
    ) -> Result<RetainedPreimages, PreimageStorageError> {
        self.reconstruct(accepted_deal, role, storage_key)
    }

    fn reconstruct(
        &self,
        accepted_deal: &AcceptedDeal,
        role: Role,
        storage_key: &PreimageStorageKey,
    ) -> Result<RetainedPreimages, PreimageStorageError> {
        let context = StorageContext::from_deal(accepted_deal, role)?;
        let plaintext = self.open_plaintext(context, storage_key)?;
        let mut ranges = [(0_usize, 0_usize); N_SLOTS];
        let mut cursor = 0_usize;
        for range in &mut ranges {
            let Some(&encoded_length) = plaintext.get(cursor) else {
                return Err(PreimageStorageError::InvalidPlaintext);
            };
            cursor += 1;
            let length = usize::from(encoded_length);
            if !(PREIMAGE_BASE_LEN..=PREIMAGE_MAX_LEN).contains(&length) {
                return Err(PreimageStorageError::InvalidPlaintext);
            }
            let end = cursor
                .checked_add(length)
                .ok_or(PreimageStorageError::InvalidPlaintext)?;
            if end > plaintext.len() {
                return Err(PreimageStorageError::InvalidPlaintext);
            }
            *range = (cursor, end);
            cursor = end;
        }
        if cursor != plaintext.len() {
            return Err(PreimageStorageError::InvalidPlaintext);
        }

        let retained = RetainedPreimages {
            preimages: core::array::from_fn(|slot| {
                let (start, end) = ranges[slot];
                plaintext[start..end].to_vec()
            }),
        };
        retained.validate_against(accepted_deal, role)?;
        Ok(retained)
    }
}

impl SecretContribution {
    pub(crate) const fn preimages(&self) -> &[Vec<u8>; N_SLOTS] {
        &self.preimages
    }

    pub(crate) const fn values(&self) -> &[u8; N_SLOTS] {
        &self.values
    }

    pub(crate) const fn encryption_randomness_values(&self) -> &[Scalar; N_SLOTS] {
        &self.encryption_randomness
    }

    pub(crate) const fn commitment_blinding_values(&self) -> &[Scalar; N_SLOTS] {
        &self.commitment_blindings
    }

    /// Borrows one raw share preimage, if `slot` is in range.
    #[must_use]
    pub fn preimage(&self, slot: usize) -> Option<&[u8]> {
        self.preimages.get(slot).map(Vec::as_slice)
    }

    /// Returns one hidden contribution value, if `slot` is in range.
    #[must_use]
    pub fn value(&self, slot: usize) -> Option<u8> {
        self.values.get(slot).copied()
    }

    /// Borrows one nonzero `ElGamal` randomness scalar, if `slot` is in range.
    #[must_use]
    pub fn encryption_randomness(&self, slot: usize) -> Option<&Scalar> {
        self.encryption_randomness.get(slot)
    }

    /// Borrows one nonzero Pedersen blinding, if `slot` is in range.
    #[must_use]
    pub fn commitment_blinding(&self, slot: usize) -> Option<&Scalar> {
        self.commitment_blindings.get(slot)
    }

    /// Erases values and cryptographic openings while retaining only the nine
    /// Bitcoin share preimages after acceptance signatures are complete.
    #[must_use]
    pub(crate) fn into_retained_preimages(mut self) -> RetainedPreimages {
        self.values.zeroize();
        self.encryption_randomness.zeroize();
        self.commitment_blindings.zeroize();
        RetainedPreimages {
            preimages: core::mem::take(&mut self.preimages),
        }
    }
}

/// Generates nine contribution statements and their zeroizing secret openings.
///
/// Each value is sampled uniformly from `0..52` using byte rejection.  Its
/// preimage has exactly `16 + value` independently filled bytes.  Encryption
/// randomness is nonzero.  Pedersen blindings are additionally resampled when
/// zero or when their resulting commitment is the identity.
///
/// This function does not construct the hash-length or encryption-link proofs.
///
/// # Errors
///
/// Returns an error if fixed generator derivation fails, the RNG cannot fill a
/// preimage, any bounded rejection sampler is exhausted, or defensive public
/// point validation fails.
pub fn generate_contribution<R>(
    joint_key: &JointPublicKey,
    rng: &mut R,
) -> Result<([SlotPublic; N_SLOTS], SecretContribution), ContributionError>
where
    R: CryptoRng + RngCore,
{
    let generators = ProtocolGenerators::derive()?;
    let mut slots = [empty_public_slot(); N_SLOTS];
    let mut secrets = SecretContribution {
        preimages: core::array::from_fn(|_| Vec::new()),
        values: [0_u8; N_SLOTS],
        encryption_randomness: [Scalar::ZERO; N_SLOTS],
        commitment_blindings: [Scalar::ZERO; N_SLOTS],
    };

    for (index, public_slot) in slots.iter_mut().enumerate() {
        let value = sample_card_value(&mut *rng)?;
        let preimage_len = PREIMAGE_BASE_LEN + usize::from(value);
        debug_assert!(preimage_len <= PREIMAGE_MAX_LEN);

        secrets.preimages[index] = vec![0_u8; preimage_len];
        rng.try_fill_bytes(secrets.preimages[index].as_mut_slice())
            .map_err(|_| ContributionError::PreimageRandomnessUnavailable)?;
        let hash = Sha256::digest(secrets.preimages[index].as_slice()).into();

        let value_scalar = Scalar::from(u64::from(value));
        let randomness = NonZeroScalar::random(&mut *rng)?;
        let (blinding, value_commitment) =
            sample_commitment_blinding(value_scalar, &generators, &mut *rng)?;
        let ciphertext =
            ElGamalCiphertext::encrypt(value_scalar, &randomness, joint_key, &generators);

        secrets.values[index] = value;
        secrets.encryption_randomness[index] = *randomness.as_scalar();
        secrets.commitment_blindings[index] = blinding;
        *public_slot = SlotPublic {
            hash,
            value_commitment: value_commitment.compress().to_bytes(),
            ciphertext: Ciphertext::from(ciphertext.to_bytes()),
        };
    }

    // Keep this defensive check at the construction boundary so a future
    // arithmetic refactor cannot emit malformed original statements.
    validate_original_contribution_points(&slots)?;
    Ok((slots, secrets))
}

/// Rejects noncanonical original points, identity `V`, and identity `R`.
///
/// Ciphertext `S` is required to decode canonically but is allowed to be the
/// identity, as required by the protocol's original-ciphertext checks.
///
/// # Errors
///
/// Returns the slot and decoding failure for the first invalid commitment or
/// ciphertext.
pub fn validate_original_contribution_points(
    slots: &[SlotPublic; N_SLOTS],
) -> Result<(), ContributionError> {
    for (slot, public) in slots.iter().enumerate() {
        decode_point(public.value_commitment, false)
            .map_err(|source| ContributionError::InvalidValueCommitment { slot, source })?;
        CiphertextBytes::from(public.ciphertext)
            .decompress_contribution()
            .map_err(|source| ContributionError::InvalidCiphertext { slot, source })?;
    }
    Ok(())
}

/// Enforces pairwise distinctness of all 18 Alice-then-Bob hash locks.
///
/// # Errors
///
/// Returns the first equal pair's global indices when any hashes are equal.
pub fn validate_global_hash_uniqueness(
    alice: &[SlotPublic; N_SLOTS],
    bob: &[SlotPublic; N_SLOTS],
) -> Result<(), ContributionError> {
    let total = 2 * N_SLOTS;
    for first in 0..total {
        for second in (first + 1)..total {
            if hash_at_global_index(alice, bob, first) == hash_at_global_index(alice, bob, second) {
                return Err(ContributionError::DuplicateHash { first, second });
            }
        }
    }
    Ok(())
}

/// Performs the contribution-level checks that require both public bundles.
///
/// Proof verification is intentionally out of scope.  Hash distinctness is
/// checked before point validity to preserve the mandated bundle-verification
/// order.
///
/// # Errors
///
/// Returns an error for duplicate hash locks or an invalid original public
/// point in either bundle.
pub fn prevalidate_public_bundles(
    alice: &PlayerBundle,
    bob: &PlayerBundle,
) -> Result<(), ContributionError> {
    validate_global_hash_uniqueness(&alice.slots, &bob.slots)?;
    validate_original_contribution_points(&alice.slots)?;
    validate_original_contribution_points(&bob.slots)
}

fn sample_commitment_blinding<R>(
    value: Scalar,
    generators: &ProtocolGenerators,
    rng: &mut R,
) -> Result<(Scalar, RistrettoPoint), ContributionError>
where
    R: CryptoRng + RngCore,
{
    for _ in 0..MAX_BLINDING_REJECTION_ATTEMPTS {
        let blinding = Scalar::random(&mut *rng);
        if blinding == Scalar::ZERO {
            continue;
        }
        let value_commitment = commit(value, blinding, generators);
        if !value_commitment.is_identity() {
            return Ok((blinding, value_commitment));
        }
    }
    Err(ContributionError::BlindingSamplingFailed)
}

const fn empty_public_slot() -> SlotPublic {
    SlotPublic {
        hash: [0_u8; 32],
        value_commitment: [0_u8; 32],
        ciphertext: Ciphertext {
            r: [0_u8; 32],
            s: [0_u8; 32],
        },
    }
}

fn hash_at_global_index<'a>(
    alice: &'a [SlotPublic; N_SLOTS],
    bob: &'a [SlotPublic; N_SLOTS],
    index: usize,
) -> &'a [u8; 32] {
    if index < N_SLOTS {
        &alice[index].hash
    } else {
        &bob[index - N_SLOTS].hash
    }
}

#[cfg(test)]
mod tests {
    use bp52_group::{
        ElGamalCiphertext, JointPublicKey, NonZeroScalar, ProtocolGenerators, commit,
    };
    use curve25519_dalek::{Scalar, traits::IsIdentity};
    use rand_core::{CryptoRng, Error as RngError, RngCore};
    use sha2::{Digest, Sha256};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use super::{
        ContributionError, MAX_BLINDING_REJECTION_ATTEMPTS, SecretContribution,
        generate_contribution, validate_global_hash_uniqueness,
        validate_original_contribution_points,
    };
    use crate::{N_SLOTS, PREIMAGE_BASE_LEN, PREIMAGE_MAX_LEN, messages::Ciphertext};

    fn joint_key() -> Result<JointPublicKey, bp52_group::GroupError> {
        let generators = ProtocolGenerators::derive()?;
        JointPublicKey::new(Scalar::from(17_u64) * generators.blinding())
    }

    struct DeterministicRng(u64);

    impl DeterministicRng {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_word(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }
    }

    impl RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            let bytes = self.next_word().to_le_bytes();
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }

        fn next_u64(&mut self) -> u64 {
            self.next_word()
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(8) {
                let bytes = self.next_word().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for DeterministicRng {}

    struct RejectFirstByteRng {
        single_byte_draws: usize,
        inner: DeterministicRng,
    }

    impl RngCore for RejectFirstByteRng {
        fn next_u32(&mut self) -> u32 {
            self.inner.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.inner.next_u64()
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            if destination.len() == 1 && self.single_byte_draws < 2 {
                destination[0] = if self.single_byte_draws == 0 {
                    208
                } else {
                    207
                };
                self.single_byte_draws += 1;
            } else {
                self.inner.fill_bytes(destination);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for RejectFirstByteRng {}

    struct RejectedValueRng;

    impl RngCore for RejectedValueRng {
        fn next_u32(&mut self) -> u32 {
            u32::MAX
        }

        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(u8::MAX);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for RejectedValueRng {}

    #[derive(Default)]
    struct ZeroGammaRng {
        scalar_draws: usize,
    }

    impl RngCore for ZeroGammaRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            match destination.len() {
                1 => destination.fill(0),
                64 if self.scalar_draws == 0 => {
                    destination.fill(1);
                    self.scalar_draws += 1;
                }
                64 => {
                    destination.fill(0);
                    self.scalar_draws += 1;
                }
                _ => destination.fill(0x42),
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for ZeroGammaRng {}

    #[test]
    fn generation_is_deterministic_for_a_deterministic_rng()
    -> Result<(), Box<dyn std::error::Error>> {
        let joint_key = joint_key()?;
        let (first_slots, first_secrets) =
            generate_contribution(&joint_key, &mut DeterministicRng::new(1))?;
        let (second_slots, second_secrets) =
            generate_contribution(&joint_key, &mut DeterministicRng::new(1))?;

        assert_eq!(first_slots, second_slots);
        assert_eq!(first_secrets.preimages, second_secrets.preimages);
        assert_eq!(first_secrets.values, second_secrets.values);
        assert_eq!(
            first_secrets.encryption_randomness,
            second_secrets.encryption_randomness
        );
        assert_eq!(
            first_secrets.commitment_blindings,
            second_secrets.commitment_blindings
        );
        Ok(())
    }

    #[test]
    fn value_sampling_rejects_bytes_at_the_208_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut rng = RejectFirstByteRng {
            single_byte_draws: 0,
            inner: DeterministicRng::new(9),
        };
        let (_, secrets) = generate_contribution(&joint_key()?, &mut rng)?;
        assert_eq!(secrets.values[0], 51);
        assert_eq!(secrets.preimages[0].len(), PREIMAGE_MAX_LEN);
        Ok(())
    }

    #[test]
    fn generated_slots_satisfy_all_construction_invariants()
    -> Result<(), Box<dyn std::error::Error>> {
        let generators = ProtocolGenerators::derive()?;
        let joint_key = joint_key()?;

        for seed in 1_u64..=64 {
            let (slots, secrets) =
                generate_contribution(&joint_key, &mut DeterministicRng::new(seed))?;
            validate_original_contribution_points(&slots)?;

            for (index, slot) in slots.iter().enumerate() {
                let value = secrets.values[index];
                assert!(value < 52);
                assert_eq!(
                    secrets.preimages[index].len(),
                    PREIMAGE_BASE_LEN + usize::from(value)
                );
                assert_eq!(
                    slot.hash,
                    <[u8; 32]>::from(Sha256::digest(&secrets.preimages[index]))
                );
                assert_ne!(secrets.encryption_randomness[index], Scalar::ZERO);
                assert_ne!(secrets.commitment_blindings[index], Scalar::ZERO);

                let value_scalar = Scalar::from(u64::from(value));
                let expected_commitment = commit(
                    value_scalar,
                    secrets.commitment_blindings[index],
                    &generators,
                );
                assert!(!expected_commitment.is_identity());
                assert_eq!(
                    slot.value_commitment,
                    expected_commitment.compress().to_bytes()
                );

                let randomness = NonZeroScalar::new(secrets.encryption_randomness[index])?;
                let expected_ciphertext =
                    ElGamalCiphertext::encrypt(value_scalar, &randomness, &joint_key, &generators);
                assert_eq!(
                    slot.ciphertext,
                    Ciphertext::from(expected_ciphertext.to_bytes())
                );
            }
        }
        Ok(())
    }

    #[test]
    fn all_eighteen_hashes_must_be_distinct() -> Result<(), Box<dyn std::error::Error>> {
        let joint_key = joint_key()?;
        let (alice, _) = generate_contribution(&joint_key, &mut DeterministicRng::new(3))?;
        let (mut bob, _) = generate_contribution(&joint_key, &mut DeterministicRng::new(4))?;
        validate_global_hash_uniqueness(&alice, &bob)?;

        bob[3].hash = alice[4].hash;
        assert_eq!(
            validate_global_hash_uniqueness(&alice, &bob),
            Err(ContributionError::DuplicateHash {
                first: 4,
                second: N_SLOTS + 3,
            })
        );
        Ok(())
    }

    #[test]
    fn prevalidation_rejects_identity_and_noncanonical_original_points()
    -> Result<(), Box<dyn std::error::Error>> {
        let joint_key = joint_key()?;
        let (mut slots, _) = generate_contribution(&joint_key, &mut DeterministicRng::new(5))?;

        slots[2].value_commitment = [0_u8; 32];
        assert_eq!(
            validate_original_contribution_points(&slots),
            Err(ContributionError::InvalidValueCommitment {
                slot: 2,
                source: bp52_group::GroupError::UnexpectedIdentity,
            })
        );

        let (mut slots, _) = generate_contribution(&joint_key, &mut DeterministicRng::new(5))?;
        slots[6].ciphertext.r = [0_u8; 32];
        assert_eq!(
            validate_original_contribution_points(&slots),
            Err(ContributionError::InvalidCiphertext {
                slot: 6,
                source: bp52_group::GroupError::UnexpectedIdentity,
            })
        );

        let (mut slots, _) = generate_contribution(&joint_key, &mut DeterministicRng::new(5))?;
        slots[7].ciphertext.s = [0xff; 32];
        assert_eq!(
            validate_original_contribution_points(&slots),
            Err(ContributionError::InvalidCiphertext {
                slot: 7,
                source: bp52_group::GroupError::InvalidPoint,
            })
        );
        Ok(())
    }

    #[test]
    fn broken_rngs_fail_bounded_rejection_sampling() -> Result<(), Box<dyn std::error::Error>> {
        let joint_key = joint_key()?;
        assert_eq!(
            generate_contribution(&joint_key, &mut RejectedValueRng).map(|_| ()),
            Err(ContributionError::Group(bp52_group::GroupError::RngFailure))
        );

        let mut zero_gamma = ZeroGammaRng::default();
        assert_eq!(
            generate_contribution(&joint_key, &mut zero_gamma).map(|_| ()),
            Err(ContributionError::BlindingSamplingFailed)
        );
        assert_eq!(zero_gamma.scalar_draws, MAX_BLINDING_REJECTION_ATTEMPTS + 1);
        Ok(())
    }

    #[test]
    fn secret_container_is_explicitly_zeroizable_and_zeroizes_on_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        fn require_traits<T: Zeroize + ZeroizeOnDrop>() {}
        require_traits::<SecretContribution>();

        let (_, mut secrets) = generate_contribution(&joint_key()?, &mut DeterministicRng::new(7))?;
        secrets.zeroize();
        assert!(secrets.preimages.iter().all(Vec::is_empty));
        assert_eq!(secrets.values, [0_u8; N_SLOTS]);
        assert_eq!(secrets.encryption_randomness, [Scalar::ZERO; N_SLOTS]);
        assert_eq!(secrets.commitment_blindings, [Scalar::ZERO; N_SLOTS]);
        Ok(())
    }
}

#[cfg(test)]
mod storage_tests {
    use rand_core::{CryptoRng, Error as RngError, RngCore};

    use super::*;
    use crate::PROTOCOL_VERSION;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Clone)]
    struct TestRng(u64);

    impl TestRng {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let bytes = self.next_u64().to_le_bytes();
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }

        fn next_u64(&mut self) -> u64 {
            let mut value = self.0;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            self.0 = value;
            value
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            for chunk in destination.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

    struct ConstantRng(u8);

    impl RngCore for ConstantRng {
        fn next_u32(&mut self) -> u32 {
            u32::from(self.0).wrapping_mul(0x0101_0101)
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.0).wrapping_mul(0x0101_0101_0101_0101)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(self.0);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for ConstantRng {}

    struct FailingRng;

    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0);
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), RngError> {
            Err(RngError::from(std::num::NonZeroU32::MIN))
        }
    }

    impl CryptoRng for FailingRng {}

    fn fixture(seed: u8) -> (RetainedPreimages, AcceptedDeal) {
        let preimages: [Vec<u8>; N_SLOTS] = core::array::from_fn(|slot| {
            let slot_byte = u8::try_from(slot).unwrap_or(0);
            vec![seed.wrapping_add(slot_byte); PREIMAGE_BASE_LEN + slot]
        });
        let hashes_a = core::array::from_fn(|slot| Sha256::digest(&preimages[slot]).into());
        (
            RetainedPreimages { preimages },
            AcceptedDeal {
                protocol_version: PROTOCOL_VERSION,
                game_id: [0x21; 32],
                attempt: 7,
                hashes_a,
                hashes_b: [[0x42; 32]; N_SLOTS],
                verification_transcript_root: [0x63; 32],
                signature_a: [0x84; 64],
                signature_b: [0xa5; 64],
            },
        )
    }

    #[test]
    fn seal_erases_only_after_success_and_open_reconstructs_preimages() -> TestResult {
        let (mut retained, deal) = fixture(1);
        let expected = retained
            .preimages
            .iter()
            .map(Vec::clone)
            .collect::<Vec<_>>();
        let mut storage_key = PreimageStorageKey::from_bytes([0x35; 32]);
        let sealed =
            retained.seal_at_rest(&deal, Role::Alice, &mut storage_key, &mut TestRng::new(11))?;
        assert!(retained.preimages.iter().all(Vec::is_empty));
        assert!(!format!("{sealed:?}").contains("35"));
        assert_eq!(
            format!("{storage_key:?}"),
            "PreimageStorageKey { key_material: \"<redacted>\", .. }"
        );
        sealed.verify(&deal, Role::Alice, &storage_key)?;

        let persisted = sealed.into_bytes();
        let opened = SealedRetainedPreimages::from_bytes(&persisted)?.open(
            &deal,
            Role::Alice,
            &storage_key,
        )?;
        for (slot, expected_preimage) in expected.iter().enumerate() {
            assert_eq!(opened.get(slot), Some(expected_preimage.as_slice()));
        }
        Ok(())
    }

    #[test]
    fn validation_and_rng_failures_leave_preimages_live() {
        let (mut retained, deal) = fixture(2);
        let original_first = retained.get(0).map(<[u8]>::to_vec);
        let mut wrong_deal = deal;
        wrong_deal.hashes_a[0][0] ^= 1;
        let mut storage_key = PreimageStorageKey::from_bytes([0x44; 32]);

        assert!(matches!(
            retained.seal_at_rest(
                &wrong_deal,
                Role::Alice,
                &mut storage_key,
                &mut TestRng::new(21)
            ),
            Err(PreimageStorageError::PreimageMismatch { slot: 0 })
        ));
        assert_eq!(retained.get(0).map(<[u8]>::to_vec), original_first);
        assert!(matches!(
            retained.seal_at_rest(&deal, Role::Alice, &mut storage_key, &mut FailingRng),
            Err(PreimageStorageError::RandomnessUnavailable)
        ));
        assert_eq!(retained.get(0).map(<[u8]>::to_vec), original_first);
    }

    #[test]
    fn tampering_wrong_keys_and_wrong_contexts_are_rejected() -> TestResult {
        let (mut retained, deal) = fixture(3);
        let mut storage_key = PreimageStorageKey::from_bytes([0x55; 32]);
        let bytes = retained
            .seal_at_rest(&deal, Role::Alice, &mut storage_key, &mut TestRng::new(31))?
            .into_bytes();

        let wrong_key = PreimageStorageKey::from_bytes([0x56; 32]);
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&bytes)?.open(&deal, Role::Alice, &wrong_key),
            Err(PreimageStorageError::AuthenticationFailed)
        ));
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&bytes)?.open(&deal, Role::Bob, &storage_key),
            Err(PreimageStorageError::ContextMismatch)
        ));
        let mut wrong_deal = deal;
        wrong_deal.attempt += 1;
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&bytes)?.open(
                &wrong_deal,
                Role::Alice,
                &storage_key
            ),
            Err(PreimageStorageError::ContextMismatch)
        ));

        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&tampered)?.open(&deal, Role::Alice, &storage_key),
            Err(PreimageStorageError::AuthenticationFailed)
        ));
        let mut nonce_tampered = bytes;
        nonce_tampered[80] ^= 1;
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&nonce_tampered)?.open(
                &deal,
                Role::Alice,
                &storage_key
            ),
            Err(PreimageStorageError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn canonical_envelope_rejects_versions_lengths_and_trailing_data() -> TestResult {
        let (mut retained, deal) = fixture(4);
        let mut storage_key = PreimageStorageKey::from_bytes([0x65; 32]);
        let bytes = retained
            .seal_at_rest(&deal, Role::Alice, &mut storage_key, &mut TestRng::new(41))?
            .into_bytes();

        let mut bad_version = bytes.clone();
        bad_version[8] = 2;
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&bad_version),
            Err(PreimageStorageError::UnsupportedVersion(2))
        ));
        let mut bad_length = bytes.clone();
        bad_length[104] = 0;
        bad_length[105] = 0;
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&bad_length),
            Err(PreimageStorageError::InvalidCiphertextLength { .. })
        ));
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&bytes[..bytes.len() - 1]),
            Err(PreimageStorageError::TruncatedEnvelope)
        ));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            SealedRetainedPreimages::from_bytes(&trailing),
            Err(PreimageStorageError::TrailingData)
        ));
        Ok(())
    }

    #[test]
    fn repeated_nonce_is_refused_and_second_owner_remains_live() -> TestResult {
        let (mut first, deal) = fixture(5);
        let (mut second, _) = fixture(5);
        let mut storage_key = PreimageStorageKey::from_bytes([0x75; 32]);
        let mut repeated_nonce = ConstantRng(0x88);
        first.seal_at_rest(&deal, Role::Alice, &mut storage_key, &mut repeated_nonce)?;
        assert!(matches!(
            second.seal_at_rest(&deal, Role::Alice, &mut storage_key, &mut repeated_nonce),
            Err(PreimageStorageError::NonceReuse)
        ));
        assert_eq!(second.get(0).map(<[u8]>::len), Some(PREIMAGE_BASE_LEN));
        Ok(())
    }
}
