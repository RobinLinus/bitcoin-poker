//! Commit-then-open digests for keys, player bundles, and decryptions.

use bp52_codec::{CodecError, Encode};
use bp52_group::hash::TaggedHash;

use crate::{Role, messages::PlayerBundle};

/// Key-share commitment domain.
pub const KEY_COMMIT_TAG: &[u8] = b"BP52/key-commit/v1";
/// Player-bundle commitment domain from the base specification.
pub const BUNDLE_COMMIT_TAG: &[u8] = b"BP52/bundle-commit/v1";
/// Partial-decryption batch commitment domain.
pub const DECRYPT_COMMIT_TAG: &[u8] = b"BP52/decrypt-commit/v1";

/// Commit/open validation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommitmentError {
    /// A bundle claimed a role different from the committing envelope.
    #[error("bundle role does not match commitment role")]
    RoleMismatch,
    /// The opened object did not reproduce its signed commitment.
    #[error("commitment opening mismatch")]
    OpeningMismatch,
    /// Canonical object encoding failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// Commits to one hidden per-attempt public-key share.
#[must_use]
pub fn key_commitment(
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
    public_key: &[u8; 32],
) -> [u8; 32] {
    let mut hash = commitment_prefix(KEY_COMMIT_TAG, game_id, attempt, role, nonce);
    hash.update(public_key);
    hash.finalize()
}

/// Verifies a key opening against its signed commitment.
///
/// # Errors
///
/// Returns [`CommitmentError::OpeningMismatch`] when the opening does not
/// reproduce `expected`.
pub fn verify_key_commitment(
    expected: &[u8; 32],
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<(), CommitmentError> {
    verify_digest(
        expected,
        &key_commitment(game_id, attempt, role, nonce, public_key),
    )
}

/// Commits to one canonical player bundle.
///
/// # Errors
///
/// Returns [`CommitmentError::RoleMismatch`] when the bundle role differs from
/// `role`, or [`CommitmentError::Codec`] when canonical encoding fails.
pub fn bundle_commitment(
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
    bundle: &PlayerBundle,
) -> Result<[u8; 32], CommitmentError> {
    if bundle.role != role {
        return Err(CommitmentError::RoleMismatch);
    }
    let mut hash = commitment_prefix(BUNDLE_COMMIT_TAG, game_id, attempt, role, nonce);
    hash.update(bundle.encode_to_vec()?);
    Ok(hash.finalize())
}

/// Verifies a player-bundle opening.
///
/// # Errors
///
/// Returns the corresponding [`CommitmentError`] when the role or canonical
/// encoding is invalid, or when the opening does not reproduce `expected`.
pub fn verify_bundle_commitment(
    expected: &[u8; 32],
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
    bundle: &PlayerBundle,
) -> Result<(), CommitmentError> {
    verify_digest(
        expected,
        &bundle_commitment(game_id, attempt, role, nonce, bundle)?,
    )
}

/// Commits to the canonical bytes `Z[108] || PartialDecryptProof`.
#[must_use]
pub fn decryption_commitment(
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
    canonical_decryption_batch: &[u8],
) -> [u8; 32] {
    let mut hash = commitment_prefix(DECRYPT_COMMIT_TAG, game_id, attempt, role, nonce);
    hash.update(canonical_decryption_batch);
    hash.finalize()
}

/// Verifies a partial-decryption batch opening.
///
/// # Errors
///
/// Returns [`CommitmentError::OpeningMismatch`] when the batch opening does not
/// reproduce `expected`.
pub fn verify_decryption_commitment(
    expected: &[u8; 32],
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
    canonical_decryption_batch: &[u8],
) -> Result<(), CommitmentError> {
    verify_digest(
        expected,
        &decryption_commitment(game_id, attempt, role, nonce, canonical_decryption_batch),
    )
}

fn commitment_prefix(
    tag: &'static [u8],
    game_id: &[u8; 32],
    attempt: u32,
    role: Role,
    nonce: &[u8; 32],
) -> TaggedHash {
    let mut hash = TaggedHash::new(tag);
    hash.update(game_id);
    hash.update(attempt.to_le_bytes());
    hash.update([role as u8]);
    hash.update(nonce);
    hash
}

fn verify_digest(expected: &[u8; 32], actual: &[u8; 32]) -> Result<(), CommitmentError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CommitmentError::OpeningMismatch)
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::{
        Ciphertext, ENCRYPTION_LINK_PROOF_SIZE, HASH_LENGTH_PROOF_SIZE, PlayerBundle, SlotPublic,
    };

    use super::{
        CommitmentError, bundle_commitment, decryption_commitment, key_commitment,
        verify_bundle_commitment, verify_decryption_commitment, verify_key_commitment,
    };
    use crate::Role;

    fn bundle(role: Role) -> PlayerBundle {
        PlayerBundle {
            role,
            slots: std::array::from_fn(|index| SlotPublic {
                hash: [u8::try_from(index).unwrap_or(0); 32],
                value_commitment: [0_u8; 32],
                ciphertext: Ciphertext {
                    r: [0_u8; 32],
                    s: [0_u8; 32],
                },
            }),
            circuit_id: [3_u8; 32],
            hash_length_proof: vec![4_u8; HASH_LENGTH_PROOF_SIZE],
            encryption_link_proof: vec![5_u8; ENCRYPTION_LINK_PROOF_SIZE],
        }
    }

    #[test]
    fn each_commitment_is_context_and_opening_bound() -> Result<(), CommitmentError> {
        let game_id = [1_u8; 32];
        let nonce = [2_u8; 32];
        let public_key = [0_u8; 32];
        let key = key_commitment(&game_id, 7, Role::Alice, &nonce, &public_key);
        assert_eq!(
            verify_key_commitment(&key, &game_id, 7, Role::Alice, &nonce, &public_key,),
            Ok(())
        );
        assert_eq!(
            verify_key_commitment(&key, &game_id, 8, Role::Alice, &nonce, &public_key),
            Err(CommitmentError::OpeningMismatch)
        );

        let player_bundle = bundle(Role::Alice);
        let bundle_digest = bundle_commitment(&game_id, 7, Role::Alice, &nonce, &player_bundle)?;
        assert_eq!(
            verify_bundle_commitment(
                &bundle_digest,
                &game_id,
                7,
                Role::Alice,
                &nonce,
                &player_bundle,
            ),
            Ok(())
        );
        assert_eq!(
            bundle_commitment(&game_id, 7, Role::Bob, &nonce, &player_bundle),
            Err(CommitmentError::RoleMismatch)
        );

        let decryption_bytes = [9_u8; 6976];
        let decrypt = decryption_commitment(&game_id, 7, Role::Alice, &nonce, &decryption_bytes);
        assert_eq!(
            verify_decryption_commitment(
                &decrypt,
                &game_id,
                7,
                Role::Alice,
                &nonce,
                &decryption_bytes,
            ),
            Ok(())
        );
        let mut changed = decryption_bytes;
        changed[0] ^= 1;
        assert_eq!(
            verify_decryption_commitment(&decrypt, &game_id, 7, Role::Alice, &nonce, &changed,),
            Err(CommitmentError::OpeningMismatch)
        );
        Ok(())
    }
}
