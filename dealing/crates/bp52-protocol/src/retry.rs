//! Domain-separated authorization for a fresh DEAL attempt.

use bp52_group::hash::TaggedHash;

const RETRY_TAG: &[u8] = b"BP52/deal-retry/v1";

/// Returns the exact digest both identities authorize after a verified retry.
#[must_use]
pub fn retry_digest(
    shared_config_hash: [u8; 32],
    attempt: u32,
    transcript_root: [u8; 32],
    next_attempt: u32,
) -> [u8; 32] {
    let mut hash = TaggedHash::new(RETRY_TAG);
    hash.update(shared_config_hash);
    hash.update(attempt.to_le_bytes());
    hash.update(transcript_root);
    hash.update(next_attempt.to_le_bytes());
    hash.finalize()
}
