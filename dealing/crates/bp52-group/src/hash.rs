//! Bitcoin-style tagged SHA-256.

use sha2::{Digest, Sha256};

/// Computes `SHA256(SHA256(tag) || SHA256(tag) || message)`.
#[must_use]
pub fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

/// Incremental tagged-SHA-256 input builder.
#[derive(Clone)]
pub struct TaggedHash {
    hasher: Sha256,
}

impl TaggedHash {
    /// Starts a tagged hash with the BIP340-style doubled tag digest.
    #[must_use]
    pub fn new(tag: &[u8]) -> Self {
        let tag_hash = Sha256::digest(tag);
        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        Self { hasher }
    }

    /// Appends one exact byte slice.
    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.hasher.update(bytes);
    }

    /// Returns the final 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{TaggedHash, tagged_sha256};

    #[test]
    fn incremental_and_one_shot_match_definition() {
        let tag = b"BP52/test/v1";
        let message = b"canonical input";
        let tag_hash = Sha256::digest(tag);
        let expected: [u8; 32] = Sha256::new()
            .chain_update(tag_hash)
            .chain_update(tag_hash)
            .chain_update(message)
            .finalize()
            .into();
        assert_eq!(tagged_sha256(tag, message), expected);

        let mut incremental = TaggedHash::new(tag);
        incremental.update(b"canonical ");
        incremental.update(b"input");
        assert_eq!(incremental.finalize(), expected);
    }
}
