//! Canonical public-key bundles committed by the compiled graph.

use std::collections::HashSet;

use crate::codec::Reader;
use crate::key::tagged_sha256;
use crate::{HASH_SIZE, KeyContext, LamportError, LamportPublicKey, LamportPurpose};

const BUNDLE_MAGIC: &[u8; 8] = b"BP52LPB1";
const BUNDLE_ROOT_TAG: &[u8] = b"BP52/lamport-bundle-root/v1";
const BUNDLE_SIGNATURE_TAG: &[u8] = b"BP52/lamport-bundle-signature/v1";

/// Defensive decoder limit, comfortably above the v1 graph's key count.
pub const MAX_BUNDLE_ENTRIES: usize = 65_536;

/// Player that generated a public-key bundle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LamportRole {
    /// Alice's bundle.
    Alice = 0,
    /// Bob's bundle.
    Bob = 1,
}

impl TryFrom<u8> for LamportRole {
    type Error = LamportError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Alice),
            1 => Ok(Self::Bob),
            other => Err(LamportError::InvalidRole(other)),
        }
    }
}

/// Public Lamport hashes assigned to one exact graph node and purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LamportPublicEntry {
    node_id: [u8; 32],
    purpose: LamportPurpose,
    bit_width: u8,
    public_hash_pairs: Vec<[[u8; HASH_SIZE]; 2]>,
}

impl LamportPublicEntry {
    /// Validates and constructs a public bundle entry.
    ///
    /// # Errors
    ///
    /// Returns an error unless both supplied widths exactly match the purpose.
    pub fn from_parts(
        node_id: [u8; 32],
        purpose: LamportPurpose,
        bit_width: u8,
        public_hash_pairs: Vec<[[u8; HASH_SIZE]; 2]>,
    ) -> Result<Self, LamportError> {
        if bit_width != purpose.bit_width() {
            return Err(LamportError::InvalidBitWidth {
                expected: purpose.bit_width(),
                actual: bit_width,
            });
        }
        if public_hash_pairs.len() != usize::from(bit_width) {
            return Err(LamportError::InvalidBitWidth {
                expected: bit_width,
                actual: u8::try_from(public_hash_pairs.len()).unwrap_or(u8::MAX),
            });
        }
        Ok(Self {
            node_id,
            purpose,
            bit_width,
            public_hash_pairs,
        })
    }

    /// Creates an entry from a validated public key.
    #[must_use]
    pub fn from_public_key(public_key: &LamportPublicKey) -> Self {
        Self {
            node_id: public_key.context().node_id,
            purpose: public_key.context().purpose,
            bit_width: public_key.context().purpose.bit_width(),
            public_hash_pairs: public_key.public_hash_pairs().to_vec(),
        }
    }

    /// Returns the path-dependent graph node identifier.
    #[must_use]
    pub const fn node_id(&self) -> [u8; 32] {
        self.node_id
    }

    /// Returns the exact purpose assigned to the node.
    #[must_use]
    pub const fn purpose(&self) -> LamportPurpose {
        self.purpose
    }

    /// Returns the explicitly committed message width.
    #[must_use]
    pub const fn bit_width(&self) -> u8 {
        self.bit_width
    }

    /// Returns the public hash pairs in most-significant-first bit order.
    #[must_use]
    pub fn public_hash_pairs(&self) -> &[[[u8; HASH_SIZE]; 2]] {
        &self.public_hash_pairs
    }

    /// Reconstructs a context-bound public key for witness verification.
    ///
    /// # Errors
    ///
    /// Returns an error if this received entry has inconsistent width data.
    pub fn to_public_key(&self, chain_game_id: [u8; 32]) -> Result<LamportPublicKey, LamportError> {
        LamportPublicKey::from_parts(
            KeyContext::new(chain_game_id, self.node_id, self.purpose),
            self.public_hash_pairs.clone(),
        )
    }

    fn canonical_order_key(&self) -> ([u8; 32], LamportPurpose) {
        (self.node_id, self.purpose)
    }

    fn encode_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.node_id);
        output.push(self.purpose as u8);
        output.push(self.bit_width);
        for pair in &self.public_hash_pairs {
            output.extend_from_slice(&pair[0]);
            output.extend_from_slice(&pair[1]);
        }
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, LamportError> {
        let node_id = reader.take_array()?;
        let purpose = LamportPurpose::try_from(reader.take_u8()?)?;
        let bit_width = reader.take_u8()?;
        if bit_width != purpose.bit_width() {
            return Err(LamportError::InvalidBitWidth {
                expected: purpose.bit_width(),
                actual: bit_width,
            });
        }
        let mut pairs = Vec::with_capacity(usize::from(bit_width));
        for _ in 0..bit_width {
            pairs.push([reader.take_array()?, reader.take_array()?]);
        }
        Self::from_parts(node_id, purpose, bit_width, pairs)
    }
}

/// Node/purpose pair expected by a deterministic compiled graph.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedLamportEntry {
    /// Exact graph node identifier.
    pub node_id: [u8; 32],
    /// Exact Lamport purpose assigned to that node.
    pub purpose: LamportPurpose,
}

impl ExpectedLamportEntry {
    /// Constructs one graph expectation.
    #[must_use]
    pub const fn new(node_id: [u8; 32], purpose: LamportPurpose) -> Self {
        Self { node_id, purpose }
    }
}

/// Canonical, identity-signed public-key bundle for one player and game.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LamportPublicBundle {
    chain_game_id: [u8; 32],
    role: LamportRole,
    entries: Vec<LamportPublicEntry>,
    bundle_root: [u8; 32],
    signature: [u8; 64],
}

impl LamportPublicBundle {
    /// Validates context-bound keys, computes their bundle root, and calls an
    /// identity signer.
    ///
    /// The callback must produce the descriptor identity key's 64-byte
    /// signature over the supplied tagged digest.
    ///
    /// # Errors
    ///
    /// Returns an error if any key belongs to another game, or for an
    /// oversized, unsorted, duplicate, or malformed public entry set.
    pub fn sign<F>(
        chain_game_id: [u8; 32],
        role: LamportRole,
        public_keys: &[LamportPublicKey],
        signer: F,
    ) -> Result<Self, LamportError>
    where
        F: FnOnce([u8; 32]) -> [u8; 64],
    {
        if public_keys
            .iter()
            .any(|key| key.context().chain_game_id != chain_game_id)
        {
            return Err(LamportError::WrongGame);
        }
        let entries: Vec<_> = public_keys
            .iter()
            .map(LamportPublicEntry::from_public_key)
            .collect();
        validate_entries(&entries)?;
        let bundle_root = compute_bundle_root(chain_game_id, role, &entries);
        let digest = compute_signing_digest(chain_game_id, role, entries.len(), bundle_root);
        let signature = signer(digest);
        Ok(Self {
            chain_game_id,
            role,
            entries,
            bundle_root,
            signature,
        })
    }

    /// Constructs a received bundle and verifies its canonical root.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid entries or a root that does not commit to
    /// the supplied game, role, and entries.
    pub fn from_signed_parts(
        chain_game_id: [u8; 32],
        role: LamportRole,
        entries: Vec<LamportPublicEntry>,
        bundle_root: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self, LamportError> {
        validate_entries(&entries)?;
        let expected_root = compute_bundle_root(chain_game_id, role, &entries);
        if bundle_root != expected_root {
            return Err(LamportError::BundleRootMismatch);
        }
        Ok(Self {
            chain_game_id,
            role,
            entries,
            bundle_root,
            signature,
        })
    }

    /// Returns the exact chain game identifier bound by this bundle.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Returns the player that generated this bundle.
    #[must_use]
    pub const fn role(&self) -> LamportRole {
        self.role
    }

    /// Returns strictly sorted public entries.
    #[must_use]
    pub fn entries(&self) -> &[LamportPublicEntry] {
        &self.entries
    }

    /// Returns the deterministic bundle commitment included in the graph.
    #[must_use]
    pub const fn bundle_root(&self) -> [u8; 32] {
        self.bundle_root
    }

    /// Returns the long-term identity signature over the bundle digest.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns the tagged digest signed by the player's identity key.
    #[must_use]
    pub fn signing_digest(&self) -> [u8; 32] {
        compute_signing_digest(
            self.chain_game_id,
            self.role,
            self.entries.len(),
            self.bundle_root,
        )
    }

    /// Verifies context, exact graph membership, root, and identity signature.
    ///
    /// # Errors
    ///
    /// Returns the first context, membership, structure, root, or identity
    /// signature validation failure.
    pub fn verify<F>(
        &self,
        expected_chain_game_id: [u8; 32],
        expected_role: LamportRole,
        expected_entries: &[ExpectedLamportEntry],
        verifier: F,
    ) -> Result<(), LamportError>
    where
        F: FnOnce([u8; 32], &[u8; 64]) -> bool,
    {
        if self.chain_game_id != expected_chain_game_id {
            return Err(LamportError::WrongGame);
        }
        if self.role != expected_role {
            return Err(LamportError::WrongRole);
        }
        validate_entries(&self.entries)?;
        if self.entries.len() != expected_entries.len() {
            return Err(LamportError::UnexpectedEntryCount {
                expected: expected_entries.len(),
                actual: self.entries.len(),
            });
        }
        for (index, (entry, expected)) in self.entries.iter().zip(expected_entries).enumerate() {
            if entry.node_id != expected.node_id || entry.purpose != expected.purpose {
                return Err(LamportError::UnexpectedEntry { index });
            }
        }
        let root = compute_bundle_root(self.chain_game_id, self.role, &self.entries);
        if self.bundle_root != root {
            return Err(LamportError::BundleRootMismatch);
        }
        if !verifier(self.signing_digest(), &self.signature) {
            return Err(LamportError::BundleSignatureInvalid);
        }
        Ok(())
    }

    /// Encodes the complete signed bundle canonically.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(BUNDLE_MAGIC);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.push(self.role as u8);
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        encoded.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            entry.encode_into(&mut encoded);
        }
        encoded.extend_from_slice(&self.bundle_root);
        encoded.extend_from_slice(&self.signature);
        encoded
    }

    /// Decodes a canonical bundle, enforcing size, widths, root, and EOF.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, noncanonical, truncated, or
    /// trailing input, including a mismatched bundle root.
    pub fn decode(encoded: &[u8]) -> Result<Self, LamportError> {
        let mut reader = Reader::new(encoded, "Lamport public bundle");
        reader.expect_magic(BUNDLE_MAGIC)?;
        let chain_game_id = reader.take_array()?;
        let role = LamportRole::try_from(reader.take_u8()?)?;
        let count_u32 = reader.take_u32()?;
        let count = usize::try_from(count_u32).map_err(|_| LamportError::CollectionTooLarge {
            kind: "Lamport public bundle",
            actual: usize::MAX,
            maximum: MAX_BUNDLE_ENTRIES,
        })?;
        if count > MAX_BUNDLE_ENTRIES {
            return Err(LamportError::CollectionTooLarge {
                kind: "Lamport public bundle",
                actual: count,
                maximum: MAX_BUNDLE_ENTRIES,
            });
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(LamportPublicEntry::decode_from(&mut reader)?);
        }
        let bundle_root = reader.take_array()?;
        let signature = reader.take_array()?;
        reader.finish()?;
        Self::from_signed_parts(chain_game_id, role, entries, bundle_root, signature)
    }
}

fn validate_entries(entries: &[LamportPublicEntry]) -> Result<(), LamportError> {
    if entries.len() > MAX_BUNDLE_ENTRIES {
        return Err(LamportError::CollectionTooLarge {
            kind: "Lamport public bundle",
            actual: entries.len(),
            maximum: MAX_BUNDLE_ENTRIES,
        });
    }

    for adjacent in entries.windows(2) {
        if adjacent[0].canonical_order_key() >= adjacent[1].canonical_order_key() {
            return Err(LamportError::EntriesNotSorted);
        }
    }

    let public_hash_count = entries
        .iter()
        .map(|entry| entry.public_hash_pairs.len().saturating_mul(2))
        .sum();
    let mut seen = HashSet::with_capacity(public_hash_count);
    for entry in entries {
        if entry.bit_width != entry.purpose.bit_width()
            || entry.public_hash_pairs.len() != usize::from(entry.bit_width)
        {
            return Err(LamportError::InvalidBitWidth {
                expected: entry.purpose.bit_width(),
                actual: entry.bit_width,
            });
        }
        for hash in entry.public_hash_pairs.iter().flatten() {
            if !seen.insert(*hash) {
                return Err(LamportError::DuplicatePublicHash);
            }
        }
    }
    Ok(())
}

fn compute_bundle_root(
    chain_game_id: [u8; 32],
    role: LamportRole,
    entries: &[LamportPublicEntry],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&chain_game_id);
    preimage.push(role as u8);
    let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    preimage.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        entry.encode_into(&mut preimage);
    }
    tagged_sha256(BUNDLE_ROOT_TAG, &preimage)
}

fn compute_signing_digest(
    chain_game_id: [u8; 32],
    role: LamportRole,
    entry_count: usize,
    bundle_root: [u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 + 1 + 4 + 32);
    preimage.extend_from_slice(&chain_game_id);
    preimage.push(role as u8);
    let count = u32::try_from(entry_count).unwrap_or(u32::MAX);
    preimage.extend_from_slice(&count.to_be_bytes());
    preimage.extend_from_slice(&bundle_root);
    tagged_sha256(BUNDLE_SIGNATURE_TAG, &preimage)
}
