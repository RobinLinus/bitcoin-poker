//! Storage contracts.
use super::{MAX_SESSION_SNAPSHOT_BYTES, PortError, fmt};

/// Stable 32-byte client session identifier.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Construct from already domain-separated bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the stable identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionId(..)")
    }
}

/// One bounded opaque durable session checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    revision: u64,
    bytes: Vec<u8>,
}

impl SessionSnapshot {
    /// Construct a durable checkpoint returned by a store.
    ///
    /// # Errors
    ///
    /// Rejects revision zero or oversized checkpoint bytes.
    pub fn new(revision: u64, bytes: Vec<u8>) -> Result<Self, PortError> {
        if revision == 0 {
            return Err(PortError::InvalidSnapshot("revision must be nonzero"));
        }
        if bytes.len() > MAX_SESSION_SNAPSHOT_BYTES {
            return Err(PortError::ObjectSize);
        }
        Ok(Self { revision, bytes })
    }

    /// Monotonically increasing revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Opaque application bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Storage-port failures shared across implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Backend failed without exposing database internals.
    #[error("session store operation failed")]
    Backend,
    /// Optimistic revision changed before the commit.
    #[error("session revision conflict")]
    Conflict,
    /// Snapshot exceeded the fixed application bound.
    #[error("session snapshot is too large")]
    SnapshotTooLarge,
    /// Durable bytes cannot be interpreted as a valid checkpoint.
    #[error("session store record is corrupt")]
    Corrupt,
}

impl StoreError {
    /// Construct a redacted backend failure while discarding implementation
    /// details from the portable boundary.
    #[must_use]
    pub const fn new(_reason: &'static str) -> Self {
        Self::Backend
    }
}

/// Optimistic transactional store for opaque client snapshots.
pub trait SessionStore {
    /// Load the current durable checkpoint, if any.
    ///
    /// # Errors
    ///
    /// Returns a redacted storage/corruption failure.
    fn load(&mut self, session_id: SessionId) -> Result<Option<SessionSnapshot>, StoreError>;
    /// Atomically commit the next checkpoint if the expected revision still
    /// matches. `None` means the session must not exist.
    ///
    /// # Errors
    ///
    /// Returns conflict, size, corruption, or redacted backend failure.
    fn commit(
        &mut self,
        session_id: SessionId,
        expected_revision: Option<u64>,
        snapshot: &[u8],
    ) -> Result<SessionSnapshot, StoreError>;
}
