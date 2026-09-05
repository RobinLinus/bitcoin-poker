//! Transactional SQLite implementation of the BP52 session-store port.
//!
//! Snapshots are opaque to this crate. Callers must encrypt secret owners
//! before including them in a snapshot; SQLite is durability, not encryption.

#![forbid(unsafe_code)]

use std::path::Path;

use poker_client_ports::{SessionId, SessionSnapshot, SessionStore, StoreError};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

/// Maximum opaque session snapshot accepted by the prototype store.
pub const MAX_SESSION_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

fn validate_snapshot_len(actual: usize) -> Result<(), SqliteStoreError> {
    if actual > MAX_SESSION_SNAPSHOT_BYTES {
        Err(SqliteStoreError::SnapshotTooLarge { actual })
    } else {
        Ok(())
    }
}

/// One SQLite connection configured for durable optimistic session updates.
#[derive(Debug)]
pub struct SqliteSessionStore {
    connection: Connection,
}

impl SqliteSessionStore {
    /// Open or create a durable client database.
    ///
    /// The connection uses WAL mode, full synchronous writes, foreign-key
    /// enforcement, and a busy timeout. Secret material must already be sealed
    /// before entering this store.
    ///
    /// # Errors
    ///
    /// Returns a redacted storage error when the file, pragmas, or schema
    /// cannot be initialized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteStoreError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|_| SqliteStoreError::Database)?;
        Self::from_connection(connection)
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self, SqliteStoreError> {
        let connection = Connection::open_in_memory().map_err(|_| SqliteStoreError::Database)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, SqliteStoreError> {
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| SqliteStoreError::Database)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
            .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
            .map_err(|_| SqliteStoreError::Database)?;
        // In-memory SQLite cannot enter WAL mode and returns `memory`; that is
        // sufficient for isolated tests. Durable files are required to return
        // exactly `wal`.
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|_| SqliteStoreError::Database)?;
        if journal_mode != "memory" {
            let selected: String = connection
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
                .map_err(|_| SqliteStoreError::Database)?;
            if !selected.eq_ignore_ascii_case("wal") {
                return Err(SqliteStoreError::Database);
            }
        }
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS bp52_sessions (
                    session_id BLOB PRIMARY KEY NOT NULL CHECK(length(session_id) = 32),
                    revision INTEGER NOT NULL CHECK(revision >= 1),
                    snapshot BLOB NOT NULL CHECK(length(snapshot) <= 67108864)
                ) WITHOUT ROWID, STRICT;",
            )
            .map_err(|_| SqliteStoreError::Database)?;
        Ok(Self { connection })
    }

    fn load_inner(
        &self,
        session_id: SessionId,
    ) -> Result<Option<SessionSnapshot>, SqliteStoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT revision, snapshot FROM bp52_sessions WHERE session_id = ?1",
                params![session_id.as_bytes().as_slice()],
                |row| {
                    let revision: i64 = row.get(0)?;
                    let bytes: Vec<u8> = row.get(1)?;
                    Ok((revision, bytes))
                },
            )
            .optional()
            .map_err(|_| SqliteStoreError::Database)?;
        row.map(|(revision, bytes)| {
            let revision = u64::try_from(revision).map_err(|_| SqliteStoreError::CorruptRecord)?;
            SessionSnapshot::new(revision, bytes).map_err(|_| SqliteStoreError::CorruptRecord)
        })
        .transpose()
    }

    fn commit_inner(
        &mut self,
        session_id: SessionId,
        expected_revision: Option<u64>,
        snapshot: &[u8],
    ) -> Result<SessionSnapshot, SqliteStoreError> {
        validate_snapshot_len(snapshot.len())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SqliteStoreError::Database)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM bp52_sessions WHERE session_id = ?1",
                params![session_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SqliteStoreError::Database)?;
        let current = current
            .map(|value| u64::try_from(value).map_err(|_| SqliteStoreError::CorruptRecord))
            .transpose()?;
        if current != expected_revision {
            return Err(SqliteStoreError::RevisionConflict {
                expected: expected_revision,
                actual: current,
            });
        }
        let next_revision = match current {
            Some(revision) => revision
                .checked_add(1)
                .ok_or(SqliteStoreError::RevisionOverflow)?,
            None => 1,
        };
        let next_i64 =
            i64::try_from(next_revision).map_err(|_| SqliteStoreError::RevisionOverflow)?;
        match current {
            None => {
                transaction
                    .execute(
                        "INSERT INTO bp52_sessions(session_id, revision, snapshot)
                         VALUES (?1, ?2, ?3)",
                        params![session_id.as_bytes().as_slice(), next_i64, snapshot],
                    )
                    .map_err(|_| SqliteStoreError::Database)?;
            }
            Some(previous_revision) => {
                let changed = transaction
                    .execute(
                        "UPDATE bp52_sessions SET revision = ?2, snapshot = ?3
                         WHERE session_id = ?1 AND revision = ?4",
                        params![
                            session_id.as_bytes().as_slice(),
                            next_i64,
                            snapshot,
                            i64::try_from(previous_revision)
                                .map_err(|_| SqliteStoreError::RevisionOverflow)?
                        ],
                    )
                    .map_err(|_| SqliteStoreError::Database)?;
                if changed != 1 {
                    return Err(SqliteStoreError::RevisionConflict {
                        expected: expected_revision,
                        actual: current,
                    });
                }
            }
        }
        transaction
            .commit()
            .map_err(|_| SqliteStoreError::Database)?;
        SessionSnapshot::new(next_revision, snapshot.to_vec())
            .map_err(|_| SqliteStoreError::CorruptRecord)
    }
}

/// Redacted durable-storage failures.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum SqliteStoreError {
    /// SQLite file, schema, locking, or commit failure.
    #[error("SQLite session store operation failed")]
    Database,
    /// Existing storage contains an invalid revision or snapshot.
    #[error("SQLite session store contains a corrupt record")]
    CorruptRecord,
    /// Optimistic revision did not match the durable state.
    #[error("session revision conflict")]
    RevisionConflict {
        /// Revision the caller expected, or no record for insertion.
        expected: Option<u64>,
        /// Revision currently stored, or no record.
        actual: Option<u64>,
    },
    /// Revision arithmetic exceeded the durable SQLite representation.
    #[error("session revision overflow")]
    RevisionOverflow,
    /// Opaque snapshot exceeded the fixed storage bound.
    #[error("session snapshot has {actual} bytes, exceeding the fixed maximum")]
    SnapshotTooLarge {
        /// Actual byte length rejected.
        actual: usize,
    },
}

impl From<SqliteStoreError> for StoreError {
    fn from(error: SqliteStoreError) -> Self {
        match error {
            SqliteStoreError::RevisionConflict { .. } => StoreError::Conflict,
            SqliteStoreError::SnapshotTooLarge { .. } => StoreError::SnapshotTooLarge,
            SqliteStoreError::CorruptRecord | SqliteStoreError::RevisionOverflow => {
                StoreError::Corrupt
            }
            _ => StoreError::new("SQLite store failure"),
        }
    }
}

impl SessionStore for SqliteSessionStore {
    fn load(&mut self, session_id: SessionId) -> Result<Option<SessionSnapshot>, StoreError> {
        Ok(self.load_inner(session_id)?)
    }

    fn commit(
        &mut self,
        session_id: SessionId,
        expected_revision: Option<u64>,
        snapshot: &[u8],
    ) -> Result<SessionSnapshot, StoreError> {
        Ok(self.commit_inner(session_id, expected_revision, snapshot)?)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{OpenOptions, remove_file};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMPORARY_DATABASE: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDatabase {
        path: PathBuf,
    }

    impl TemporaryDatabase {
        fn create() -> Result<Self, std::io::Error> {
            loop {
                let sequence = NEXT_TEMPORARY_DATABASE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "bp52-client-store-{}-{sequence}.sqlite",
                    std::process::id()
                ));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(_) => return Ok(Self { path }),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            let _ = remove_file(&self.path);
            let _ = remove_file(self.path.with_extension("sqlite-wal"));
            let _ = remove_file(self.path.with_extension("sqlite-shm"));
        }
    }

    fn session(byte: u8) -> SessionId {
        SessionId::from_bytes([byte; 32])
    }

    #[test]
    fn optimistic_commits_are_atomic_and_monotonic() -> Result<(), SqliteStoreError> {
        let mut store = SqliteSessionStore::open_in_memory()?;
        let id = session(1);
        assert_eq!(store.load_inner(id)?, None);
        let first = store.commit_inner(id, None, b"one")?;
        assert_eq!(first.revision(), 1);
        assert_eq!(first.bytes(), b"one");
        let second = store.commit_inner(id, Some(1), b"two")?;
        assert_eq!(second.revision(), 2);
        assert_eq!(store.load_inner(id)?, Some(second));
        assert_eq!(
            store.commit_inner(id, Some(1), b"stale"),
            Err(SqliteStoreError::RevisionConflict {
                expected: Some(1),
                actual: Some(2),
            })
        );
        assert_eq!(
            store.load_inner(id)?.map(|value| value.bytes().to_vec()),
            Some(b"two".to_vec())
        );
        Ok(())
    }

    #[test]
    fn insertion_requires_absent_revision() -> Result<(), SqliteStoreError> {
        let mut store = SqliteSessionStore::open_in_memory()?;
        let id = session(2);
        store.commit_inner(id, None, b"one")?;
        assert_eq!(
            store.commit_inner(id, None, b"replacement"),
            Err(SqliteStoreError::RevisionConflict {
                expected: None,
                actual: Some(1),
            })
        );
        Ok(())
    }

    #[test]
    fn oversized_snapshots_fail_without_creating_a_record() -> Result<(), SqliteStoreError> {
        let store = SqliteSessionStore::open_in_memory()?;
        let id = session(3);
        assert_eq!(
            validate_snapshot_len(MAX_SESSION_SNAPSHOT_BYTES + 1),
            Err(SqliteStoreError::SnapshotTooLarge {
                actual: MAX_SESSION_SNAPSHOT_BYTES + 1,
            })
        );
        assert_eq!(store.load_inner(id)?, None);
        Ok(())
    }

    #[test]
    fn file_store_reopens_and_rejects_stale_concurrent_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = TemporaryDatabase::create()?;
        let id = session(4);
        let mut first = SqliteSessionStore::open(&database.path)?;
        assert_eq!(
            first
                .connection
                .pragma_query_value::<String, _>(None, "journal_mode", |row| row.get(0))?,
            "wal"
        );
        assert_eq!(
            first
                .connection
                .pragma_query_value::<u32, _>(None, "synchronous", |row| row.get(0))?,
            2
        );
        first.commit_inner(id, None, b"one")?;

        let mut stale = SqliteSessionStore::open(&database.path)?;
        assert_eq!(stale.load_inner(id)?.map(|value| value.revision()), Some(1));
        first.commit_inner(id, Some(1), b"two")?;
        assert_eq!(
            stale.commit_inner(id, Some(1), b"stale"),
            Err(SqliteStoreError::RevisionConflict {
                expected: Some(1),
                actual: Some(2),
            })
        );

        drop(stale);
        drop(first);
        let reopened = SqliteSessionStore::open(&database.path)?;
        let durable = reopened
            .load_inner(id)?
            .ok_or(SqliteStoreError::CorruptRecord)?;
        assert_eq!(durable.revision(), 2);
        assert_eq!(durable.bytes(), b"two");
        Ok(())
    }
}
