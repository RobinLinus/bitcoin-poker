use std::fs::{OpenOptions, remove_file};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn create() -> Result<Self, std::io::Error> {
        loop {
            let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bp52-relay-server-{}-{sequence}.sqlite",
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

fn open_test_relay(path: &Path) -> Result<RelayServer, Box<dyn std::error::Error>> {
    let deployment: DeploymentConfig =
        serde_json::from_str(include_str!("../../../deployments/mutinynet/client.json"))?;
    Ok(RelayServer::open_with_deployment(path, &deployment)?)
}

#[test]
fn database_uses_durable_pragmas_and_never_stores_raw_capabilities()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let server = open_test_relay(&temporary.path)?;
    let mut connection = server
        .database
        .connection
        .lock()
        .map_err(|_| std::io::Error::other("poisoned test database"))?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    assert!(journal.eq_ignore_ascii_case("wal"));
    assert_eq!(synchronous, 2);
    let game_id = [1_u8; 32];
    let player = [2_u8; 32];
    let invite = [3_u8; 32];
    create_game_db(
        &mut connection,
        game_id,
        capability_digest(PLAYER_TOKEN_TAG, player),
        capability_digest(INVITE_SECRET_TAG, invite),
    )?;
    let stored: (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT player_one_hash, invite_hash FROM relay_games WHERE game_id = ?1",
        params![game_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_ne!(stored.0, player);
    assert_ne!(stored.1, invite);
    Ok(())
}

#[test]
fn parsers_require_canonical_external_values() {
    assert!(decode_hex::<32>(&"ab".repeat(32)).is_some());
    assert!(decode_hex::<32>(&"AB".repeat(32)).is_none());
    assert!(decode_hex::<32>("00").is_none());
    assert!(validate_kind("deal.envelope").is_ok());
    assert!(validate_kind("Deal Envelope").is_err());
    assert_eq!(decode_payload("AA==", 1), Ok(vec![0]));
    assert!(decode_payload("AA", 1).is_err());
}

#[test]
fn mutation_removes_expired_rooms() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let server = open_test_relay(&temporary.path)?;
    let mut connection = server
        .database
        .connection
        .lock()
        .map_err(|_| std::io::Error::other("poisoned test database"))?;
    create_game_db(
        &mut connection,
        [1; 32],
        capability_digest(PLAYER_TOKEN_TAG, [2; 32]),
        capability_digest(INVITE_SECRET_TAG, [3; 32]),
    )?;
    connection.execute(
        "UPDATE relay_games SET expires_at_ms = created_at_ms WHERE game_id = ?1",
        params![[1_u8; 32].as_slice()],
    )?;
    create_game_db(
        &mut connection,
        [4; 32],
        capability_digest(PLAYER_TOKEN_TAG, [5; 32]),
        capability_digest(INVITE_SECRET_TAG, [6; 32]),
    )?;
    let rooms: i64 =
        connection.query_row("SELECT COUNT(*) FROM relay_games", [], |row| row.get(0))?;
    assert_eq!(rooms, 1);
    Ok(())
}

#[tokio::test]
async fn configurable_limits_reject_room_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let server = open_test_relay(&temporary.path)?.with_limits(Limits {
        message_bytes: 8,
        game_bytes: 3,
        game_messages: 1,
    });
    let game = [4_u8; 32];
    let first = [5_u8; 32];
    let second = [6_u8; 32];
    let invite = [7_u8; 32];
    server
        .database
        .run(move |connection| {
            create_game_db(
                connection,
                game,
                capability_digest(PLAYER_TOKEN_TAG, first),
                capability_digest(INVITE_SECRET_TAG, invite),
            )?;
            join_game_db(
                connection,
                game,
                capability_digest(PLAYER_TOKEN_TAG, second),
                capability_digest(INVITE_SECRET_TAG, invite),
            )?;
            Ok(())
        })
        .await?;
    let first_hash = capability_digest(PLAYER_TOKEN_TAG, first);
    server
        .database
        .run(move |connection| {
            post_message_db(
                connection,
                game,
                first_hash,
                [8; 32],
                "opaque",
                &[1, 2, 3],
                server.limits,
            )?;
            let Err(error) = post_message_db(
                connection,
                game,
                first_hash,
                [9; 32],
                "opaque",
                &[4],
                server.limits,
            ) else {
                return Err(ApiError::internal());
            };
            assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
            Ok(())
        })
        .await?;
    Ok(())
}
