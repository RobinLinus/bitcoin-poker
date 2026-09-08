use std::fs::{OpenOptions, remove_file};
use std::path::{Path, PathBuf};
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

fn open_test_relay(_path: &Path) -> Result<RelayServer, Box<dyn std::error::Error>> {
    let deployment: DeploymentConfig =
        serde_json::from_str(include_str!("../../../deployments/mutinynet/client.json"))?;
    Ok(RelayServer::open_with_deployment(&deployment)?)
}

#[test]
fn queue_uses_memory_and_never_stores_raw_capabilities()
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
    assert!(journal.eq_ignore_ascii_case("memory"));
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


#[test]
fn relay_capacity_exceeds_old_limit_but_remains_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let server = open_test_relay(&temporary.path)?;
    let mut connection = server.database.connection.lock().map_err(|_| std::io::Error::other("poisoned"))?;
    let player = capability_digest(PLAYER_TOKEN_TAG, [2;32]);
    let invite = capability_digest(INVITE_SECRET_TAG, [3;32]);
    for game in [[1;32],[4;32]] { create_game_db(&mut connection, game, player, invite)?; }
    join_game_db(&mut connection,[1;32],capability_digest(PLAYER_TOKEN_TAG,[5;32]),invite)?;
    // Seed aggregate accounting instead of allocating gigabytes of test payloads.
    connection.execute("UPDATE relay_games SET message_bytes = ?1 WHERE game_id = ?2",params![1024_i64*1024*1024,[4_u8;32].as_slice()])?;
    post_message_db(&mut connection,[1;32],player,[6;32],"opaque",&[1],Limits::production())?;
    connection.execute("UPDATE relay_games SET message_bytes = ?1 WHERE game_id = ?2",params![(MAX_RELAY_BYTES-1) as i64,[4_u8;32].as_slice()])?;
    let error = post_message_db(&mut connection,[1;32],player,[7;32],"opaque",&[1],Limits::production()).err().ok_or("capacity limit not enforced")?;
    assert_eq!(error.status,StatusCode::INSUFFICIENT_STORAGE);
    Ok(())
}

#[test]
fn delivered_payloads_are_discarded_only_after_both_browsers_save_them() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let server = open_test_relay(&temporary.path)?;
    let mut c = server.database.connection.lock().map_err(|_| "poisoned")?;
    let game=[11;32]; let alice=capability_digest(PLAYER_TOKEN_TAG,[12;32]);
    let bob=capability_digest(PLAYER_TOKEN_TAG,[13;32]); let invite=capability_digest(INVITE_SECRET_TAG,[14;32]);
    create_game_db(&mut c,game,alice,invite)?;
    join_game_db(&mut c,game,bob,invite)?;
    post_message_db(&mut c,game,alice,[15;32],"opaque",&[1,2,3],Limits::production())?;
    store::ack_messages_db(&mut c,game,alice,1)?;
    assert_eq!(get_messages_db(&mut c,game,bob,0,64)?.messages.len(),1);
    assert!(store::ack_messages_db(&mut c,game,bob,2).is_err());
    store::ack_messages_db(&mut c,game,bob,1)?;
    assert!(get_messages_db(&mut c,game,bob,0,64)?.messages.is_empty());
    let retained:i64=c.query_row("SELECT message_bytes FROM relay_games",[],|r|r.get(0))?;
    assert_eq!(retained,0);
    assert!(post_message_db(&mut c,game,alice,[15;32],"opaque",&[1,2,3],Limits::production())?.value.duplicate);
    assert!(post_message_db(&mut c,game,alice,[15;32],"opaque",&[9],Limits::production()).is_err());
    // An old acknowledgement cannot erase a new undelivered message.
    post_message_db(&mut c,game,bob,[16;32],"opaque",&[4],Limits::production())?;
    store::ack_messages_db(&mut c,game,bob,0)?;
    assert_eq!(get_messages_db(&mut c,game,alice,1,64)?.messages.len(),1);
    Ok(())
}

#[test]
fn guest_can_restore_room_before_host_without_binding_the_host_capability() -> Result<(), Box<dyn std::error::Error>> {
    let temporary=TemporaryDatabase::create()?;
    let server=open_test_relay(&temporary.path)?;
    let mut c=server.database.connection.lock().map_err(|_| "poisoned")?;
    let game=[71;32];let host=capability_digest(PLAYER_TOKEN_TAG,[72;32]);let guest=capability_digest(PLAYER_TOKEN_TAG,[73;32]);let invite=capability_digest(INVITE_SECRET_TAG,[74;32]);
    assert!(!join_game_db(&mut c,game,guest,invite)?.joined);
    assert!(!get_game_db(&mut c,game,guest)?.joined);
    assert!(get_messages_db(&mut c,game,guest,257,64)?.messages.is_empty());
    assert!(create_game_db(&mut c,game,host,[99;32]).is_err());
    assert!(create_game_db(&mut c,game,guest,invite).is_err());
    assert!(join_game_db(&mut c,game,host,invite).is_err());
    assert!(create_game_db(&mut c,game,host,invite)?.value.joined);
    assert!(get_game_db(&mut c,game,guest)?.joined);
    post_message_db(&mut c,game,guest,[75;32],"opaque",&[1],Limits::production())?;
    assert_eq!(get_messages_db(&mut c,game,host,0,64)?.messages.len(),1);
    assert!(create_game_db(&mut c,game,[88;32],invite).is_err());
    Ok(())
}

#[tokio::test]
async fn socket_delivery_skips_duplicate_payloads_without_acknowledging_them() -> Result<(),Box<dyn std::error::Error>> {
    let server=open_test_relay(Path::new("unused"))?;
    let state=AppState{changes:server.changes.clone(),database:server.database.clone(),limits:server.limits,deployment:server.deployment.clone()};
    let game="a1".repeat(32);
    let request=|sender:&str|routes::ExchangeRequest{player_token:if sender=="alice"{"a2".repeat(32)}else{"a3".repeat(32)},invite_secret:"a4".repeat(32),sender:sender.into(),epoch:None,after:0,messages:vec![]};
    let mut alice=request("alice");let mut bob=request("bob");
    let first=routes::exchange_binary(state.clone(),game.clone(),alice.clone(),None,None).await?;
    alice.epoch=Some(first.page.epoch.clone());bob.epoch=alice.epoch.clone();
    routes::exchange_binary(state.clone(),game.clone(),bob.clone(),None,None).await?;
    alice.messages.push(PostMessageRequest{message_id:"a5".repeat(32),kind:"channel.batch".into(),payload:STANDARD.encode([1,2,3])});
    routes::exchange_binary(state.clone(),game.clone(),alice.clone(),None,None).await?;
    let pushed=routes::push_room(state.clone(),game.clone(),bob.clone()).await?;
    assert_eq!(pushed.messages.len(),1);
    let response=routes::exchange_binary(state.clone(),game.clone(),bob.clone(),None,Some((pushed.epoch.clone(),pushed.next_cursor))).await?;
    assert!(response.page.messages.is_empty());assert_eq!(response.page.next_cursor,pushed.next_cursor);
    // Dropping the socket before saving its push must still permit redelivery.
    let reconnect=routes::exchange_binary(state.clone(),game.clone(),bob.clone(),None,None).await?;
    assert_eq!(reconnect.page.messages.len(),1);
    let wrong_epoch=routes::exchange_binary(state,game,bob,None,Some(("stale".into(),pushed.next_cursor))).await?;
    assert_eq!(wrong_epoch.page.messages.len(),1);
    Ok(())
}
