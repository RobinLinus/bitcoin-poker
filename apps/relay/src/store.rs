//! Store.

use super::*;

pub(super) fn configure_database(connection: &mut Connection) -> Result<(), RelayBuildError> {
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .and_then(|()| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .map_err(|_| RelayBuildError::Database)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| RelayBuildError::Database)?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS relay_games (
                game_id BLOB PRIMARY KEY NOT NULL CHECK(length(game_id) = 32),
                epoch BLOB NOT NULL DEFAULT (randomblob(16)),
                player_one_hash BLOB CHECK(player_one_hash IS NULL OR length(player_one_hash) = 32),
                player_two_hash BLOB CHECK(player_two_hash IS NULL OR length(player_two_hash) = 32),
                invite_hash BLOB NOT NULL CHECK(length(invite_hash) = 32),
                ack_one INTEGER NOT NULL DEFAULT 0,
                ack_two INTEGER NOT NULL DEFAULT 0,
                last_cursor INTEGER NOT NULL DEFAULT 0 CHECK(last_cursor >= 0),
                message_count INTEGER NOT NULL DEFAULT 0 CHECK(message_count >= 0),
                message_bytes INTEGER NOT NULL DEFAULT 0 CHECK(message_bytes >= 0),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                joined_at_ms INTEGER CHECK(joined_at_ms IS NULL OR joined_at_ms >= created_at_ms),
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= created_at_ms)
            ) WITHOUT ROWID, STRICT;
            CREATE TABLE IF NOT EXISTS relay_messages (
                game_id BLOB NOT NULL CHECK(length(game_id) = 32),
                cursor INTEGER NOT NULL CHECK(cursor >= 1),
                message_id BLOB NOT NULL CHECK(length(message_id) = 32),
                sender INTEGER NOT NULL CHECK(sender IN (0, 1)),
                kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 32),
                payload_hash BLOB NOT NULL,
                payload BLOB CHECK(length(payload) <= 16777216),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                PRIMARY KEY(game_id, cursor),
                UNIQUE(game_id, message_id),
                FOREIGN KEY(game_id) REFERENCES relay_games(game_id) ON DELETE CASCADE
            ) WITHOUT ROWID, STRICT;",
        )
        .map_err(|_| RelayBuildError::Database)?;
    transaction
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS relay_messages_by_id
                ON relay_messages(game_id, message_id);
             CREATE INDEX IF NOT EXISTS relay_games_by_expiry
                ON relay_games(expires_at_ms);",
        )
        .and_then(|()| transaction.pragma_update(None, "user_version", 1))
        .map_err(|_| RelayBuildError::Database)?;
    transaction.commit().map_err(|_| RelayBuildError::Database)
}

pub(super) fn create_game_db(
    connection: &mut Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    player_hash: [u8; 32],
    invite_hash: [u8; 32],
) -> Result<Mutation<GameResponse>, ApiError> {
    let transaction = immediate_transaction(connection)?;
    let now = now_ms()?;
    cleanup_expired(&transaction, now)?;
    let existing = transaction
        .query_row(
            "SELECT player_one_hash, invite_hash, player_two_hash, last_cursor
             FROM relay_games WHERE game_id = ?1",
            params![game_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?;
    let (joined, last_cursor, created) =
        if let Some((stored_player, stored_invite, peer, cursor)) = existing {
            if stored_player.as_deref().is_some_and(|stored| !constant_time_eq(stored, &player_hash))
                || !constant_time_eq(&stored_invite, &invite_hash)
            {
                return Err(ApiError::conflict(
                    "game_exists",
                    "gameId is already bound to different capabilities",
                ));
            }
            if peer.as_deref().is_some_and(|stored| constant_time_eq(stored, &player_hash)) {
                return Err(ApiError::bad_request("players must use independent capabilities"));
            }
            transaction
                .execute(
                    "UPDATE relay_games SET expires_at_ms = ?2, player_one_hash = ?3, joined_at_ms = CASE WHEN player_two_hash IS NOT NULL THEN COALESCE(joined_at_ms, ?4) ELSE NULL END WHERE game_id = ?1",
                    params![game_id.as_slice(), checked_i64(expiry_from(now)?)?, player_hash.as_slice(), checked_i64(now)?],
                )
                .map_err(|_| ApiError::internal())?;
            (peer.is_some(), checked_u64(cursor)?, false)
        } else {
            let game_count: i64 = transaction
                .query_row("SELECT COUNT(*) FROM relay_games", [], |row| row.get(0))
                .map_err(|_| ApiError::internal())?;
            if checked_u64(game_count)? >= MAX_RELAY_GAMES {
                return Err(ApiError::storage_full("relay game limit reached"));
            }
            transaction
                .execute(
                    "INSERT INTO relay_games(
                    game_id, player_one_hash, invite_hash, created_at_ms, expires_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        game_id.as_slice(),
                        player_hash.as_slice(),
                        invite_hash.as_slice(),
                        checked_i64(now)?,
                        checked_i64(expiry_from(now)?)?
                    ],
                )
                .map_err(|_| ApiError::internal())?;
            (false, 0, true)
        };
    transaction.commit().map_err(|_| ApiError::internal())?;
    Ok(Mutation {
        value: GameResponse {
            game_id: encode_hex(game_id),
            joined,
            last_cursor,
        },
        created,
    })
}

pub(super) fn join_game_db(
    connection: &mut Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    player_hash: [u8; 32],
    invite_hash: [u8; 32],
) -> Result<GameResponse, ApiError> {
    let transaction = immediate_transaction(connection)?;
    let now = now_ms()?;
    cleanup_expired(&transaction, now)?;
    let existing = transaction
        .query_row(
            "SELECT player_one_hash, player_two_hash, invite_hash, last_cursor
             FROM relay_games WHERE game_id = ?1",
            params![game_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?;
    let Some((player_one, player_two, stored_invite, last_cursor)) = existing else {
        let count: i64 = transaction.query_row("SELECT COUNT(*) FROM relay_games", [], |row| row.get(0)).map_err(|_| ApiError::internal())?;
        if checked_u64(count)? >= MAX_RELAY_GAMES { return Err(ApiError::storage_full("relay game limit reached")); }
        transaction.execute("INSERT INTO relay_games(game_id, player_two_hash, invite_hash, created_at_ms, expires_at_ms) VALUES (?1,?2,?3,?4,?5)", params![game_id.as_slice(), player_hash.as_slice(), invite_hash.as_slice(), checked_i64(now)?, checked_i64(expiry_from(now)?)?]).map_err(|_| ApiError::internal())?;
        transaction.commit().map_err(|_| ApiError::internal())?;
        return Ok(GameResponse { game_id: encode_hex(game_id), joined: false, last_cursor: 0 });
    };
    if !constant_time_eq(&stored_invite, &invite_hash) {
        return Err(ApiError::unauthorized());
    }
    if player_one.as_deref().is_some_and(|stored| constant_time_eq(stored, &player_hash)) {
        return Err(ApiError::bad_request(
            "joining player must use an independent capability",
        ));
    }
    match player_two {
        Some(stored_player) if constant_time_eq(&stored_player, &player_hash) => {}
        Some(_) => {
            return Err(ApiError::conflict(
                "game_already_joined",
                "the second player capability is already fixed",
            ));
        }
        None => {
            transaction
                .execute(
                    "UPDATE relay_games
                     SET player_two_hash = ?2, joined_at_ms = ?3, expires_at_ms = ?4
                     WHERE game_id = ?1 AND player_two_hash IS NULL",
                    params![
                        game_id.as_slice(),
                        player_hash.as_slice(),
                        checked_i64(now)?,
                        checked_i64(expiry_from(now)?)?
                    ],
                )
                .map_err(|_| ApiError::internal())?;
        }
    }
    transaction
        .execute(
            "UPDATE relay_games SET expires_at_ms = ?2 WHERE game_id = ?1",
            params![game_id.as_slice(), checked_i64(expiry_from(now)?)?],
        )
        .map_err(|_| ApiError::internal())?;
    transaction.commit().map_err(|_| ApiError::internal())?;
    Ok(GameResponse {
        game_id: encode_hex(game_id),
        joined: player_one.is_some(),
        last_cursor: checked_u64(last_cursor)?,
    })
}

pub(super) fn get_game_db(
    connection: &mut Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    token_hash: [u8; 32],
) -> Result<GameResponse, ApiError> {
    let authorization = authorize(connection, game_id, token_hash)?;
    Ok(GameResponse {
        game_id: encode_hex(game_id),
        joined: authorization.joined,
        last_cursor: authorization.last_cursor,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn post_message_db(
    connection: &mut Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    token_hash: [u8; 32],
    message_id: [u8; IDENTIFIER_BYTES],
    kind: &str,
    payload: &[u8],
    limits: Limits,
) -> Result<Mutation<PostMessageResponse>, ApiError> {
    let transaction = immediate_transaction(connection)?;
    let now = now_ms()?;
    cleanup_expired(&transaction, now)?;
    let authorization = authorize(&transaction, game_id, token_hash)?;
    if !authorization.joined {
        return Err(ApiError::conflict(
            "game_not_joined",
            "both player capabilities must be fixed before messages are accepted",
        ));
    }
    let existing = transaction
        .query_row(
            "SELECT cursor, sender, kind, payload_hash
             FROM relay_messages WHERE game_id = ?1 AND message_id = ?2",
            params![game_id.as_slice(), message_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?;
    if let Some((cursor, sender, stored_kind, stored_payload)) = existing {
        if sender == i64::from(authorization.sender)
            && stored_kind == kind
            && constant_time_eq(&stored_payload, &Sha256::digest(payload))
        {
            transaction
                .execute(
                    "UPDATE relay_games SET expires_at_ms = ?2 WHERE game_id = ?1",
                    params![game_id.as_slice(), checked_i64(expiry_from(now)?)?],
                )
                .map_err(|_| ApiError::internal())?;
            transaction.commit().map_err(|_| ApiError::internal())?;
            return Ok(Mutation {
                value: PostMessageResponse {
                    message_id: encode_hex(message_id),
                    cursor: checked_u64(cursor)?,
                    duplicate: true,
                },
                created: false,
            });
        }
        return Err(ApiError::conflict(
            "message_id_conflict",
            "messageId is already bound to different bytes",
        ));
    }
    if authorization.message_count >= limits.game_messages {
        return Err(ApiError::too_large("game message count limit reached"));
    }
    let global_message_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM relay_messages", [], |row| row.get(0))
        .map_err(|_| ApiError::internal())?;
    if checked_u64(global_message_count)? >= MAX_RELAY_MESSAGES {
        return Err(ApiError::storage_full("relay message count limit reached"));
    }
    let payload_len = u64::try_from(payload.len()).map_err(|_| ApiError::internal())?;
    let next_bytes = authorization
        .message_bytes
        .checked_add(payload_len)
        .ok_or_else(ApiError::internal)?;
    if next_bytes > limits.game_bytes {
        return Err(ApiError::too_large("game payload byte limit reached"));
    }
    let global_bytes: Option<i64> = transaction
        .query_row("SELECT SUM(message_bytes) FROM relay_games", [], |row| {
            row.get(0)
        })
        .map_err(|_| ApiError::internal())?;
    let global_bytes = global_bytes.map_or(Ok(0), checked_u64)?;
    if global_bytes
        .checked_add(payload_len)
        .is_none_or(|total| total > MAX_RELAY_BYTES)
    {
        return Err(ApiError::storage_full("relay byte limit reached"));
    }
    let cursor = authorization
        .last_cursor
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    let next_count = authorization
        .message_count
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    transaction
        .execute(
            "INSERT INTO relay_messages(
                game_id, cursor, message_id, sender, kind, payload, created_at_ms, payload_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                game_id.as_slice(),
                checked_i64(cursor)?,
                message_id.as_slice(),
                i64::from(authorization.sender),
                kind,
                payload,
                checked_i64(now)?,
                Sha256::digest(payload).as_slice()
            ],
        )
        .map_err(|_| ApiError::internal())?;
    let changed = transaction
        .execute(
            "UPDATE relay_games
             SET last_cursor = ?2, message_count = ?3, message_bytes = ?4, expires_at_ms = ?6
             WHERE game_id = ?1 AND last_cursor = ?5",
            params![
                game_id.as_slice(),
                checked_i64(cursor)?,
                checked_i64(next_count)?,
                checked_i64(next_bytes)?,
                checked_i64(authorization.last_cursor)?,
                checked_i64(expiry_from(now)?)?
            ],
        )
        .map_err(|_| ApiError::internal())?;
    if changed != 1 {
        return Err(ApiError::internal());
    }
    transaction.commit().map_err(|_| ApiError::internal())?;
    Ok(Mutation {
        value: PostMessageResponse {
            message_id: encode_hex(message_id),
            cursor,
            duplicate: false,
        },
        created: true,
    })
}

pub(super) fn get_messages_db(
    connection: &mut Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    token_hash: [u8; 32],
    after: u64,
    limit: usize,
) -> Result<PollResponse, ApiError> {
    read_messages_db(connection, game_id, token_hash, after, limit, false)
}

pub(super) fn read_messages_db(
    connection: &mut Connection, game_id: [u8;32], token_hash: [u8;32],
    after: u64, limit: usize, peer_only: bool,
) -> Result<PollResponse, ApiError> {
    let authorization = authorize(connection, game_id, token_hash)?;
    let mut statement = connection
        .prepare(
            "SELECT cursor, message_id, sender, kind, payload, created_at_ms
             FROM relay_messages
             WHERE game_id = ?1 AND cursor > ?2 AND payload IS NOT NULL AND (?4 = 0 OR sender != ?5)
             ORDER BY cursor ASC LIMIT ?3",
        )
        .map_err(|_| ApiError::internal())?;
    let mut rows = statement
        .query(params![
            game_id.as_slice(),
            checked_i64(after)?,
            i64::try_from(limit).map_err(|_| ApiError::internal())?,
            i64::from(peer_only), i64::from(authorization.sender)
        ])
        .map_err(|_| ApiError::internal())?;
    let mut messages = Vec::with_capacity(limit);
    let mut page_bytes = 0_usize;
    while let Some(row) = rows.next().map_err(|_| ApiError::internal())? {
        let payload: Vec<u8> = row.get(4).map_err(|_| ApiError::internal())?;
        let Some(next_page_bytes) = page_bytes.checked_add(payload.len()) else {
            return Err(ApiError::internal());
        };
        if !messages.is_empty() && next_page_bytes > if peer_only {2*1024*1024} else {MAX_PAGE_PAYLOAD_BYTES} {
            break;
        }
        page_bytes = next_page_bytes;
        let raw_message_id: Vec<u8> = row.get(1).map_err(|_| ApiError::internal())?;
        let message_id: [u8; IDENTIFIER_BYTES] =
            fixed_array(&raw_message_id).ok_or_else(ApiError::internal)?;
        let sender = sender_name(row.get(2).map_err(|_| ApiError::internal())?)?;
        messages.push(MessageResponse {
            cursor: checked_u64(row.get(0).map_err(|_| ApiError::internal())?)?,
            message_id: encode_hex(message_id),
            sender,
            kind: row.get(3).map_err(|_| ApiError::internal())?,
            payload,
            created_at_ms: checked_u64(row.get(5).map_err(|_| ApiError::internal())?)?,
        });
    }
    let next_cursor = messages.last().map_or(if peer_only {authorization.last_cursor} else {after}, |message| message.cursor);
    Ok(PollResponse {
        epoch: room_epoch(connection, game_id)?,
        joined: authorization.joined,
        messages,
        next_cursor,
    })
}

pub(super) fn room_epoch(connection: &Connection, game_id: [u8;32]) -> Result<String, ApiError> {
    connection.query_row("SELECT lower(hex(epoch)) FROM relay_games WHERE game_id=?1", params![game_id.as_slice()], |row| row.get(0)).map_err(|_| ApiError::internal())
}

pub(super) fn immediate_transaction(
    connection: &mut Connection,
) -> Result<Transaction<'_>, ApiError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ApiError::internal())
}

pub(super) fn cleanup_expired(transaction: &Transaction<'_>, now: u64) -> Result<(), ApiError> {
    transaction
        .execute(
            "DELETE FROM relay_games WHERE expires_at_ms <= ?1",
            params![checked_i64(now)?],
        )
        .map(|_| ())
        .map_err(|_| ApiError::internal())
}

pub(super) fn expiry_from(now: u64) -> Result<u64, ApiError> {
    now.checked_add(GAME_TTL_MS).ok_or_else(ApiError::internal)
}

pub(super) fn ack_messages_db(connection: &mut Connection, game: [u8;32], token: [u8;32], cursor: u64) -> Result<(), ApiError> {
    let tx = immediate_transaction(connection)?;
    let auth = authorize(&tx, game, token)?;
    if cursor > auth.last_cursor { return Err(ApiError::bad_request("invalid delivery cursor")); }
    let acknowledged: i64=tx.query_row(if auth.sender==0 {"SELECT ack_one FROM relay_games WHERE game_id=?1"} else {"SELECT ack_two FROM relay_games WHERE game_id=?1"}, params![game.as_slice()], |row| row.get(0)).map_err(|_|ApiError::internal())?;
    if cursor<=checked_u64(acknowledged)? {return Ok(());}

    let sql = if auth.sender == 0 {
        "UPDATE relay_games SET ack_one=MAX(ack_one,?2) WHERE game_id=?1"
    } else { "UPDATE relay_games SET ack_two=MAX(ack_two,?2) WHERE game_id=?1" };
    tx.execute(sql, params![game.as_slice(), checked_i64(cursor)?]).map_err(|_| ApiError::internal())?;
    // Keep only a digest for idempotent POST retries. No delivered message contents remain.
    tx.execute("UPDATE relay_messages SET payload=NULL WHERE game_id=?1 AND cursor <= (SELECT MIN(ack_one,ack_two) FROM relay_games WHERE game_id=?1)", params![game.as_slice()]).map_err(|_| ApiError::internal())?;
    tx.execute("UPDATE relay_games SET message_bytes=(SELECT COALESCE(SUM(length(payload)),0) FROM relay_messages WHERE game_id=?1), message_count=(SELECT COUNT(*) FROM relay_messages WHERE game_id=?1 AND payload IS NOT NULL) WHERE game_id=?1", params![game.as_slice()]).map_err(|_| ApiError::internal())?;
    tx.commit().map_err(|_| ApiError::internal())
}
