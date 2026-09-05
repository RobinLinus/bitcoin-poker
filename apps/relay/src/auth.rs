//! Auth.

use super::{
    AUTHORIZATION, ApiError, Authorization, CAPABILITY_BYTES, Connection, ConstantTimeEq, Digest,
    HeaderMap, IDENTIFIER_BYTES, OptionalExtension, Sha256, checked_u64, decode_hex, now_ms,
    params,
};

pub(super) fn authorize(
    connection: &Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    token_hash: [u8; 32],
) -> Result<Authorization, ApiError> {
    let row = connection
        .query_row(
            "SELECT player_one_hash, player_two_hash, last_cursor, message_count, message_bytes,
                    expires_at_ms
             FROM relay_games WHERE game_id = ?1",
            params![game_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::unauthorized)?;
    let (player_one, player_two, last_cursor, message_count, message_bytes, expires_at) = row;
    if checked_u64(expires_at)? <= now_ms()? {
        return Err(ApiError::unauthorized());
    }
    let first = constant_time_eq(&player_one, &token_hash);
    let second = player_two
        .as_deref()
        .is_some_and(|stored| constant_time_eq(stored, &token_hash));
    let sender = match (first, second) {
        (true, false) => 0,
        (false, true) => 1,
        _ => return Err(ApiError::unauthorized()),
    };
    Ok(Authorization {
        sender,
        joined: player_two.is_some(),
        last_cursor: checked_u64(last_cursor)?,
        message_count: checked_u64(message_count)?,
        message_bytes: checked_u64(message_bytes)?,
    })
}

pub(super) fn bearer_token(headers: &HeaderMap) -> Result<[u8; CAPABILITY_BYTES], ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(ApiError::unauthorized)?
        .to_str()
        .map_err(|_| ApiError::unauthorized())?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(ApiError::unauthorized)?;
    decode_capability(token).map_err(|_| ApiError::unauthorized())
}

pub(super) fn decode_capability(value: &str) -> Result<[u8; CAPABILITY_BYTES], ApiError> {
    decode_hex(value)
        .ok_or_else(|| ApiError::bad_request("capabilities must be 64 lowercase hex characters"))
}

pub(super) fn capability_digest(tag: &[u8], capability: [u8; CAPABILITY_BYTES]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(capability);
    hasher.finalize().into()
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}
