//! Transient public seat allocation. Poker and funds remain browser-owned.
use super::*;
const LEASE_MS: u64 = 45_000;
const TICKET_TAG: &[u8] = b"BP52/matchmaking/ticket/v1";

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    ticket: String,
    wallet_id: String,
    game_id: String,
    player_token: String,
    invite_secret: String,
    action: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Response {
    status: String,
    game_id: Option<String>,
    sender: Option<String>,
    invite_secret: Option<String>,
}
impl Response {
    fn status(status: &str) -> Self {
        Self {
            status: status.into(),
            game_id: None,
            sender: None,
            invite_secret: None,
        }
    }
}
pub(super) fn configure(c: &Connection) -> Result<(), rusqlite::Error> {
    c.execute_batch("CREATE TABLE matchmaking (
      ticket BLOB PRIMARY KEY, participant BLOB NOT NULL, player BLOB NOT NULL,
      game BLOB NOT NULL, invite TEXT NOT NULL, sender TEXT NOT NULL,
      status TEXT NOT NULL, lease INTEGER NOT NULL, created INTEGER NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
    ); CREATE INDEX matchmaking_waiting ON matchmaking(status, created);")
}

// All allocation, retry and cancellation operations share one database transaction.
fn update(c: &mut Connection, r: Request) -> Result<Response, ApiError> {
    if !matches!(r.action.as_str(), "enter" | "poll" | "cancel") {
        return Err(ApiError::bad_request("Invalid matchmaking action"));
    }
    let ticket = capability_digest(TICKET_TAG, decode_capability(&r.ticket)?);
    let participant = decode_capability(&r.wallet_id)?;
    let player = capability_digest(PLAYER_TOKEN_TAG, decode_capability(&r.player_token)?);
    let game = decode_identifier(&r.game_id, "Invalid proposed game")?;
    decode_capability(&r.invite_secret)?;
    let now = now_ms()?;
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ApiError::internal())?;
    tx.execute("UPDATE matchmaking SET status='expired' WHERE status='reserved' AND game IN (SELECT game FROM matchmaking WHERE status='reserved' AND lease<=?1)",params![now]).map_err(|_|ApiError::internal())?;
    tx.execute(
        "UPDATE matchmaking SET status='expired' WHERE status='waiting' AND lease<=?1",
        params![now],
    )
    .map_err(|_| ApiError::internal())?;
    tx.execute(
        "DELETE FROM matchmaking WHERE created < ?1",
        params![now.saturating_sub(GAME_TTL_MS)],
    )
    .map_err(|_| ApiError::internal())?;
    let existing: Option<(Vec<u8>, Vec<u8>, Vec<u8>, String, String, String)> = tx
        .query_row(
            "SELECT participant,player,game,invite,sender,status FROM matchmaking WHERE ticket=?1",
            params![ticket.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?;
    if let Some((owner, token, assigned, invite, sender, status)) = existing {
        if !constant_time_eq(&owner, &participant) || !constant_time_eq(&token, &player) {
            return Err(ApiError::conflict(
                "ticket_owner",
                "This matchmaking ticket belongs to another player",
            ));
        }
        let mut status = status;
        if matches!(status.as_str(), "waiting" | "reserved") && r.action == "cancel" {
            if status == "reserved" {
                tx.execute(
                    "UPDATE matchmaking SET status='expired' WHERE game=?1 AND status='reserved'",
                    params![assigned],
                )
                .map_err(|_| ApiError::internal())?;
            }
            status = "cancelled".into();
        } else if status == "reserved" {
            tx.execute(
                "UPDATE matchmaking SET acknowledged=1 WHERE ticket=?1",
                params![ticket.as_slice()],
            )
            .map_err(|_| ApiError::internal())?;
            let ready:u64=tx.query_row("SELECT count(*) FROM matchmaking WHERE game=?1 AND status='reserved' AND acknowledged=1",params![assigned],|row|row.get(0)).map_err(|_|ApiError::internal())?;
            if ready == 2 {
                tx.execute(
                    "UPDATE matchmaking SET status='matched' WHERE game=?1 AND status='reserved'",
                    params![assigned],
                )
                .map_err(|_| ApiError::internal())?;
                status = "matched".into();
            }
        }
        tx.execute(
            "UPDATE matchmaking SET status=?1,lease=?2 WHERE ticket=?3",
            params![status, now + LEASE_MS, ticket.as_slice()],
        )
        .map_err(|_| ApiError::internal())?;
        tx.commit().map_err(|_| ApiError::internal())?;
        return Ok(Response {
            status,
            game_id: Some(encode_hex::<32>(
                assigned.try_into().map_err(|_| ApiError::internal())?,
            )),
            sender: Some(sender),
            invite_secret: Some(invite),
        });
    }
    if r.action == "poll" {
        return Ok(Response::status("missing"));
    }
    let tickets: u64 = tx
        .query_row("SELECT count(*) FROM matchmaking", [], |row| row.get(0))
        .map_err(|_| ApiError::internal())?;
    if tickets >= MAX_RELAY_GAMES {
        return Err(ApiError::conflict(
            "queue_full",
            "Matchmaking is busy. Try again shortly.",
        ));
    }
    // A cancellation arriving before enter leaves a tombstone, preventing a delayed enter.
    if r.action == "cancel" {
        tx.execute(
            "INSERT INTO matchmaking VALUES (?1,?2,?3,?4,?5,'alice','cancelled',?6,?7,0)",
            params![
                ticket.as_slice(),
                participant.as_slice(),
                player.as_slice(),
                game.as_slice(),
                r.invite_secret,
                now + LEASE_MS,
                now
            ],
        )
        .map_err(|_| ApiError::internal())?;
        tx.commit().map_err(|_| ApiError::internal())?;
        return Ok(Response::status("cancelled"));
    }
    if r.action == "poll" {
        return Ok(Response::status("missing"));
    }
    let duplicate: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM matchmaking WHERE participant=?1 AND status IN ('waiting','reserved'))",params![participant.as_slice()],|row|row.get(0)).map_err(|_|ApiError::internal())?;
    if duplicate {
        return Err(ApiError::conflict(
            "already_waiting",
            "This wallet is already finding an opponent in another window",
        ));
    }
    let count: u64 = tx
        .query_row("SELECT count(*) FROM matchmaking", [], |row| row.get(0))
        .map_err(|_| ApiError::internal())?;
    if count >= MAX_RELAY_GAMES {
        return Err(ApiError::conflict(
            "queue_full",
            "Matchmaking is busy. Try again shortly.",
        ));
    }
    // Public waiting tickets are the only discovery source. Private rooms never qualify.
    let waiting: Option<(Vec<u8>,Vec<u8>,String)> = tx.query_row(
      "SELECT m.ticket,m.game,m.invite FROM matchmaking m JOIN relay_games g ON g.game_id=m.game
       WHERE m.status='waiting' AND m.participant!=?1 AND g.player_two_hash IS NULL AND g.expires_at_ms>?2
       ORDER BY m.created,m.rowid LIMIT 1",params![participant.as_slice(),now],
      |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(|_|ApiError::internal())?;
    let (assigned, invite, sender, status) = if let Some((host, assigned, invite)) = waiting {
        tx.execute("UPDATE relay_games SET player_two_hash=?1,joined_at_ms=?2 WHERE game_id=?3 AND player_two_hash IS NULL",params![player.as_slice(),now,assigned]).map_err(|_|ApiError::internal())?;
        tx.execute(
            "UPDATE matchmaking SET status='reserved' WHERE ticket=?1",
            params![host],
        )
        .map_err(|_| ApiError::internal())?;
        (assigned, invite, "bob", "reserved")
    } else {
        let count: u64 = tx
            .query_row("SELECT count(*) FROM relay_games", [], |row| row.get(0))
            .map_err(|_| ApiError::internal())?;
        if count >= MAX_RELAY_GAMES {
            return Err(ApiError::conflict(
                "queue_full",
                "Matchmaking is busy. Try again shortly.",
            ));
        }
        let invite_hash =
            capability_digest(INVITE_SECRET_TAG, decode_capability(&r.invite_secret)?);
        tx.execute("INSERT INTO relay_games (game_id,player_one_hash,invite_hash,created_at_ms,expires_at_ms) VALUES (?1,?2,?3,?4,?5)",
          params![game.as_slice(),player.as_slice(),invite_hash.as_slice(),now,now+GAME_TTL_MS]).map_err(|_|ApiError::conflict("game_exists","Proposed table already exists"))?;
        (game.to_vec(), r.invite_secret, "alice", "waiting")
    };
    tx.execute(
        "INSERT INTO matchmaking VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            ticket.as_slice(),
            participant.as_slice(),
            player.as_slice(),
            assigned,
            invite,
            sender,
            status,
            now + LEASE_MS,
            now,
            i32::from(sender == "bob")
        ],
    )
    .map_err(|_| ApiError::internal())?;
    tx.commit().map_err(|_| ApiError::internal())?;
    Ok(Response {
        status: status.into(),
        game_id: Some(encode_hex::<32>(
            assigned.try_into().map_err(|_| ApiError::internal())?,
        )),
        sender: Some(sender.into()),
        invite_secret: Some(invite),
    })
}

pub(super) async fn handle(
    State(state): State<AppState>,
    request: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Response>, ApiError> {
    let Json(request) = request.map_err(|e| json_rejection(&e))?;
    let mut changes = state.changes.subscribe();
    let req = request.clone();
    let mut response = state.database.run(move |c| update(c, req)).await?;
    if request.action != "poll" || response.status == "matched" {
        if let Some(id) = &response.game_id {
            let _ = state.changes.send(decode_identifier(id, "Invalid game")?);
        }
    }
    if request.action == "poll" && matches!(response.status.as_str(), "waiting" | "reserved") {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(15), changes.recv()).await;
        response = state.database.run(move |c| update(c, request)).await?;
    }
    if response.status == "matched" {
        if let Some(id) = &response.game_id {
            let _ = state.changes.send(decode_identifier(id, "Invalid game")?);
        }
    }
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn db() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        configure_database(&mut c).unwrap();
        configure(&c).unwrap();
        c
    }
    fn req(n: u8) -> Request {
        Request {
            ticket: encode_hex([n; 32]),
            wallet_id: encode_hex([n + 20; 32]),
            game_id: encode_hex([n + 40; 32]),
            player_token: encode_hex([n + 60; 32]),
            invite_secret: encode_hex([n + 80; 32]),
            action: "enter".into(),
        }
    }
    #[test]
    fn pairs_retries_and_private_isolation() {
        let mut c = db();
        create_game_db(&mut c, [200; 32], [201; 32], [202; 32]).unwrap();
        let a = update(&mut c, req(1)).unwrap();
        assert_eq!(a.status, "waiting");
        let b = update(&mut c, req(2)).unwrap();
        assert_eq!(b.status, "reserved");
        assert_eq!(a.game_id, b.game_id);
        assert_eq!(b.sender.as_deref(), Some("bob"));
        let retry = update(&mut c, req(1)).unwrap();
        assert_eq!(retry.status, "matched");
        assert_eq!(retry.game_id, a.game_id);
        let next = update(&mut c, req(3)).unwrap();
        assert_eq!(next.status, "waiting");
        assert_ne!(next.game_id, a.game_id);
    }
    #[test]
    fn cancel_expire_and_owner_checks() {
        let mut c = db();
        let mut a = req(1);
        a.action = "cancel".into();
        assert_eq!(update(&mut c, a).unwrap().status, "cancelled");
        assert_eq!(update(&mut c, req(1)).unwrap().status, "cancelled");
        update(&mut c, req(2)).unwrap();
        c.execute("UPDATE matchmaking SET lease=0 WHERE status='waiting'", [])
            .unwrap();
        assert_eq!(update(&mut c, req(3)).unwrap().status, "waiting");
        assert_eq!(update(&mut c, req(2)).unwrap().status, "expired");
        let mut wrong = req(3);
        wrong.player_token = encode_hex([99; 32]);
        assert!(update(&mut c, wrong).is_err());
        let mut duplicate = req(4);
        duplicate.wallet_id = req(3).wallet_id;
        assert!(update(&mut c, duplicate).is_err());
    }
    #[test]
    fn cancellation_after_match_returns_assignment() {
        let mut c = db();
        update(&mut c, req(1)).unwrap();
        update(&mut c, req(2)).unwrap();
        update(&mut c, req(1)).unwrap();
        let mut a = req(1);
        a.action = "cancel".into();
        assert_eq!(update(&mut c, a).unwrap().status, "matched");
    }
}
