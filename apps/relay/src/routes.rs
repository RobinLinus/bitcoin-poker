//! Routes.

use super::{
    ApiError, AppState, AxumPath, BrowserDeploymentConfig, CreateGameRequest,
    DEFAULT_PAGE_MESSAGES, HeaderMap, INVITE_SECRET_TAG, IntoResponse, JoinGameRequest, Json,
    JsonRejection, MAX_PAGE_MESSAGES, PLAYER_TOKEN_TAG, PollQuery, PostMessageRequest, Query,
    QueryRejection, State, StatusCode, bearer_token, capability_digest, create_game_db,
    decode_capability, decode_identifier, decode_payload, get_game_db, get_messages_db,
    join_game_db, json_rejection, post_message_db, validate_kind,
};

pub(super) async fn create_game(
    State(state): State<AppState>,
    request: Result<Json<CreateGameRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(request) = request.map_err(|error| json_rejection(&error))?;
    let game_id = decode_identifier(
        &request.game_id,
        "gameId must be 64 lowercase hex characters",
    )?;
    let player_token = decode_capability(&request.player_token)?;
    let invite_secret = decode_capability(&request.invite_secret)?;
    let player_hash = capability_digest(PLAYER_TOKEN_TAG, player_token);
    let invite_hash = capability_digest(INVITE_SECRET_TAG, invite_secret);
    let result = state
        .database
        .run(move |connection| create_game_db(connection, game_id, player_hash, invite_hash))
        .await?;
    if result.created {let _=state.changes.send(game_id);}
    let status = if result.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(result.value)))
}

pub(super) async fn join_game(
    State(state): State<AppState>,
    AxumPath(game_id): AxumPath<String>,
    request: Result<Json<JoinGameRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(request) = request.map_err(|error| json_rejection(&error))?;
    let game_id = decode_identifier(&game_id, "game id path is invalid")?;
    let player_token = decode_capability(&request.player_token)?;
    let invite_secret = decode_capability(&request.invite_secret)?;
    let player_hash = capability_digest(PLAYER_TOKEN_TAG, player_token);
    let invite_hash = capability_digest(INVITE_SECRET_TAG, invite_secret);
    let response = state
        .database
        .run(move |connection| join_game_db(connection, game_id, player_hash, invite_hash))
        .await?;
    if response.joined {let _=state.changes.send(game_id);}
    Ok((StatusCode::OK, Json(response)))
}

pub(super) async fn get_game(
    State(state): State<AppState>,
    AxumPath(game_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let game_id = decode_identifier(&game_id, "game id path is invalid")?;
    let token = bearer_token(&headers)?;
    let token_hash = capability_digest(PLAYER_TOKEN_TAG, token);
    let response = state
        .database
        .run(move |connection| get_game_db(connection, game_id, token_hash))
        .await?;
    Ok(Json(response))
}

pub(super) async fn post_message(
    State(state): State<AppState>,
    AxumPath(game_id): AxumPath<String>,
    headers: HeaderMap,
    request: Result<Json<PostMessageRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(request) = request.map_err(|error| json_rejection(&error))?;
    let game_id = decode_identifier(&game_id, "game id path is invalid")?;
    let token = bearer_token(&headers)?;
    let token_hash = capability_digest(PLAYER_TOKEN_TAG, token);
    let message_id = decode_identifier(
        &request.message_id,
        "messageId must be 64 lowercase hex characters",
    )?;
    validate_kind(&request.kind)?;
    let payload = decode_payload(&request.payload, state.limits.message_bytes)?;
    let kind = request.kind;
    let limits = state.limits;
    let result = state
        .database
        .run(move |connection| {
            post_message_db(
                connection, game_id, token_hash, message_id, &kind, &payload, limits,
            )
        })
        .await?;
    if result.created {let _=state.changes.send(game_id);}
    let status = if result.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(result.value)))
}

pub(super) async fn get_messages(
    State(state): State<AppState>,
    AxumPath(game_id): AxumPath<String>,
    headers: HeaderMap,
    query: Result<Query<PollQuery>, QueryRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("poll query is invalid"))?;
    let game_id = decode_identifier(&game_id, "game id path is invalid")?;
    let token = bearer_token(&headers)?;
    let token_hash = capability_digest(PLAYER_TOKEN_TAG, token);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_MESSAGES);
    if limit == 0 || limit > MAX_PAGE_MESSAGES {
        return Err(ApiError::bad_request("limit must be between 1 and 64"));
    }
    if i64::try_from(query.after).is_err() {
        return Err(ApiError::bad_request(
            "after cursor is outside the valid range",
        ));
    }
    let response = state
        .database
        .run(move |connection| get_messages_db(connection, game_id, token_hash, query.after, limit))
        .await?;
    Ok(Json(response))
}

pub(super) async fn get_deployment_config(
    State(state): State<AppState>,
) -> Json<BrowserDeploymentConfig> {
    Json((*state.deployment).clone())
}

/// Delivery is acknowledged only after the browser has saved the page locally.
pub(super) async fn ack_messages(
    State(state): State<AppState>, AxumPath(game_id): AxumPath<String>, headers: HeaderMap,
    request: Result<Json<super::AckRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(request) = request.map_err(|e| json_rejection(&e))?;
    let game = decode_identifier(&game_id, "invalid room")?;
    let token = capability_digest(PLAYER_TOKEN_TAG, bearer_token(&headers)?);
    state.database.run(move |c| super::store::ack_messages_db(c, game, token, request.cursor)).await?;
    Ok(StatusCode::NO_CONTENT)
}


#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SessionPollRequest {
    player_token: String,
    invite_secret: String,
    sender: String,
    after: u64,
}

/// Restore this seat and fetch its messages under the same queue lock.
/// Room loss on relay restart is routine, not an authorization failure.
pub(super) async fn poll_session(
    State(state): State<AppState>, AxumPath(game_id): AxumPath<String>,
    request: Result<Json<SessionPollRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(request) = request.map_err(|e| json_rejection(&e))?;
    let game = decode_identifier(&game_id, "invalid room")?;
    let token = capability_digest(PLAYER_TOKEN_TAG, decode_capability(&request.player_token)?);
    let invite = capability_digest(INVITE_SECRET_TAG, decode_capability(&request.invite_secret)?);
    if !matches!(request.sender.as_str(), "alice" | "bob") || request.after > i64::MAX as u64 {
        return Err(ApiError::bad_request("invalid polling request"));
    }
    let page = state.database.run(move |c| {
        if request.sender == "alice" { create_game_db(c, game, token, invite)?; }
        else { join_game_db(c, game, token, invite)?; }
        get_messages_db(c, game, token, request.after, MAX_PAGE_MESSAGES)
    }).await?;
    Ok(Json(page))
}

#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExchangeRequest {
    pub(super) player_token: String,
    pub(super) invite_secret: String,
    pub(super) sender: String,
    pub(super) epoch: Option<String>,
    pub(super) after: u64,
    pub(super) messages: Vec<PostMessageRequest>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExchangeResponse {
    #[serde(flatten)]
    pub(super) page: super::PollResponse,
    pub(super) accepted: Vec<String>,
}

/// One round trip restores a seat, acknowledges durable delivery, uploads a
/// bounded batch, and returns peer messages. Epoch changes invalidate cursors.
pub(super) async fn exchange_session(
    State(state): State<AppState>, AxumPath(game_id): AxumPath<String>,
    request: Result<Json<ExchangeRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(request) = request.map_err(|e| json_rejection(&e))?;
    Ok(Json(exchange_room(state, game_id, request).await?))
}

pub(super) async fn exchange_room(state:AppState,game_id:String,request:ExchangeRequest)->Result<ExchangeResponse,ApiError> {
    exchange_binary(state,game_id,request,None,None).await
}
pub(super) async fn exchange_binary(state:AppState,game_id:String,request:ExchangeRequest,raw:Option<Vec<Vec<u8>>>,delivered:Option<(String,u64)>)->Result<ExchangeResponse,ApiError> {
    if raw.as_ref().is_some_and(|r|r.len()!=request.messages.len()) {return Err(ApiError::bad_request("attachment count mismatch"));}
    let mut raw=raw.map(Vec::into_iter);
    let game = decode_identifier(&game_id, "invalid room")?;
    let token = capability_digest(PLAYER_TOKEN_TAG, decode_capability(&request.player_token)?);
    let invite = capability_digest(INVITE_SECRET_TAG, decode_capability(&request.invite_secret)?);
    if !matches!(request.sender.as_str(), "alice" | "bob") || request.after > i64::MAX as u64 || request.messages.len()>32 {
        return Err(ApiError::bad_request("invalid exchange request"));
    }
    let mut messages=Vec::new();
    let mut total=0usize;
    for message in request.messages {
        let id=decode_identifier(&message.message_id,"invalid message id")?;
        validate_kind(&message.kind)?;
        let payload=if let Some(raw)=raw.as_mut() {raw.next().ok_or_else(||ApiError::bad_request("missing payload"))?}
            else {decode_payload(&message.payload,state.limits.message_bytes)?};
        if payload.is_empty() || payload.len()>state.limits.message_bytes {return Err(ApiError::too_large("invalid payload size"));}
        total=total.checked_add(payload.len()).ok_or_else(ApiError::internal)?;
        if total>super::MAX_MESSAGE_BYTES {return Err(ApiError::too_large("exchange payload limit reached"));}
        messages.push((id,message.kind,payload));
    }
    let limits=state.limits;
    let (response,changed)=state.database.run(move |c| {
        let mut changed=super::auth::authorize(c,game,token).is_err();
        if changed {
            if request.sender=="alice" {create_game_db(c,game,token,invite)?;}
            else {join_game_db(c,game,token,invite)?;}
        }
        let auth=super::auth::authorize(c,game,token)?;
        if (auth.sender==0)!=(request.sender=="alice") {return Err(ApiError::unauthorized());}
        let epoch=super::store::room_epoch(c,game)?;
        let after=if request.epoch.as_ref()==Some(&epoch) {request.after} else {0};
        if after>0 {super::store::ack_messages_db(c,game,token,after)?;}
        let mut accepted=Vec::new();
        // A first subscription has no prior cursor to acknowledge and can
        // upload immediately. A known stale epoch must still replay from zero.
        if auth.joined && (request.epoch.is_none() || request.epoch.as_ref()==Some(&epoch)) {
            for (id,kind,payload) in messages {
                let result=post_message_db(c,game,token,id,&kind,&payload,limits)?;
                changed |= result.created;
                accepted.push(result.value.message_id);
            }
        }
        // A live socket has already delivered these bytes in earlier frames.
        // Skip retransmission in its response, but retain them until a durable ACK.
        let read_after=delivered.filter(|(sent_epoch,_)|sent_epoch==&epoch)
            .map_or(after,|(_,cursor)|after.max(cursor));
        let page=super::store::read_messages_db(c,game,token,read_after,MAX_PAGE_MESSAGES,true)?;
        Ok((ExchangeResponse{page,accepted},changed))
    }).await?;
    if changed {let _=state.changes.send(game);}
    Ok(response)
}

// Delivery never acknowledges bytes. Only the browser's durable cursor can do so.
pub(super) async fn push_room(state:AppState,game_id:String,request:ExchangeRequest)->Result<super::PollResponse,ApiError> {
    let game=decode_identifier(&game_id,"invalid room")?;
    let token=capability_digest(PLAYER_TOKEN_TAG,decode_capability(&request.player_token)?);
    state.database.run(move |c| {
        let auth=super::auth::authorize(c,game,token)?;
        if (auth.sender==0)!=(request.sender=="alice") {return Err(ApiError::unauthorized());}
        let epoch=super::store::room_epoch(c,game)?;
        let after=if request.epoch.as_ref()==Some(&epoch) {request.after}else{0};
        super::store::read_messages_db(c,game,token,after,MAX_PAGE_MESSAGES,true)
    }).await
}
