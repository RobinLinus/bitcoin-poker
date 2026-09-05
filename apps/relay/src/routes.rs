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
