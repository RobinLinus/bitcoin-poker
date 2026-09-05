//! Opaque, capability-authenticated message relay for BP52 clients.
//!
//! The relay assigns durable per-game cursors and stores uninterpreted message
//! bytes. It deliberately does not decode BP52 dealing, chain, transaction, or
//! secret-key data. Clients remain responsible for authenticating protocol
//! messages, end-to-end encryption, validation, and durable local recovery.
//! The prototype permits complete large setup bundles in one message. A later
//! profile should replace those large bodies with content-addressed chunks so
//! interrupted transfers can resume without retrying an entire bundle.
//!
//! The JSON field called `gameId` is only a client-random relay-room locator.
//! It is not, and must never be substituted for, the descriptor-bound
//! BP52-DEAL or BP52-CHAIN `game_id` computed later by protocol code.
//!
//! Hard live-storage quotas and a 24-hour inactivity expiry bound disk use,
//! but this process is not an Internet edge. A public deployment must still
//! impose IP-aware request and connection rate limits at its HTTPS proxy.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderName, HeaderValue,
    REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bp52_chain_compiler::HEADS_UP_FIXED_LIMIT_V1_PROFILE;
use bp52_client_ports::{
    BrowserDeploymentConfig, DeploymentConfig, FeeScheduleConfig, GameDeploymentConfig,
    ProtocolProfileName, RevealOrderConfig, TimeoutPolicyName,
};
use bp52_origin::{
    ACTIVATION_FEE_SAT, CONTRIBUTION_SAT, FUNDING_FEE_SAT, GAMEPLAY_ROOT_VALUE_SAT,
    ORIGIN_VALUE_SAT, P2WSH_MIN_NON_DUST_SAT, REFUND_DELAY_BLOCKS, REFUND_FEE_SAT,
    REFUND_VALUE_PER_PARTICIPANT_SAT,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const IDENTIFIER_BYTES: usize = 32;
const CAPABILITY_BYTES: usize = 32;
const MAX_KIND_BYTES: usize = 32;
const MAX_PAGE_MESSAGES: usize = 64;
const DEFAULT_PAGE_MESSAGES: usize = 32;
const MAX_PAGE_PAYLOAD_BYTES: usize = 24 * 1024 * 1024;
const MAX_JSON_BODY_BYTES: usize = 24 * 1024 * 1024;
const PLAYER_TOKEN_TAG: &[u8] = b"BP52/relay/player-token/v1";
const INVITE_SECRET_TAG: &[u8] = b"BP52/relay/invite-secret/v1";
const GAME_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_RELAY_GAMES: u64 = 10_000;
const MAX_RELAY_MESSAGES: u64 = 100_000;
const MAX_RELAY_BYTES: u64 = 1024 * 1024 * 1024;

/// Maximum decoded payload accepted in one opaque relay message.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum decoded payload bytes retained for one game.
pub const MAX_GAME_BYTES: usize = 256 * 1024 * 1024;
/// Maximum messages retained for one game.
pub const MAX_GAME_MESSAGES: u64 = 8_192;

/// Opened relay service backed by one durable SQLite database.
#[derive(Clone)]
pub struct RelayServer {
    database: Database,
    limits: Limits,
    deployment: Arc<BrowserDeploymentConfig>,
    security_headers: SecurityHeaders,
}

impl RelayServer {
    /// Open or create a relay database using an explicit, Rust-validated deployment.
    ///
    /// # Errors
    ///
    /// Returns a redacted initialization error if configuration or database setup fails.
    pub fn open_with_deployment(
        path: impl AsRef<Path>,
        deployment: &DeploymentConfig,
    ) -> Result<Self, RelayBuildError> {
        let deployment = resolve_deployment(deployment)?;
        let security_headers = SecurityHeaders::new(&deployment)?;
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|_| RelayBuildError::Database)?;
        configure_database(&mut connection)?;
        let now = now_ms().map_err(|_| RelayBuildError::Database)?;
        connection
            .execute(
                "DELETE FROM relay_games WHERE expires_at_ms <= ?1",
                params![checked_i64(now).map_err(|_| RelayBuildError::Database)?],
            )
            .map_err(|_| RelayBuildError::Database)?;
        Ok(Self {
            database: Database {
                connection: Arc::new(Mutex::new(connection)),
            },
            limits: Limits::production(),
            deployment: Arc::new(deployment),
            security_headers,
        })
    }

    /// Build the same-origin HTTP API router.
    ///
    /// No CORS headers are installed. Deploy the router behind the same HTTPS
    /// origin as the browser application and forward `/api/v1/*` to it.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/", get(index_page))
            .route("/bootstrap.js", get(bootstrap_script))
            .route("/styles.css", get(style_sheet))
            .route("/wasm/manifest.json", get(wasm_manifest))
            .route("/wasm/wallet.wasm", get(wallet_wasm))
            .route("/wasm/origin.wasm", get(origin_wasm))
            .route("/wasm/deal.wasm", get(deal_wasm))
            .route("/wasm/dlog52.wasm", get(dlog52_wasm))
            .route("/wasm/game.wasm", get(game_wasm))
            .route("/wasm/chain.wasm", get(chain_wasm))
            .route("/wasm/transaction.wasm", get(transaction_wasm))
            .route("/origin-client.js", get(origin_client_script))
            .route("/browser/flow/game-client.js", get(game_client_script))
            .route(
                "/browser/flow/chain-game-client.js",
                get(chain_game_client_script),
            )
            .route(
                "/browser/flow/game-chain-safety.js",
                get(game_chain_safety_script),
            )
            .route("/browser/flow/orchestration.js", get(orchestration_script))
            .route(
                "/browser/flow/origin-coordination.js",
                get(origin_coordination_script),
            )
            .route("/browser/flow/setup-planner.js", get(setup_planner_script))
            .route("/browser/flow/table-stakes.js", get(table_stakes_script))
            .route("/browser/flow/table-view.js", get(table_view_script))
            .route("/browser/ui/bitcoin-amount.js", get(bitcoin_amount_script))
            .route(
                "/browser/worker/rpc-client.js",
                get(worker_rpc_client_script),
            )
            .route(
                "/browser/worker/serial-dispatch.js",
                get(worker_serial_dispatch_script),
            )
            .route("/browser/deal/deal-runtime.js", get(deal_runtime_script))
            .route("/browser/deal/deal-worker.js", get(deal_worker_script))
            .route(
                "/browser/deal/dlog52-runtime.js",
                get(dlog52_runtime_script),
            )
            .route("/browser/deal/dlog52-worker.js", get(dlog52_worker_script))
            .route("/dlog52", get(dlog52_page))
            .route("/dlog52-demo.js", get(dlog52_demo_script))
            .route("/dlog52-game.js", get(dlog52_game_script))
            .route(
                "/browser/deal/proof-schedule.js",
                get(deal_proof_schedule_script),
            )
            .route(
                "/browser/deal/deal-proof-worker.js",
                get(deal_proof_worker_script),
            )
            .route("/browser/game/game-runtime.js", get(game_runtime_script))
            .route("/browser/game/game-worker.js", get(game_worker_script))
            .route(
                "/browser/game/offchain-ratchet.js",
                get(offchain_ratchet_script),
            )
            .route("/browser/chain/chain-runtime.js", get(chain_runtime_script))
            .route("/browser/chain/chain-worker.js", get(chain_worker_script))
            .route("/browser/chain/chain-client.js", get(chain_client_script))
            .route(
                "/browser/chain/setup-schedule.js",
                get(chain_setup_schedule_script),
            )
            .route(
                "/browser/chain/preauthorization-verifier-pool.js",
                get(preauthorization_verifier_pool_script),
            )
            .route(
                "/browser/chain/preauthorization-verifier-worker.js",
                get(preauthorization_verifier_worker_script),
            )
            .route(
                "/browser/config/runtime-config.js",
                get(runtime_config_script),
            )
            .route("/browser/config/wasm-loader.js", get(wasm_loader_script))
            .route("/browser/session/resume-store.js", get(resume_store_script))
            .route(
                "/browser/chain-adapter/index.js",
                get(chain_adapter_index_script),
            )
            .route("/browser/chain-adapter/esplora.js", get(esplora_script))
            .route(
                "/browser/chain-adapter/transaction-runtime.js",
                get(transaction_runtime_script),
            )
            .route("/app.js", get(application_script))
            .route("/api/v1/config", get(get_deployment_config))
            .route("/api/v1/games", post(create_game))
            .route("/api/v1/games/{game_id}", get(get_game))
            .route("/api/v1/games/{game_id}/join", post(join_game))
            .route(
                "/api/v1/games/{game_id}/messages",
                post(post_message).get(get_messages),
            )
            .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
            .layer(middleware::from_fn_with_state(
                self.security_headers.clone(),
                add_security_headers,
            ))
            .with_state(AppState {
                database: self.database.clone(),
                limits: self.limits,
                deployment: Arc::clone(&self.deployment),
            })
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

impl std::fmt::Debug for RelayServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayServer")
            .finish_non_exhaustive()
    }
}

/// Redacted relay initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RelayBuildError {
    /// SQLite could not be opened, configured, or initialized.
    #[error("relay database initialization failed")]
    Database,
    /// Deployment JSON or one of its public invariants was invalid.
    #[error("relay deployment configuration failed")]
    Configuration,
}

#[derive(Clone)]
struct Database {
    connection: Arc<Mutex<Connection>>,
}

impl Database {
    async fn run<T, F>(&self, operation: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, ApiError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut guard = connection.lock().map_err(|_| ApiError::internal())?;
            operation(&mut guard)
        })
        .await
        .map_err(|_| ApiError::internal())?
    }
}

#[derive(Clone, Copy)]
struct Limits {
    message_bytes: usize,
    game_bytes: u64,
    game_messages: u64,
}

impl Limits {
    const fn production() -> Self {
        Self {
            message_bytes: MAX_MESSAGE_BYTES,
            game_bytes: MAX_GAME_BYTES as u64,
            game_messages: MAX_GAME_MESSAGES,
        }
    }
}

#[derive(Clone)]
struct AppState {
    database: Database,
    limits: Limits,
    deployment: Arc<BrowserDeploymentConfig>,
}

#[derive(Clone)]
struct SecurityHeaders {
    content_security_policy: HeaderValue,
}

impl SecurityHeaders {
    fn new(deployment: &BrowserDeploymentConfig) -> Result<Self, RelayBuildError> {
        let esplora_origin = deployment
            .chain
            .esplora_origin()
            .map_err(|_| RelayBuildError::Configuration)?;
        let value = format!(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' {esplora_origin}; worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        );
        let content_security_policy =
            HeaderValue::try_from(value).map_err(|_| RelayBuildError::Configuration)?;
        Ok(Self {
            content_security_policy,
        })
    }
}

fn resolve_deployment(
    deployment: &DeploymentConfig,
) -> Result<BrowserDeploymentConfig, RelayBuildError> {
    if deployment.protocol_profile != ProtocolProfileName::HeadsUpFixedLimitV1 {
        return Err(RelayBuildError::Configuration);
    }
    let audited_game = audited_game_config(&deployment.game);
    deployment
        .resolve_for_profile(deployment.protocol_profile, &audited_game)
        .map_err(|_| RelayBuildError::Configuration)
}

fn audited_game_config(operator: &GameDeploymentConfig) -> GameDeploymentConfig {
    let profile = HEADS_UP_FIXED_LIMIT_V1_PROFILE;
    GameDeploymentConfig {
        staging_contribution_sat: CONTRIBUTION_SAT,
        origin_funding_fee_sat: FUNDING_FEE_SAT,
        origin_value_sat: ORIGIN_VALUE_SAT,
        activation_fee_sat: ACTIVATION_FEE_SAT,
        gameplay_root_value_sat: GAMEPLAY_ROOT_VALUE_SAT,
        origin_refund_fee_sat: REFUND_FEE_SAT,
        refund_output_sat: REFUND_VALUE_PER_PARTICIPANT_SAT,
        refund_csv_blocks: REFUND_DELAY_BLOCKS,
        unit_sat: profile.unit_sat,
        max_bets_per_street: profile.max_bets_per_street,
        starting_stack_sat: profile.stack_per_player_sat,
        fee_reserve_sat: profile.fee_reserve_sat,
        dust_threshold_sat: P2WSH_MIN_NON_DUST_SAT,
        fees: FeeScheduleConfig {
            betting_sat: profile.betting_vbytes * profile.relay_sat_per_vbyte,
            reveal_sat: profile.reveal_vbytes * profile.relay_sat_per_vbyte,
            alice_showdown_sat: profile.alice_showdown_vbytes * profile.relay_sat_per_vbyte,
            bob_payout_sat: profile.bob_payout_vbytes * profile.relay_sat_per_vbyte,
            timeout_sat: profile.timeout_vbytes * profile.relay_sat_per_vbyte,
        },
        button: operator.button,
        reveal_order: RevealOrderConfig {
            flop_first: operator.reveal_order.flop_first,
            turn_first: operator.reveal_order.turn_first,
            river_first: operator.reveal_order.river_first,
        },
        split_remainder_recipient: operator.split_remainder_recipient,
        timeout_policy: TimeoutPolicyName::PotOnly,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateGameRequest {
    game_id: String,
    player_token: String,
    invite_secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JoinGameRequest {
    player_token: String,
    invite_secret: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostMessageRequest {
    message_id: String,
    kind: String,
    payload: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PollQuery {
    #[serde(default)]
    after: u64,
    limit: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GameResponse {
    game_id: String,
    joined: bool,
    last_cursor: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PostMessageResponse {
    message_id: String,
    cursor: u64,
    duplicate: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PollResponse {
    messages: Vec<MessageResponse>,
    next_cursor: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageResponse {
    cursor: u64,
    message_id: String,
    sender: &'static str,
    kind: String,
    payload: String,
    created_at_ms: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{message}")]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message,
        }
    }

    const fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "a valid capability is required",
        }
    }

    const fn conflict(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message,
        }
    }

    const fn too_large(message: &'static str) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "limit_exceeded",
            message,
        }
    }

    const fn storage_full(message: &'static str) -> Self {
        Self {
            status: StatusCode::INSUFFICIENT_STORAGE,
            code: "relay_capacity_reached",
            message,
        }
    }

    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "relay operation failed",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

#[derive(Clone, Copy)]
struct Mutation<T> {
    value: T,
    created: bool,
}

async fn create_game(
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

async fn join_game(
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

async fn get_game(
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

async fn post_message(
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

async fn get_messages(
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

async fn add_security_headers(
    State(security_headers): State<SecurityHeaders>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        security_headers.content_security_policy,
    );
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-embedder-policy"),
        // Public Esplora deployments commonly omit CORP even when they allow
        // credential-free CORS. `credentialless` preserves cross-origin
        // isolation for the Wasm workers while stripping ambient credentials
        // from those configured backend requests.
        HeaderValue::from_static("credentialless"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    response
}

async fn get_deployment_config(State(state): State<AppState>) -> Json<BrowserDeploymentConfig> {
    Json((*state.deployment).clone())
}

async fn index_page() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        include_str!("../web/index.html"),
    )
}

async fn bootstrap_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../web/bootstrap.js"),
    )
}

async fn style_sheet() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        include_str!("../web/styles.css"),
    )
}

async fn wasm_manifest() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        )],
        include_str!("../web/wasm/manifest.json"),
    )
}

fn wasm_asset(bytes: &'static [u8]) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("application/wasm"))],
        bytes,
    )
}

async fn wallet_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/wallet.wasm"))
}

async fn origin_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/origin.wasm"))
}

async fn deal_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/deal.wasm"))
}

async fn dlog52_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/dlog52.wasm"))
}

async fn game_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/game.wasm"))
}

async fn chain_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/chain.wasm"))
}

async fn transaction_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../web/wasm/transaction.wasm"))
}

async fn application_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../web/app.js"),
    )
}

async fn origin_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../web/origin-client.js"),
    )
}

async fn game_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/game-client.js"),
    )
}

async fn chain_game_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/chain-game-client.js"),
    )
}

async fn game_chain_safety_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/game-chain-safety.js"),
    )
}

async fn orchestration_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/orchestration.js"),
    )
}

async fn origin_coordination_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/origin-coordination.js"),
    )
}

async fn setup_planner_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/setup-planner.js"),
    )
}

async fn table_stakes_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/table-stakes.js"),
    )
}

async fn table_view_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/flow/table-view.js"),
    )
}

async fn bitcoin_amount_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/ui/bitcoin-amount.js"),
    )
}

async fn worker_rpc_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/worker/rpc-client.js"),
    )
}

async fn worker_serial_dispatch_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/worker/serial-dispatch.js"),
    )
}

async fn deal_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/deal/deal-runtime.js"),
    )
}

async fn deal_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/deal/deal-worker.js"),
    )
}

async fn dlog52_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/deal/dlog52-runtime.js"),
    )
}

async fn dlog52_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/deal/dlog52-worker.js"),
    )
}

async fn dlog52_page() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        include_str!("../web/dlog52.html"),
    )
}

async fn dlog52_demo_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../web/dlog52-demo.js"),
    )
}

async fn dlog52_game_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../web/dlog52-game.js"),
    )
}

async fn deal_proof_schedule_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/deal/proof-schedule.js"),
    )
}

async fn deal_proof_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/deal/deal-proof-worker.js"),
    )
}

async fn game_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/game/game-runtime.js"),
    )
}

async fn game_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/game/game-worker.js"),
    )
}

async fn offchain_ratchet_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/game/offchain-ratchet.js"),
    )
}

async fn chain_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain/chain-runtime.js"),
    )
}

async fn chain_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain/chain-worker.js"),
    )
}

async fn chain_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain/chain-client.js"),
    )
}

async fn preauthorization_verifier_pool_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain/preauthorization-verifier-pool.js"),
    )
}

async fn chain_setup_schedule_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain/setup-schedule.js"),
    )
}

async fn preauthorization_verifier_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain/preauthorization-verifier-worker.js"),
    )
}

async fn runtime_config_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/config/runtime-config.js"),
    )
}

async fn wasm_loader_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/config/wasm-loader.js"),
    )
}

async fn resume_store_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/session/resume-store.js"),
    )
}

async fn chain_adapter_index_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain-adapter/index.js"),
    )
}

async fn esplora_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain-adapter/esplora.js"),
    )
}

async fn transaction_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../browser/chain-adapter/transaction-runtime.js"),
    )
}

fn json_rejection(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::too_large("JSON request body exceeds the fixed limit")
    } else {
        ApiError::bad_request("request body must match the canonical JSON shape")
    }
}

fn configure_database(connection: &mut Connection) -> Result<(), RelayBuildError> {
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .and_then(|()| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .map_err(|_| RelayBuildError::Database)?;
    let selected: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .map_err(|_| RelayBuildError::Database)?;
    if !selected.eq_ignore_ascii_case("wal") {
        return Err(RelayBuildError::Database);
    }
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| RelayBuildError::Database)?;
    if !(0..=1).contains(&schema_version) {
        return Err(RelayBuildError::Database);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| RelayBuildError::Database)?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS relay_games (
                game_id BLOB PRIMARY KEY NOT NULL CHECK(length(game_id) = 32),
                player_one_hash BLOB NOT NULL CHECK(length(player_one_hash) = 32),
                player_two_hash BLOB CHECK(player_two_hash IS NULL OR length(player_two_hash) = 32),
                invite_hash BLOB NOT NULL CHECK(length(invite_hash) = 32),
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
                payload BLOB NOT NULL CHECK(length(payload) <= 16777216),
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

fn create_game_db(
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
            "SELECT player_one_hash, invite_hash, player_two_hash IS NOT NULL, last_cursor
             FROM relay_games WHERE game_id = ?1",
            params![game_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?;
    let (joined, last_cursor, created) =
        if let Some((stored_player, stored_invite, joined, cursor)) = existing {
            if !constant_time_eq(&stored_player, &player_hash)
                || !constant_time_eq(&stored_invite, &invite_hash)
            {
                return Err(ApiError::conflict(
                    "game_exists",
                    "gameId is already bound to different capabilities",
                ));
            }
            transaction
                .execute(
                    "UPDATE relay_games SET expires_at_ms = ?2 WHERE game_id = ?1",
                    params![game_id.as_slice(), checked_i64(expiry_from(now)?)?],
                )
                .map_err(|_| ApiError::internal())?;
            (joined, checked_u64(cursor)?, false)
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

fn join_game_db(
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
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::unauthorized)?;
    let (player_one, player_two, stored_invite, last_cursor) = existing;
    if !constant_time_eq(&stored_invite, &invite_hash) {
        return Err(ApiError::unauthorized());
    }
    if constant_time_eq(&player_one, &player_hash) {
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
        joined: true,
        last_cursor: checked_u64(last_cursor)?,
    })
}

fn get_game_db(
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
fn post_message_db(
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
            "SELECT cursor, sender, kind, payload
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
            && constant_time_eq(&stored_payload, payload)
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
                game_id, cursor, message_id, sender, kind, payload, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                game_id.as_slice(),
                checked_i64(cursor)?,
                message_id.as_slice(),
                i64::from(authorization.sender),
                kind,
                payload,
                checked_i64(now)?
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

fn get_messages_db(
    connection: &mut Connection,
    game_id: [u8; IDENTIFIER_BYTES],
    token_hash: [u8; 32],
    after: u64,
    limit: usize,
) -> Result<PollResponse, ApiError> {
    authorize(connection, game_id, token_hash)?;
    let mut statement = connection
        .prepare(
            "SELECT cursor, message_id, sender, kind, payload, created_at_ms
             FROM relay_messages
             WHERE game_id = ?1 AND cursor > ?2
             ORDER BY cursor ASC LIMIT ?3",
        )
        .map_err(|_| ApiError::internal())?;
    let mut rows = statement
        .query(params![
            game_id.as_slice(),
            checked_i64(after)?,
            i64::try_from(limit).map_err(|_| ApiError::internal())?
        ])
        .map_err(|_| ApiError::internal())?;
    let mut messages = Vec::with_capacity(limit);
    let mut page_bytes = 0_usize;
    while let Some(row) = rows.next().map_err(|_| ApiError::internal())? {
        let payload: Vec<u8> = row.get(4).map_err(|_| ApiError::internal())?;
        let Some(next_page_bytes) = page_bytes.checked_add(payload.len()) else {
            return Err(ApiError::internal());
        };
        if !messages.is_empty() && next_page_bytes > MAX_PAGE_PAYLOAD_BYTES {
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
            payload: STANDARD.encode(payload),
            created_at_ms: checked_u64(row.get(5).map_err(|_| ApiError::internal())?)?,
        });
    }
    let next_cursor = messages.last().map_or(after, |message| message.cursor);
    Ok(PollResponse {
        messages,
        next_cursor,
    })
}

#[derive(Clone, Copy)]
struct Authorization {
    sender: u8,
    joined: bool,
    last_cursor: u64,
    message_count: u64,
    message_bytes: u64,
}

fn authorize(
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

fn immediate_transaction(connection: &mut Connection) -> Result<Transaction<'_>, ApiError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ApiError::internal())
}

fn cleanup_expired(transaction: &Transaction<'_>, now: u64) -> Result<(), ApiError> {
    transaction
        .execute(
            "DELETE FROM relay_games WHERE expires_at_ms <= ?1",
            params![checked_i64(now)?],
        )
        .map(|_| ())
        .map_err(|_| ApiError::internal())
}

fn expiry_from(now: u64) -> Result<u64, ApiError> {
    now.checked_add(GAME_TTL_MS).ok_or_else(ApiError::internal)
}

fn bearer_token(headers: &HeaderMap) -> Result<[u8; CAPABILITY_BYTES], ApiError> {
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

fn decode_capability(value: &str) -> Result<[u8; CAPABILITY_BYTES], ApiError> {
    decode_hex(value)
        .ok_or_else(|| ApiError::bad_request("capabilities must be 64 lowercase hex characters"))
}

fn decode_identifier(value: &str, error: &'static str) -> Result<[u8; IDENTIFIER_BYTES], ApiError> {
    decode_hex(value).ok_or_else(|| ApiError::bad_request(error))
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.checked_mul(2)? {
        return None;
    }
    let bytes = value.as_bytes();
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        let high = decode_nibble(*bytes.get(index.checked_mul(2)?)?)?;
        let low = decode_nibble(*bytes.get(index.checked_mul(2)?.checked_add(1)?)?)?;
        *output = (high << 4) | low;
    }
    Some(decoded)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_hex<const N: usize>(bytes: [u8; N]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(N * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_payload(value: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    let maximum_encoded = maximum
        .div_ceil(3)
        .checked_mul(4)
        .ok_or_else(ApiError::internal)?;
    if value.len() > maximum_encoded {
        return Err(ApiError::too_large(
            "message payload exceeds the fixed limit",
        ));
    }
    let payload = STANDARD
        .decode(value)
        .map_err(|_| ApiError::bad_request("payload must be canonical padded base64"))?;
    if payload.len() > maximum {
        return Err(ApiError::too_large(
            "message payload exceeds the fixed limit",
        ));
    }
    if STANDARD.encode(&payload) != value {
        return Err(ApiError::bad_request(
            "payload must be canonical padded base64",
        ));
    }
    Ok(payload)
}

fn validate_kind(kind: &str) -> Result<(), ApiError> {
    let bytes = kind.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_KIND_BYTES {
        return Err(ApiError::bad_request(
            "kind length must be between 1 and 32",
        ));
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(ApiError::bad_request("kind has invalid characters"));
    }
    if !bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(ApiError::bad_request("kind has invalid characters"));
    }
    Ok(())
}

fn capability_digest(tag: &[u8], capability: [u8; CAPABILITY_BYTES]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(capability);
    hasher.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn fixed_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

fn now_ms() -> Result<u64, ApiError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| ApiError::internal())
}

fn checked_u64(value: i64) -> Result<u64, ApiError> {
    u64::try_from(value).map_err(|_| ApiError::internal())
}

fn checked_i64(value: u64) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::internal())
}

fn sender_name(value: i64) -> Result<&'static str, ApiError> {
    match value {
        0 => Ok("alice"),
        1 => Ok("bob"),
        _ => Err(ApiError::internal()),
    }
}

#[cfg(test)]
mod tests {
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
        let journal: String =
            connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        let synchronous: i64 =
            connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
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
}
