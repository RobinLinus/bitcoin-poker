//! Opaque, capability-authenticated message relay for BP52 clients.
//!
//! The relay assigns transient per-room cursors and stores uninterpreted message
//! bytes. It deliberately does not decode BP52 dealing, chain, transaction, or
//! secret-key data. Clients remain responsible for authenticating protocol
//! messages, end-to-end encryption, validation, and durable local recovery.
//! The prototype permits complete large setup bundles in one message. A later
//! profile should replace those large bodies with content-addressed chunks so
//! interrupted transfers can resume without retrying an entire bundle.
//!
//! The JSON field called `gameId` is only a client-random relay-room locator.
//! It is not, and must never be substituted for, the descriptor-bound
//! dlog deal or chain `game_id` computed later by protocol code.
//!
//! Hard live-storage quotas and a 24-hour inactivity expiry bound memory use,
//! but this process is not an Internet edge. A public deployment must still
//! impose IP-aware request and connection rate limits at its HTTPS proxy.

#![forbid(unsafe_code)]

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
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params,
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
// Channel preparation retains tens of MiB per room for the 24-hour replay window.
// Reserve shared capacity for 32 rooms at the per-game maximum.
const MAX_RELAY_BYTES: u64 = 32 * MAX_GAME_BYTES as u64;

/// Maximum decoded payload accepted in one opaque relay message.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum decoded payload bytes retained for one game.
pub const MAX_GAME_BYTES: usize = 256 * 1024 * 1024;
/// Maximum messages retained for one game.
pub const MAX_GAME_MESSAGES: u64 = 8_192;

/// Opened relay service backed by a transient in-memory delivery queue.
#[derive(Clone)]
pub struct RelayServer {
    changes: tokio::sync::broadcast::Sender<[u8;32]>,
    database: Database,
    limits: Limits,
    deployment: Arc<BrowserDeploymentConfig>,
    security_headers: SecurityHeaders,
}

impl RelayServer {
    /// Create an in-memory relay using an explicit, Rust-validated deployment.
    ///
    /// # Errors
    ///
    /// Returns a redacted initialization error if configuration or database setup fails.
    pub fn open_with_deployment(
        deployment: &DeploymentConfig,
    ) -> Result<Self, RelayBuildError> {
        let deployment = resolve_deployment(deployment)?;
        let security_headers = SecurityHeaders::new(&deployment)?;
        let mut connection = Connection::open_in_memory().map_err(|_| RelayBuildError::Database)?;
        configure_database(&mut connection)?;
        matchmaking::configure(&connection).map_err(|_| RelayBuildError::Database)?;
        let now = now_ms().map_err(|_| RelayBuildError::Database)?;
        connection
            .execute(
                "DELETE FROM relay_games WHERE expires_at_ms <= ?1",
                params![checked_i64(now).map_err(|_| RelayBuildError::Database)?],
            )
            .map_err(|_| RelayBuildError::Database)?;
        Ok(Self {
            changes: tokio::sync::broadcast::channel(256).0,
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
            .route("/assets/{version}/{*path}", get(assets::versioned_asset))
            .route("/tools/onchain-e2e", get(assets::onchain_page))
            .route("/tools/channel-e2e", get(assets::channel_e2e_page))
            .route("/tools/relay-e2e", get(assets::relay_e2e_page))
            .route("/src/onchain/{name}", get(assets::onchain_asset))
            .route("/wasm/session.wasm", get(assets::session_wasm))
            .route(
                "/src/storage/preparation-checkpoint-store.js",
                get(assets::preparation_store_script),
            )
            .route("/src/main.js", get(bootstrap_script))
            .route("/src/practice/render-table.js", get(render_table_script))
            .route("/src/funding/engine.js", get(funding_engine_script))
            .route("/src/funding/worker.js", get(funding_worker_script))
            .route(
                "/src/bitcoin/esplora-worker.js",
                get(bitcoin_esplora_worker_script),
            )
            .route(
                "/src/practice/room-session.js",
                get(practice_room_session_script),
            )
            .route(
                "/src/practice/demo-identities.js",
                get(practice_demo_identities_script),
            )
            .route("/src/ui/styles.css", get(style_sheet))
            .route("/wasm/manifest.json", get(wasm_manifest))
            .route("/wasm/wallet.wasm", get(wallet_wasm))
            .route("/wasm/origin.wasm", get(origin_wasm))
            .route("/wasm/dealer.wasm", get(dealer_wasm))
            .route("/wasm/transaction.wasm", get(transaction_wasm))
            .route("/src/funding/client.js", get(origin_client_script))
            .route("/src/ui/bitcoin-amount.js", get(bitcoin_amount_script))
            .route("/src/workers/rpc-client.js", get(worker_rpc_client_script))
            .route(
                "/src/workers/serial-dispatch.js",
                get(worker_serial_dispatch_script),
            )
            .route("/src/dealing/participant.js", get(dealer_runtime_script))
            .route("/src/dealing/worker.js", get(dealer_worker_script))
            .route("/tools/deal", get(dealer_page))
            .route("/tools/deal/main.js", get(dealer_demo_script))
            .route("/src/practice/table-controller.js", get(dealer_game_script))
            .route(
                "/src/practice/signed-move-log.js",
                get(offchain_ratchet_script),
            )
            .route("/src/config/deployment.js", get(runtime_config_script))
            .route("/src/wasm/loader.js", get(wasm_loader_script))
            .route(
                "/src/storage/seat-session-store.js",
                get(resume_store_script),
            )
            .route(
                "/src/bitcoin/chain-observer.js",
                get(chain_adapter_index_script),
            )
            .route("/src/bitcoin/esplora-client.js", get(esplora_script))
            .route(
                "/src/bitcoin/transaction-inspector.js",
                get(transaction_runtime_script),
            )
            .route("/api/v1/socket", get(socket::upgrade))
            .route("/api/v1/config", get(get_deployment_config))
            .route("/api/v1/matchmaking", post(matchmaking::handle))
            .route("/api/v1/games", post(create_game))
            .route("/api/v1/games/{game_id}/ack", post(routes::ack_messages))
            .route("/api/v1/games/{game_id}/poll", post(routes::poll_session))
            .route("/api/v1/games/{game_id}/exchange", post(routes::exchange_session))
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
                changes: self.changes.clone(),
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
    changes: tokio::sync::broadcast::Sender<[u8;32]>,
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

#[derive(Clone, Deserialize)]
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
    epoch: String,
    joined: bool,
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
    #[serde(serialize_with="serialize_payload")]
    payload: Vec<u8>,
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

async fn add_security_headers(
    State(security_headers): State<SecurityHeaders>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.entry(CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
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

async fn chain_adapter_index_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/bitcoin/chain-observer.js"),
    )
}

async fn esplora_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/bitcoin/esplora-client.js"),
    )
}

fn json_rejection(rejection: &JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::too_large("JSON request body exceeds the fixed limit")
    } else {
        ApiError::bad_request("request body must match the canonical JSON shape")
    }
}

#[derive(Clone, Copy)]
struct Authorization {
    sender: u8,
    joined: bool,
    last_cursor: u64,
    message_count: u64,
    message_bytes: u64,
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

mod assets;
use assets::{
    bitcoin_amount_script, bitcoin_esplora_worker_script, bootstrap_script, dealer_demo_script,
    dealer_game_script, dealer_page, dealer_runtime_script, dealer_wasm, dealer_worker_script,
    funding_engine_script, funding_worker_script, index_page, offchain_ratchet_script,
    origin_client_script, origin_wasm, practice_demo_identities_script,
    practice_room_session_script, render_table_script, resume_store_script, runtime_config_script,
    style_sheet, transaction_runtime_script, transaction_wasm, wallet_wasm, wasm_loader_script,
    wasm_manifest, worker_rpc_client_script, worker_serial_dispatch_script,
};

mod store;
use store::{
    configure_database, create_game_db, get_game_db, get_messages_db, join_game_db, post_message_db,
};

mod auth;
use auth::{authorize, bearer_token, capability_digest, constant_time_eq, decode_capability};

mod matchmaking;
mod routes;
use routes::{create_game, get_deployment_config, get_game, get_messages, join_game, post_message};

#[cfg(test)]
mod tests;

/// Practice application configuration.
pub mod config;
use config::resolve_deployment;
pub use config::{BrowserDeploymentConfig, DeploymentConfig};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest { cursor: u64 }

mod socket;
mod wire;

fn serialize_payload<S:serde::Serializer>(value:&[u8], serializer:S)->Result<S::Ok,S::Error> {
    serializer.serialize_str(&STANDARD.encode(value))
}
