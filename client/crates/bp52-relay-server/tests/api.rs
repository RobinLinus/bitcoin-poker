//! End-to-end HTTP contract tests for the opaque relay.

use std::collections::{HashSet, VecDeque};
use std::fs::{OpenOptions, remove_file};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
};
use axum::http::{Method, Request, StatusCode};
use bp52_client_ports::DeploymentConfig;
use bp52_relay_server::RelayServer;
use serde_json::{Value, json};
use tower::ServiceExt as _;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn create() -> Result<Self, std::io::Error> {
        loop {
            let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bp52-relay-api-{}-{sequence}.sqlite",
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

fn open_test_relay(path: &PathBuf) -> Result<RelayServer, Box<dyn std::error::Error>> {
    let deployment: DeploymentConfig =
        serde_json::from_str(include_str!("../../../deployments/mutinynet/client.json"))?;
    Ok(RelayServer::open_with_deployment(path, &deployment)?)
}

struct ApiResponse {
    status: StatusCode,
    json: Value,
}

async fn json_request(
    app: &Router,
    method: Method,
    uri: &str,
    authorization: Option<&str>,
    body: Option<Value>,
) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = authorization {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = if let Some(value) = body {
        builder = builder.header(CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&value)?)
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(builder.body(body)?).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 40 * 1024 * 1024).await?;
    let json = serde_json::from_slice(&bytes)?;
    Ok(ApiResponse { status, json })
}

fn game_id() -> String {
    "01".repeat(32)
}

fn alice_token() -> String {
    "02".repeat(32)
}

fn bob_token() -> String {
    "03".repeat(32)
}

fn invite_secret() -> String {
    "04".repeat(32)
}

async fn create(app: &Router) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    json_request(
        app,
        Method::POST,
        "/api/v1/games",
        None,
        Some(json!({
            "gameId": game_id(),
            "playerToken": alice_token(),
            "inviteSecret": invite_secret()
        })),
    )
    .await
}

async fn join(app: &Router) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    json_request(
        app,
        Method::POST,
        &format!("/api/v1/games/{}/join", game_id()),
        None,
        Some(json!({
            "playerToken": bob_token(),
            "inviteSecret": invite_secret()
        })),
    )
    .await
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn complete_capability_and_message_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let app = open_test_relay(&temporary.path)?.router();

    let created = create(&app).await?;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json["joined"], false);
    assert_eq!(created.json["lastCursor"], 0);

    let retry = create(&app).await?;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.json, created.json);

    let status = json_request(
        &app,
        Method::GET,
        &format!("/api/v1/games/{}", game_id()),
        Some(&alice_token()),
        None,
    )
    .await?;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.json["joined"], false);

    let before_join = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/messages", game_id()),
        Some(&alice_token()),
        Some(json!({
            "messageId": "05".repeat(32),
            "kind": "opaque.v1",
            "payload": "AA=="
        })),
    )
    .await?;
    assert_eq!(before_join.status, StatusCode::CONFLICT);
    assert_eq!(before_join.json["error"]["code"], "game_not_joined");

    let joined = join(&app).await?;
    assert_eq!(joined.status, StatusCode::OK);
    assert_eq!(joined.json["joined"], true);
    assert_eq!(join(&app).await?.status, StatusCode::OK);

    let first_body = json!({
        "messageId": "05".repeat(32),
        "kind": "opaque.v1",
        "payload": "YWxpY2U="
    });
    let first = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/messages", game_id()),
        Some(&alice_token()),
        Some(first_body.clone()),
    )
    .await?;
    assert_eq!(first.status, StatusCode::CREATED);
    assert_eq!(first.json["cursor"], 1);
    assert_eq!(first.json["duplicate"], false);

    let duplicate = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/messages", game_id()),
        Some(&alice_token()),
        Some(first_body),
    )
    .await?;
    assert_eq!(duplicate.status, StatusCode::OK);
    assert_eq!(duplicate.json["cursor"], 1);
    assert_eq!(duplicate.json["duplicate"], true);

    let collision = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/messages", game_id()),
        Some(&bob_token()),
        Some(json!({
            "messageId": "05".repeat(32),
            "kind": "opaque.v1",
            "payload": "Ym9i"
        })),
    )
    .await?;
    assert_eq!(collision.status, StatusCode::CONFLICT);
    assert_eq!(collision.json["error"]["code"], "message_id_conflict");

    let second = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/messages", game_id()),
        Some(&bob_token()),
        Some(json!({
            "messageId": "06".repeat(32),
            "kind": "anything.opaque",
            "payload": "Ym9i"
        })),
    )
    .await?;
    assert_eq!(second.status, StatusCode::CREATED);
    assert_eq!(second.json["cursor"], 2);

    let page = json_request(
        &app,
        Method::GET,
        &format!("/api/v1/games/{}/messages?after=0", game_id()),
        Some(&alice_token()),
        None,
    )
    .await?;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.json["nextCursor"], 2);
    assert_eq!(page.json["messages"][0]["sender"], "alice");
    assert_eq!(page.json["messages"][0]["payload"], "YWxpY2U=");
    assert_eq!(page.json["messages"][1]["sender"], "bob");
    assert_eq!(page.json["messages"][1]["kind"], "anything.opaque");

    let remaining = json_request(
        &app,
        Method::GET,
        &format!("/api/v1/games/{}/messages?after=1", game_id()),
        Some(&bob_token()),
        None,
    )
    .await?;
    assert_eq!(remaining.json["nextCursor"], 2);
    assert_eq!(remaining.json["messages"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn capabilities_are_isolated_and_join_is_immutable() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TemporaryDatabase::create()?;
    let app = open_test_relay(&temporary.path)?.router();
    create(&app).await?;

    let unauthorized = json_request(
        &app,
        Method::GET,
        &format!("/api/v1/games/{}", game_id()),
        Some(&"ff".repeat(32)),
        None,
    )
    .await?;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);

    let wrong_invite = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/join", game_id()),
        None,
        Some(json!({
            "playerToken": bob_token(),
            "inviteSecret": "ff".repeat(32)
        })),
    )
    .await?;
    assert_eq!(wrong_invite.status, StatusCode::UNAUTHORIZED);

    assert_eq!(join(&app).await?.status, StatusCode::OK);
    let replacement = json_request(
        &app,
        Method::POST,
        &format!("/api/v1/games/{}/join", game_id()),
        None,
        Some(json!({
            "playerToken": "ee".repeat(32),
            "inviteSecret": invite_secret()
        })),
    )
    .await?;
    assert_eq!(replacement.status, StatusCode::CONFLICT);
    assert_eq!(replacement.json["error"]["code"], "game_already_joined");
    Ok(())
}

#[tokio::test]
async fn malformed_inputs_and_unknown_fields_are_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = TemporaryDatabase::create()?;
    let app = open_test_relay(&temporary.path)?.router();
    let uppercase = json_request(
        &app,
        Method::POST,
        "/api/v1/games",
        None,
        Some(json!({
            "gameId": "AB".repeat(32),
            "playerToken": alice_token(),
            "inviteSecret": invite_secret()
        })),
    )
    .await?;
    assert_eq!(uppercase.status, StatusCode::BAD_REQUEST);

    let unknown = json_request(
        &app,
        Method::POST,
        "/api/v1/games",
        None,
        Some(json!({
            "gameId": game_id(),
            "playerToken": alice_token(),
            "inviteSecret": invite_secret(),
            "admin": true
        })),
    )
    .await?;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.json["error"]["code"], "invalid_request");
    Ok(())
}

#[tokio::test]
async fn data_survives_reopening_the_server() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    {
        let app = open_test_relay(&temporary.path)?.router();
        create(&app).await?;
        join(&app).await?;
    }
    let reopened = open_test_relay(&temporary.path)?.router();
    let status = json_request(
        &reopened,
        Method::GET,
        &format!("/api/v1/games/{}", game_id()),
        Some(&alice_token()),
        None,
    )
    .await?;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.json["joined"], true);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn static_assets_are_same_origin_and_hardened() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let app = open_test_relay(&temporary.path)?.router();
    for (path, content_type) in [
        ("/", "text/html; charset=utf-8"),
        ("/styles.css", "text/css; charset=utf-8"),
        ("/wasm/manifest.json", "application/json; charset=utf-8"),
        ("/wasm/wallet.wasm", "application/wasm"),
        ("/wasm/origin.wasm", "application/wasm"),
        ("/wasm/deal.wasm", "application/wasm"),
        ("/wasm/game.wasm", "application/wasm"),
        ("/wasm/chain.wasm", "application/wasm"),
        ("/wasm/transaction.wasm", "application/wasm"),
        ("/origin-client.js", "text/javascript; charset=utf-8"),
        (
            "/browser/flow/game-client.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/flow/chain-game-client.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/flow/game-chain-safety.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/deal/deal-worker.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/worker/serial-dispatch.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/game/game-worker.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/chain/chain-runtime.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/chain/chain-worker.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/chain/chain-client.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/config/runtime-config.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/config/wasm-loader.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/session/resume-store.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/chain-adapter/index.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/chain-adapter/esplora.js",
            "text/javascript; charset=utf-8",
        ),
        (
            "/browser/chain-adapter/transaction-runtime.js",
            "text/javascript; charset=utf-8",
        ),
        ("/app.js", "text/javascript; charset=utf-8"),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(content_type)
        );
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        let policy = response
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok());
        assert!(policy.is_some_and(|value| value.contains("connect-src 'self'")));
        assert_eq!(
            response
                .headers()
                .get("cross-origin-embedder-policy")
                .and_then(|value| value.to_str().ok()),
            Some("credentialless")
        );
    }

    let config = json_request(&app, Method::GET, "/api/v1/config", None, None).await?;
    assert_eq!(config.status, StatusCode::OK);
    assert_eq!(config.json["schemaVersion"], 2);
    assert_eq!(config.json["protocolProfile"], "headsUpFixedLimitV1");
    assert_eq!(config.json["protocolProfileCode"], 1);
    assert_eq!(config.json["chain"]["bitcoinNetworkCode"], 2);
    assert_eq!(config.json["chain"]["walletNetworkCode"], 1);
    assert_eq!(config.json["game"]["stagingContributionSat"], 27_000);
    assert_eq!(config.json["game"]["unitSat"], 100);
    assert_eq!(config.json["game"]["maxBetsPerStreet"], 4);
    assert_eq!(
        config.json["chain"]["profileIdHex"],
        "e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680"
    );
    assert_eq!(
        config.json["deploymentDigestHex"].as_str().map(str::len),
        Some(64)
    );
    Ok(())
}

fn static_module_specifiers(source: &str) -> Vec<String> {
    let mut specifiers = Vec::new();
    let mut declaration = String::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if declaration.is_empty()
            && !trimmed.starts_with("import ")
            && !trimmed.starts_with("export {")
            && !trimmed.starts_with("export *")
        {
            continue;
        }

        if !declaration.is_empty() {
            declaration.push(' ');
        }
        declaration.push_str(trimmed);
        if !trimmed.contains(';') {
            continue;
        }

        let normalized = declaration.split_whitespace().collect::<Vec<_>>().join(" ");
        let import_body = normalized.strip_prefix("import ");
        let module_source = import_body
            .filter(|body| body.starts_with(['\'', '"']))
            .or_else(|| normalized.rsplit_once(" from ").map(|(_, source)| source));
        if let Some(module_source) = module_source {
            let mut characters = module_source.chars();
            if let Some(quote @ ('\'' | '"')) = characters.next() {
                if let Some(end) = characters.as_str().find(quote) {
                    specifiers.push(characters.as_str()[..end].to_owned());
                }
            }
        }
        declaration.clear();
    }

    assert!(
        declaration.is_empty(),
        "unterminated static module declaration"
    );
    specifiers
}

fn resolve_same_origin_module(referrer: &str, specifier: &str) -> Option<String> {
    if specifier.starts_with("//") || specifier.contains(':') {
        return None;
    }
    assert!(
        specifier.starts_with('/') || specifier.starts_with("./") || specifier.starts_with("../"),
        "bare module specifier {specifier:?} imported by {referrer}"
    );

    let specifier = specifier.split('#').next().unwrap_or(specifier);
    let (specifier_path, query) = specifier
        .split_once('?')
        .map_or((specifier, None), |(path, query)| (path, Some(query)));
    let referrer_path = referrer.split(['?', '#']).next().unwrap_or(referrer);
    let unresolved = if specifier_path.starts_with('/') {
        specifier_path.to_owned()
    } else {
        let directory = referrer_path
            .rsplit_once('/')
            .map_or("/", |(directory, _)| directory);
        format!("{directory}/{specifier_path}")
    };

    let mut segments = Vec::new();
    for segment in unresolved.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            value => segments.push(value),
        }
    }
    let mut resolved = format!("/{}", segments.join("/"));
    if let Some(query) = query {
        resolved.push('?');
        resolved.push_str(query);
    }
    Some(resolved)
}

#[test]
fn module_discovery_handles_supported_static_import_forms() {
    let source = r#"
        import { first } from "./first.js";
        import {
          second,
        } from "../second.js";
        import "/side-effect.js";
        export { third } from './third.js';
        export { localOnly };
        const ignored = "import from './not-a-module.js'";
    "#;
    assert_eq!(
        static_module_specifiers(source),
        [
            "./first.js",
            "../second.js",
            "/side-effect.js",
            "./third.js"
        ]
    );
    assert_eq!(
        resolve_same_origin_module("/browser/flow/main.js", "../worker/rpc-client.js"),
        Some(String::from("/browser/worker/rpc-client.js"))
    );
}

#[tokio::test]
async fn every_static_app_module_is_served() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let app = open_test_relay(&temporary.path)?.router();
    let mut pending = VecDeque::from([(String::from("/app.js"), String::from("entry point"))]);
    let mut discovered = HashSet::from([String::from("/app.js")]);

    while let Some((path, imported_by)) = pending.pop_front() {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(&path).body(Body::empty())?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "module {path} imported by {imported_by} is not served"
        );
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/javascript; charset=utf-8"),
            "module {path} imported by {imported_by} has the wrong content type"
        );
        let source = String::from_utf8(
            to_bytes(response.into_body(), 8 * 1024 * 1024)
                .await?
                .to_vec(),
        )?;
        for specifier in static_module_specifiers(&source) {
            let Some(imported) = resolve_same_origin_module(&path, &specifier) else {
                continue;
            };
            if discovered.insert(imported.clone()) {
                pending.push_back((imported, path.clone()));
            }
        }
    }

    assert!(
        discovered.len() > 1,
        "the app module graph was unexpectedly empty"
    );
    Ok(())
}

#[test]
fn application_uses_the_configured_gameplay_confirmation_depth() {
    let script = include_str!("../web/app.js");
    assert!(script.contains("minConfirmations: CHAIN_CONFIG.confirmations.gameplay"));
    assert!(!script.contains("minConfirmations: 1"));
}

#[tokio::test]
async fn explicit_deployment_controls_config_and_csp() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = TemporaryDatabase::create()?;
    let mut deployment: DeploymentConfig =
        serde_json::from_str(include_str!("../../../deployments/mutinynet/client.json"))?;
    deployment.chain.esplora_url = "http://127.0.0.1:3999/esplora".to_owned();
    deployment.chain.explorer_url = "http://127.0.0.1:3999".to_owned();
    let app = RelayServer::open_with_deployment(&temporary.path, &deployment)?.router();
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty())?)
        .await?;
    let policy = response
        .headers()
        .get(CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok());
    assert!(policy.is_some_and(|value| {
        value.contains("connect-src 'self' http://127.0.0.1:3999;")
            && !value.contains("mutinynet.com")
    }));
    let config = json_request(&app, Method::GET, "/api/v1/config", None, None).await?;
    assert_eq!(
        config.json["chain"]["esploraUrl"],
        "http://127.0.0.1:3999/esplora"
    );
    Ok(())
}
