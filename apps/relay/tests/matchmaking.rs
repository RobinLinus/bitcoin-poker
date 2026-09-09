//! Public allocation tests use opaque synthetic capabilities, never wallet funds.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use poker_relay::{DeploymentConfig, RelayServer};
use serde_json::{Value, json};
use tower::ServiceExt;
fn router() -> Router {
    let config: DeploymentConfig =
        serde_json::from_str(include_str!("../../../deployments/mutinynet/client.json")).unwrap();
    RelayServer::open_with_deployment(&config).unwrap().router()
}
fn req(n: u8) -> Value {
    let hex = |v: u8| format!("{v:02x}").repeat(32);
    json!({"ticket":hex(n),"walletId":hex(n+20),"gameId":hex(n+40),"playerToken":hex(n+60),"inviteSecret":hex(n+80),"action":"enter"})
}
async fn call(app: Router, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::post("/api/v1/matchmaking")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    (
        response.status(),
        serde_json::from_slice(&to_bytes(response.into_body(), 100000).await.unwrap()).unwrap(),
    )
}
#[tokio::test]
async fn concurrent_clicks_claim_unique_pairs() {
    let app = router();
    let mut tasks = vec![];
    for n in 1..=9 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move { call(app, req(n)).await }));
    }
    let mut rooms = std::collections::HashMap::<String, Vec<String>>::new();
    for t in tasks {
        let (status, r) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{r}");
        rooms
            .entry(r["gameId"].as_str().unwrap().into())
            .or_default()
            .push(r["sender"].as_str().unwrap().into());
    }
    assert_eq!(rooms.len(), 5);
    assert_eq!(rooms.values().filter(|v| v.len() == 1).count(), 1);
    for seats in rooms.values().filter(|v| v.len() == 2) {
        assert!(seats.contains(&"alice".into()));
        assert!(seats.contains(&"bob".into()));
    }
}
#[tokio::test]
async fn waiting_host_is_notified_and_retry_retains_assignment() {
    let app = router();
    let (_, host) = call(app.clone(), req(1)).await;
    assert_eq!(host["status"], "waiting");
    let mut poll = req(1);
    poll["action"] = "poll".into();
    let task = tokio::spawn(call(app.clone(), poll));
    let (_, guest) = call(app.clone(), req(2)).await;
    assert_eq!(host["gameId"], guest["gameId"]);
    let (_, matched) = tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(matched["status"], "matched");
    let (_, again) = call(app.clone(), req(2)).await;
    assert_eq!(again["status"], "matched");
    assert_eq!(again["gameId"], host["gameId"]);
    let mut unauthorized = req(2);
    unauthorized["playerToken"] = req(3)["playerToken"].clone();
    assert_eq!(call(app, unauthorized).await.0, StatusCode::CONFLICT);
}
#[tokio::test]
async fn cancellation_wins_before_pair_acknowledgement() {
    let app = router();
    call(app.clone(), req(1)).await;
    call(app.clone(), req(2)).await;
    let mut cancel = req(1);
    cancel["action"] = "cancel".into();
    assert_eq!(call(app.clone(), cancel).await.1["status"], "cancelled");
    assert_eq!(call(app.clone(), req(2)).await.1["status"], "expired");
    assert_eq!(call(app, req(3)).await.1["status"], "waiting");
}

#[tokio::test]
async fn separate_windows_using_the_same_wallet_cannot_match_each_other() {
    let app = router();
    let (_, first) = call(app.clone(), req(1)).await;
    let mut second = req(2);
    second["walletId"] = req(1)["walletId"].clone();
    let (status, error) = call(app.clone(), second).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "already_waiting");
    let (_, other) = call(app.clone(), req(3)).await;
    assert_eq!(first["gameId"], other["gameId"]);
    assert_eq!(other["status"], "reserved");
}
