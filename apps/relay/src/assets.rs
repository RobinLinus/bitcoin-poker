//! Assets.

use super::{CONTENT_TYPE, HeaderValue, IntoResponse};

pub(super) async fn index_page() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        include_str!("../../web/index.html"),
    )
}

pub(super) async fn bootstrap_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/main.js"),
    )
}

pub(super) async fn style_sheet() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        include_str!("../../web/src/ui/styles.css"),
    )
}

pub(super) async fn wasm_manifest() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        )],
        include_str!("../../web/public/wasm/manifest.json"),
    )
}

pub(super) fn wasm_asset(bytes: &'static [u8]) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("application/wasm"))],
        bytes,
    )
}

pub(super) async fn wallet_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../../web/public/wasm/wallet.wasm"))
}

pub(super) async fn origin_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../../web/public/wasm/origin.wasm"))
}

pub(super) async fn dealer_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../../web/public/wasm/dealer.wasm"))
}

pub(super) async fn transaction_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../../web/public/wasm/transaction.wasm"))
}

pub(super) async fn origin_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/funding/client.js"),
    )
}

pub(super) async fn bitcoin_amount_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/ui/bitcoin-amount.js"),
    )
}

pub(super) async fn worker_rpc_client_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/workers/rpc-client.js"),
    )
}

pub(super) async fn worker_serial_dispatch_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/workers/serial-dispatch.js"),
    )
}

pub(super) async fn dealer_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/dealing/participant.js"),
    )
}

pub(super) async fn dealer_worker_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/dealing/worker.js"),
    )
}

pub(super) async fn dealer_page() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        include_str!("../../../tools/browser-deal-demo/index.html"),
    )
}

pub(super) async fn dealer_demo_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../../tools/browser-deal-demo/main.js"),
    )
}

pub(super) async fn dealer_game_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/practice/table-controller.js"),
    )
}

pub(super) async fn offchain_ratchet_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/practice/signed-move-log.js"),
    )
}

pub(super) async fn runtime_config_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/config/deployment.js"),
    )
}

pub(super) async fn wasm_loader_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/wasm/loader.js"),
    )
}

pub(super) async fn resume_store_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/storage/seat-session-store.js"),
    )
}

pub(super) async fn transaction_runtime_script() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/javascript; charset=utf-8"),
        )],
        include_str!("../../web/src/bitcoin/transaction-inspector.js"),
    )
}

pub(super) async fn funding_engine_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../web/src/funding/engine.js"),
    )
}

pub(super) async fn funding_worker_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../web/src/funding/worker.js"),
    )
}

pub(super) async fn bitcoin_esplora_worker_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../web/src/bitcoin/esplora-worker.js"),
    )
}

pub(super) async fn practice_room_session_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../web/src/practice/room-session.js"),
    )
}

pub(super) async fn practice_demo_identities_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../web/src/practice/demo-identities.js"),
    )
}

pub(super) async fn render_table_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../web/src/practice/render-table.js"),
    )
}
