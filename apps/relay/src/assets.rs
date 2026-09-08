//! Assets.

use super::{CONTENT_TYPE, HeaderValue, IntoResponse};
use sha2::{Digest, Sha256};
include!(concat!(env!("OUT_DIR"), "/web-assets.rs"));

pub(super) fn asset_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let mut hash=Sha256::new();
        for (path,mime,bytes) in VERSIONED_ASSETS {
            hash.update(path.as_bytes());hash.update([0]);hash.update(mime.as_bytes());hash.update([0]);
            hash.update((bytes.len() as u64).to_le_bytes());hash.update(bytes);
        }
        super::encode_hex::<32>(hash.finalize().into())
    })
}
fn versioned_html(html: &str) -> String {
    let base=format!("/assets/{}",asset_version());
    html.replace("<html ",&format!("<html data-asset-base=\"{base}\" "))
        .replace("\"/src/",&format!("\"{base}/src/"))
        .replace("\"/wasm/",&format!("\"{base}/wasm/"))
}
pub(super) async fn versioned_asset(super::AxumPath((version,path)):super::AxumPath<(String,String)>) -> super::Response {
    if version!=asset_version() {return super::StatusCode::NOT_FOUND.into_response();}
    let Some((_,mime,bytes))=VERSIONED_ASSETS.iter().find(|(name,_,_)|*name==path) else {return super::StatusCode::NOT_FOUND.into_response();};
    ([(CONTENT_TYPE,HeaderValue::from_static(mime)),
      (super::CACHE_CONTROL,HeaderValue::from_static("public, max-age=31536000, immutable"))],*bytes).into_response()
}

pub(super) async fn index_page() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        versioned_html(include_str!("../../web/index.html")),
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

/// Dedicated local on-chain test page and its explicit source assets.
pub(super) async fn onchain_page() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/html; charset=utf-8")],
        versioned_html(include_str!("../../web/src/onchain/index.html")),
    )
}
pub(super) async fn onchain_asset(
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    let (mime, source) = match name.as_str() {
        "table-controller.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/table-controller.js"),
        ),
        "display-view.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/display-view.js"),
        ),
        "table-feedback.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/table-feedback.js"),
        ),
        "table-session.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/table-session.js"),
        ),
        "controller.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/controller.js"),
        ),
        "wasm-client.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/wasm-client.js"),
        ),
        "checkpoint-parts.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../../web/src/onchain/checkpoint-parts.js"),
        ),
        "channel-e2e.js" => ("text/javascript", include_str!("../../web/src/onchain/channel-e2e.js")),
        "channel-inbox.js" => ("text/javascript", include_str!("../../web/src/onchain/channel-inbox.js")),
        "relay-inbox.js" => ("text/javascript", include_str!("../../web/src/onchain/relay-inbox.js")),
        "defense-worker.js" => ("text/javascript", include_str!("../../web/src/onchain/defense-worker.js")),
        "browser-defense.js" => ("text/javascript", include_str!("../../web/src/onchain/browser-defense.js")),
        "channel-worker.js" => ("text/javascript", include_str!("../../web/src/onchain/channel-worker.js")),
        "dealer-progress.js" => ("text/javascript", include_str!("../../web/src/onchain/dealer-progress.js")),
        "relay-e2e.js" => ("text/javascript", include_str!("../../web/src/onchain/relay-e2e.js")),
        "diagnostics.js" => ("text/javascript", include_str!("../../web/src/onchain/diagnostics.js")),
        "binary-codec.js" => ("text/javascript", include_str!("../../web/src/onchain/binary-codec.js")),
        "preparation-wire.js" => ("text/javascript", include_str!("../../web/src/onchain/preparation-wire.js")),
        "relay-socket.js" => ("text/javascript", include_str!("../../web/src/onchain/relay-socket.js")),
        "relay-socket-worker.js" => ("text/javascript", include_str!("../../web/src/onchain/relay-socket-worker.js")),
        "hand-buffer.js" => ("text/javascript", include_str!("../../web/src/onchain/hand-buffer.js")),
        "channel-redeal.js" => ("text/javascript", include_str!("../../web/src/onchain/channel-redeal.js")),
        "construction-worker.js" => ("text/javascript", include_str!("../../web/src/onchain/construction-worker.js")),
        "player-worker.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/player-worker.js"),
        ),
        "crypto-worker.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/crypto-worker.js"),
        ),
        "local-wallet.js" => ("text/javascript", include_str!("../../web/src/onchain/local-wallet.js")),
        "funding-worker.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/funding-worker.js"),
        ),
        "style.css" => ("text/css", include_str!("../../web/src/onchain/style.css")),
        "report.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/report.js"),
        ),
        "crypto-pool.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/crypto-pool.js"),
        ),
        "chain-retry.js" => (
            "text/javascript",
            include_str!("../../web/src/onchain/chain-retry.js"),
        ),
        _ => return axum::http::StatusCode::NOT_FOUND.into_response(),
    };
    ([(CONTENT_TYPE, mime)], source).into_response()
}
pub(super) async fn session_wasm() -> impl IntoResponse {
    wasm_asset(include_bytes!("../../web/public/wasm/session.wasm"))
}
pub(super) async fn preparation_store_script() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript")],
        include_str!("../../web/src/storage/preparation-checkpoint-store.js"),
    )
}

pub(super) async fn channel_e2e_page() -> impl IntoResponse { ([(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],versioned_html(include_str!("../../web/src/onchain/channel-e2e.html"))) }
pub(super) async fn relay_e2e_page() -> impl IntoResponse { ([(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],versioned_html(include_str!("../../web/src/onchain/relay-e2e.html"))) }
