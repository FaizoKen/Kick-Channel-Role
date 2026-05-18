use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::services::kick;
use crate::AppState;

pub async fn favicon() -> impl IntoResponse {
    // 30-day immutable cache. The favicon bytes are baked into the binary
    // via `include_bytes!`, so they only ever change on a redeploy — at
    // which point we accept browsers serving the old icon for up to 30
    // days.
    (
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=2592000, immutable"),
        ],
        include_bytes!("../../favicon.ico").as_slice(),
    )
}

/// Probes an external dependency with a short timeout. Mirrors the
/// Form/YouTube health schema: any HTTP response (even 401/404, since we
/// hit the API base unauthenticated) counts as "up" — we're checking
/// reachability, not authorization.
async fn check_service(http: &reqwest::Client, name: &str, url: &str) -> Value {
    let start = std::time::Instant::now();
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(3), http.get(url).send()).await;
    let latency = start.elapsed().as_millis() as u64;

    let is_up = matches!(result, Ok(Ok(_)));

    json!({
        "name": name,
        "status": if is_up { "up" } else { "down" },
        "latency_ms": latency
    })
}

/// Liveness — process is up. Returns 503 if the DB is unreachable so a
/// container orchestrator restarts a stuck pod instead of letting it serve
/// failing requests. The Kick API check is informational only: Kick being
/// down is not a reason to restart *our* pod, so it never flips the HTTP
/// status — it only downgrades the body `status` to "degraded".
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_fut = async {
        let start = std::time::Instant::now();
        let ok = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&state.pool)
            .await
            .is_ok();
        (ok, start.elapsed().as_millis() as u64)
    };
    let kick_fut = check_service(&state.http, "Kick API", kick::API_BASE);

    let ((db_ok, db_latency), kick_check) = tokio::join!(db_fut, kick_fut);

    // HTTP status stays tied to the DB only — that's the liveness contract.
    let http_status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    // Body status reflects combined health (same vocabulary as the
    // YouTube/Form plugins): healthy / degraded / unhealthy.
    let kick_down = kick_check["status"] == "down";
    let body_status = match (db_ok, kick_down) {
        (true, false) => "healthy",
        (false, _) => "unhealthy",
        (true, true) => "degraded",
    };

    let body = Json(json!({
        "status": body_status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": {
                "status": if db_ok { "up" } else { "down" },
                "latency_ms": db_latency
            }
        },
        "services": [kick_check]
    }));
    (http_status, body)
}

/// Readiness — should this replica receive traffic right now? Flips to 503
/// the moment shutdown begins so the load balancer can drain us before the
/// HTTP server actually stops accepting connections.
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.draining.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "draining" })),
        )
    } else {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    }
}
