use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

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

/// Liveness — process is up. Returns 503 if the DB is unreachable so a
/// container orchestrator restarts a stuck pod instead of letting it serve
/// failing requests.
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let start = std::time::Instant::now();
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .is_ok();
    let db_latency = start.elapsed().as_millis() as u64;

    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = Json(json!({
        "status": if db_ok { "healthy" } else { "unhealthy" },
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": {
                "status": if db_ok { "up" } else { "down" },
                "latency_ms": db_latency
            }
        }
    }));
    (status, body)
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
