//! Member-facing verification flow: link a Kick account to a Discord ID.
//!
//! Routes:
//!   GET  /verify                       — landing page (HTML)
//!   POST /verify/login                 — redirect to Auth Gateway Discord login
//!   POST /verify/kick                  — start Kick OAuth (PKCE)
//!   GET  /verify/status                — JSON status for the page's JS
//!
//! Convention 27/36: login redirects use a *relative* `return_to=`, and the
//! landing page renders an in-page sign-in prompt — never auto-redirects.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::AppError;
use crate::routes::oauth;
use crate::services::auth::read_session;
use crate::services::csrf;
use crate::services::kick;
use crate::AppState;

const VERIFY_PAGE: &str = include_str!("../../templates/verify.html");

// ---------------------------------------------------------------------
// GET /verify
// ---------------------------------------------------------------------

pub async fn verify_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let html = VERIFY_PAGE.replace("{{BASE_URL}}", &state.config.base_url);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

// ---------------------------------------------------------------------
// GET /verify/status — used by the page's JS to decide which CTA to show
// ---------------------------------------------------------------------

pub async fn verify_status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Value>, AppError> {
    let discord = read_session(&jar, &state.config.session_secret).ok();

    let kick_link: Option<(i64, String)> = match &discord {
        Some((did, _)) => {
            sqlx::query_as(
                "SELECT kick_user_id, kick_username FROM kick_users WHERE discord_id = $1",
            )
            .bind(did)
            .fetch_optional(&state.pool)
            .await?
        }
        None => None,
    };

    Ok(Json(json!({
        "signed_in_discord": discord.is_some(),
        "discord_username": discord.as_ref().map(|(_, n)| n.clone()),
        "linked_kick": kick_link.is_some(),
        "kick_user_id": kick_link.as_ref().map(|(id, _)| id),
        "kick_username": kick_link.as_ref().map(|(_, u)| u.clone()),
    })))
}

// ---------------------------------------------------------------------
// POST /verify/unlink — self-service: drop the caller's Kick link
// ---------------------------------------------------------------------

pub async fn verify_unlink(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    // State-changing, cookie-authed → same Origin gate as /verify/kick.
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    // Delete the link, returning the Kick user id so we can also drop the
    // now-orphaned per-channel relation rows. `channel_relations` is keyed by
    // `kick_user_id` with no FK to `kick_users`, so nothing cascades — we
    // must clean it explicitly or a re-link would inherit stale facts.
    let removed: Option<(i64,)> =
        sqlx::query_as("DELETE FROM kick_users WHERE discord_id = $1 RETURNING kick_user_id")
            .bind(&discord_id)
            .fetch_optional(&state.pool)
            .await?;

    let Some((kick_user_id,)) = removed else {
        return Err(AppError::NotFound(
            "No linked Kick account to unlink.".into(),
        ));
    };

    sqlx::query("DELETE FROM channel_relations WHERE kick_user_id = $1")
        .bind(kick_user_id)
        .execute(&state.pool)
        .await?;

    // Re-evaluate every role this member held: with the link gone they
    // qualify for nothing, so the worker strips the roles via RoleLogic and
    // clears `role_assignments`. Same enqueue the link flow uses — keeps role
    // state eventually consistent without blocking the response. (The user
    // disappears from the public users list immediately, since that now
    // lists by `kick_users`.)
    crate::services::jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    tracing::info!(discord_id = %discord_id, kick_user_id, "Viewer unlinked");

    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------
// POST /verify/refresh — member-triggered "re-check my data now"
// ---------------------------------------------------------------------

/// Per-channel floor between member-triggered reconciles. Kick has no
/// per-viewer pull — relation facts come from per-channel broadcaster-token
/// list endpoints — so a member refresh re-pulls the whole channel. This
/// cooldown (read from `broadcasters.last_synced_at`, shared by all viewers)
/// bounds the cost so a reload loop or a busy channel can't trigger
/// back-to-back full reconciles.
const REFRESH_COOLDOWN_SECS: f64 = 300.0;

/// When a linked viewer opens the verify page the page calls this so their
/// channel relationships get re-pulled from Kick ahead of the 6h reconcile,
/// and their roles are corrected — no unlink/re-link needed. For each channel
/// the viewer has a relation with whose last reconcile is older than the
/// cooldown (and that doesn't already have a refresh queued), we enqueue a
/// `channel_refresh`; that re-pulls facts and fans out a `channel_sync`. We
/// also enqueue a cheap `player_sync` so roles re-evaluate immediately against
/// whatever's already cached (e.g. relations webhooks already updated).
pub async fn verify_refresh(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    // State-changing, cookie-authed → same Origin gate as /verify/kick.
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    // Nothing to refresh without a linked Kick account.
    let kick_user_id: Option<i64> =
        sqlx::query_scalar("SELECT kick_user_id FROM kick_users WHERE discord_id = $1")
            .bind(&discord_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some(kick_user_id) = kick_user_id else {
        return Ok(Json(json!({ "refreshed": false })));
    };

    // Channels this viewer has a relation with, whose last full reconcile is
    // older than the cooldown and that don't already have a refresh queued.
    let channels: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT cr.kick_channel_id \
         FROM channel_relations cr \
         JOIN broadcasters b ON b.kick_channel_id = cr.kick_channel_id \
         WHERE cr.kick_user_id = $1 \
           AND (b.last_synced_at IS NULL OR b.last_synced_at < now() - make_interval(secs => $2)) \
           AND NOT EXISTS ( \
               SELECT 1 FROM jobs j \
               WHERE j.kind = 'channel_refresh' \
                 AND j.status IN ('pending', 'in_progress') \
                 AND (j.payload->>'kick_channel_id')::bigint = cr.kick_channel_id \
           )",
    )
    .bind(kick_user_id)
    .bind(REFRESH_COOLDOWN_SECS)
    .fetch_all(&state.pool)
    .await?;

    for cid in &channels {
        crate::services::jobs::enqueue_channel_refresh(&state.pool, *cid).await?;
    }

    // Cheap immediate re-evaluation of this viewer's roles against current
    // cached facts. The channel_refresh above runs its own channel_sync once
    // fresh facts land.
    crate::services::jobs::enqueue_player_sync(&state.pool, &discord_id).await?;

    Ok(Json(json!({ "refreshed": !channels.is_empty() })))
}

// ---------------------------------------------------------------------
// POST /verify/login — Convention 27: relative return_to
// ---------------------------------------------------------------------

pub async fn verify_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // We can't return to a full URL — the Auth Gateway only accepts paths.
    // The path is taken from the BASE_URL's pathname.
    let path = path_only(&state.config.base_url);
    let return_to = format!("{path}/verify");
    let url = format!(
        "{}/auth/login?return_to={}",
        state.config.auth_gateway_url,
        urlencoding::encode(&return_to)
    );
    Redirect::to(&url)
}

fn path_only(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(slash) = base_url[after_scheme..].find('/') {
            return base_url[after_scheme + slash..]
                .trim_end_matches('/')
                .to_string();
        }
    }
    String::new()
}

// ---------------------------------------------------------------------
// POST /verify/kick — start the viewer OAuth (PKCE) flow
// ---------------------------------------------------------------------

pub async fn verify_kick(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    csrf::verify_origin(&headers, &state.allowed_origins)?;
    let (discord_id, _) = read_session(&jar, &state.config.session_secret)?;

    let client_id = state.config.kick.client_id.as_deref().ok_or_else(|| {
        AppError::Internal("KICK_CLIENT_ID is not configured on this server.".into())
    })?;

    let state_token = Uuid::new_v4().to_string();
    let code_verifier = kick::new_code_verifier();
    oauth::insert_state(
        &state,
        &state_token,
        &code_verifier,
        "viewer",
        &discord_id,
        None,
        None,
    )
    .await?;

    let url = build_authorize(
        client_id,
        &oauth::viewer_redirect_uri(&state.config.base_url),
        oauth::VIEWER_SCOPES,
        &state_token,
        &code_verifier,
    );
    Ok(Json(json!({ "authorize_url": url })))
}

fn build_authorize(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    code_verifier: &str,
) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier));
    let qs = serde_urlencoded::to_string([
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scope),
        ("state", state),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ])
    .expect("urlencoded never fails for &str");
    format!("{}?{}", kick::AUTHORIZE_URL, qs)
}
