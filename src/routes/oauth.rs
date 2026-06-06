//! Kick OAuth callback for the broadcaster connect flow.
//!
//! Phase 3 covers broadcaster only; Phase 4 adds the viewer callback.
//! Both flows share PKCE state in `kick_oauth_states` (column `flow`
//! disambiguates).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum_extra::extract::cookie::CookieJar;
use bytes::Bytes;
use serde::Deserialize;

use crate::error::AppError;
use crate::services::auth::read_session;
use crate::services::crypto;
use crate::services::kick::KickClient;
use crate::AppState;

const SUCCESS_PAGE: &str = include_str!("../../templates/oauth_done.html");
/// Viewer post-link success page. The broadcaster connect flow uses
/// `SUCCESS_PAGE` (an admin popup that auto-closes); the viewer link flow
/// is a normal top-level navigation, so it gets its own "You're linked!"
/// page with a button back to /verify.
const VIEWER_DONE_PAGE: &str = include_str!("../../templates/verify_done.html");

/// Kick user IDs below this cutoff are treated as "OG" (early-adopter badge).
/// The exact threshold is community-set; configurable later via env if needed.
pub const OG_USER_ID_THRESHOLD: i64 = 1_000_000;

/// Per-channel floor between link-triggered reconciles. A channel_refresh
/// re-pulls the whole channel's membership, so when many viewers link at once
/// (e.g. after an @everyone) this bounds it to ~one full reconcile per channel
/// per window — the freshly-pulled facts cover every viewer who linked in it.
const LINK_CHANNEL_REFRESH_COOLDOWN_SECS: f64 = 300.0;

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(sqlx::FromRow)]
struct OauthState {
    code_verifier: String,
    flow: String,
    discord_id: String,
    guild_id: Option<String>,
}

pub async fn broadcaster_callback(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    match broadcaster_callback_inner(state, q).await {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn broadcaster_callback_inner(
    state: Arc<AppState>,
    q: CallbackQuery,
) -> Result<Bytes, AppError> {
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return Err(AppError::BadRequest(format!(
            "Kick returned an error during authorization: {err} ({desc})"
        )));
    }
    let code = q
        .code
        .ok_or_else(|| AppError::BadRequest("Missing `code` from Kick callback.".into()))?;
    let st = q
        .state
        .ok_or_else(|| AppError::BadRequest("Missing `state` from Kick callback.".into()))?;

    // Consume the state row in a single DELETE … RETURNING so it can't be
    // replayed even on race.
    let row: Option<OauthState> = sqlx::query_as(
        "DELETE FROM kick_oauth_states \
         WHERE state = $1 AND expires_at > now() \
         RETURNING code_verifier, flow, discord_id, guild_id",
    )
    .bind(&st)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or_else(|| {
        AppError::BadRequest(
            "OAuth state expired or unknown — start the connect flow again.".into(),
        )
    })?;
    if row.flow != "broadcaster" {
        return Err(AppError::BadRequest(
            "OAuth state was issued for a different flow.".into(),
        ));
    }
    let guild_id = row
        .guild_id
        .ok_or_else(|| AppError::BadRequest("Broadcaster flow missing guild_id.".into()))?;

    // Build a KickClient using config credentials. If the operator hasn't
    // set KICK_CLIENT_ID/KICK_CLIENT_SECRET we 500 here with a clear error
    // (it's an ops misconfiguration, not user input).
    let client = build_kick_client(&state)?;

    let redirect_uri = broadcaster_redirect_uri(&state.config.base_url);

    let tokens = client
        .exchange_code(&code, &redirect_uri, &row.code_verifier)
        .await?;
    let refresh_token = tokens.refresh_token.clone().ok_or_else(|| {
        AppError::KickApi("Kick did not return a refresh_token — connect cannot persist.".into())
    })?;

    let user = client.get_authenticated_user(&tokens.access_token).await?;
    let channel = client
        .get_channel_by_user(user.user_id, &tokens.access_token)
        .await
        .ok();

    let slug = channel
        .as_ref()
        .map(|c| c.slug.clone())
        .unwrap_or_else(|| user.name.clone().to_ascii_lowercase());
    let is_live = channel
        .as_ref()
        .and_then(|c| c.stream.as_ref())
        .map(|s| s.is_live)
        .unwrap_or(false);
    let viewer_count = channel
        .as_ref()
        .and_then(|c| c.stream.as_ref())
        .map(|s| s.viewer_count)
        .unwrap_or(0);
    let category = channel
        .as_ref()
        .and_then(|c| c.category.as_ref())
        .and_then(|cat| cat.name.clone());
    let scopes: Vec<String> = tokens
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect();

    let secret = &state.config.session_secret;
    let access_enc = crypto::encrypt(secret, tokens.access_token.as_bytes());
    let refresh_enc = crypto::encrypt(secret, refresh_token.as_bytes());
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(tokens.expires_in.max(60));

    // Upsert broadcaster + insert guild_broadcasters in one transaction so
    // a partial write can't leave dangling state.
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO broadcasters (\
             kick_channel_id, kick_slug, display_name, access_token_enc, refresh_token_enc,\
             token_expires_at, token_scopes, is_live, current_category, viewer_count,\
             last_synced_at, updated_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now(), now())\
         ON CONFLICT (kick_channel_id) DO UPDATE SET \
             kick_slug = EXCLUDED.kick_slug, \
             display_name = EXCLUDED.display_name, \
             access_token_enc = EXCLUDED.access_token_enc, \
             refresh_token_enc = EXCLUDED.refresh_token_enc, \
             token_expires_at = EXCLUDED.token_expires_at, \
             token_scopes = EXCLUDED.token_scopes, \
             is_live = EXCLUDED.is_live, \
             current_category = EXCLUDED.current_category, \
             viewer_count = EXCLUDED.viewer_count, \
             last_synced_at = now(), \
             updated_at = now()",
    )
    .bind(user.user_id)
    .bind(&slug)
    .bind(&user.name)
    .bind(&access_enc)
    .bind(&refresh_enc)
    .bind(expires_at)
    .bind(&scopes)
    .bind(is_live)
    .bind(category.as_deref())
    .bind(viewer_count)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO guild_broadcasters (guild_id, kick_channel_id, connected_by_discord_id) \
         VALUES ($1,$2,$3) \
         ON CONFLICT (guild_id, kick_channel_id) DO NOTHING",
    )
    .bind(&guild_id)
    .bind(user.user_id)
    .bind(&row.discord_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Best-effort: register webhook subscriptions for this channel. Failures
    // here don't fail the connect — the reconcile worker (Phase 9) is the
    // safety net, and the admin can re-trigger via the connect flow.
    subscribe_channel_events(&state, &client, user.user_id, &tokens.access_token).await;

    tracing::info!(
        guild_id = %guild_id,
        kick_channel_id = user.user_id,
        slug = %slug,
        connected_by = %row.discord_id,
        "Broadcaster connected"
    );

    // Render the success page with a small bit of substitution.
    let html = SUCCESS_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{KICK_USERNAME}}", &user.name)
        .replace("{{GUILD_ID}}", &guild_id);
    Ok(Bytes::from(html))
}

fn build_kick_client(state: &Arc<AppState>) -> Result<KickClient, AppError> {
    let id = state
        .config
        .kick
        .client_id
        .clone()
        .ok_or_else(|| AppError::Internal("KICK_CLIENT_ID is not configured.".into()))?;
    let secret = state
        .config
        .kick
        .client_secret
        .clone()
        .ok_or_else(|| AppError::Internal("KICK_CLIENT_SECRET is not configured.".into()))?;
    Ok(KickClient::new(id, secret))
}

pub fn broadcaster_redirect_uri(base_url: &str) -> String {
    format!("{base_url}/oauth/kick/broadcaster/callback")
}

pub fn viewer_redirect_uri(base_url: &str) -> String {
    format!("{base_url}/oauth/kick/viewer/callback")
}

/// Insert a new PKCE state row. `expires_at` defaults to now + 10 min.
pub async fn insert_state(
    state: &Arc<AppState>,
    state_token: &str,
    code_verifier: &str,
    flow: &str,
    discord_id: &str,
    guild_id: Option<&str>,
    return_to: Option<&str>,
) -> Result<(), AppError> {
    let expires_at =
        chrono::Utc::now() + chrono::Duration::from_std(Duration::from_secs(10 * 60)).unwrap();
    sqlx::query(
        "INSERT INTO kick_oauth_states (state, code_verifier, flow, discord_id, guild_id, return_to, expires_at)\
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(state_token)
    .bind(code_verifier)
    .bind(flow)
    .bind(discord_id)
    .bind(guild_id)
    .bind(return_to)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// Scopes requested for the broadcaster flow. Matches what the Kick app
/// registration has enabled (per the developer-portal screenshot the user
/// went through during setup):
/// "Read user information", "Read channel information",
/// "Subscribe to events (read chat feed, follows, subscribes, gifts)",
/// "Read KICKs related information".
pub const BROADCASTER_SCOPES: &str = "user:read channel:read events:subscribe";

/// Viewer flow needs only the bare minimum — identify the linking user.
pub const VIEWER_SCOPES: &str = "user:read";

/// Event types we subscribe to per channel. TODO(kick-docs): confirm exact
/// names against Kick's events catalog at integration time.
pub const EVENT_TYPES: &[&str] = &[
    "channel.followed",
    "channel.subscription.new",
    "channel.subscription.renewal",
    "channel.subscription.gifts",
    "channel.subscription.cancel",
    "livestream.online",
    "livestream.offline",
];

/// Register (idempotently) all webhook subscriptions for a channel and
/// persist their Kick subscription IDs. Best-effort: logs and continues.
async fn subscribe_channel_events(
    state: &Arc<AppState>,
    client: &KickClient,
    broadcaster_user_id: i64,
    access_token: &str,
) {
    for et in EVENT_TYPES {
        match client
            .subscribe_event(et, broadcaster_user_id, access_token)
            .await
        {
            Ok(sub_id) => {
                if let Err(e) = sqlx::query(
                    "INSERT INTO webhook_subscriptions \
                       (kick_channel_id, event_type, kick_subscription_id) \
                     VALUES ($1,$2,$3) \
                     ON CONFLICT (kick_channel_id, event_type) \
                     DO UPDATE SET kick_subscription_id = EXCLUDED.kick_subscription_id, \
                                   status = 'active'",
                )
                .bind(broadcaster_user_id)
                .bind(et)
                .bind(&sub_id)
                .execute(&state.pool)
                .await
                {
                    tracing::warn!(et, "persist webhook_subscription failed: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(
                    broadcaster_user_id,
                    et,
                    "Kick event subscribe failed (will rely on reconcile worker): {e}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------
// Viewer callback
// ---------------------------------------------------------------------

pub async fn viewer_callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    match viewer_callback_inner(state, jar, q).await {
        Ok(html) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn viewer_callback_inner(
    state: Arc<AppState>,
    jar: CookieJar,
    q: CallbackQuery,
) -> Result<Bytes, AppError> {
    if let Some(err) = q.error {
        let desc = q.error_description.unwrap_or_default();
        return Err(AppError::BadRequest(format!(
            "Kick returned an error: {err} ({desc})"
        )));
    }
    let code = q
        .code
        .ok_or_else(|| AppError::BadRequest("Missing `code` from Kick callback.".into()))?;
    let st = q
        .state
        .ok_or_else(|| AppError::BadRequest("Missing `state` from Kick callback.".into()))?;

    let row: Option<OauthState> = sqlx::query_as(
        "DELETE FROM kick_oauth_states \
         WHERE state = $1 AND expires_at > now() \
         RETURNING code_verifier, flow, discord_id, guild_id",
    )
    .bind(&st)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or_else(|| {
        AppError::BadRequest("OAuth state expired or unknown — start the link flow again.".into())
    })?;
    if row.flow != "viewer" {
        return Err(AppError::BadRequest(
            "OAuth state was issued for a different flow.".into(),
        ));
    }

    let client = build_kick_client(&state)?;
    let redirect_uri = viewer_redirect_uri(&state.config.base_url);
    let tokens = client
        .exchange_code(&code, &redirect_uri, &row.code_verifier)
        .await?;
    let user = client.get_authenticated_user(&tokens.access_token).await?;

    // The public Kick profile URL uses the channel *slug* (lowercase, with
    // `_` → `-`), not the display name — e.g. "Faizo_Ken" lives at
    // kick.com/faizo-ken, and linking to the display name hits Kick's
    // "Oops" page. Fetch the canonical slug best-effort (same call the
    // broadcaster flow uses); fall back to a normalized display name.
    let kick_slug = client
        .get_channel_by_user(user.user_id, &tokens.access_token)
        .await
        .ok()
        .map(|c| c.slug)
        .unwrap_or_else(|| user.name.to_ascii_lowercase().replace('_', "-"));

    // We do NOT persist the viewer's tokens — per-channel facts come from the
    // broadcaster's token. All we need is the Kick user_id to bind the link.
    let is_og = user.user_id < OG_USER_ID_THRESHOLD;

    // Pull the Discord display name from the session cookie so the public
    // users page can show "DiscordName · @kickslug". The cookie is always
    // present in a normal verify flow (same browser, same domain); on a
    // weird flow (cookie cleared mid-OAuth) we just store NULL — the page
    // falls back to the discord_id.
    let discord_name: Option<String> = read_session(&jar, &state.config.session_secret)
        .ok()
        .map(|(_, name)| name);

    // Upsert by discord_id; ON CONFLICT (kick_user_id) is the real safety
    // net for "same Kick account, two Discord IDs" — we reject that.
    //
    // `discord_name` uses COALESCE so a NULL on this insert (cookie gone)
    // doesn't blank out a previously stored name on re-link.
    let result = sqlx::query(
        "INSERT INTO kick_users (\
             discord_id, kick_user_id, kick_username, kick_created_at, is_og, discord_name, linked_at, refreshed_at\
         ) VALUES ($1,$2,$3,$4,$5,$6, now(), now())\
         ON CONFLICT (discord_id) DO UPDATE SET \
             kick_user_id = EXCLUDED.kick_user_id, \
             kick_username = EXCLUDED.kick_username, \
             kick_created_at = EXCLUDED.kick_created_at, \
             is_og = EXCLUDED.is_og, \
             discord_name = COALESCE(EXCLUDED.discord_name, kick_users.discord_name), \
             refreshed_at = now()",
    )
    .bind(&row.discord_id)
    .bind(user.user_id)
    .bind(&user.name)
    // kick_created_at: Kick's user object may not expose this on the public
    // /users endpoint. If it does, parse it; otherwise default to "now" so
    // account_age_days = 0 until the reconcile worker (Phase 9) backfills.
    .bind(chrono::Utc::now())
    .bind(is_og)
    .bind(&discord_name)
    .execute(&state.pool)
    .await;

    if let Err(e) = result {
        // Check for the unique violation on kick_user_id — means this Kick
        // account is already linked to a different Discord ID.
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23505")
                && db_err.constraint() == Some("kick_users_kick_user_id_key")
            {
                return Err(AppError::Forbidden(format!(
                    "Kick account {} is already linked to a different Discord account. \
                     Unlink there first, then try again.",
                    user.name
                )));
            }
        }
        return Err(AppError::from(e));
    }

    // Seed empty `channel_relations` rows now so the user is visible on the
    // public users page the moment the redirect completes. Without this they
    // would only appear after the player_sync worker runs — fast in practice
    // but observably stale if the queue is backed up. Best-effort: a failure
    // here doesn't block the link.
    match crate::services::auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        &row.discord_id,
    )
    .await
    {
        Ok(guild_ids) => {
            if let Err(e) = crate::services::sync::ensure_baseline_relations(
                &state.pool,
                &row.discord_id,
                &guild_ids,
            )
            .await
            {
                tracing::warn!(
                    discord_id = %row.discord_id,
                    "ensure_baseline_relations failed at link time: {e}"
                );
            }

            // Kick exposes a viewer's follow/sub status only through the
            // broadcaster-token list endpoints, so a user who *already* followed
            // or subscribed before linking shows all-false until the next
            // periodic reconcile — up to 6h away. Pull their channels' facts now
            // via a channel_refresh (re-pulls membership, then fans out a
            // channel_sync that re-evaluates roles). Deduped against any
            // already-queued refresh and gated by the broadcaster's last
            // reconcile, so a burst of linkers collapses to ~one reconcile per
            // channel. Follows/subs made *after* linking arrive in real time via
            // webhooks, so this only needs to cover the pre-link gap.
            let channels: Vec<i64> = sqlx::query_scalar(
                "SELECT gb.kick_channel_id \
                 FROM guild_broadcasters gb \
                 JOIN broadcasters b ON b.kick_channel_id = gb.kick_channel_id \
                 WHERE gb.guild_id = ANY($1) \
                   AND (b.last_synced_at IS NULL \
                        OR b.last_synced_at < now() - make_interval(secs => $2)) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM jobs j \
                       WHERE j.kind = 'channel_refresh' \
                         AND j.status IN ('pending', 'in_progress') \
                         AND (j.payload->>'kick_channel_id')::bigint = gb.kick_channel_id \
                   )",
            )
            .bind(&guild_ids)
            .bind(LINK_CHANNEL_REFRESH_COOLDOWN_SECS)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

            for cid in &channels {
                if let Err(e) =
                    crate::services::jobs::enqueue_channel_refresh(&state.pool, *cid).await
                {
                    tracing::warn!(
                        discord_id = %row.discord_id,
                        kick_channel_id = cid,
                        "enqueue channel_refresh at link failed: {e}"
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                discord_id = %row.discord_id,
                "auth_gateway guild lookup failed at link time: {e}"
            );
        }
    }

    // Enqueue a player_sync for this user so workers re-evaluate all their
    // role_links. enqueue() fires pg_notify internally.
    crate::services::jobs::enqueue_player_sync(&state.pool, &row.discord_id).await?;

    tracing::info!(
        discord_id = %row.discord_id,
        kick_user_id = user.user_id,
        kick_username = %user.name,
        "Viewer linked"
    );

    // Render the viewer "You're linked!" success page. It has a button back
    // to /verify, which reads /verify/status and shows the linked state if
    // the user returns there.
    let html = VIEWER_DONE_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{KICK_USERNAME}}", &user.name)
        .replace("{{KICK_SLUG}}", &kick_slug)
        .replace("{{KICK_USER_ID}}", &user.user_id.to_string());
    Ok(Bytes::from(html))
}
