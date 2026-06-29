//! Admin routes. Phase 3 introduces broadcaster connect/list/disconnect;
//! Phase 6 will add the iframe role-config page and the rule-tree save
//! handler. Direct-nav admin pages authenticate via cookie + Auth Gateway
//! manager check (Convention 45 — dual-mode pages).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::AppError;
use crate::models::condition::{ConditionOperator, ConditionTarget, TargetKind};
use crate::models::rule::{RuleTree, MAX_CONDITIONS_PER_GROUP, MAX_GROUPS};
use crate::routes::oauth;
use crate::services::auth::{extract_bearer, require_guild_admin, require_manager};
use crate::services::rule_sql::{self, Bind};
use crate::services::rule_validator::{self, RuleTreeBody};
use crate::services::security_headers::admin_iframe_csp;
use crate::services::{auth_gateway, csrf, jobs, kick, rl_token};
use crate::AppState;

const ROLE_CONFIG_TEMPLATE: &str = include_str!("../../templates/role_config.html");

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/broadcasters/connect
// Starts the broadcaster OAuth flow. Returns the authorize URL JSON.
// ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct ConnectResponse {
    pub authorize_url: String,
}

pub async fn broadcaster_connect(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<ConnectResponse>, AppError> {
    // Bearer (iframe-session) is CSRF-safe by token binding; only the cookie
    // path needs the Origin allowlist (Convention 42).
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    let discord_id = require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    if state.config.kick.client_id.is_none() {
        return Err(AppError::Internal(
            "KICK_CLIENT_ID is not configured on this server.".into(),
        ));
    }

    let state_token = Uuid::new_v4().to_string();
    let code_verifier = kick::new_code_verifier();
    oauth::insert_state(
        &state,
        &state_token,
        &code_verifier,
        "broadcaster",
        &discord_id,
        Some(&guild_id),
        None,
    )
    .await?;

    let client_id = state.config.kick.client_id.as_deref().unwrap();
    let url = build_authorize_url(
        client_id,
        &oauth::broadcaster_redirect_uri(&state.config.base_url),
        oauth::BROADCASTER_SCOPES,
        &state_token,
        &code_verifier,
    );

    Ok(Json(ConnectResponse { authorize_url: url }))
}

fn build_authorize_url(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    code_verifier: &str,
) -> String {
    // We re-implement the URL here (instead of constructing a KickClient)
    // because connect doesn't need any of the API methods — only the URL
    // shape, which is pure config.
    let challenge = pkce_s256_for_admin(code_verifier);
    let qs = serde_urlencoded::to_string([
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scope),
        ("state", state),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ])
    .expect("urlencoded never fails for &str");
    format!("{}?{}", kick::AUTHORIZE_URL, qs)
}

fn pkce_s256_for_admin(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/broadcasters
// List channels connected to this guild. Used by the iframe UI's channel
// picker.
// ---------------------------------------------------------------------

#[derive(sqlx::FromRow, Serialize)]
pub struct BroadcasterRow {
    pub kick_channel_id: i64,
    pub kick_slug: String,
    pub display_name: String,
    pub is_live: bool,
    pub current_category: Option<String>,
    pub viewer_count: i32,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

pub async fn broadcaster_list(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;
    let rows: Vec<BroadcasterRow> = sqlx::query_as(
        "SELECT b.kick_channel_id, b.kick_slug, b.display_name, b.is_live, \
                b.current_category, b.viewer_count, gb.connected_at \
         FROM guild_broadcasters gb \
         JOIN broadcasters b USING (kick_channel_id) \
         WHERE gb.guild_id = $1 \
         ORDER BY gb.connected_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "broadcasters": rows })))
}

// ---------------------------------------------------------------------
// DELETE /admin/{guild_id}/broadcasters/{channel_id}
// Disconnect a channel from this guild. Leaves `broadcasters` row intact
// (other guilds may still use it).
// ---------------------------------------------------------------------

pub async fn broadcaster_disconnect(
    State(state): State<Arc<AppState>>,
    Path((guild_id, channel_id)): Path<(String, i64)>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    // Best-effort: clear references from role_links in this guild before
    // dropping the join row, so a follow-up rule_tree save doesn't FK-fail.
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE role_links SET kick_channel_id = NULL, updated_at = now() \
         WHERE guild_id = $1 AND kick_channel_id = $2",
    )
    .bind(&guild_id)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;

    let result =
        sqlx::query("DELETE FROM guild_broadcasters WHERE guild_id = $1 AND kick_channel_id = $2")
            .bind(&guild_id)
            .bind(channel_id)
            .execute(&mut *tx)
            .await?;

    tx.commit().await?;

    Ok(Json(json!({
        "removed": result.rows_affected() > 0
    })))
}

// ---------------------------------------------------------------------
// Iframe role-config page (dual-mode: rl_token JWT entry OR cookie+manager)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigPageQuery {
    #[serde(default)]
    rl_token: Option<String>,
}

pub async fn role_config_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Query(query): Query<RoleConfigPageQuery>,
) -> Response {
    let has_rl_token = query
        .rl_token
        .as_deref()
        .map(|t| !t.is_empty())
        .unwrap_or(false);

    // Path 1: iframe entry — verify rl_token, mint an iframe-session token.
    // `read_only` is true when a developer is impersonating the user.
    let (iframe_session, read_only) = match query.rl_token.as_deref() {
        Some(token) if !token.is_empty() => {
            match verify_iframe_entry(&state, &guild_id, &role_id, token).await {
                Ok((t, ro)) => (Some(t), ro),
                Err(resp) => return resp,
            }
        }
        _ => (None, false),
    };

    // Path 2: direct nav — cookie + manager check. A cross-site iframe will
    // NOT carry our first-party `rl_session` cookie, so if we land here while
    // embedded it almost always means RoleLogic never appended `?rl_token=`
    // (usually a BASE_URL / registered-plugin-URL mismatch). Surface that
    // precisely instead of a dead-end "sign in" the user can't action.
    if iframe_session.is_none() {
        if let Err(e) = require_manager(&state, &jar, &guild_id).await {
            if !has_rl_token && looks_embedded(&headers) {
                tracing::warn!(
                    guild_id,
                    role_id,
                    base_url = %state.config.base_url,
                    "role_config_page reached inside an iframe with no rl_token — \
                     RoleLogic did not pass an auth token. Verify BASE_URL exactly \
                     matches the plugin URL registered in RoleLogic (https, \
                     including the /kick-channel-role path prefix)."
                );
                return render_iframe_no_token(&state);
            }
            return render_signin_page(&state, &e.to_string());
        }
    }

    let body = ROLE_CONFIG_TEMPLATE
        .replace("__BASE_URL__", &state.config.base_url)
        .replace("__GUILD_ID__", &guild_id)
        .replace("__ROLE_ID__", &role_id)
        .replace("__IFRAME_TOKEN__", iframe_session.as_deref().unwrap_or(""))
        .replace("__READ_ONLY__", if read_only { "1" } else { "0" });

    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
            (
                header::CACHE_CONTROL,
                "private, max-age=300, must-revalidate".to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

/// Verify `?rl_token=…` (Convention 43: six checks, in order) and return a
/// freshly minted iframe-session token. On failure returns a rendered error
/// page so the iframe shows something useful instead of an empty body.
async fn verify_iframe_entry(
    state: &AppState,
    guild_id: &str,
    role_id: &str,
    rl_token_str: &str,
) -> Result<(String, bool), Response> {
    let api_token: Option<String> =
        sqlx::query_scalar("SELECT api_token FROM role_links WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id)
            .bind(role_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| render_inline_error(state, &format!("Database error: {e}")))?;

    let Some(api_token) = api_token else {
        return Err(render_inline_error(
            state,
            "This role link isn't registered with this plugin yet.",
        ));
    };

    let verified =
        rl_token::verify(rl_token_str, &api_token, &state.config.base_url).map_err(|e| {
            let msg = match e {
                rl_token::RlTokenError::Expired => {
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard."
                }
                rl_token::RlTokenError::BadSignature | rl_token::RlTokenError::Malformed => {
                    "Invalid auth token."
                }
                rl_token::RlTokenError::WrongAudience => "Token is for a different plugin.",
                rl_token::RlTokenError::WrongIssuer => "Token was not issued by RoleLogic.",
            };
            render_inline_error(state, msg)
        })?;

    // Cross-check claims vs path (Convention 43 step 6).
    if verified.guild_id != guild_id || verified.role_id != role_id {
        return Err(render_inline_error(
            state,
            "Token does not match this role link.",
        ));
    }

    if verified.read_only {
        tracing::info!(
            guild_id,
            role_id,
            target = %verified.discord_id,
            actor = verified.actor_id.as_deref().unwrap_or("?"),
            "Role config opened read-only (developer impersonation)"
        );
    }

    // Carry the read-only flag into the minted iframe-session so every XHR is
    // gated; return it too so the page renders in read-only mode.
    let token = rl_token::mint_iframe_session(
        &verified.discord_id,
        guild_id,
        role_id,
        verified.read_only,
        &state.config.session_secret,
    );
    Ok((token, verified.read_only))
}

fn render_inline_error(state: &AppState, message: &str) -> Response {
    let base_url = &state.config.base_url;
    let msg = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cannot load configuration</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.5}}
h1{{color:#fca5a5;font-size:18px;margin-bottom:10px}}p{{color:#9aa3b2}}</style>
</head><body><h1>Cannot load configuration</h1><p>{msg}</p>
<p style="margin-top:14px;color:#7a8497">If you opened this from the RoleLogic dashboard, close and reopen the role's plugin tab.</p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

/// Heuristic: is this request the document load of a cross-site iframe?
/// Used only to pick the right *message* (never for authz), so trusting the
/// browser-set `Sec-Fetch-*` hints is fine here.
fn looks_embedded(headers: &HeaderMap) -> bool {
    let h = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let dest = h("sec-fetch-dest");
    dest == "iframe" || dest == "frame" || h("sec-fetch-site") == "cross-site"
}

/// Shown when the page is embedded but RoleLogic didn't append `?rl_token=`.
/// This is almost always a deployment-config issue, so the copy points the
/// operator at the actual fix rather than asking the end user to "sign in".
fn render_iframe_no_token(state: &AppState) -> Response {
    let base_url = &state.config.base_url;
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration unavailable</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:32px 24px;line-height:1.55;max-width:560px}}
h1{{color:#fbbf24;font-size:18px;margin:0 0 10px}}p{{color:#9aa3b2;margin:8px 0}}
code{{background:#0b0d12;padding:2px 6px;border-radius:4px;font-size:12px}}</style>
</head><body>
<h1>RoleLogic didn't pass an authentication token</h1>
<p>This plugin page must be opened from inside the RoleLogic dashboard, which
attaches a one-time token. None arrived with this request.</p>
<p><strong>If you're the server admin:</strong> close this tab and reopen the
role's plugin tab from RoleLogic. If it keeps happening, the plugin is
mis-registered — its <code>BASE_URL</code> must exactly match the URL
configured for this plugin in RoleLogic: HTTPS, no trailing slash, and
including the <code>/kick-channel-role</code> path prefix.</p>
<p style="color:#7a8497;font-size:12px;margin-top:16px">Configured BASE_URL:
<code>{base_url}</code></p>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

/// Direct-nav (non-iframe) sign-in prompt. Convention 36: render an in-page
/// "Login with Discord" the user clicks themselves; never auto-redirect.
fn render_signin_page(state: &AppState, reason: &str) -> Response {
    let base_url = &state.config.base_url;
    let reason = reason
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Kick Channel Role</title>
<link rel="icon" href="{base_url}/favicon.ico">
<style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e8eaed;padding:48px 24px;max-width:520px;margin:0 auto;line-height:1.55}}
h1{{font-size:22px;margin:0 0 12px}}p{{color:#9aa3b2}}
a.btn{{display:inline-block;margin-top:18px;background:#5865f2;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600}}
.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:18px}}
.actions a.btn{{margin-top:0}}
form.logout-form{{margin:0}}
button.logout{{background:none;color:#8a93a4;border:1px solid #2a2f3a;
  padding:10px 16px;border-radius:8px;font-size:13px;font-weight:600;
  cursor:pointer;font-family:inherit}}
button.logout:hover{{color:#fca5a5;border-color:#5c2630}}</style>
</head><body>
<h1>Sign in to continue</h1>
<p>You need <strong>Manage Server</strong> on this guild to edit its
Kick-Channel-Role configuration.</p>
<p style="color:#7a8497;font-size:12px">{reason}</p>
<div class="actions">
  <a class="btn" id="login">Sign in with Discord</a>
  <form class="logout-form" method="POST" action="/auth/logout">
    <button type="submit" class="logout">Sign out &amp; try another account</button>
  </form>
</div>
<script>
const ORIGIN=new URL("{base_url}").origin;
const RET=encodeURIComponent(location.pathname);
document.getElementById('login').href=ORIGIN+'/auth/login?return_to='+RET;
document.querySelectorAll('form.logout-form').forEach(f=>{{
  f.action=ORIGIN+'/auth/logout?return_to='+RET;
}});
</script>
</body></html>"##
    );
    let csp = admin_iframe_csp(state.config.rl_dashboard_origin.as_deref());
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, csp),
        ],
        body,
    )
        .into_response()
}

/// Dual gate: `Authorization: Bearer ifs:…` (iframe) OR cookie+manager
/// (direct nav). Returns the caller's discord_id (Convention 45).
/// Outcome of an access check for the role-config endpoints: who is calling and
/// whether the session is read-only (a developer impersonating the user).
struct RoleConfigAccess {
    #[allow(dead_code)]
    discord_id: String,
    read_only: bool,
}

async fn require_role_config_access(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &HeaderMap,
    guild_id: &str,
    role_id: &str,
) -> Result<RoleConfigAccess, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id || s.role_id != role_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this role link.".into(),
            ));
        }
        return Ok(RoleConfigAccess {
            discord_id: s.discord_id,
            read_only: s.read_only,
        });
    }
    // No iframe-session Bearer → direct-nav path. `require_manager` reads and
    // verifies the `rl_session` cookie itself, so there's no separate
    // pre-check here (an extra one only produced a more confusing message).
    let discord_id = require_manager(state, jar, guild_id).await?;
    Ok(RoleConfigAccess {
        discord_id,
        read_only: false,
    })
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id}/data
// ---------------------------------------------------------------------

pub async fn role_config_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<i64>, Value, i32)>(
        "SELECT kick_channel_id, rule_tree, rule_tree_version \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("This role link doesn't exist. Has it been added in RoleLogic?".into())
    })?;
    let (kick_channel_id, rule_tree, rule_tree_version) = link;
    let tree: RuleTree = serde_json::from_value(rule_tree).unwrap_or_default();

    let channels = sqlx::query_as::<_, BroadcasterRow>(
        "SELECT b.kick_channel_id, b.kick_slug, b.display_name, b.is_live, \
                b.current_category, b.viewer_count, gb.connected_at \
         FROM guild_broadcasters gb \
         JOIN broadcasters b USING (kick_channel_id) \
         WHERE gb.guild_id = $1 ORDER BY gb.connected_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;

    // Surface the public users-list settings here so admins discover the
    // feature: without this they'd never see the public page exists.
    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    Ok(Json(json!({
        "guild_id": guild_id,
        "role_id": role_id,
        "config": {
            "kick_channel_id": kick_channel_id,
            "grant_on_any_relation": tree.grant_on_any_relation,
            "groups": tree.groups,
        },
        "rule_tree_version": rule_tree_version,
        "channels": channels,
        "targets": target_catalog(),
        "operators": operator_catalog(),
        "limits": {
            "max_groups": MAX_GROUPS,
            "max_conditions_per_group": MAX_CONDITIONS_PER_GROUP,
        },
        // Per-guild verify URL. The `?guild=<id>` query param is what the
        // verify page reads to (a) show "Verifying for <Server>" context and
        // (b) auto-clear any existing opt-out so users who previously
        // disabled this server are re-enrolled in one click — no detour
        // through /auth/my_servers, no re-linking the Kick account.
        //
        // Guild IDs are Discord snowflakes (digits only) so they're safe to
        // splice directly into the query string without percent-encoding.
        "verify_url": format!("{}/verify?guild={}", state.config.base_url, guild_id),
        "users": {
            "url": format!("{}/users/{}", state.config.base_url, guild_id),
            "view_permission": view_permission,
        },
    })))
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/role/{role_id}/save  (optimistic-locked)
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RoleConfigSaveBody {
    pub rule_tree_version: i32,
    #[serde(flatten)]
    pub tree: RuleTreeBody,
}

pub async fn role_config_save(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RoleConfigSaveBody>,
) -> Result<Json<Value>, AppError> {
    // Bearer (iframe-session) is CSRF-safe by token binding; only the cookie
    // path needs the Origin allowlist.
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    let access = require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;
    // Read-only sessions (a developer impersonating the user) may view but not
    // write — the server-side half of the read-only contract.
    if access.read_only {
        return Err(AppError::Forbidden(
            "This configuration is read-only while impersonating a user.".into(),
        ));
    }

    let expected_version = body.rule_tree_version;

    // If a channel is chosen, it must be one connected to THIS guild.
    if let Some(cid) = body.tree.kick_channel_id {
        // Select the BIGINT PK (not a bare `SELECT 1`, which Postgres types
        // as INT4 and would mismatch an i64 decode).
        let ok: Option<i64> = sqlx::query_scalar(
            "SELECT kick_channel_id FROM guild_broadcasters \
             WHERE guild_id = $1 AND kick_channel_id = $2",
        )
        .bind(&guild_id)
        .bind(cid)
        .fetch_optional(&state.pool)
        .await?;
        if ok.is_none() {
            return Err(AppError::BadRequest(
                "Selected Kick channel isn't connected to this server.".into(),
            ));
        }
    }

    let parsed = rule_validator::parse_rule_tree(body.tree)?;

    // A relation rule (followers / subs / VIPs / mods / custom groups) is
    // evaluated against a specific Kick channel; with none bound it would
    // silently grant the role to nobody (Convention 42 / the preview
    // "nobody" short-circuit in `preview_count_for`). Reject so the dashboard
    // surfaces the reason via rl:toast instead of persisting a no-op rule.
    // Note: kept here (not in the shared `parse_rule_tree`) so the
    // POST /preview path can still show a "0 match" dry-run without a channel.
    if parsed.kick_channel_id.is_none()
        && !parsed.rule_tree.grant_on_any_relation
        && !parsed.rule_tree.groups.is_empty()
    {
        return Err(AppError::BadRequest(
            "Pick the Kick channel this rule checks against before saving — \
             without a connected channel it would grant the role to nobody."
                .into(),
        ));
    }

    let tree_json = serde_json::to_value(&parsed.rule_tree)
        .map_err(|e| AppError::Internal(format!("serialize rule_tree: {e}")))?;

    // Optimistic lock: only update if the version still matches what the
    // editor loaded. CASE prevents a second tab from silently clobbering.
    let result = sqlx::query(
        "UPDATE role_links \
         SET kick_channel_id = $1, rule_tree = $2, \
             rule_tree_version = rule_tree_version + 1, updated_at = now() \
         WHERE guild_id = $3 AND role_id = $4 AND rule_tree_version = $5",
    )
    .bind(parsed.kick_channel_id)
    .bind(&tree_json)
    .bind(&guild_id)
    .bind(&role_id)
    .bind(expected_version)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        // Either the link doesn't exist or the version moved on.
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
        )
        .bind(&guild_id)
        .bind(&role_id)
        .fetch_optional(&state.pool)
        .await?;
        return match exists {
            None => Err(AppError::NotFound(
                "This role link doesn't exist. Has it been added in RoleLogic?".into(),
            )),
            Some(_) => Err(AppError::StaleVersion),
        };
    }

    let new_version: i32 = sqlx::query_scalar(
        "SELECT rule_tree_version FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_one(&state.pool)
    .await?;

    if let Err(e) = jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await {
        tracing::warn!(
            guild_id,
            role_id,
            "enqueue config_sync after save failed: {e}"
        );
    }

    tracing::info!(
        guild_id,
        role_id,
        groups = parsed.rule_tree.groups.len(),
        grant_on_any = parsed.rule_tree.grant_on_any_relation,
        "Role rule_tree updated"
    );

    Ok(Json(
        json!({ "success": true, "rule_tree_version": new_version }),
    ))
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/role/{role_id}/preview
// Dry-run: how many guild members would currently match? No RoleLogic call.
// ---------------------------------------------------------------------

pub async fn role_config_preview(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    let link = sqlx::query_as::<_, (Option<i64>, Value)>(
        "SELECT kick_channel_id, rule_tree FROM role_links WHERE guild_id=$1 AND role_id=$2",
    )
    .bind(&guild_id)
    .bind(&role_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Role link not found.".into()))?;
    let (channel_id, raw_tree) = link;
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    preview_count_for(&state, &guild_id, channel_id, &tree).await
}

/// POST variant: previews a proposed (unsaved) rule. Used by the iframe's
/// "Preview" button so admins can see the match count for the rule they're
/// currently building before they commit it. Validation mirrors save.
pub async fn role_config_preview_edit(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, role_id)): Path<(String, String)>,
    Json(body): Json<RuleTreeBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_role_config_access(&state, &jar, &headers, &guild_id, &role_id).await?;

    // Channel (if provided) must belong to this guild.
    if let Some(cid) = body.kick_channel_id {
        let ok: Option<i64> = sqlx::query_scalar(
            "SELECT kick_channel_id FROM guild_broadcasters \
             WHERE guild_id = $1 AND kick_channel_id = $2",
        )
        .bind(&guild_id)
        .bind(cid)
        .fetch_optional(&state.pool)
        .await?;
        if ok.is_none() {
            return Err(AppError::BadRequest(
                "Selected Kick channel isn't connected to this server.".into(),
            ));
        }
    }

    let parsed = rule_validator::parse_rule_tree(body)?;
    preview_count_for(&state, &guild_id, parsed.kick_channel_id, &parsed.rule_tree).await
}

/// Shared core for GET (saved tree) and POST (proposed tree) previews.
async fn preview_count_for(
    state: &Arc<AppState>,
    guild_id: &str,
    channel_id: Option<i64>,
    tree: &RuleTree,
) -> Result<Json<Value>, AppError> {
    // Mirror the sync engine's Convention-42 guard (services::sync): a rule
    // grants to nobody only when it is NOT channel-agnostic AND it has no
    // channel bound or no groups. `grant_on_any_relation` is channel-agnostic,
    // so the default "Anyone who linked their Kick" preset (which carries no
    // channel) must NOT short-circuit here — it matches every linked member.
    let nobody = !tree.grant_on_any_relation && (channel_id.is_none() || tree.groups.is_empty());
    if nobody {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }

    let member_ids = match auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(json!({
                "available": false,
                "reason": "Member list temporarily unavailable; preview will work once the Auth Gateway responds."
            })))
        }
    };
    if member_ids.is_empty() {
        return Ok(Json(
            json!({ "matching": 0, "linked": 0, "available": true }),
        ));
    }

    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kick_users WHERE discord_id = ANY($1::text[])")
            .bind(&member_ids)
            .fetch_one(&state.pool)
            .await?;

    // Channel-agnostic "anyone who linked Kick" rule: every linked member
    // qualifies, so matching == linked. No channel join (mirrors
    // services::sync, which counts kick_users directly for this case).
    if tree.grant_on_any_relation {
        return Ok(Json(json!({
            "available": true,
            "matching": linked,
            "linked": linked,
        })));
    }

    // Channel-scoped rule. The `nobody` guard above guarantees a channel is
    // bound and at least one group exists for this path.
    let channel_id = channel_id.expect("channel bound for non-grant preview");

    let (rule_where, binds) = rule_sql::build_rule_where(tree, 2);
    let query = format!(
        "SELECT count(DISTINCT ku.discord_id) \
         FROM kick_users ku \
         LEFT JOIN channel_relations cr \
           ON cr.kick_user_id = ku.kick_user_id AND cr.kick_channel_id = $1 \
         WHERE ku.discord_id = ANY($2::text[]) AND ({rule_where})"
    );
    let mut q = sqlx::query_scalar::<_, i64>(&query)
        .bind(channel_id)
        .bind(&member_ids);
    for b in &binds {
        q = match b {
            Bind::Bool(v) => q.bind(*v),
            Bind::Int(v) => q.bind(*v),
            Bind::Text(v) => q.bind(v.clone()),
            Bind::TextArray(v) => q.bind(v.clone()),
        };
    }
    let matching: i64 = q.fetch_one(&state.pool).await?;

    Ok(Json(json!({
        "available": true,
        "matching": matching,
        "linked": linked,
    })))
}

// ---------------------------------------------------------------------
// Catalogs consumed by the rule-builder front-end
// ---------------------------------------------------------------------

fn kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::Bool => "bool",
        TargetKind::Int => "int",
        TargetKind::String => "string",
    }
}

fn target_catalog() -> Vec<Value> {
    use ConditionTarget::*;
    let entries: &[(ConditionTarget, &str, &str)] = &[
        (IsFollower, "Is a follower", "viewer"),
        (FollowAgeDays, "Days since first followed", "viewer"),
        (IsSubscriber, "Is an active subscriber", "viewer"),
        (SubMonthsCumulative, "Total months subscribed", "viewer"),
        (SubStreakMonths, "Current sub-streak (months)", "viewer"),
        (IsGiftRecipient, "Sub was gifted to them", "viewer"),
        (GiftedSubsGiven, "Subs they have gifted", "viewer"),
        (IsVip, "Is a channel VIP", "viewer"),
        (IsModerator, "Is a channel moderator", "viewer"),
        (KicksDonatedToChannel, "KICKs donated to channel", "viewer"),
        (ChatMessages30d, "Chat messages (last 30d)", "viewer"),
        (IsOg, "Has the Kick OG badge", "viewer"),
        (AccountAgeDays, "Kick account age (days)", "viewer"),
        (CountryCode, "Country code", "viewer"),
        (Username, "Kick username", "viewer"),
    ];
    entries
        .iter()
        .map(|(t, label, group)| {
            json!({
                "key": t.as_str(),
                "label": label,
                "kind": kind_str(t.kind()),
                "group": group,
            })
        })
        .collect()
}

fn operator_catalog() -> Vec<Value> {
    use ConditionOperator::*;
    let all = [
        (Eq, "equals"),
        (Neq, "not equals"),
        (Gt, "greater than"),
        (Gte, "at least"),
        (Lt, "less than"),
        (Lte, "at most"),
        (Between, "between"),
        (Contains, "contains"),
        (Regex, "matches regex"),
        (In, "is one of"),
        (NotIn, "is not one of"),
    ];
    all.iter()
        .map(|(op, label)| {
            json!({
                "key": op.as_str(),
                "label": label,
                "valid_for": {
                    "bool": op.valid_for(TargetKind::Bool),
                    "int": op.valid_for(TargetKind::Int),
                    "string": op.valid_for(TargetKind::String),
                },
                "needs_value_end": matches!(op, Between),
                "value_is_list": matches!(op, In | NotIn),
            })
        })
        .collect()
}
