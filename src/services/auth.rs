//! Admin-permission helpers used by routes that mix cookie-auth (direct nav)
//! and iframe-Bearer auth (RoleLogic iframe).
//!
//! Direct-nav routes call `require_manager()` which reads `rl_session`,
//! verifies it locally, then queries the Auth Gateway for guild manage-server
//! permission. Iframe-Bearer routes verify the `ifs:` token via
//! [services::rl_token::verify_iframe_session] before reaching this module.

use std::sync::Arc;

use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;

use crate::error::AppError;
use crate::services::rl_token;
use crate::services::session::verify_session;
use crate::AppState;

#[derive(Debug, Deserialize)]
struct GuildPermissionResp {
    #[serde(default)]
    is_member: bool,
    #[serde(default)]
    is_manager: bool,
}

/// Pull `rl_session` cookie value via CookieJar (Convention 35) and verify it.
pub fn read_session(jar: &CookieJar, secret: &str) -> Result<(String, String), AppError> {
    let cookie = jar.get("rl_session").ok_or_else(|| {
        AppError::UnauthorizedWith("Not signed in. Log in with Discord to continue.".into())
    })?;
    verify_session(cookie.value(), secret)
        .ok_or_else(|| AppError::UnauthorizedWith("Session expired or invalid.".into()))
}

/// Verify the caller has manage-server on `guild_id`. Returns the caller's
/// discord_id on success.
pub async fn require_manager(
    state: &Arc<AppState>,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<String, AppError> {
    let (discord_id, _) = read_session(jar, &state.config.session_secret)?;

    // Forward the cookie value to the Auth Gateway. Convention 31:
    // re-encode through Cookie::encoded() so the gateway's `parse_encoded`
    // doesn't double-decode names containing percent-escapes.
    let cookie_val = jar
        .get("rl_session")
        .map(|c| {
            Cookie::build(("rl_session", c.value().to_string()))
                .build()
                .encoded()
                .to_string()
        })
        .unwrap_or_default();

    let url = format!(
        "{}/auth/guild_permission?guild_id={guild_id}",
        state.config.auth_gateway_url
    );
    let resp = state
        .http
        .get(&url)
        .header("Cookie", cookie_val)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway permission request: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::UnauthorizedWith(format!(
            "Auth Gateway rejected the request ({status}): {body}"
        )));
    }
    let parsed: GuildPermissionResp = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    if !parsed.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if !parsed.is_manager {
        return Err(AppError::Forbidden(
            "You need Manage Server to do this.".into(),
        ));
    }
    Ok(discord_id)
}

/// Extract an `Authorization: Bearer ifs:…` token if present. Used by
/// dual-mode admin XHRs (Convention 42/45).
pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(String::from)
}

/// Guild-scoped dual gate for admin actions that aren't tied to a single
/// role link (broadcaster connect/list/disconnect, per-guild settings).
///
/// Accepts EITHER an iframe-session `Bearer ifs:…` bound to this guild, OR
/// the `rl_session` cookie + Auth-Gateway manager check (direct nav). The
/// iframe-session is only minted after a valid RoleLogic `rl_token` for a
/// role link in this guild, so guild-scoped trust is appropriate here
/// (Convention 45). Returns the caller's discord_id.
pub async fn require_guild_admin(
    state: &Arc<AppState>,
    jar: &CookieJar,
    headers: &axum::http::HeaderMap,
    guild_id: &str,
) -> Result<String, AppError> {
    if let Some(bearer) = extract_bearer(headers) {
        let s = rl_token::verify_iframe_session(&bearer, &state.config.session_secret).ok_or_else(
            || {
                AppError::UnauthorizedWith(
                    "Your session expired. Reopen the plugin in the RoleLogic dashboard.".into(),
                )
            },
        )?;
        if s.guild_id != guild_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this server.".into(),
            ));
        }
        return Ok(s.discord_id);
    }
    require_manager(state, jar, guild_id).await
}

pub struct GuildPermission {
    /// Resolved caller identity — carried for audit logging / future
    /// per-user gating even though the users-page gate only reads the flags.
    #[allow(dead_code)]
    pub discord_id: String,
    pub is_member: bool,
    pub is_manager: bool,
}

/// Resolve the caller's (member, manager) flags for a guild. Used by the
/// public users-list page, which gates on `guild_settings.view_permission`.
pub async fn guild_permission(
    state: &Arc<AppState>,
    jar: &CookieJar,
    guild_id: &str,
) -> Result<GuildPermission, AppError> {
    let (discord_id, _) = read_session(jar, &state.config.session_secret)?;
    let cookie_val = jar
        .get("rl_session")
        .map(|c| {
            Cookie::build(("rl_session", c.value().to_string()))
                .build()
                .encoded()
                .to_string()
        })
        .unwrap_or_default();

    let url = format!(
        "{}/auth/guild_permission?guild_id={guild_id}",
        state.config.auth_gateway_url
    );
    let resp = state
        .http
        .get(&url)
        .header("Cookie", cookie_val)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway permission request: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::UnauthorizedWith(format!(
            "Auth Gateway rejected the request ({status}): {body}"
        )));
    }
    let parsed: GuildPermissionResp = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("auth_gateway response not JSON: {e}")))?;
    Ok(GuildPermission {
        discord_id,
        is_member: parsed.is_member,
        is_manager: parsed.is_manager,
    })
}
