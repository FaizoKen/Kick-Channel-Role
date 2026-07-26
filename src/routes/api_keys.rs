//! Manager-facing CRUD for the guild's `/api/v1` keys.
//!
//! Mounted under `/admin/{guild_id}/api-keys` and gated by the same dual
//! cookie-or-iframe-Bearer check as every other admin action (Convention
//! 45), plus a read-only-impersonation refusal on the two mutating routes.
//!
//! The raw token exists in exactly one response body, once, at creation. We
//! store only its SHA-256, so "show me that key again" is not a feature we
//! can offer and not one we want to — the recovery path is revoke-and-remint.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::api_key::{self, MAX_ACTIVE_KEYS_PER_GUILD, SCOPE_USERS_READ};
use crate::services::auth::{extract_bearer, require_guild_admin_ctx};
use crate::services::csrf;
use crate::AppState;

const MAX_LABEL_LEN: usize = 60;

/// Cookie-authed calls need an Origin check; iframe-Bearer calls carry no
/// ambient credential so they are not CSRF-able (mirrors `set_view_permission`).
fn csrf_guard(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(), AppError> {
    if extract_bearer(headers).is_none() {
        csrf::verify_origin(headers, &state.allowed_origins)?;
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    id: i64,
    label: String,
    prefix: String,
    scopes: Vec<String>,
    created_by: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl KeyRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "prefix": self.prefix,
            "scopes": self.scopes,
            "created_by": self.created_by,
            "created_at": self.created_at.to_rfc3339(),
            "last_used_at": self.last_used_at.map(|x| x.to_rfc3339()),
        })
    }
}

// ---------------------------------------------------------------------
// GET /admin/{guild_id}/api-keys
// ---------------------------------------------------------------------

/// List the guild's live keys. Never returns a token — `prefix` is the only
/// part of the secret that survives creation, and it exists so an operator
/// can match a row against a log line.
pub async fn list(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    require_guild_admin_ctx(&state, &jar, &headers, &guild_id).await?;

    let rows: Vec<KeyRow> = sqlx::query_as::<_, KeyRow>(
        "SELECT id, label, prefix, scopes, created_by, created_at, last_used_at \
           FROM guild_api_keys \
          WHERE guild_id = $1 AND revoked_at IS NULL \
          ORDER BY created_at DESC",
    )
    .bind(&guild_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(json!({
        "keys": rows.iter().map(KeyRow::to_json).collect::<Vec<_>>(),
        "max_keys": MAX_ACTIVE_KEYS_PER_GUILD,
        "docs_url": format!("{}/api/v1", state.config.base_url),
    })))
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/api-keys
// ---------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct CreateBody {
    pub label: String,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<CreateBody>,
) -> Result<Json<Value>, AppError> {
    csrf_guard(&state, &headers)?;
    let admin = require_guild_admin_ctx(&state, &jar, &headers, &guild_id).await?;
    let created_by = admin.require_writable()?.to_string();

    let label = body.label.trim();
    if label.is_empty() {
        return Err(AppError::BadRequest(
            "Give the key a label so you can tell your integrations apart.".into(),
        ));
    }
    if label.chars().count() > MAX_LABEL_LEN {
        return Err(AppError::BadRequest(format!(
            "Label is too long (max {MAX_LABEL_LEN} characters)."
        )));
    }

    // Cap live keys per guild. Checked before the insert rather than via a
    // constraint because the limit is a product decision, not an invariant —
    // and a clear 400 beats a unique-violation 409 the UI has to translate.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM guild_api_keys WHERE guild_id = $1 AND revoked_at IS NULL",
    )
    .bind(&guild_id)
    .fetch_one(&state.pool)
    .await?;
    if live >= MAX_ACTIVE_KEYS_PER_GUILD {
        return Err(AppError::BadRequest(format!(
            "This server already has {MAX_ACTIVE_KEYS_PER_GUILD} active API keys. \
             Revoke one before creating another."
        )));
    }

    let minted = api_key::mint();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO guild_api_keys (guild_id, token_hash, prefix, label, scopes, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&guild_id)
    .bind(&minted.hash)
    .bind(&minted.prefix)
    .bind(label)
    .bind(vec![SCOPE_USERS_READ.to_string()])
    .bind(&created_by)
    .fetch_one(&state.pool)
    .await?;

    // Audit trail: the token itself is never logged, only its public prefix.
    tracing::info!(
        guild_id = %guild_id,
        key_id = id,
        prefix = %minted.prefix,
        created_by = %created_by,
        "API key created"
    );

    Ok(Json(json!({
        "id": id,
        "label": label,
        "prefix": minted.prefix,
        "scopes": [SCOPE_USERS_READ],
        // The only time this value is ever transmitted.
        "token": minted.raw,
        "warning": "Copy this token now — it is stored hashed and cannot be shown again.",
    })))
}

// ---------------------------------------------------------------------
// DELETE /admin/{guild_id}/api-keys/{id}
// ---------------------------------------------------------------------

/// Revoke by marking, not deleting: the row stays so `created_by` /
/// `created_at` / `last_used_at` remain answerable after an incident.
/// Revocation takes effect on the next request — `authenticate` reads
/// `revoked_at` on every call, with no cached decision to expire.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((guild_id, key_id)): Path<(String, i64)>,
) -> Result<Json<Value>, AppError> {
    csrf_guard(&state, &headers)?;
    let admin = require_guild_admin_ctx(&state, &jar, &headers, &guild_id).await?;
    let revoked_by = admin.require_writable()?.to_string();

    // `guild_id` in the WHERE is what stops a manager of guild A from
    // revoking guild B's key by guessing its sequential id.
    let affected = sqlx::query(
        "UPDATE guild_api_keys SET revoked_at = now(), revoked_by = $3 \
          WHERE id = $1 AND guild_id = $2 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(&guild_id)
    .bind(&revoked_by)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound(
            "No such active API key for this server.".into(),
        ));
    }

    tracing::info!(
        guild_id = %guild_id,
        key_id,
        revoked_by = %revoked_by,
        "API key revoked"
    );
    Ok(Json(json!({ "success": true })))
}
