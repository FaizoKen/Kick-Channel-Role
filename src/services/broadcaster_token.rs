//! Get a usable Kick access token for a broadcaster, transparently
//! refreshing (and re-persisting, encrypted) when it's within the refresh
//! window. Centralized so live_poll / reconcile / any future caller never
//! hand-roll the decrypt → check-expiry → refresh → re-encrypt dance.

use std::sync::Arc;

use crate::error::AppError;
use crate::services::crypto;
use crate::services::kick::KickClient;
use crate::AppState;

/// Refresh if the token expires within this window.
const REFRESH_SKEW_SECS: i64 = 5 * 60;

pub async fn valid_access_token(
    state: &Arc<AppState>,
    client: &KickClient,
    kick_channel_id: i64,
) -> Result<String, AppError> {
    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, chrono::DateTime<chrono::Utc>)>(
        "SELECT access_token_enc, refresh_token_enc, token_expires_at \
         FROM broadcasters WHERE kick_channel_id = $1",
    )
    .bind(kick_channel_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("broadcaster {kick_channel_id} not found")))?;

    let (access_enc, refresh_enc, expires_at) = row;
    let secret = &state.config.session_secret;

    let needs_refresh =
        expires_at <= chrono::Utc::now() + chrono::Duration::seconds(REFRESH_SKEW_SECS);

    if !needs_refresh {
        let token = crypto::decrypt(secret, &access_enc)
            .map_err(|e| AppError::Internal(format!("decrypt access token: {e}")))?;
        return String::from_utf8(token)
            .map_err(|_| AppError::Internal("access token not UTF-8".into()));
    }

    // Refresh.
    let refresh = crypto::decrypt(secret, &refresh_enc)
        .map_err(|e| AppError::Internal(format!("decrypt refresh token: {e}")))?;
    let refresh = String::from_utf8(refresh)
        .map_err(|_| AppError::Internal("refresh token not UTF-8".into()))?;

    let tokens = client.refresh_token(&refresh).await?;
    let new_refresh = tokens.refresh_token.unwrap_or(refresh);
    let new_access_enc = crypto::encrypt(secret, tokens.access_token.as_bytes());
    let new_refresh_enc = crypto::encrypt(secret, new_refresh.as_bytes());
    let new_expiry = chrono::Utc::now() + chrono::Duration::seconds(tokens.expires_in.max(60));

    sqlx::query(
        "UPDATE broadcasters SET access_token_enc=$1, refresh_token_enc=$2, \
         token_expires_at=$3, updated_at=now() WHERE kick_channel_id=$4",
    )
    .bind(&new_access_enc)
    .bind(&new_refresh_enc)
    .bind(new_expiry)
    .bind(kick_channel_id)
    .execute(&state.pool)
    .await?;

    Ok(tokens.access_token)
}
