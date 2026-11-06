//! Get a usable Kick access token for a broadcaster, transparently
//! refreshing (and re-persisting, encrypted) when it's within the refresh
//! window. Centralized so reconcile / any future caller never hand-roll the
//! decrypt → check-expiry → refresh → re-encrypt dance.
//!
//! Two things make this more than a cache check:
//!
//! * **One refresh at a time per channel.** Kick rotates refresh tokens, so a
//!   refresh token is single-use. Two callers refreshing the same channel at
//!   once (the reconcile loop and a member-triggered `channel_refresh` job)
//!   would both spend the same token; the loser gets `invalid_grant`, and a
//!   provider that treats reuse as theft revokes the winner's new token too.
//!   A transaction-scoped advisory lock serialises refreshes per channel, and
//!   the row is re-read under it, so a caller that waited uses the token the
//!   other one just stored.
//! * **A revoked sign-in is final.** Kick answers a dead refresh token with
//!   `invalid_grant` (the streamer removed the app, changed their password,
//!   Kick reset sessions…). That never recovers by retrying, so the first one
//!   stamps `broadcasters.token_invalid_at` (migration 015), callers get
//!   `Ok(None)`, and nothing calls Kick's token endpoint for that channel
//!   again until the broadcaster reconnects, which clears the stamp.

use std::sync::Arc;

use crate::error::AppError;
use crate::services::crypto;
use crate::services::kick::KickClient;
use crate::AppState;

/// Refresh if the token expires within this window.
const REFRESH_SKEW_SECS: i64 = 5 * 60;

type TokenRow = (
    Vec<u8>,
    Vec<u8>,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
);

const SELECT_TOKEN_ROW: &str = "SELECT access_token_enc, refresh_token_enc, token_expires_at, \
     token_invalid_at FROM broadcasters WHERE kick_channel_id = $1";

fn needs_refresh(expires_at: chrono::DateTime<chrono::Utc>) -> bool {
    expires_at <= chrono::Utc::now() + chrono::Duration::seconds(REFRESH_SKEW_SECS)
}

fn decrypt_str(state: &AppState, enc: &[u8], what: &str) -> Result<String, AppError> {
    let bytes = crypto::decrypt(&state.config.session_secret, enc)
        .map_err(|e| AppError::Internal(format!("decrypt {what}: {e}")))?;
    String::from_utf8(bytes).map_err(|_| AppError::Internal(format!("{what} not UTF-8")))
}

/// The channel's current access token, refreshed first if it is about to
/// expire. `Ok(None)` means Kick has revoked the channel's sign-in and the
/// broadcaster must reconnect; `Err` is a transient failure worth retrying.
pub async fn valid_access_token(
    state: &Arc<AppState>,
    client: &KickClient,
    kick_channel_id: i64,
) -> Result<Option<String>, AppError> {
    // Fast path, no lock: the common case is a token that is still good.
    let (access_enc, _, expires_at, invalid_at) = sqlx::query_as::<_, TokenRow>(SELECT_TOKEN_ROW)
        .bind(kick_channel_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("broadcaster {kick_channel_id} not found")))?;
    if invalid_at.is_some() {
        return Ok(None);
    }
    if !needs_refresh(expires_at) {
        return decrypt_str(state, &access_enc, "access token").map(Some);
    }

    // Slow path: refresh under a per-channel lock, re-reading the row once we
    // hold it — another caller may have refreshed (or found the grant
    // revoked) while we waited.
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('kick_token_refresh:' || $1::text, 0))",
    )
    .bind(kick_channel_id)
    .execute(&mut *tx)
    .await?;
    let (access_enc, refresh_enc, expires_at, invalid_at) =
        sqlx::query_as::<_, TokenRow>(SELECT_TOKEN_ROW)
            .bind(kick_channel_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("broadcaster {kick_channel_id} not found"))
            })?;
    if invalid_at.is_some() {
        return Ok(None);
    }
    if !needs_refresh(expires_at) {
        return decrypt_str(state, &access_enc, "access token").map(Some);
    }

    let refresh = decrypt_str(state, &refresh_enc, "refresh token")?;
    let tokens = match client.refresh_token(&refresh).await {
        Ok(t) => t,
        Err(AppError::KickGrantRevoked(status)) => {
            let marked = sqlx::query(
                "UPDATE broadcasters SET token_invalid_at = now(), updated_at = now() \
                 WHERE kick_channel_id = $1 AND token_invalid_at IS NULL",
            )
            .bind(kick_channel_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            tx.commit().await?;
            if marked > 0 {
                // Logged once, when it happens — not every cycle after.
                tracing::warn!(
                    kick_channel_id,
                    %status,
                    "Kick revoked this channel's sign-in (invalid_grant); \
                     the role settings now ask the broadcaster to reconnect"
                );
            }
            return Ok(None);
        }
        Err(e) => return Err(e),
    };

    let new_refresh = tokens.refresh_token.unwrap_or(refresh);
    let secret = &state.config.session_secret;
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
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Some(tokens.access_token))
}
