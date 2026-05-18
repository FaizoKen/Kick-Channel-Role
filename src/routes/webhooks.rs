//! Kick webhook ingestor. Single app-wide URL (`/webhooks/kick`); Kick
//! routes every event for every subscribed channel here. We:
//!   1. verify the HMAC signature (reject unsigned/old/forged),
//!   2. dedupe on message_id (Kick retries on 5xx + occasional double-fire),
//!   3. apply the fact change to `channel_relations` / `broadcasters`,
//!   4. enqueue a player_sync (or channel_sync) so roles converge.
//!
//! TODO(kick-docs): the exact header names, signed-message construction, and
//! event payload field paths are based on Twitch-EventSub conventions and
//! must be reconciled against Kick's webhook spec at integration time. The
//! mechanics (verify → dedupe → apply → enqueue) are spec-independent.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::Value;

use crate::services::jobs;
use crate::services::kick::KickClient;
use crate::AppState;

// Header names — TODO(kick-docs): confirm. Twitch uses `Twitch-Eventsub-*`.
const H_MESSAGE_ID: &str = "kick-event-message-id";
const H_TIMESTAMP: &str = "kick-event-message-timestamp";
const H_SIGNATURE: &str = "kick-event-signature";
const H_EVENT_TYPE: &str = "kick-event-type";

pub async fn kick_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let hv = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
    let message_id = hv(H_MESSAGE_ID).to_string();
    let timestamp = hv(H_TIMESTAMP).to_string();
    let signature = hv(H_SIGNATURE).to_string();
    let header_event_type = hv(H_EVENT_TYPE).to_string();

    let Some(secret) = state.config.kick.webhook_secret.as_deref() else {
        tracing::error!("Webhook received but KICK_WEBHOOK_SECRET is not configured");
        return (StatusCode::INTERNAL_SERVER_ERROR, "not configured");
    };

    if message_id.is_empty() || timestamp.is_empty() || signature.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing signature headers");
    }

    if !KickClient::verify_webhook_signature(&message_id, &timestamp, &body, secret, &signature) {
        tracing::warn!(message_id, "Webhook signature verification failed");
        return (StatusCode::UNAUTHORIZED, "bad signature");
    }

    // Idempotency: first writer wins; duplicates are acked without reprocess.
    let inserted = sqlx::query(
        "INSERT INTO webhook_deliveries (message_id, event_type) VALUES ($1, $2) \
         ON CONFLICT (message_id) DO NOTHING",
    )
    .bind(&message_id)
    .bind(&header_event_type)
    .execute(&state.pool)
    .await;
    match inserted {
        Ok(r) if r.rows_affected() == 0 => {
            return (StatusCode::OK, "duplicate ignored");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("webhook_deliveries insert failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error");
        }
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(message_id, "Webhook body not JSON: {e}");
            return (StatusCode::BAD_REQUEST, "bad json");
        }
    };

    let event_type = if !header_event_type.is_empty() {
        header_event_type
    } else {
        payload
            .get("event")
            .and_then(Value::as_str)
            .or_else(|| payload.get("type").and_then(Value::as_str))
            .unwrap_or("")
            .to_string()
    };

    if let Err(e) = apply_event(&state, &event_type, &payload).await {
        // We've already deduped this message_id, so a transient failure here
        // would be lost on Kick's retry. Re-open the delivery for retry by
        // deleting the idempotency row, then 500 so Kick resends.
        let _ = sqlx::query("DELETE FROM webhook_deliveries WHERE message_id = $1")
            .bind(&message_id)
            .execute(&state.pool)
            .await;
        tracing::error!(message_id, event_type, "apply_event failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "apply failed");
    }

    (StatusCode::OK, "ok")
}

/// Pull the first integer found at any of the given dot-free keys, searched
/// at the top level and under common envelope keys (`data`, `event`).
fn dig_i64(p: &Value, keys: &[&str]) -> Option<i64> {
    let scopes = [Some(p), p.get("data"), p.get("event")];
    for scope in scopes.into_iter().flatten() {
        for k in keys {
            if let Some(n) = scope.get(*k).and_then(Value::as_i64) {
                return Some(n);
            }
            // user_id sometimes nested under {"user":{"id":N}}
            if let Some(n) = scope
                .get(k.trim_end_matches("_id"))
                .and_then(|o| o.get("id"))
                .and_then(Value::as_i64)
            {
                return Some(n);
            }
        }
    }
    None
}

fn dig_str(p: &Value, keys: &[&str]) -> Option<String> {
    let scopes = [Some(p), p.get("data"), p.get("event")];
    for scope in scopes.into_iter().flatten() {
        for k in keys {
            if let Some(s) = scope.get(*k).and_then(Value::as_str) {
                return Some(s.to_string());
            }
        }
    }
    None
}

async fn apply_event(
    state: &Arc<AppState>,
    event_type: &str,
    p: &Value,
) -> Result<(), crate::error::AppError> {
    let pool = &state.pool;
    let channel_id = dig_i64(p, &["broadcaster_user_id", "channel_id", "broadcaster_id"]);
    let user_id = dig_i64(p, &["user_id", "subscriber_id", "follower_id"]);

    // Normalize a few likely spellings.
    let et = event_type.to_ascii_lowercase();

    // Live state is kept only for the admin "LIVE" badge — no rule depends
    // on it anymore, so we update the column but do NOT fan out a re-sync
    // (that was the mass add/remove-everyone path we removed by design).
    if et.contains("stream.online") || et.contains("livestream.online") {
        if let Some(cid) = channel_id {
            sqlx::query(
                "UPDATE broadcasters SET is_live = true, live_started_at = now(), \
                 current_category = COALESCE($2, current_category), updated_at = now() \
                 WHERE kick_channel_id = $1",
            )
            .bind(cid)
            .bind(dig_str(p, &["category", "category_name"]))
            .execute(pool)
            .await?;
        }
        return Ok(());
    }
    if et.contains("stream.offline") || et.contains("livestream.offline") {
        if let Some(cid) = channel_id {
            sqlx::query(
                "UPDATE broadcasters SET is_live = false, last_live_at = now(), \
                 viewer_count = 0, updated_at = now() WHERE kick_channel_id = $1",
            )
            .bind(cid)
            .execute(pool)
            .await?;
        }
        return Ok(());
    }

    let (Some(cid), Some(uid)) = (channel_id, user_id) else {
        tracing::warn!(event_type, "webhook missing channel/user id; skipping");
        return Ok(());
    };

    // Ensure a channel_relations row exists, then patch the changed facts.
    ensure_relation(pool, cid, uid).await?;

    if et.contains("unfollow") {
        sqlx::query("UPDATE channel_relations SET is_follower=false, last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(uid).execute(pool).await?;
    } else if et.contains("follow") {
        sqlx::query("UPDATE channel_relations SET is_follower=true, followed_at=COALESCE(followed_at, now()), last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(uid).execute(pool).await?;
    } else if et.contains("subscription.gift") || et.contains("gifts") {
        // Gifter sent subs; recipients each become subscribers. The gifter is
        // identified by `gifter_user_id`; recipients under `user_ids`/`giftees`.
        if let Some(gifter) = dig_i64(p, &["gifter_user_id", "gifter_id"]) {
            ensure_relation(pool, cid, gifter).await?;
            let qty = dig_i64(p, &["quantity", "amount", "count"]).unwrap_or(1);
            sqlx::query("UPDATE channel_relations SET gifted_subs_given = gifted_subs_given + $3, last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
                .bind(cid).bind(gifter).bind(qty).execute(pool).await?;
            enqueue_for_kick_user(state, gifter).await?;
        }
        sqlx::query("UPDATE channel_relations SET is_subscriber=true, sub_is_gift=true, subscribed_at=COALESCE(subscribed_at, now()), sub_streak_months=GREATEST(sub_streak_months,1), sub_months_cumulative=GREATEST(sub_months_cumulative,1), last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(uid).execute(pool).await?;
    } else if et.contains("subscription.renew") || et.contains("renewal") {
        let months = dig_i64(p, &["months", "cumulative_months", "total_months"]);
        sqlx::query(
            "UPDATE channel_relations SET is_subscriber=true, \
             sub_months_cumulative = GREATEST(sub_months_cumulative + 1, COALESCE($3, sub_months_cumulative)), \
             sub_streak_months = sub_streak_months + 1, last_synced_at=now() \
             WHERE kick_channel_id=$1 AND kick_user_id=$2",
        )
        .bind(cid).bind(uid).bind(months).execute(pool).await?;
    } else if et.contains("subscription.new")
        || et.contains("subscription.create")
        || (et.contains("subscription") && !et.contains("cancel") && !et.contains("end"))
    {
        sqlx::query("UPDATE channel_relations SET is_subscriber=true, subscribed_at=COALESCE(subscribed_at, now()), sub_months_cumulative=GREATEST(sub_months_cumulative,1), sub_streak_months=GREATEST(sub_streak_months,1), last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(uid).execute(pool).await?;
    } else if et.contains("subscription.cancel")
        || et.contains("subscription.end")
        || et.contains("subscription.expire")
    {
        sqlx::query("UPDATE channel_relations SET is_subscriber=false, sub_streak_months=0, last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(uid).execute(pool).await?;
    } else {
        tracing::debug!(event_type, "unhandled webhook event type; recorded only");
        return Ok(());
    }

    enqueue_for_kick_user(state, uid).await?;
    Ok(())
}

async fn ensure_relation(
    pool: &sqlx::PgPool,
    channel_id: i64,
    user_id: i64,
) -> Result<(), crate::error::AppError> {
    sqlx::query(
        "INSERT INTO channel_relations (kick_channel_id, kick_user_id) \
         VALUES ($1,$2) ON CONFLICT (kick_channel_id, kick_user_id) DO NOTHING",
    )
    .bind(channel_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Enqueue a player_sync for the Discord user behind a Kick user_id, if linked.
async fn enqueue_for_kick_user(
    state: &Arc<AppState>,
    kick_user_id: i64,
) -> Result<(), crate::error::AppError> {
    let discord_id: Option<String> =
        sqlx::query_scalar("SELECT discord_id FROM kick_users WHERE kick_user_id = $1")
            .bind(kick_user_id)
            .fetch_optional(&state.pool)
            .await?;
    if let Some(did) = discord_id {
        jobs::enqueue_player_sync(&state.pool, &did).await?;
    }
    Ok(())
}
