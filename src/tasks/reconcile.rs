//! Reconcile worker — the webhook-loss safety net. Every 6h, for each
//! connected channel: refresh live state, rebuild the membership facts
//! (followers / subscribers / VIPs / mods) from the broadcaster-token list
//! endpoints, then fan out a channel_sync so role assignments converge even
//! if some webhooks were dropped. Also GCs expired OAuth state + old
//! webhook-delivery idempotency rows.
//!
//! Webhook-accumulated counters (`gifted_subs_given`, `chat_messages_30d`,
//! `kicks_donated`) are intentionally NOT reset here — they can't be
//! re-derived from list endpoints and the webhook stream is authoritative
//! for them.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::services::broadcaster_token::valid_access_token;
use crate::services::jobs;
use crate::services::kick::KickClient;
use crate::tasks::shutdown::ShutdownGuard;
use crate::AppState;

const TICK: Duration = Duration::from_secs(6 * 60 * 60);
/// Run a first reconcile shortly after boot, then every TICK.
const INITIAL_DELAY: Duration = Duration::from_secs(90);

pub async fn run(state: Arc<AppState>, mut shutdown: ShutdownGuard) {
    tracing::info!("Reconcile worker started");

    tokio::select! {
        _ = tokio::time::sleep(INITIAL_DELAY) => {}
        _ = shutdown.wait() => return,
    }

    let mut interval = tokio::time::interval(TICK);
    loop {
        gc(&state).await;

        if let Some(client) = build_client(&state) {
            let channels: Vec<i64> = sqlx::query_scalar("SELECT kick_channel_id FROM broadcasters")
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();

            for cid in channels {
                if shutdown.is_triggered() {
                    break;
                }
                if let Err(e) = reconcile_channel(&state, &client, cid).await {
                    tracing::warn!(kick_channel_id = cid, "reconcile failed: {e}");
                }
            }
        }

        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.wait() => break,
        }
    }

    tracing::info!("Reconcile worker stopped");
}

/// Build a Kick API client from configured OAuth credentials. `None` when the
/// plugin isn't configured for Kick (no client id/secret) — callers should
/// treat that as "nothing to reconcile" rather than an error.
pub fn build_client(state: &Arc<AppState>) -> Option<KickClient> {
    Some(KickClient::new(
        state.config.kick.client_id.clone()?,
        state.config.kick.client_secret.clone()?,
    ))
}

async fn gc(state: &Arc<AppState>) {
    let _ = sqlx::query("DELETE FROM kick_oauth_states WHERE expires_at < now()")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query(
        "DELETE FROM webhook_deliveries WHERE received_at < now() - interval '24 hours'",
    )
    .execute(&state.pool)
    .await;
}

/// Re-pull one channel's live state + membership facts from the broadcaster's
/// list endpoints, write them to `channel_relations`, and fan out a
/// `channel_sync`. Used by the periodic reconcile loop and by the on-demand
/// `channel_refresh` job (member-triggered from the verify page).
pub async fn reconcile_channel(
    state: &Arc<AppState>,
    client: &KickClient,
    cid: i64,
) -> Result<(), crate::error::AppError> {
    let token = valid_access_token(state, client, cid).await?;

    // 1. Live state.
    if let Ok(ch) = client.refresh_channel_live_state(cid, &token).await {
        let is_live = ch.stream.as_ref().map(|s| s.is_live).unwrap_or(false);
        let viewers = ch.stream.as_ref().map(|s| s.viewer_count).unwrap_or(0);
        let category = ch.category.as_ref().and_then(|c| c.name.clone());
        let _ = sqlx::query(
            "UPDATE broadcasters SET is_live=$2, current_category=$3, viewer_count=$4, \
             last_synced_at=now(), updated_at=now() WHERE kick_channel_id=$1",
        )
        .bind(cid)
        .bind(is_live)
        .bind(category.as_deref())
        .bind(viewers)
        .execute(&state.pool)
        .await;
    }

    // 2. Membership facts. Each list endpoint is authoritative for its own
    // boolean — reset, then set the current members true, inside one tx.
    let followers = client.list_followers(cid, &token).await.unwrap_or_default();
    let subscribers = client
        .list_subscribers(cid, &token)
        .await
        .unwrap_or_default();
    let vips = client.list_vips(cid, &token).await.unwrap_or_default();
    let mods = client
        .list_moderators(cid, &token)
        .await
        .unwrap_or_default();

    let mut tx = state.pool.begin().await?;

    // Ensure rows exist for everyone we're about to touch.
    let mut everyone: HashSet<i64> = HashSet::new();
    for f in &followers {
        everyone.insert(f.user_id);
    }
    for s in &subscribers {
        everyone.insert(s.user_id);
    }
    for v in &vips {
        everyone.insert(v.user_id);
    }
    for m in &mods {
        everyone.insert(m.user_id);
    }
    for uid in &everyone {
        sqlx::query(
            "INSERT INTO channel_relations (kick_channel_id, kick_user_id) \
             VALUES ($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(cid)
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    }

    // Reset the four authoritative booleans for this channel.
    sqlx::query(
        "UPDATE channel_relations SET is_follower=false, is_subscriber=false, \
         is_vip=false, is_moderator=false WHERE kick_channel_id=$1",
    )
    .bind(cid)
    .execute(&mut *tx)
    .await?;

    for f in &followers {
        let followed_at = chrono::DateTime::parse_from_rfc3339(&f.followed_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .ok();
        sqlx::query(
            "UPDATE channel_relations SET is_follower=true, \
             followed_at=COALESCE($3, followed_at), last_synced_at=now() \
             WHERE kick_channel_id=$1 AND kick_user_id=$2",
        )
        .bind(cid)
        .bind(f.user_id)
        .bind(followed_at)
        .execute(&mut *tx)
        .await?;
    }
    for s in &subscribers {
        sqlx::query(
            "UPDATE channel_relations SET is_subscriber=true, sub_is_gift=$3, \
             sub_months_cumulative=GREATEST(sub_months_cumulative, COALESCE($4,1)), \
             sub_streak_months=GREATEST(sub_streak_months,1), last_synced_at=now() \
             WHERE kick_channel_id=$1 AND kick_user_id=$2",
        )
        .bind(cid)
        .bind(s.user_id)
        .bind(s.is_gift)
        .bind(s.months_total)
        .execute(&mut *tx)
        .await?;
    }
    for v in &vips {
        sqlx::query("UPDATE channel_relations SET is_vip=true, last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(v.user_id).execute(&mut *tx).await?;
    }
    for m in &mods {
        sqlx::query("UPDATE channel_relations SET is_moderator=true, last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2")
            .bind(cid).bind(m.user_id).execute(&mut *tx).await?;
    }

    tx.commit().await?;

    // 3. Re-evaluate every role link bound to this channel.
    jobs::enqueue_channel_sync(&state.pool, cid).await?;
    Ok(())
}
