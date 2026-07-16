//! Reconcile worker. Every 6h, for each connected channel: refresh live
//! state, expire lapsed subscriptions, then fan out a channel_sync so role
//! assignments converge even if some webhooks were dropped. Also GCs
//! expired OAuth state + old webhook-delivery idempotency rows.
//!
//! Kick's public API has NO list endpoints for followers / subscribers /
//! VIPs / moderators, so — unlike the Twitch plugin — membership facts
//! cannot be rebuilt here; the webhook stream (incl. chat badges) is the
//! only source and is authoritative. An earlier version of this worker
//! called imagined list endpoints, treated their failure as an empty list,
//! and wiped every relationship flag to false each cycle — never reset
//! facts to defaults on a fetch failure.
//!
//! Sub expiry: Kick sends no subscription-cancelled event. Subscription
//! webhooks record `expires_at`; here we flip `is_subscriber` off once
//! that timestamp is a grace-window in the past (renewal webhooks push it
//! forward before that in the healthy path).

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

/// Refresh one channel's live state, expire lapsed subscriptions, and fan
/// out a `channel_sync`. Used by the periodic reconcile loop and by the
/// on-demand `channel_refresh` job (member-triggered from the verify page).
pub async fn reconcile_channel(
    state: &Arc<AppState>,
    client: &KickClient,
    cid: i64,
) -> Result<(), crate::error::AppError> {
    let token = valid_access_token(state, client, cid).await?;

    // 0. Self-heal webhook subscriptions: (re)subscribe any event type this
    // channel has no active subscription for. Covers channels connected
    // before a subscription bug-fix or an EVENT_TYPES catalog change —
    // without this, only a broadcaster reconnect would pick those up.
    if let Err(e) =
        crate::routes::oauth::subscribe_missing_channel_events(state, client, cid, &token).await
    {
        tracing::warn!(kick_channel_id = cid, "subscription self-heal failed: {e}");
    }

    // 1. Live state (also proves the broadcaster token still works).
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

    // 2. Expire lapsed subscriptions. A renewal webhook advances
    // `sub_expires_at` before this fires in the healthy path; the 2-day
    // grace absorbs webhook delivery lag and renewal retries so we don't
    // flap a role off and back on around the billing edge.
    sqlx::query(
        "UPDATE channel_relations SET is_subscriber=false, sub_streak_months=0, \
         last_synced_at=now() \
         WHERE kick_channel_id=$1 AND is_subscriber \
           AND sub_expires_at IS NOT NULL \
           AND sub_expires_at < now() - interval '2 days'",
    )
    .bind(cid)
    .execute(&state.pool)
    .await?;

    // 3. Re-evaluate every role link bound to this channel.
    jobs::enqueue_channel_sync(&state.pool, cid).await?;
    Ok(())
}
