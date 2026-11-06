//! Kick webhook ingestor. Single app-wide URL (`/webhooks/kick`); Kick
//! routes every event for every subscribed channel here. We:
//!   1. verify the RSA signature (reject unsigned/old/forged) using Kick's
//!      published public key (`GET /public/v1/public-key`, cached in
//!      AppState, refetched once on a miss to survive key rotation),
//!   2. dedupe on message_id (Kick retries on 5xx + occasional double-fire),
//!   3. apply the fact change to `channel_relations` / `broadcasters`,
//!   4. enqueue a player_sync so roles converge.
//!
//! Payload shapes follow docs.kick.com "Webhook Payloads": user objects are
//! nested (`broadcaster.user_id`, `follower.user_id`, `subscriber.user_id`,
//! `gifter.user_id`, `giftees[].user_id`, `sender.user_id`).
//!
//! Kick has NO unfollow or subscription-cancelled events and no list
//! endpoints to rebuild from, so:
//!   * sub lapses are handled by `sub_expires_at` (stored here from the
//!     event's `expires_at`) + the reconcile worker's expiry sweep;
//!   * VIP / moderator / OG are channel badges visible only on
//!     `chat.message.sent` — each chat message is an authoritative snapshot
//!     of the sender's badge set for that channel, so we sync those three
//!     booleans (set AND clear) from it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::services::jobs;
use crate::services::kick;
use crate::AppState;

// Header names per docs.kick.com "Webhook Security" (matched
// case-insensitively by axum's HeaderMap).
const H_MESSAGE_ID: &str = "kick-event-message-id";
const H_TIMESTAMP: &str = "kick-event-message-timestamp";
const H_SIGNATURE: &str = "kick-event-signature";
const H_EVENT_TYPE: &str = "kick-event-type";

/// Least time between forced key refetches. This route is outside the per-IP
/// limiter, so a signature miss must not cost a call to Kick every time; a
/// real rotation is still picked up within this window.
const FORCED_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Get Kick's signing key from the AppState cache, fetching it on first use.
/// `force` bypasses the cache (signature-miss path: key may have rotated),
/// at most once per `FORCED_REFETCH_INTERVAL`; `None` inside that window.
async fn signing_key(state: &Arc<AppState>, force: bool) -> Option<rsa::RsaPublicKey> {
    if !force {
        if let Some(k) = state.kick_public_key.read().await.as_ref() {
            return Some(k.clone());
        }
    } else {
        let mut last = state.kick_public_key_refetched_at.lock().await;
        if last.is_some_and(|at| at.elapsed() < FORCED_REFETCH_INTERVAL) {
            return None;
        }
        *last = Some(Instant::now());
    }
    match kick::fetch_public_key(&state.http).await {
        Ok(k) => {
            *state.kick_public_key.write().await = Some(k.clone());
            Some(k)
        }
        Err(e) => {
            tracing::error!("failed to fetch Kick public key: {e}");
            None
        }
    }
}

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

    if message_id.is_empty() || timestamp.is_empty() || signature.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing signature headers");
    }

    let Some(key) = signing_key(&state, false).await else {
        // Can't verify without the key; 500 so Kick retries later.
        return (StatusCode::INTERNAL_SERVER_ERROR, "no signing key");
    };
    let mut verified =
        kick::verify_webhook_signature(&key, &message_id, &timestamp, &body, &signature);
    if !verified {
        // One forced refetch: the cached key may predate a rotation.
        if let Some(fresh) = signing_key(&state, true).await {
            verified =
                kick::verify_webhook_signature(&fresh, &message_id, &timestamp, &body, &signature);
        }
    }
    if !verified {
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

/// `payload.<obj>.user_id` — the shape every Kick webhook uses for people.
fn user_id_of(p: &Value, obj: &str) -> Option<i64> {
    p.get(obj)?.get("user_id")?.as_i64()
}

/// `payload.<obj>.<key>` as a Kick identifier (slug or username) fit to store
/// and later put in a kick.com URL; anything else is ignored.
fn identifier_of<'a>(p: &'a Value, obj: &str, key: &str) -> Option<&'a str> {
    p.get(obj)?
        .get(key)?
        .as_str()
        .filter(|s| crate::services::kick::is_kick_identifier(s))
}

/// Keep stored names current from the event itself. Kick lets streamers and
/// viewers rename, and every event names the channel (`broadcaster.
/// channel_slug`, `broadcaster.username`) and its actor (`sender`,
/// `follower`, …). A renamed channel's old slug made every follow probe for
/// it answer "Channel not found" and broke its kick.com links — in 11-2026,
/// 11 of 162 connected channels, one with 212 linked members — and an old
/// slug someone else later claims points the probe at the wrong channel.
/// Each UPDATE only writes when a name actually changed. Best-effort: a
/// failure here must never drop the event.
async fn note_identities(pool: &sqlx::PgPool, cid: i64, p: &Value) {
    if let Some(slug) = identifier_of(p, "broadcaster", "channel_slug") {
        let name = identifier_of(p, "broadcaster", "username");
        if let Err(e) = store_channel_name(pool, cid, slug, name).await {
            tracing::debug!(kick_channel_id = cid, "broadcaster rename not stored: {e}");
        }
    }
    for actor in ["sender", "follower", "subscriber", "gifter"] {
        let (Some(uid), Some(username)) = (
            user_id_of(p, actor).filter(|id| *id > 0),
            identifier_of(p, actor, "username"),
        ) else {
            continue;
        };
        if let Err(e) = sqlx::query(
            "UPDATE kick_users SET kick_username = $2 \
             WHERE kick_user_id = $1 AND kick_username IS DISTINCT FROM $2",
        )
        .bind(uid)
        .bind(username)
        .execute(pool)
        .await
        {
            tracing::debug!(kick_user_id = uid, "viewer rename not stored: {e}");
        }
    }
}

/// Store a channel's current slug (and display name, when known). Writes
/// nothing when neither changed. Slugs are unique (`idx_broadcasters_slug`),
/// so if another connected channel still holds this slug from before its own
/// rename, Kick has just told us it is stale: it is parked on a placeholder
/// that no kick.com URL or follow probe accepts (`~` fails both checks) until
/// that channel's own event or reconcile stores its real name.
pub(crate) async fn store_channel_name(
    pool: &sqlx::PgPool,
    cid: i64,
    slug: &str,
    display_name: Option<&str>,
) -> Result<(), sqlx::Error> {
    async fn write(
        pool: &sqlx::PgPool,
        cid: i64,
        slug: &str,
        display_name: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE broadcasters SET kick_slug = $2, \
                    display_name = COALESCE($3, display_name), updated_at = now() \
             WHERE kick_channel_id = $1 \
               AND (kick_slug IS DISTINCT FROM $2 \
                    OR ($3::text IS NOT NULL AND display_name IS DISTINCT FROM $3))",
        )
        .bind(cid)
        .bind(slug)
        .bind(display_name)
        .execute(pool)
        .await
        .map(|_| ())
    }

    match write(pool, cid, slug, display_name).await {
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => {
            sqlx::query(
                "UPDATE broadcasters SET kick_slug = '~renamed-' || kick_channel_id::text \
                 WHERE lower(kick_slug) = lower($2) AND kick_channel_id <> $1",
            )
            .bind(cid)
            .bind(slug)
            .execute(pool)
            .await?;
            write(pool, cid, slug, display_name).await
        }
        other => other,
    }
}

fn ts_of(p: &Value, key: &str) -> Option<DateTime<Utc>> {
    p.get(key)
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
}

async fn apply_event(
    state: &Arc<AppState>,
    event_type: &str,
    p: &Value,
) -> Result<(), crate::error::AppError> {
    let pool = &state.pool;
    let et = event_type.to_ascii_lowercase();

    // Every event carries the channel as `broadcaster.user_id`.
    let Some(cid) = user_id_of(p, "broadcaster") else {
        tracing::warn!(event_type, "webhook missing broadcaster.user_id; skipping");
        return Ok(());
    };

    note_identities(pool, cid, p).await;

    match et.as_str() {
        // Live state is kept only for the admin "LIVE" badge — no rule
        // depends on it, so we update the column but do NOT fan out a
        // re-sync (that was the mass add/remove-everyone path we removed
        // by design).
        "livestream.status.updated" => {
            let is_live = p.get("is_live").and_then(Value::as_bool).unwrap_or(false);
            if is_live {
                sqlx::query(
                    "UPDATE broadcasters SET is_live = true, \
                     live_started_at = COALESCE($2, now()), updated_at = now() \
                     WHERE kick_channel_id = $1",
                )
                .bind(cid)
                .bind(ts_of(p, "started_at"))
                .execute(pool)
                .await?;
            } else {
                sqlx::query(
                    "UPDATE broadcasters SET is_live = false, last_live_at = now(), \
                     viewer_count = 0, updated_at = now() WHERE kick_channel_id = $1",
                )
                .bind(cid)
                .execute(pool)
                .await?;
            }
        }
        "livestream.metadata.updated" => {
            let category = p
                .get("metadata")
                .and_then(|m| m.get("category"))
                .and_then(|c| c.get("name"))
                .and_then(Value::as_str)
                .or_else(|| {
                    p.get("category")
                        .and_then(|c| c.get("name"))
                        .and_then(Value::as_str)
                });
            if let Some(cat) = category {
                sqlx::query(
                    "UPDATE broadcasters SET current_category = $2, updated_at = now() \
                     WHERE kick_channel_id = $1",
                )
                .bind(cid)
                .bind(cat)
                .execute(pool)
                .await?;
            }
        }
        // No unfollow event exists — a stale follow persists until the
        // viewer re-links or support clears it. Documented limitation.
        "channel.followed" => {
            let Some(uid) = user_id_of(p, "follower") else {
                tracing::warn!(event_type, "missing follower.user_id");
                return Ok(());
            };
            ensure_relation(pool, cid, uid).await?;
            sqlx::query(
                "UPDATE channel_relations SET is_follower=true, \
                 followed_at=COALESCE(followed_at, now()), last_synced_at=now() \
                 WHERE kick_channel_id=$1 AND kick_user_id=$2",
            )
            .bind(cid)
            .bind(uid)
            .execute(pool)
            .await?;
            enqueue_for_kick_user(state, uid).await?;
        }
        "channel.subscription.new" => {
            let Some(uid) = user_id_of(p, "subscriber") else {
                tracing::warn!(event_type, "missing subscriber.user_id");
                return Ok(());
            };
            ensure_relation(pool, cid, uid).await?;
            sqlx::query(
                "UPDATE channel_relations SET is_subscriber=true, \
                 subscribed_at=COALESCE(subscribed_at, COALESCE($3, now())), \
                 sub_expires_at=COALESCE($4, sub_expires_at), \
                 sub_months_cumulative=GREATEST(sub_months_cumulative, COALESCE($5, 1)), \
                 sub_streak_months=GREATEST(sub_streak_months, 1), \
                 last_synced_at=now() \
                 WHERE kick_channel_id=$1 AND kick_user_id=$2",
            )
            .bind(cid)
            .bind(uid)
            .bind(ts_of(p, "created_at"))
            .bind(ts_of(p, "expires_at"))
            .bind(p.get("duration").and_then(Value::as_i64))
            .execute(pool)
            .await?;
            enqueue_for_kick_user(state, uid).await?;
        }
        "channel.subscription.renewal" => {
            let Some(uid) = user_id_of(p, "subscriber") else {
                tracing::warn!(event_type, "missing subscriber.user_id");
                return Ok(());
            };
            ensure_relation(pool, cid, uid).await?;
            // `duration` is the subscription's total months when Kick sends
            // it; fall back to a simple increment when absent.
            sqlx::query(
                "UPDATE channel_relations SET is_subscriber=true, \
                 sub_expires_at=COALESCE($4, sub_expires_at), \
                 sub_months_cumulative=GREATEST(sub_months_cumulative + 1, COALESCE($3, 0)), \
                 sub_streak_months=sub_streak_months + 1, \
                 last_synced_at=now() \
                 WHERE kick_channel_id=$1 AND kick_user_id=$2",
            )
            .bind(cid)
            .bind(uid)
            .bind(p.get("duration").and_then(Value::as_i64))
            .bind(ts_of(p, "expires_at"))
            .execute(pool)
            .await?;
            enqueue_for_kick_user(state, uid).await?;
        }
        "channel.subscription.gifts" => {
            let expires_at = ts_of(p, "expires_at");
            let giftees: Vec<i64> = p
                .get("giftees")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|g| g.get("user_id").and_then(Value::as_i64))
                        .collect()
                })
                .unwrap_or_default();

            if let Some(gifter) = user_id_of(p, "gifter") {
                // Kick reports anonymous gifters with user_id 0 / null.
                if gifter > 0 {
                    ensure_relation(pool, cid, gifter).await?;
                    sqlx::query(
                        "UPDATE channel_relations SET \
                         gifted_subs_given = gifted_subs_given + $3, last_synced_at=now() \
                         WHERE kick_channel_id=$1 AND kick_user_id=$2",
                    )
                    .bind(cid)
                    .bind(gifter)
                    .bind(giftees.len().max(1) as i64)
                    .execute(pool)
                    .await?;
                    enqueue_for_kick_user(state, gifter).await?;
                }
            }
            for uid in giftees {
                ensure_relation(pool, cid, uid).await?;
                sqlx::query(
                    "UPDATE channel_relations SET is_subscriber=true, sub_is_gift=true, \
                     subscribed_at=COALESCE(subscribed_at, now()), \
                     sub_expires_at=COALESCE($3, sub_expires_at), \
                     sub_months_cumulative=GREATEST(sub_months_cumulative, 1), \
                     sub_streak_months=GREATEST(sub_streak_months, 1), \
                     last_synced_at=now() \
                     WHERE kick_channel_id=$1 AND kick_user_id=$2",
                )
                .bind(cid)
                .bind(uid)
                .bind(expires_at)
                .execute(pool)
                .await?;
                enqueue_for_kick_user(state, uid).await?;
            }
        }
        // Chat is the ONLY place Kick exposes channel badges (VIP / mod /
        // OG / founder / subscriber months), so this event doubles as our
        // badge-fact sync. High-volume: only enqueue a player_sync when a
        // badge-derived fact actually changed; the pure chat counter
        // converges via the reconcile worker's periodic channel_sync.
        "chat.message.sent" => {
            let Some(uid) = user_id_of(p, "sender") else {
                tracing::warn!(event_type, "missing sender.user_id");
                return Ok(());
            };
            ensure_relation(pool, cid, uid).await?;

            let badges: Vec<(&str, Option<i64>)> = p
                .get("sender")
                .and_then(|s| s.get("identity"))
                .and_then(|i| i.get("badges"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|b| {
                            b.get("type")
                                .and_then(Value::as_str)
                                .map(|t| (t, b.get("count").and_then(Value::as_i64)))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let has = |t: &str| badges.iter().any(|(bt, _)| *bt == t);
            let count_of = |t: &str| badges.iter().find(|(bt, _)| *bt == t).and_then(|(_, c)| *c);

            // Activity counter + presence — always.
            sqlx::query(
                "UPDATE channel_relations SET chat_messages_30d = chat_messages_30d + 1, \
                 last_seen_at = now() WHERE kick_channel_id=$1 AND kick_user_id=$2",
            )
            .bind(cid)
            .bind(uid)
            .execute(pool)
            .await?;
            // …and today's bucket, which is what keeps that counter a real
            // 30-day window: the reconcile worker recomputes it from the last
            // 30 days of buckets (migration 014, tasks::reconcile).
            sqlx::query(
                "INSERT INTO chat_activity_days (kick_channel_id, kick_user_id, day, messages) \
                 VALUES ($1, $2, (now() AT TIME ZONE 'UTC')::date, 1) \
                 ON CONFLICT (kick_channel_id, kick_user_id, day) \
                 DO UPDATE SET messages = chat_activity_days.messages + 1",
            )
            .bind(cid)
            .bind(uid)
            .execute(pool)
            .await?;

            let mut changed = false;

            // Badge snapshot is authoritative for the three channel badges:
            // set AND clear (a de-VIPed viewer loses the flag on next chat).
            let (is_mod, is_vip, is_og) = (has("moderator"), has("vip"), has("og"));
            let r = sqlx::query(
                "UPDATE channel_relations SET is_moderator=$3, is_vip=$4, is_og=$5, \
                 last_synced_at=now() \
                 WHERE kick_channel_id=$1 AND kick_user_id=$2 \
                   AND (is_moderator IS DISTINCT FROM $3 \
                     OR is_vip IS DISTINCT FROM $4 \
                     OR is_og IS DISTINCT FROM $5)",
            )
            .bind(cid)
            .bind(uid)
            .bind(is_mod)
            .bind(is_vip)
            .bind(is_og)
            .execute(pool)
            .await?;
            changed |= r.rows_affected() > 0;

            // Subscriber badge: set-only (the sub lifecycle is owned by
            // subscription events + the expiry sweep; a badge seen in chat
            // can safely raise the floor but never clears the flag). The
            // subscriber badge `count` is months subscribed. The `founder`
            // badge is not a subscription: Kick keeps it on lapsed early subs.
            if has("subscriber") {
                let months = count_of("subscriber").unwrap_or(1).max(1);
                let r = sqlx::query(
                    "UPDATE channel_relations SET is_subscriber=true, \
                     subscribed_at=COALESCE(subscribed_at, now()), \
                     sub_months_cumulative=GREATEST(sub_months_cumulative, $3), \
                     sub_streak_months=GREATEST(sub_streak_months, 1), \
                     last_synced_at=now() \
                     WHERE kick_channel_id=$1 AND kick_user_id=$2 \
                       AND (is_subscriber = false OR sub_months_cumulative < $3)",
                )
                .bind(cid)
                .bind(uid)
                .bind(months)
                .execute(pool)
                .await?;
                changed |= r.rows_affected() > 0;

                // The badge proves the sub is active now, so the expiry sweep
                // must not take it away in the next few days. Without this,
                // a sub whose renewal never reached us (stored expiry weeks
                // old, or none at all) was flipped off every 6-hour reconcile
                // and back on at their next message. A renewal event still
                // sets the exact date. Writes only when the expiry is unset
                // or under a day away.
                sqlx::query(
                    "UPDATE channel_relations \
                     SET sub_expires_at = now() + interval '3 days' \
                     WHERE kick_channel_id=$1 AND kick_user_id=$2 AND is_subscriber \
                       AND (sub_expires_at IS NULL OR sub_expires_at < now() + interval '1 day')",
                )
                .bind(cid)
                .bind(uid)
                .execute(pool)
                .await?;
            }

            // Sub-gifter badge count raises the gifted-subs floor (webhook
            // increments stay authoritative for the exact number).
            if let Some(gifted) = count_of("sub_gifter") {
                let r = sqlx::query(
                    "UPDATE channel_relations SET gifted_subs_given=$3, last_synced_at=now() \
                     WHERE kick_channel_id=$1 AND kick_user_id=$2 AND gifted_subs_given < $3",
                )
                .bind(cid)
                .bind(uid)
                .bind(gifted)
                .execute(pool)
                .await?;
                changed |= r.rows_affected() > 0;
            }

            if changed {
                enqueue_for_kick_user(state, uid).await?;
            }
        }
        "kicks.gifted" => {
            let Some(uid) = user_id_of(p, "sender").or_else(|| user_id_of(p, "gifter")) else {
                tracing::warn!(event_type, "missing sender.user_id");
                return Ok(());
            };
            let amount = p
                .get("gift")
                .and_then(|g| g.get("amount"))
                .and_then(Value::as_i64)
                .or_else(|| p.get("amount").and_then(Value::as_i64))
                .unwrap_or(0);
            if amount > 0 {
                ensure_relation(pool, cid, uid).await?;
                sqlx::query(
                    "UPDATE channel_relations SET kicks_donated = kicks_donated + $3, \
                     last_synced_at=now() WHERE kick_channel_id=$1 AND kick_user_id=$2",
                )
                .bind(cid)
                .bind(uid)
                .bind(amount)
                .execute(pool)
                .await?;
                enqueue_for_kick_user(state, uid).await?;
            }
        }
        _ => {
            tracing::debug!(event_type, "unhandled webhook event type; recorded only");
        }
    }

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
