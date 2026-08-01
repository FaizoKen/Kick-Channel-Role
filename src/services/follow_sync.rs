//! Applies [`crate::services::kick_probe`] outcomes to `channel_relations`.
//!
//! Kept separate from the probe itself so the *policy* — what a given answer
//! is allowed to change — is readable in one place and testable without any
//! network I/O.
//!
//! # Policy
//!
//! | Outcome | Effect |
//! |---|---|
//! | usable, following | `is_follower = true` immediately; backfills `followed_at` |
//! | usable, not following | counts one miss; removes the follow only after `unfollow_confirmations` **separately-spaced** misses |
//! | unavailable | nothing at all |
//!
//! The asymmetry is deliberate. A positive answer can only ever *grant*, so a
//! wrong one costs a role somebody didn't earn — recoverable, and the sweep
//! will correct it. A negative answer *revokes*, so a wrong one takes a role
//! away from a paying subscriber or long-time follower. Those are not
//! equally bad, and the code should not pretend they are.
//!
//! Everything other than the follow flag is applied **set-only** (`OR` /
//! `GREATEST`): the subscription lifecycle belongs to the subscription
//! webhooks plus the expiry sweep in [`crate::tasks::reconcile`], and the
//! channel badges belong to the `chat.message.sent` snapshot. The probe can
//! add a fact those paths structurally missed, but it must not fight them for
//! ownership.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::error::AppError;
use crate::services::kick_probe::{CardFacts, ProbeOutcome};
use crate::AppState;

/// Minimum gap between two misses that both count toward removal. Two probes
/// inside this window are one observation. With the default confirmation
/// threshold of 3 this puts at least ~12h of consistent "not following"
/// between a real unfollow and the role actually coming off.
const MISS_SPACING: chrono::Duration = chrono::Duration::hours(6);

/// One channel the viewer might have a relationship with.
#[derive(Debug, sqlx::FromRow)]
struct RelationRow {
    kick_channel_id: i64,
    kick_slug: String,
    is_follower: bool,
    is_subscriber: bool,
    is_vip: bool,
    is_moderator: bool,
    is_og: bool,
    sub_months_cumulative: i32,
    follow_probe_misses: i16,
    follow_missed_at: Option<DateTime<Utc>>,
}

/// What a probe run did, for logging and for the verify page's live status.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct ProbeReport {
    /// Channels we attempted.
    pub attempted: usize,
    /// Channels that came back with a usable answer.
    pub usable: usize,
    /// Channels where the viewer was confirmed to be following.
    pub following: usize,
    /// Channels where a follow was actually removed this run.
    pub removed: usize,
    /// Whether any stored fact changed (⇒ roles need re-evaluating).
    pub changed: bool,
}

impl ProbeReport {
    /// True when every attempt failed to produce an answer — i.e. the probe
    /// is effectively unavailable right now and the caller should fall back to
    /// the guided re-follow flow rather than telling the member "you don't
    /// follow this channel".
    pub fn all_unavailable(&self) -> bool {
        self.attempted > 0 && self.usable == 0
    }
}

/// Probe every channel this viewer could hold a relationship with and apply
/// the results.
///
/// This is the "check status at verification" entry point: it is what makes a
/// member who followed *before* linking show up as a follower without the
/// unfollow/re-follow dance. Safe to call repeatedly; enqueues a `player_sync`
/// itself when something changed.
pub async fn probe_and_apply_for_player(
    state: &Arc<AppState>,
    discord_id: &str,
) -> Result<ProbeReport, AppError> {
    let Some(probe) = state.follow_probe.as_ref() else {
        return Ok(ProbeReport::default());
    };

    let linked: Option<(i64, String)> =
        sqlx::query_as("SELECT kick_user_id, kick_username FROM kick_users WHERE discord_id = $1")
            .bind(discord_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((kick_user_id, kick_username)) = linked else {
        return Ok(ProbeReport::default());
    };

    // Baseline rows are seeded at link time, so this covers exactly the
    // channels in the guilds the member belongs to.
    let rows: Vec<RelationRow> = sqlx::query_as(
        "SELECT cr.kick_channel_id, b.kick_slug, cr.is_follower, cr.is_subscriber, \
                cr.is_vip, cr.is_moderator, cr.is_og, cr.sub_months_cumulative, \
                cr.follow_probe_misses, cr.follow_missed_at \
         FROM channel_relations cr \
         JOIN broadcasters b USING (kick_channel_id) \
         WHERE cr.kick_user_id = $1",
    )
    .bind(kick_user_id)
    .fetch_all(&state.pool)
    .await?;

    let mut report = ProbeReport::default();

    for row in rows {
        report.attempted += 1;
        let outcome = probe.probe(&row.kick_slug, &kick_username).await;

        let facts = match outcome {
            ProbeOutcome::Usable(f) => {
                report.usable += 1;
                f
            }
            ProbeOutcome::Unavailable(reason) => {
                // No answer ⇒ no fact is written. The stored relationship
                // stays exactly as the webhook stream left it.
                //
                // We do stamp the *attempt*, which carries no opinion about
                // the relationship — it only tells the backfill this row was
                // tried, so a permanently unreachable one can't monopolise
                // every batch and starve the rest of the backlog.
                tracing::debug!(
                    kick_channel_id = row.kick_channel_id,
                    slug = %row.kick_slug,
                    "follow probe unavailable: {reason}"
                );
                sqlx::query(
                    "UPDATE channel_relations SET follow_probe_attempted_at = now() \
                     WHERE kick_channel_id = $1 AND kick_user_id = $2",
                )
                .bind(row.kick_channel_id)
                .bind(kick_user_id)
                .execute(&state.pool)
                .await?;
                continue;
            }
        };

        if facts.is_following {
            report.following += 1;
        }

        let decision = decide(&row, &facts, state.config.kick.unfollow_confirmations);
        if decision.removes_follow {
            report.removed += 1;
        }
        if decision.changed_facts {
            report.changed = true;
        }

        apply(state, kick_user_id, &row, &facts, &decision).await?;
    }

    if report.all_unavailable() {
        // Every attempt came back with no answer. Usually transient, but a
        // sustained run of this is how we'd find out Kick changed or closed
        // the endpoint — at which point members fall back to the guided
        // re-follow flow and nothing is silently wrong.
        tracing::warn!(
            discord_id = %discord_id,
            attempted = report.attempted,
            "follow probe returned no usable answer for any channel"
        );
    }

    if report.changed {
        crate::services::jobs::enqueue_player_sync(&state.pool, discord_id).await?;
        tracing::info!(
            discord_id = %discord_id,
            kick_user_id,
            attempted = report.attempted,
            following = report.following,
            removed = report.removed,
            "follow probe changed facts; re-evaluating roles"
        );
    }

    Ok(report)
}

/// The write decision for one (viewer, channel) pair. Pure — no I/O — so the
/// removal rule can be tested directly.
#[derive(Debug, PartialEq, Eq)]
struct Decision {
    is_follower: bool,
    /// New miss counter to store.
    misses: i16,
    /// Whether to stamp `follow_missed_at` (i.e. this miss counted).
    counted_miss: bool,
    /// Whether this write flips the follow off.
    removes_follow: bool,
    /// Whether any *role-relevant* fact changes (drives the re-sync).
    changed_facts: bool,
}

fn decide(row: &RelationRow, facts: &CardFacts, confirmations: i16) -> Decision {
    if facts.is_following {
        // Positive: authoritative, immediate, and clears any accumulated
        // doubt. This is the path that fixes the reported bug.
        let gained_extras = (facts.is_subscriber && !row.is_subscriber)
            || (facts.is_vip && !row.is_vip)
            || (facts.is_moderator && !row.is_moderator)
            || (facts.is_og && !row.is_og)
            || (facts.subscribed_for_months > row.sub_months_cumulative as i64);
        return Decision {
            is_follower: true,
            misses: 0,
            counted_miss: false,
            removes_follow: false,
            changed_facts: !row.is_follower || gained_extras,
        };
    }

    // Negative. Extras are still applied set-only below (someone can be a
    // subscriber or a mod without following), so they can still change facts.
    let gained_extras = (facts.is_subscriber && !row.is_subscriber)
        || (facts.is_vip && !row.is_vip)
        || (facts.is_moderator && !row.is_moderator)
        || (facts.is_og && !row.is_og)
        || (facts.subscribed_for_months > row.sub_months_cumulative as i64);

    if !row.is_follower {
        // Nothing to revoke. Don't accumulate misses against a row that never
        // claimed a follow — otherwise the counter is meaningless noise.
        return Decision {
            is_follower: false,
            misses: 0,
            counted_miss: false,
            removes_follow: false,
            changed_facts: gained_extras,
        };
    }

    // We believe they follow, but Kick says otherwise. Only count this if it
    // is an independent observation, spaced from the last one.
    let counts = row
        .follow_missed_at
        .is_none_or(|last| Utc::now() - last >= MISS_SPACING);

    if !counts {
        return Decision {
            is_follower: true,
            misses: row.follow_probe_misses,
            counted_miss: false,
            removes_follow: false,
            changed_facts: gained_extras,
        };
    }

    let misses = row.follow_probe_misses.saturating_add(1);
    if misses >= confirmations {
        Decision {
            is_follower: false,
            misses: 0,
            counted_miss: true,
            removes_follow: true,
            changed_facts: true,
        }
    } else {
        Decision {
            is_follower: true,
            misses,
            counted_miss: true,
            removes_follow: false,
            changed_facts: gained_extras,
        }
    }
}

async fn apply(
    state: &Arc<AppState>,
    kick_user_id: i64,
    row: &RelationRow,
    facts: &CardFacts,
    decision: &Decision,
) -> Result<(), AppError> {
    // `followed_at` is COALESCEd so a webhook-recorded follow date always wins
    // over the probe's; when we're recovering a pre-existing follower it's
    // NULL and the card's `following_since` fills the gap — which is also what
    // finally puts a real date in the public users page's FOLLOWED column
    // instead of an em dash. On removal it's cleared so a later re-follow
    // can't inherit a stale age.
    sqlx::query(
        "UPDATE channel_relations SET \
             is_follower = $3, \
             followed_at = CASE WHEN $3 THEN COALESCE(followed_at, $4, now()) ELSE NULL END, \
             follow_confirmed_at = CASE WHEN $3 THEN now() ELSE follow_confirmed_at END, \
             follow_probed_at = now(), \
             follow_probe_attempted_at = now(), \
             follow_missed_at = CASE WHEN $5 THEN now() ELSE follow_missed_at END, \
             follow_probe_misses = $6, \
             is_subscriber = is_subscriber OR $7, \
             sub_months_cumulative = GREATEST(sub_months_cumulative, $8), \
             is_vip = is_vip OR $9, \
             is_moderator = is_moderator OR $10, \
             is_og = is_og OR $11, \
             last_synced_at = now() \
         WHERE kick_channel_id = $1 AND kick_user_id = $2",
    )
    .bind(row.kick_channel_id)
    .bind(kick_user_id)
    .bind(decision.is_follower)
    .bind(facts.following_since)
    .bind(decision.counted_miss)
    .bind(decision.misses)
    .bind(facts.is_subscriber)
    .bind(i32::try_from(facts.subscribed_for_months.clamp(0, i32::MAX as i64)).unwrap_or(0))
    .bind(facts.is_vip)
    .bind(facts.is_moderator)
    .bind(facts.is_og)
    .execute(&state.pool)
    .await?;

    if decision.removes_follow {
        tracing::info!(
            kick_user_id,
            kick_channel_id = row.kick_channel_id,
            slug = %row.kick_slug,
            "follow removed after {} confirmed negative probes",
            state.config.kick.unfollow_confirmations
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Staleness sweep
// ---------------------------------------------------------------------------

/// How long a known follow may go unverified before the sweep re-checks it.
/// Expressed in seconds to match `make_interval(secs => …)`, which the rest of
/// this codebase uses (its `days` argument takes an int, not a float).
const RECHECK_AFTER_SECS: f64 = 3.0 * 24.0 * 60.0 * 60.0;

/// How long to wait before retrying a relation whose probe never produced a
/// usable answer. Long enough that a Kick-side outage doesn't turn the
/// backfill into a retry storm, short enough to recover within a day.
const BACKFILL_RETRY_AFTER_SECS: f64 = 24.0 * 60.0 * 60.0;

/// Enqueue follow probes for the least-recently-checked viewers.
///
/// Called from the reconcile worker. Bounded per run so the sweep can never
/// turn into a burst of traffic at Kick, and it walks oldest-first so every
/// relation is eventually revisited. Only viewers we currently believe follow
/// something are swept — a viewer with no follows has nothing to revoke and
/// nothing to gain here (their recovery happens at verification instead).
pub async fn sweep_stale_follows(
    state: &Arc<AppState>,
    max_viewers: i64,
) -> Result<usize, AppError> {
    if state.follow_probe.is_none() {
        return Ok(0);
    }

    let discord_ids: Vec<String> = sqlx::query_scalar(
        "SELECT ku.discord_id \
         FROM channel_relations cr \
         JOIN kick_users ku USING (kick_user_id) \
         WHERE cr.is_follower \
           AND (cr.follow_probed_at IS NULL \
                OR cr.follow_probed_at < now() - make_interval(secs => $1)) \
           AND NOT EXISTS ( \
               SELECT 1 FROM jobs j \
               WHERE j.kind = 'follow_probe' \
                 AND j.status IN ('pending', 'in_progress') \
                 AND j.payload->>'discord_id' = ku.discord_id \
           ) \
         GROUP BY ku.discord_id \
         ORDER BY min(cr.follow_probed_at) NULLS FIRST \
         LIMIT $2",
    )
    .bind(RECHECK_AFTER_SECS)
    .bind(max_viewers)
    .fetch_all(&state.pool)
    .await?;

    for discord_id in &discord_ids {
        if let Err(e) = crate::services::jobs::enqueue_follow_probe(&state.pool, discord_id).await {
            tracing::warn!(discord_id = %discord_id, "enqueue follow_probe (sweep) failed: {e}");
        }
    }

    if !discord_ids.is_empty() {
        tracing::info!(count = discord_ids.len(), "follow sweep enqueued re-checks");
    }
    Ok(discord_ids.len())
}

/// Probe viewers whose relationships have **never** been successfully read.
///
/// [`sweep_stale_follows`] deliberately only revisits relations we already
/// believe are follows, because its job is catching unfollows. That leaves the
/// population this whole feature exists for completely untouched: everyone who
/// linked *before* the probe shipped and is sitting at `is_follower = false`
/// through no fault of their own. They would otherwise only be recovered if
/// they happened to revisit the verify page, and a member who has given up on
/// a broken-looking plugin is exactly the member who never comes back.
///
/// This drains that backlog without anyone having to do anything. It is
/// self-limiting rather than a one-shot script: a relation leaves the set as
/// soon as one probe returns a usable answer (in either direction), so the
/// query stops matching once the backlog is gone and costs nothing thereafter.
/// Relations whose probe failed keep their `follow_probed_at` NULL and are
/// retried after [`BACKFILL_RETRY_AFTER_SECS`], ordered least-recently-tried
/// first so no row can monopolise the batch.
///
/// Runs alongside the sweep on the reconcile tick, and skips viewers who
/// already have a probe queued so repeated cycles can't pile up duplicates.
pub async fn backfill_unprobed(state: &Arc<AppState>, max_viewers: i64) -> Result<usize, AppError> {
    if state.follow_probe.is_none() {
        return Ok(0);
    }

    let discord_ids: Vec<String> = sqlx::query_scalar(
        "SELECT ku.discord_id \
         FROM channel_relations cr \
         JOIN kick_users ku USING (kick_user_id) \
         WHERE cr.follow_probed_at IS NULL \
           AND (cr.follow_probe_attempted_at IS NULL \
                OR cr.follow_probe_attempted_at < now() - make_interval(secs => $1)) \
           AND NOT EXISTS ( \
               SELECT 1 FROM jobs j \
               WHERE j.kind = 'follow_probe' \
                 AND j.status IN ('pending', 'in_progress') \
                 AND j.payload->>'discord_id' = ku.discord_id \
           ) \
         GROUP BY ku.discord_id \
         ORDER BY min(cr.follow_probe_attempted_at) NULLS FIRST \
         LIMIT $2",
    )
    .bind(BACKFILL_RETRY_AFTER_SECS)
    .bind(max_viewers)
    .fetch_all(&state.pool)
    .await?;

    for discord_id in &discord_ids {
        if let Err(e) = crate::services::jobs::enqueue_follow_probe(&state.pool, discord_id).await {
            tracing::warn!(discord_id = %discord_id, "enqueue follow_probe (backfill) failed: {e}");
        }
    }

    if !discord_ids.is_empty() {
        tracing::info!(
            count = discord_ids.len(),
            "follow backfill enqueued probes for never-checked viewers"
        );
    }
    Ok(discord_ids.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(is_follower: bool, misses: i16, missed_ago_hours: Option<i64>) -> RelationRow {
        RelationRow {
            kick_channel_id: 1,
            kick_slug: "itztmgg".into(),
            is_follower,
            is_subscriber: false,
            is_vip: false,
            is_moderator: false,
            is_og: false,
            sub_months_cumulative: 0,
            follow_probe_misses: misses,
            follow_missed_at: missed_ago_hours.map(|h| Utc::now() - chrono::Duration::hours(h)),
        }
    }

    fn following() -> CardFacts {
        CardFacts {
            is_following: true,
            ..Default::default()
        }
    }
    fn not_following() -> CardFacts {
        CardFacts::default()
    }

    #[test]
    fn preexisting_follower_is_granted_on_first_positive_probe() {
        // The reported bug: followed before linking, no webhook ever fired.
        let d = decide(&row(false, 0, None), &following(), 3);
        assert!(d.is_follower);
        assert!(d.changed_facts, "must trigger a role re-sync");
        assert!(!d.removes_follow);
    }

    #[test]
    fn positive_probe_clears_accumulated_misses() {
        let d = decide(&row(true, 2, Some(24)), &following(), 3);
        assert_eq!(d.misses, 0);
        assert!(d.is_follower);
    }

    #[test]
    fn steady_state_follower_causes_no_resync_churn() {
        let mut r = row(true, 0, None);
        r.is_follower = true;
        let d = decide(&r, &following(), 3);
        assert!(d.is_follower);
        assert!(!d.changed_facts, "no change ⇒ no pointless player_sync");
    }

    #[test]
    fn single_negative_never_revokes() {
        let d = decide(&row(true, 0, None), &not_following(), 3);
        assert!(d.is_follower, "one bad read must not cost a role");
        assert_eq!(d.misses, 1);
        assert!(!d.removes_follow);
    }

    #[test]
    fn revokes_only_on_the_configured_number_of_spaced_negatives() {
        // Two prior spaced misses already recorded; this is the third.
        let d = decide(&row(true, 2, Some(24)), &not_following(), 3);
        assert!(!d.is_follower);
        assert!(d.removes_follow);
        assert!(d.changed_facts);
        assert_eq!(d.misses, 0, "counter resets after acting");
    }

    #[test]
    fn rapid_rechecks_cannot_inflate_the_miss_count() {
        // Member mashing "Re-check now": last miss was minutes ago.
        let d = decide(&row(true, 2, Some(0)), &not_following(), 3);
        assert!(d.is_follower, "spacing gate must hold the role");
        assert_eq!(d.misses, 2, "counter must not advance");
        assert!(!d.counted_miss);
    }

    #[test]
    fn non_follower_negatives_do_not_accumulate() {
        let d = decide(&row(false, 0, None), &not_following(), 3);
        assert_eq!(d.misses, 0);
        assert!(!d.changed_facts);
    }

    #[test]
    fn extras_are_recovered_even_when_not_following() {
        // Subscribed before linking but never followed — the same pre-link
        // blind spot, different fact.
        let facts = CardFacts {
            is_following: false,
            subscribed_for_months: 4,
            is_subscriber: true,
            ..Default::default()
        };
        let d = decide(&row(false, 0, None), &facts, 3);
        assert!(d.changed_facts, "recovered sub must trigger a re-sync");
        assert!(!d.is_follower);
    }

    #[test]
    fn a_higher_confirmation_threshold_is_honoured() {
        let d = decide(&row(true, 4, Some(24)), &not_following(), 6);
        assert!(d.is_follower, "5 of 6 — not yet");
        assert_eq!(d.misses, 5);
    }

    /// Exercise every hand-written statement this module and the verify page
    /// added, against a real Postgres.
    ///
    /// None of it is checked by the compiler: the new columns from migration
    /// 013, each bind's inferred type (`SMALLINT` for the miss counter, the
    /// `COALESCE(followed_at, $4, now())` timestamptz inference, the
    /// `make_interval(secs => …)` double), and the `USING (kick_channel_id)`
    /// joins are all validated by the server at execution time. A typo in any
    /// of them is a runtime 500 that compiles and ships happily — and it would
    /// land on the exact verification path this change exists to fix.
    ///
    /// Skips when `DATABASE_URL` is unset or unreachable. Runs migrations
    /// first (so 013 is present), then reads only — seeds nothing, and every
    /// write is scoped to a sentinel key pair that matches no real row.
    #[tokio::test]
    async fn new_sql_is_accepted_by_postgres() {
        dotenvy::dotenv().ok();
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping live-schema check");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("database unreachable — skipping live-schema check");
            return;
        };
        crate::db::run_migrations(&pool).await;

        // 1. The per-viewer relation read (probe input).
        let rows = sqlx::query_as::<_, RelationRow>(
            "SELECT cr.kick_channel_id, b.kick_slug, cr.is_follower, cr.is_subscriber, \
                    cr.is_vip, cr.is_moderator, cr.is_og, cr.sub_months_cumulative, \
                    cr.follow_probe_misses, cr.follow_missed_at \
             FROM channel_relations cr \
             JOIN broadcasters b USING (kick_channel_id) \
             WHERE cr.kick_user_id = $1",
        )
        .bind(-1_i64)
        .fetch_all(&pool)
        .await;
        assert!(rows.is_ok(), "relation read: {:?}", rows.err());

        // 2. The apply UPDATE, with every bind populated. Scoped to a
        // (-1, -1) key that cannot exist, so this matches zero rows while
        // still forcing Postgres to type-check all 11 parameters.
        let upd = sqlx::query(
            "UPDATE channel_relations SET \
                 is_follower = $3, \
                 followed_at = CASE WHEN $3 THEN COALESCE(followed_at, $4, now()) ELSE NULL END, \
                 follow_confirmed_at = CASE WHEN $3 THEN now() ELSE follow_confirmed_at END, \
                 follow_probed_at = now(), \
                 follow_missed_at = CASE WHEN $5 THEN now() ELSE follow_missed_at END, \
                 follow_probe_misses = $6, \
                 is_subscriber = is_subscriber OR $7, \
                 sub_months_cumulative = GREATEST(sub_months_cumulative, $8), \
                 is_vip = is_vip OR $9, \
                 is_moderator = is_moderator OR $10, \
                 is_og = is_og OR $11, \
                 last_synced_at = now() \
             WHERE kick_channel_id = $1 AND kick_user_id = $2",
        )
        .bind(-1_i64)
        .bind(-1_i64)
        .bind(true)
        .bind(Some(Utc::now()))
        .bind(true)
        .bind(1_i16)
        .bind(true)
        .bind(3_i32)
        .bind(true)
        .bind(true)
        .bind(true)
        .execute(&pool)
        .await;
        assert!(upd.is_ok(), "apply update: {:?}", upd.err());
        assert_eq!(
            upd.unwrap().rows_affected(),
            0,
            "sentinel key must not touch real rows"
        );

        // 3. The staleness sweep.
        let sweep = sqlx::query_scalar::<_, String>(
            "SELECT ku.discord_id \
             FROM channel_relations cr \
             JOIN kick_users ku USING (kick_user_id) \
             WHERE cr.is_follower \
               AND (cr.follow_probed_at IS NULL \
                    OR cr.follow_probed_at < now() - make_interval(secs => $1)) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM jobs j \
                   WHERE j.kind = 'follow_probe' \
                     AND j.status IN ('pending', 'in_progress') \
                     AND j.payload->>'discord_id' = ku.discord_id \
               ) \
             GROUP BY ku.discord_id \
             ORDER BY min(cr.follow_probed_at) NULLS FIRST \
             LIMIT $2",
        )
        .bind(RECHECK_AFTER_SECS)
        .bind(1_i64)
        .fetch_all(&pool)
        .await;
        assert!(sweep.is_ok(), "sweep: {:?}", sweep.err());

        // 3b. The backfill.
        let backfill = sqlx::query_scalar::<_, String>(
            "SELECT ku.discord_id \
             FROM channel_relations cr \
             JOIN kick_users ku USING (kick_user_id) \
             WHERE cr.follow_probed_at IS NULL \
               AND (cr.follow_probe_attempted_at IS NULL \
                    OR cr.follow_probe_attempted_at < now() - make_interval(secs => $1)) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM jobs j \
                   WHERE j.kind = 'follow_probe' \
                     AND j.status IN ('pending', 'in_progress') \
                     AND j.payload->>'discord_id' = ku.discord_id \
               ) \
             GROUP BY ku.discord_id \
             ORDER BY min(cr.follow_probe_attempted_at) NULLS FIRST \
             LIMIT $2",
        )
        .bind(BACKFILL_RETRY_AFTER_SECS)
        .bind(1_i64)
        .fetch_all(&pool)
        .await;
        assert!(backfill.is_ok(), "backfill: {:?}", backfill.err());

        // 4. The verify page's per-channel status read, both scoped and
        // unscoped (the `$2::text = ''` branch).
        for guild in ["", "619762818266431547"] {
            let rel = sqlx::query(
                "SELECT cr.kick_channel_id, b.kick_slug, b.display_name, \
                        cr.is_follower, cr.is_subscriber, cr.is_vip, cr.is_og, cr.is_moderator, \
                        (cr.follow_probed_at IS NOT NULL) AS probed \
                 FROM channel_relations cr \
                 JOIN broadcasters b USING (kick_channel_id) \
                 WHERE cr.kick_user_id = $1 \
                   AND ($2::text = '' OR EXISTS ( \
                           SELECT 1 FROM guild_broadcasters gb \
                           WHERE gb.guild_id = $2::text \
                             AND gb.kick_channel_id = cr.kick_channel_id)) \
                 ORDER BY b.display_name \
                 LIMIT 50",
            )
            .bind(-1_i64)
            .bind(guild)
            .fetch_all(&pool)
            .await;
            assert!(
                rel.is_ok(),
                "relations read (guild={guild:?}): {:?}",
                rel.err()
            );
        }

        // 5. The in-flight probe dedupe both call sites rely on.
        let dedupe = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM jobs \
                 WHERE kind = 'follow_probe' \
                   AND status IN ('pending', 'in_progress') \
                   AND payload->>'discord_id' = $1 \
             )",
        )
        .bind("0")
        .fetch_one(&pool)
        .await;
        assert!(dedupe.is_ok(), "probe dedupe: {:?}", dedupe.err());
    }

    /// End-to-end: stubbed Kick user-card endpoint → probe → Postgres → the
    /// follow decision, exercising the actual reported bug and its fix.
    ///
    /// The unit tests above cover the decision rules in isolation and the
    /// query test covers the SQL, but neither proves the pieces are wired
    /// together correctly — that a member who followed *before* linking
    /// actually ends up with `is_follower = true`. This does, and it's the
    /// only test that would catch a mistake in the loop, the bind order, or
    /// the `COALESCE(followed_at, …)` backfill.
    ///
    /// `KICK_PROBE_BASE_URL` exists precisely so this can point at a stub
    /// instead of the live site. Skips without a reachable `DATABASE_URL`.
    /// Seeds negative sentinel IDs and deletes them again.
    #[tokio::test]
    async fn probe_recovers_a_preexisting_follower_end_to_end() {
        use std::sync::atomic::{AtomicBool, Ordering};

        dotenvy::dotenv().ok();
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping end-to-end probe check");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("database unreachable — skipping end-to-end probe check");
            return;
        };
        crate::db::run_migrations(&pool).await;

        const CH: i64 = -9001;
        const UID: i64 = -9001;
        const DISCORD: &str = "test-probe-discord-9001";
        const SLUG: &str = "stub-probe-chan-9001";
        const UNAME: &str = "StubProbeUser9001";

        // --- stub Kick, with a flag to flip it to "not following" ---
        let following = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&following);
        let app = axum::Router::new().route(
            "/api/v2/channels/{slug}/users/{username}",
            axum::routing::get(move || {
                let flag = Arc::clone(&flag);
                async move {
                    let since = if flag.load(Ordering::SeqCst) {
                        "\"2025-11-02 18:04:11\""
                    } else {
                        "null"
                    };
                    axum::response::Response::builder()
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(format!(
                            r#"{{"id":1,"username":"{UNAME}","following_since":{since},
                                 "subscribed_for":0,"badges":[]}}"#
                        )))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stub_base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // --- seed ---
        let cleanup = |p: sqlx::PgPool| async move {
            // channel_relations cascades from broadcasters.
            let _ = sqlx::query("DELETE FROM broadcasters WHERE kick_channel_id = $1")
                .bind(CH)
                .execute(&p)
                .await;
            let _ = sqlx::query("DELETE FROM kick_users WHERE discord_id = $1")
                .bind(DISCORD)
                .execute(&p)
                .await;
            let _ = sqlx::query("DELETE FROM jobs WHERE payload->>'discord_id' = $1")
                .bind(DISCORD)
                .execute(&p)
                .await;
        };
        cleanup(pool.clone()).await;

        sqlx::query(
            "INSERT INTO broadcasters (kick_channel_id, kick_slug, display_name, \
                 access_token_enc, refresh_token_enc, token_expires_at) \
             VALUES ($1,$2,'Stub Probe Chan','\\x00'::bytea,'\\x00'::bytea, now() + interval '1 day')",
        )
        .bind(CH)
        .bind(SLUG)
        .execute(&pool)
        .await
        .expect("seed broadcaster");
        sqlx::query(
            "INSERT INTO kick_users (discord_id, kick_user_id, kick_username, kick_created_at) \
             VALUES ($1,$2,$3, now())",
        )
        .bind(DISCORD)
        .bind(UID)
        .bind(UNAME)
        .execute(&pool)
        .await
        .expect("seed kick_user");
        // The pre-existing follower: linked, relation row seeded, but
        // is_follower=false because no `channel.followed` webhook ever fired.
        sqlx::query("INSERT INTO channel_relations (kick_channel_id, kick_user_id) VALUES ($1,$2)")
            .bind(CH)
            .bind(UID)
            .execute(&pool)
            .await
            .expect("seed relation");

        // --- state wired to the stub ---
        let mut config = crate::config::AppConfig::from_env();
        config.kick.follow_probe_base_url = stub_base.clone();
        config.kick.unfollow_confirmations = 3;
        let state = Arc::new(crate::AppState {
            pool: pool.clone(),
            rl_client: crate::services::rolelogic::RoleLogicClient::new(
                config.rolelogic_api_url.clone(),
            ),
            http: reqwest::Client::new(),
            allowed_origins: vec![],
            draining: std::sync::atomic::AtomicBool::new(false),
            jobs_notify: Arc::new(tokio::sync::Notify::new()),
            kick_public_key: tokio::sync::RwLock::new(None),
            api_rate_limiter: crate::services::api_key::new_rate_limiter(),
            follow_probe: Some(crate::services::kick_probe::FollowProbe::new(
                stub_base, 600,
            )),
            config,
        });

        // --- 1. the fix: a pre-existing follower is recovered ---
        let report = probe_and_apply_for_player(&state, DISCORD)
            .await
            .expect("probe run");
        assert_eq!(report.attempted, 1);
        assert_eq!(report.usable, 1, "stub must give a usable answer");
        assert_eq!(report.following, 1);
        assert!(report.changed, "must trigger a role re-sync");

        let (is_follower, followed_at): (bool, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT is_follower, followed_at FROM channel_relations \
             WHERE kick_channel_id = $1 AND kick_user_id = $2",
        )
        .bind(CH)
        .bind(UID)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(is_follower, "pre-existing follower must now hold the role");
        assert_eq!(
            followed_at.map(|d| d.to_rfc3339()),
            Some("2025-11-02T18:04:11+00:00".to_string()),
            "follow date must be backfilled from the card (fixes the '—' column)"
        );

        // A player_sync must have been queued, or the role never actually
        // reaches Discord.
        let queued: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM jobs WHERE kind = 'player_sync' \
                            AND payload->>'discord_id' = $1)",
        )
        .bind(DISCORD)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(queued, "role re-evaluation must be enqueued");

        // --- 2. a single negative must NOT revoke ---
        following.store(false, Ordering::SeqCst);
        probe_and_apply_for_player(&state, DISCORD).await.unwrap();
        let still: bool = sqlx::query_scalar(
            "SELECT is_follower FROM channel_relations \
             WHERE kick_channel_id = $1 AND kick_user_id = $2",
        )
        .bind(CH)
        .bind(UID)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            still,
            "one negative read must never cost a member their role"
        );

        // --- 3. removal only after the configured spaced confirmations ---
        // Age the last miss past MISS_SPACING to simulate observations spread
        // over time, rather than sleeping 6h.
        for round in 2..=3 {
            sqlx::query(
                "UPDATE channel_relations SET follow_missed_at = now() - interval '7 hours' \
                 WHERE kick_channel_id = $1 AND kick_user_id = $2",
            )
            .bind(CH)
            .bind(UID)
            .execute(&pool)
            .await
            .unwrap();
            probe_and_apply_for_player(&state, DISCORD).await.unwrap();

            let held: bool = sqlx::query_scalar(
                "SELECT is_follower FROM channel_relations \
                 WHERE kick_channel_id = $1 AND kick_user_id = $2",
            )
            .bind(CH)
            .bind(UID)
            .fetch_one(&pool)
            .await
            .unwrap();
            if round < 3 {
                assert!(held, "round {round}: below threshold, must still hold");
            } else {
                assert!(!held, "round {round}: third spaced negative must revoke");
            }
        }

        cleanup(pool).await;
    }

    /// The backfill must rescue a member who linked before the probe existed
    /// and has not touched the verify page since — the population the sweep
    /// deliberately ignores, and the reason a plain "re-check on visit" fix
    /// would have left your existing linked users broken.
    ///
    /// Also asserts the two properties that keep it from becoming an ongoing
    /// cost or a retry storm: it stops selecting a row once that row has a
    /// usable answer, and it skips viewers who already have a probe queued.
    #[tokio::test]
    async fn backfill_rescues_stranded_members_and_then_drains() {
        dotenvy::dotenv().ok();
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping backfill check");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("database unreachable — skipping backfill check");
            return;
        };
        crate::db::run_migrations(&pool).await;

        const CH: i64 = -9002;
        const UID: i64 = -9002;
        const DISCORD: &str = "test-backfill-discord-9002";
        const SLUG: &str = "stub-backfill-chan-9002";

        let cleanup = |p: sqlx::PgPool| async move {
            let _ = sqlx::query("DELETE FROM broadcasters WHERE kick_channel_id = $1")
                .bind(CH)
                .execute(&p)
                .await;
            let _ = sqlx::query("DELETE FROM kick_users WHERE discord_id = $1")
                .bind(DISCORD)
                .execute(&p)
                .await;
            let _ = sqlx::query("DELETE FROM jobs WHERE payload->>'discord_id' = $1")
                .bind(DISCORD)
                .execute(&p)
                .await;
        };
        cleanup(pool.clone()).await;

        sqlx::query(
            "INSERT INTO broadcasters (kick_channel_id, kick_slug, display_name, \
                 access_token_enc, refresh_token_enc, token_expires_at) \
             VALUES ($1,$2,'Stub Backfill','\\x00'::bytea,'\\x00'::bytea, now() + interval '1 day')",
        )
        .bind(CH)
        .bind(SLUG)
        .execute(&pool)
        .await
        .expect("seed broadcaster");
        sqlx::query(
            "INSERT INTO kick_users (discord_id, kick_user_id, kick_username, kick_created_at) \
             VALUES ($1,$2,'StubBackfillUser', now())",
        )
        .bind(DISCORD)
        .bind(UID)
        .execute(&pool)
        .await
        .expect("seed kick_user");
        // The stranded member: linked long ago, never probed, not a follower
        // as far as we know — invisible to the sweep by design.
        sqlx::query("INSERT INTO channel_relations (kick_channel_id, kick_user_id) VALUES ($1,$2)")
            .bind(CH)
            .bind(UID)
            .execute(&pool)
            .await
            .expect("seed relation");

        let state = Arc::new(crate::AppState {
            pool: pool.clone(),
            rl_client: crate::services::rolelogic::RoleLogicClient::new(
                "http://127.0.0.1:1".into(),
            ),
            http: reqwest::Client::new(),
            allowed_origins: vec![],
            draining: std::sync::atomic::AtomicBool::new(false),
            jobs_notify: Arc::new(tokio::sync::Notify::new()),
            kick_public_key: tokio::sync::RwLock::new(None),
            api_rate_limiter: crate::services::api_key::new_rate_limiter(),
            // Base URL is irrelevant here: we only exercise selection, not the
            // HTTP call. It must be Some, or the backfill short-circuits.
            follow_probe: Some(crate::services::kick_probe::FollowProbe::new(
                "http://127.0.0.1:1".into(),
                600,
            )),
            config: crate::config::AppConfig::from_env(),
        });

        let picked = |p: sqlx::PgPool| async move {
            sqlx::query_scalar::<_, String>(
                "SELECT ku.discord_id \
                 FROM channel_relations cr \
                 JOIN kick_users ku USING (kick_user_id) \
                 WHERE cr.follow_probed_at IS NULL \
                   AND (cr.follow_probe_attempted_at IS NULL \
                        OR cr.follow_probe_attempted_at < now() - make_interval(secs => $1)) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM jobs j \
                       WHERE j.kind = 'follow_probe' \
                         AND j.status IN ('pending', 'in_progress') \
                         AND j.payload->>'discord_id' = ku.discord_id \
                   ) \
                   AND ku.discord_id = $2 \
                 GROUP BY ku.discord_id",
            )
            .bind(BACKFILL_RETRY_AFTER_SECS)
            .bind(DISCORD)
            .fetch_all(&p)
            .await
            .unwrap()
        };

        // 1. The stranded member is selected — the sweep would never see them.
        assert_eq!(
            picked(pool.clone()).await.len(),
            1,
            "a never-probed member must be picked up by the backfill"
        );
        let swept = sqlx::query_scalar::<_, String>(
            "SELECT ku.discord_id FROM channel_relations cr \
             JOIN kick_users ku USING (kick_user_id) \
             WHERE cr.is_follower AND ku.discord_id = $1 GROUP BY ku.discord_id",
        )
        .bind(DISCORD)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(swept.is_empty(), "sweep must not cover non-followers");

        // 2. Enqueuing dedupes: with a probe in flight they drop out.
        let n = backfill_unprobed(&state, 500).await.expect("backfill");
        assert!(n >= 1, "backfill should have enqueued at least our member");
        assert!(
            picked(pool.clone()).await.is_empty(),
            "a viewer with a probe already queued must not be re-enqueued"
        );

        // 3. Once a probe lands a usable answer the row leaves the set for
        //    good — this is what makes the backfill self-draining rather than
        //    a permanent tax on every reconcile cycle.
        sqlx::query("DELETE FROM jobs WHERE payload->>'discord_id' = $1")
            .bind(DISCORD)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            picked(pool.clone()).await.len(),
            1,
            "requeueable while unprobed"
        );
        sqlx::query(
            "UPDATE channel_relations SET follow_probed_at = now(), \
                    follow_probe_attempted_at = now() \
             WHERE kick_channel_id = $1 AND kick_user_id = $2",
        )
        .bind(CH)
        .bind(UID)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            picked(pool.clone()).await.is_empty(),
            "a successfully probed row must drop out of the backlog permanently"
        );

        // 4. A failed probe (attempted, never answered) is retried, but only
        //    after the cooldown — not on every cycle.
        sqlx::query(
            "UPDATE channel_relations SET follow_probed_at = NULL, \
                    follow_probe_attempted_at = now() \
             WHERE kick_channel_id = $1 AND kick_user_id = $2",
        )
        .bind(CH)
        .bind(UID)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            picked(pool.clone()).await.is_empty(),
            "a just-failed probe must wait out the cooldown"
        );
        sqlx::query(
            "UPDATE channel_relations SET follow_probe_attempted_at = now() - interval '2 days' \
             WHERE kick_channel_id = $1 AND kick_user_id = $2",
        )
        .bind(CH)
        .bind(UID)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            picked(pool.clone()).await.len(),
            1,
            "after the cooldown a failed probe must be retried"
        );

        cleanup(pool).await;
    }

    #[test]
    fn all_unavailable_detects_a_dark_probe() {
        let r = ProbeReport {
            attempted: 2,
            usable: 0,
            ..Default::default()
        };
        assert!(r.all_unavailable());
        let ok = ProbeReport {
            attempted: 2,
            usable: 1,
            ..Default::default()
        };
        assert!(!ok.all_unavailable());
        assert!(!ProbeReport::default().all_unavailable());
    }
}
