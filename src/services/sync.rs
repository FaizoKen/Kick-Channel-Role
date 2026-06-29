//! Sync engine — per-player (lightweight) and per-role-link (bulk).
//!
//! Dispatch targets for jobs claimed by [`crate::tasks::job_worker`].
//!
//! Convention 38: guild membership comes from the Auth Gateway
//! `/auth/internal/*`, never a local JOIN. Convention 40: gateway HTTP
//! failures bubble up (the worker retries) — we never clear a role on a
//! transient lookup failure. Convention 47: a RoleLinkNotFound deletes the
//! orphan local row instead of retrying forever.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use futures_util::stream::{self, StreamExt};

use crate::error::AppError;
use crate::models::facts::Facts;
use crate::models::rule::RuleTree;
use crate::services::condition_eval;
use crate::services::rule_sql::{self, Bind};
use crate::services::{auth_gateway, jobs};
use crate::AppState;

#[derive(sqlx::FromRow)]
struct FactsRow {
    is_follower: bool,
    followed_at: Option<DateTime<Utc>>,
    is_subscriber: bool,
    sub_months_cumulative: i32,
    sub_streak_months: i32,
    sub_is_gift: bool,
    gifted_subs_given: i32,
    is_vip: bool,
    is_moderator: bool,
    kicks_donated: i32,
    chat_messages_30d: i32,
    is_og: bool,
    kick_created_at: DateTime<Utc>,
    country_code: Option<String>,
    kick_username: String,
}

impl From<FactsRow> for Facts {
    fn from(r: FactsRow) -> Self {
        Facts {
            is_follower: r.is_follower,
            followed_at: r.followed_at,
            is_subscriber: r.is_subscriber,
            sub_months_cumulative: r.sub_months_cumulative as i64,
            sub_streak_months: r.sub_streak_months as i64,
            sub_is_gift: r.sub_is_gift,
            gifted_subs_given: r.gifted_subs_given as i64,
            is_vip: r.is_vip,
            is_moderator: r.is_moderator,
            kicks_donated: r.kicks_donated as i64,
            chat_messages_30d: r.chat_messages_30d as i64,
            is_og: r.is_og,
            kick_created_at: Some(r.kick_created_at),
            country_code: r.country_code,
            username: r.kick_username,
        }
    }
}

const FACTS_SELECT: &str = "SELECT \
    COALESCE(cr.is_follower, false)        AS is_follower, \
    cr.followed_at                         AS followed_at, \
    COALESCE(cr.is_subscriber, false)      AS is_subscriber, \
    COALESCE(cr.sub_months_cumulative, 0)  AS sub_months_cumulative, \
    COALESCE(cr.sub_streak_months, 0)      AS sub_streak_months, \
    COALESCE(cr.sub_is_gift, false)        AS sub_is_gift, \
    COALESCE(cr.gifted_subs_given, 0)      AS gifted_subs_given, \
    COALESCE(cr.is_vip, false)             AS is_vip, \
    COALESCE(cr.is_moderator, false)       AS is_moderator, \
    COALESCE(cr.kicks_donated, 0)          AS kicks_donated, \
    COALESCE(cr.chat_messages_30d, 0)      AS chat_messages_30d, \
    ku.is_og                               AS is_og, \
    ku.kick_created_at                     AS kick_created_at, \
    ku.country_code                        AS country_code, \
    ku.kick_username                       AS kick_username \
  FROM kick_users ku \
  LEFT JOIN channel_relations cr \
    ON cr.kick_user_id = ku.kick_user_id AND cr.kick_channel_id = $2 \
  WHERE ku.discord_id = $1";

// ---------------------------------------------------------------------------
// Baseline relation seeding
// ---------------------------------------------------------------------------

/// Insert an empty `channel_relations` row for every (broadcaster connected
/// to one of `guild_ids`, this user) pair that doesn't already have one.
///
/// This is what makes a freshly linked user appear on the public users page
/// even when they have no follow/sub/etc. activity yet. The same JOIN that
/// powers that page would otherwise drop them until the next webhook event
/// or reconcile pass enriches a row.
///
/// All flags default to false / 0. Webhook events and reconcile will set
/// real values later — they UPSERT on `(kick_channel_id, kick_user_id)`.
pub async fn ensure_baseline_relations(
    pool: &sqlx::PgPool,
    discord_id: &str,
    guild_ids: &[String],
) -> Result<(), AppError> {
    if guild_ids.is_empty() {
        return Ok(());
    }
    let kick_user_id: Option<i64> =
        sqlx::query_scalar("SELECT kick_user_id FROM kick_users WHERE discord_id = $1")
            .bind(discord_id)
            .fetch_optional(pool)
            .await?;
    let Some(kuid) = kick_user_id else {
        return Ok(());
    };

    sqlx::query(
        "INSERT INTO channel_relations (kick_channel_id, kick_user_id) \
         SELECT gb.kick_channel_id, $1 \
         FROM guild_broadcasters gb \
         WHERE gb.guild_id = ANY($2) \
         ON CONFLICT (kick_channel_id, kick_user_id) DO NOTHING",
    )
    .bind(kuid)
    .bind(guild_ids)
    .execute(pool)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-player sync
// ---------------------------------------------------------------------------

pub async fn sync_for_player(discord_id: &str, state: &AppState) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;
    if guild_ids.is_empty() {
        return Ok(());
    }

    // Ensure a baseline `channel_relations` row exists for every broadcaster
    // in every guild this user belongs to. Without this, a freshly linked
    // user with no follow/sub activity wouldn't appear on the public users
    // page (the listing INNER JOINs `channel_relations`). Defaults are all
    // false / 0; webhook + reconcile passes enrich the row later.
    ensure_baseline_relations(pool, discord_id, &guild_ids).await?;

    // No `kick_channel_id IS NOT NULL` filter: a "grant to anyone who linked
    // Kick" rule (grant_on_any_relation) is channel-agnostic and may have no
    // channel bound at all.
    let role_links = sqlx::query_as::<_, (String, String, String, Option<i64>, serde_json::Value)>(
        "SELECT guild_id, role_id, api_token, kick_channel_id, rule_tree \
             FROM role_links WHERE guild_id = ANY($1)",
    )
    .bind(&guild_ids[..])
    .fetch_all(pool)
    .await?;
    if role_links.is_empty() {
        return Ok(());
    }

    // "Linked" = the member connected a Kick account at all. This is the only
    // fact a grant_on_any_relation rule needs, and it's channel-independent.
    let is_linked: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kick_users WHERE discord_id = $1)")
            .bind(discord_id)
            .fetch_one(pool)
            .await?;

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    enum Action {
        Add(String, String, String),
        Remove(String, String, String),
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, channel_id, raw_tree) in &role_links {
        let tree: RuleTree = serde_json::from_value(raw_tree.clone()).unwrap_or_default();

        let qualifies = if tree.grant_on_any_relation {
            // Channel-agnostic: just needs a linked Kick account.
            is_linked
        } else if channel_id.is_none() {
            // Conditions reference channel facts but no channel is bound
            // (Convention 42 — grant to nobody).
            false
        } else {
            let facts_row: Option<FactsRow> = sqlx::query_as(FACTS_SELECT)
                .bind(discord_id)
                .bind(channel_id)
                .fetch_optional(pool)
                .await?;
            match facts_row {
                Some(row) => condition_eval::evaluate(&tree, &Facts::from(row)),
                None => false, // not linked → qualifies for nothing
            }
        };

        let assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, assigned) {
            (true, false) => actions.push(Action::Add(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            (false, true) => actions.push(Action::Remove(
                guild_id.clone(),
                role_id.clone(),
                api_token.clone(),
            )),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let did = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl = rl_client.clone();
            let did = did.clone();
            async move {
                match action {
                    Action::Add(g, r, tok) => {
                        match rl.add_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(g, r, did, limit, "user limit reached");
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "add_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                    Action::Remove(g, r, tok) => {
                        match rl.remove_user(&g, &r, &did, &tok).await {
                            Err(AppError::RoleLinkNotFound) => {
                                delete_orphan_role_link(&g, &r, &pool).await;
                                return;
                            }
                            Err(e) => {
                                tracing::error!(g, r, did, "remove_user failed: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        let _ = sqlx::query(
                            "DELETE FROM role_assignments \
                             WHERE guild_id=$1 AND role_id=$2 AND discord_id=$3",
                        )
                        .bind(&g)
                        .bind(&r)
                        .bind(&did)
                        .execute(&pool)
                        .await;
                    }
                }
            }
        })
        .await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-role-link sync (bulk)
// ---------------------------------------------------------------------------

pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl = &state.rl_client;

    let link = sqlx::query_as::<_, (String, Option<i64>, serde_json::Value)>(
        "SELECT api_token, kick_channel_id, rule_tree \
         FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, channel_id, raw_tree)) = link else {
        return Ok(());
    };
    let tree: RuleTree = serde_json::from_value(raw_tree).unwrap_or_default();

    // Convention 42: NOT grant_on_any AND (no channel bound OR no groups) ⇒
    // the rule references channel facts it doesn't have / matches nothing ⇒
    // grant to nobody. grant_on_any is channel-agnostic so it's exempt.
    if !tree.grant_on_any_relation && (channel_id.is_none() || tree.groups.is_empty()) {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let member_ids = auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;
    if member_ids.is_empty() {
        drain_to_empty(guild_id, role_id, &api_token, state).await?;
        return Ok(());
    }

    let (_count, user_limit) = match rl.get_user_info(guild_id, role_id, &api_token).await {
        Ok(v) => v,
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(AppError::RoleLinkDisabled) => return Ok(()),
        Err(e) => return Err(e),
    };

    let qualifying: Vec<String> = if tree.grant_on_any_relation {
        // Channel-agnostic: every guild member who linked a Kick account.
        sqlx::query_scalar(
            "SELECT discord_id FROM kick_users \
             WHERE discord_id = ANY($1::text[]) \
             ORDER BY discord_id LIMIT $2",
        )
        .bind(&member_ids)
        .bind(user_limit as i64)
        .fetch_all(pool)
        .await?
    } else {
        // Channel-scoped rule. The Convention-42 guard above guarantees a
        // channel is bound here.
        let channel_id = channel_id.expect("channel bound for non-grant rule");
        // $1 = channel_id, $2 = member_ids, rule binds from $3, limit last.
        let (rule_where, binds) = rule_sql::build_rule_where(&tree, 2);
        let limit_idx = 2 + binds.len() + 1;
        let query = format!(
            "SELECT DISTINCT ku.discord_id \
             FROM kick_users ku \
             LEFT JOIN channel_relations cr \
               ON cr.kick_user_id = ku.kick_user_id AND cr.kick_channel_id = $1 \
             WHERE ku.discord_id = ANY($2::text[]) \
               AND ({rule_where}) \
             ORDER BY ku.discord_id \
             LIMIT ${limit_idx}"
        );
        let mut q = sqlx::query_scalar::<_, String>(&query)
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
        q = q.bind(user_limit as i64);
        q.fetch_all(pool).await?
    };

    // Skip the RoleLogic PUT entirely when the computed set already equals
    // what's assigned. This is the key cost guard for high-churn rules like
    // "live now": a mid-stream category switch, a viewer-count tick, or any
    // unrelated webhook re-runs this function, but if the 10k-member set is
    // unchanged we do one cheap local SELECT and return — no PUT, no Discord
    // role-change storm. Both lists are ordered + de-duped (the query is
    // `DISTINCT … ORDER BY`; this mirror read is `ORDER BY`), so `==` is an
    // exact set comparison.
    let current: Vec<String> = sqlx::query_scalar(
        "SELECT discord_id FROM role_assignments \
         WHERE guild_id = $1 AND role_id = $2 ORDER BY discord_id",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_all(pool)
    .await?;
    if current == qualifying {
        return Ok(());
    }

    match rl
        .upload_users(guild_id, role_id, &qualifying, &api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;
    if !qualifying.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id)
        .bind(role_id)
        .bind(&qualifying)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn drain_to_empty(
    guild_id: &str,
    role_id: &str,
    api_token: &str,
    state: &AppState,
) -> Result<(), AppError> {
    // Already empty ⇒ nothing to clear. Stops a repeated "grant nobody" /
    // off-air re-sync from re-PUTting an empty set every cycle.
    let any: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE guild_id=$1 AND role_id=$2)",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_one(&state.pool)
    .await?;
    if !any {
        return Ok(());
    }

    match state
        .rl_client
        .upload_users(guild_id, role_id, &[], api_token)
        .await
    {
        Ok(_) => {}
        Err(AppError::RoleLinkNotFound) => {
            delete_orphan_role_link(guild_id, role_id, &state.pool).await;
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    sqlx::query("DELETE FROM role_assignments WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel sync — fan a per-channel state change out to all bound role links.
// ---------------------------------------------------------------------------

pub async fn sync_for_channel(kick_channel_id: i64, state: &AppState) -> Result<(), AppError> {
    let links = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_links WHERE kick_channel_id = $1",
    )
    .bind(kick_channel_id)
    .fetch_all(&state.pool)
    .await?;
    for (guild_id, role_id) in links {
        jobs::enqueue_config_sync(&state.pool, &guild_id, &role_id).await?;
    }
    Ok(())
}

/// Delete a role_link the RoleLogic API reports as gone (Convention 47).
/// CASCADE clears role_assignments. Best-effort: never propagates DB errors.
async fn delete_orphan_role_link(guild_id: &str, role_id: &str, pool: &sqlx::PgPool) {
    tracing::warn!(
        guild_id,
        role_id,
        "Role link not found on RoleLogic; removing orphaned local row"
    );
    if let Err(e) = sqlx::query("DELETE FROM role_links WHERE guild_id=$1 AND role_id=$2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await
    {
        tracing::error!(guild_id, role_id, "Failed to delete orphan role_link: {e}");
    }
}
