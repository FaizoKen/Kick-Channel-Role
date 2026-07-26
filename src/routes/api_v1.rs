//! `/api/v1/*` — read-only machine API over a guild's linked Kick users.
//!
//! Authenticated by a guild-scoped API key (`Authorization: Bearer kck_…`,
//! see [services::api_key]), NOT by the `rl_session` cookie. Three things
//! follow from that and are worth stating up front:
//!
//! 1. **No endpoint takes a `guild_id`.** The key carries it. A caller
//!    cannot ask about a guild it wasn't issued for, so there is no
//!    cross-guild authorization check that could be forgotten.
//!
//! 2. **Membership comes from the Auth Gateway's server-to-server API**
//!    (`/auth/internal/guild_member_ids`), not the cookie-authed
//!    `/auth/guild_members` the browser page uses — there is no user cookie
//!    to forward here. Same source of truth, same `plugin=` opt-out filter,
//!    different transport.
//!
//! 3. **This surface is versioned and independent of the HTML page's JSON.**
//!    `/users/{guild}/data` may change shape whenever the page needs it to;
//!    `/api/v1` is a contract with third parties and changes only by adding
//!    fields or minting a `/api/v2`.
//!
//! Deliberately *not* gated on `guild_settings.view_permission`. That knob
//! governs which humans may browse the public page; a key is an explicit,
//! individually revocable grant a manager made on purpose. Tying the two
//! would let a UI toggle silently break a production integration. The
//! management UI says so in as many words.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::api_key::{self, ApiKeyContext, SCOPE_USERS_READ};
use crate::services::auth_gateway;
use crate::AppState;

/// Page size when the caller doesn't say, and the ceiling we'll honour.
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

/// Every response carries this. The payload is per-guild private data — it
/// must never land in a shared or intermediary cache.
fn private_json(body: Value) -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], Json(body))
}

// ---------------------------------------------------------------------
// GET /api/v1
// ---------------------------------------------------------------------

/// Unauthenticated discovery document. Static text only — it describes the
/// contract, it does not touch the database and reveals nothing about any
/// guild. Having one means an integrator handed only a base URL can find
/// their way without us writing a separate docs site.
pub async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base = &state.config.base_url;
    private_json(json!({
        "service": "kick-channel-role",
        "version": "v1",
        "auth": {
            "scheme": "Authorization: Bearer kck_…",
            "note": "Keys are guild-scoped and minted by a server manager from \
                     the plugin's role settings in the RoleLogic dashboard. No \
                     endpoint takes a guild id — the key carries it.",
            "scopes": [SCOPE_USERS_READ],
        },
        "endpoints": [
            { "method": "GET", "path": format!("{base}/api/v1/whoami"),
              "description": "Confirm a key and see which server it points at." },
            { "method": "GET", "path": format!("{base}/api/v1/users"),
              "description": "Linked members of the server, newest schema in `relation`.",
              "query": {
                  "limit": format!("1–{MAX_LIMIT}, default {DEFAULT_LIMIT}"),
                  "cursor": "opaque; pass back page.next_cursor",
                  "updated_since": "RFC 3339; only records changed at or after it",
                  "relation": "follower | subscriber | vip | og | moderator",
              } },
            { "method": "GET", "path": format!("{base}/api/v1/users/{{discord_id}}"),
              "description": "One member. 404 if not a member, not linked, or opted out." },
        ],
        "limits": {
            "requests_per_minute": api_key::RATE_PER_MINUTE,
            "burst": api_key::RATE_BURST,
            "note": "429 responses carry Retry-After (seconds).",
        },
    }))
}

// ---------------------------------------------------------------------
// GET /api/v1/whoami
// ---------------------------------------------------------------------

/// Key introspection. Exists so an integrator can verify their credential
/// and see which guild it points at without pulling a user list — the first
/// call anyone makes when wiring this up, and the one that makes a
/// misconfigured key obvious instead of mysterious.
pub async fn whoami(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let ctx = api_key::authenticate(&state, &headers, SCOPE_USERS_READ).await?;
    let guild_name = guild_name_only(&state, &ctx.guild_id).await;

    Ok(private_json(json!({
        "guild": { "id": ctx.guild_id, "name": guild_name },
        "key": { "label": ctx.label, "scopes": ctx.scopes },
    })))
}

// ---------------------------------------------------------------------
// GET /api/v1/users
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Page size, clamped to [1, MAX_LIMIT].
    pub limit: Option<i64>,
    /// Opaque forward cursor — pass back `page.next_cursor` verbatim.
    /// (It happens to be the last Discord ID of the previous page; that is
    /// an implementation detail callers should not rely on.)
    pub cursor: Option<String>,
    /// RFC 3339 timestamp. Returns only users whose record changed at or
    /// after it, so a poller can stay current without refetching everything.
    pub updated_since: Option<String>,
    /// Restrict to one relation: follower | subscriber | vip | og | moderator.
    pub relation: Option<String>,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, AppError> {
    let ctx = api_key::authenticate(&state, &headers, SCOPE_USERS_READ).await?;

    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let updated_since = parse_updated_since(q.updated_since.as_deref())?;
    let relation = parse_relation(q.relation.as_deref())?;

    let (member_ids, guild_name) = members(&state, &ctx).await?;

    // Over-fetch by one: if the extra row materialises there is another
    // page, which is cheaper and more accurate than a second COUNT query.
    let mut rows = fetch_users(
        &state.pool,
        &ctx.guild_id,
        &member_ids,
        UserFilter {
            after: q.cursor.as_deref(),
            updated_since,
            relation,
            only_discord_id: None,
            limit: limit + 1,
        },
    )
    .await?;

    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        rows.last().map(|r| r.discord_id.clone())
    } else {
        None
    };

    // Which key pulled member data, and how much of it. `last_used_at` says
    // a key is live; this says what it actually read — the difference that
    // matters when a guild asks what an integration has seen.
    tracing::debug!(
        key_id = ctx.key_id,
        guild_id = %ctx.guild_id,
        returned = rows.len(),
        "api/v1 users listed"
    );

    Ok(private_json(json!({
        "guild": { "id": ctx.guild_id, "name": guild_name },
        "users": rows.iter().map(UserRow::to_json).collect::<Vec<_>>(),
        "page": {
            "limit": limit,
            "count": rows.len(),
            "has_more": has_more,
            "next_cursor": next_cursor,
        },
    })))
}

// ---------------------------------------------------------------------
// GET /api/v1/users/{discord_id}
// ---------------------------------------------------------------------

/// Single-user lookup — the "does this member qualify?" call, so an
/// integration doesn't have to page the whole guild to answer one question.
///
/// 404 covers three cases on purpose: not a member of this guild, a member
/// who never linked Kick, and a member who opted out of this plugin. From
/// outside they are the same fact — we have nothing to tell you about this
/// person — and distinguishing them would leak guild membership to a key
/// that is only entitled to the linked-user list.
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(discord_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let ctx = api_key::authenticate(&state, &headers, SCOPE_USERS_READ).await?;
    let (member_ids, guild_name) = members(&state, &ctx).await?;

    let rows = fetch_users(
        &state.pool,
        &ctx.guild_id,
        &member_ids,
        UserFilter {
            after: None,
            updated_since: None,
            relation: None,
            only_discord_id: Some(&discord_id),
            limit: 1,
        },
    )
    .await?;

    let user = rows.first().ok_or_else(|| {
        AppError::NotFound("No linked user with that Discord ID in this server.".into())
    })?;

    tracing::debug!(
        key_id = ctx.key_id,
        guild_id = %ctx.guild_id,
        "api/v1 single user read"
    );

    Ok(private_json(json!({
        "guild": { "id": ctx.guild_id, "name": guild_name },
        "user": user.to_json(),
    })))
}

// ---------------------------------------------------------------------
// Shared plumbing
// ---------------------------------------------------------------------

/// Who is in this guild, per the Auth Gateway, minus anyone who opted out of
/// this plugin here. Errors bubble: returning an empty list on a transient
/// gateway hiccup would tell an integration that every member vanished
/// (Convention 40).
async fn members(
    state: &Arc<AppState>,
    ctx: &ApiKeyContext,
) -> Result<(Vec<String>, Option<String>), AppError> {
    auth_gateway::fetch_guild_member_ids_full(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        &ctx.guild_id,
    )
    .await
}

/// Resolve just the guild's display name.
///
/// The gateway exposes no name-only endpoint, so this pays for the full
/// member list and throws it away. That is acceptable *only* because
/// `whoami` is a setup-time call an integrator makes once or twice, not a
/// polling path — do not reach for this helper anywhere hot.
///
/// Failure is non-fatal: the key is still valid, we just can't name the
/// server. That is the right trade for an endpoint whose job is to tell a
/// confused integrator that their credential works.
async fn guild_name_only(state: &Arc<AppState>, guild_id: &str) -> Option<String> {
    match auth_gateway::fetch_guild_member_ids_full(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await
    {
        Ok((_, name)) => name,
        Err(e) => {
            tracing::warn!(guild_id, "whoami could not resolve guild name: {e}");
            None
        }
    }
}

fn parse_updated_since(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, AppError> {
    match raw {
        None => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|d| Some(d.with_timezone(&Utc)))
            .map_err(|_| {
                AppError::BadRequest(format!(
                    "`updated_since` must be an RFC 3339 timestamp (e.g. \
                     2026-07-27T00:00:00Z); got `{s}`."
                ))
            }),
    }
}

/// Map the caller's `relation` to a SQL fragment. The mapping is a closed
/// match returning compile-time constants — no caller-supplied text ever
/// reaches the query string.
fn parse_relation(raw: Option<&str>) -> Result<Option<&'static str>, AppError> {
    let Some(s) = raw else { return Ok(None) };
    let col = match s {
        "follower" => "is_follower",
        "subscriber" => "is_subscriber",
        "vip" => "is_vip",
        "og" => "is_og",
        "moderator" => "is_moderator",
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown `relation` filter `{other}` (expected follower, \
                 subscriber, vip, og, or moderator)."
            )))
        }
    };
    Ok(Some(col))
}

struct UserFilter<'a> {
    after: Option<&'a str>,
    updated_since: Option<DateTime<Utc>>,
    relation: Option<&'static str>,
    only_discord_id: Option<&'a str>,
    limit: i64,
}

#[derive(sqlx::FromRow)]
struct UserRow {
    discord_id: String,
    discord_name: Option<String>,
    kick_username: String,
    kick_user_id: i64,
    is_follower: bool,
    is_subscriber: bool,
    is_vip: bool,
    is_og: bool,
    is_moderator: bool,
    sub_months_cumulative: i32,
    sub_streak_months: i32,
    gifted_subs_given: i32,
    followed_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    linked_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    /// Field names mirror the plugin's own condition targets
    /// (`sub_months_cumulative`, `is_og`, …) so a rule an admin sees in the
    /// dashboard and a field an integration reads here are the same word.
    fn to_json(&self) -> Value {
        json!({
            "discord_id": self.discord_id,
            "discord_name": self.discord_name,
            "kick_user_id": self.kick_user_id,
            "kick_username": self.kick_username,
            "linked_at": self.linked_at.to_rfc3339(),
            "updated_at": self.updated_at.to_rfc3339(),
            "relation": {
                "is_follower": self.is_follower,
                "is_subscriber": self.is_subscriber,
                "is_vip": self.is_vip,
                "is_og": self.is_og,
                "is_moderator": self.is_moderator,
                "sub_months_cumulative": self.sub_months_cumulative,
                "sub_streak_months": self.sub_streak_months,
                "gifted_subs_given": self.gifted_subs_given,
                "followed_at": self.followed_at.map(|x| x.to_rfc3339()),
                "last_seen_at": self.last_seen_at.map(|x| x.to_rfc3339()),
            },
        })
    }
}

/// One row per linked member of the guild, collapsing that member's
/// relations across every channel the guild has connected (OR / max / sum) —
/// the same shape the HTML page uses, so the two never disagree about who is
/// a subscriber.
///
/// Ordered by `discord_id` rather than the page's `kick_username`: the
/// primary key is unique and immutable, which is what makes the cursor
/// stable. Ordering by a mutable, non-unique display name would silently
/// skip or duplicate rows across pages when someone renames mid-scan.
/// Takes a bare pool rather than `AppState` so the SQL can be exercised
/// against a real database in tests without standing up the whole app.
async fn fetch_users(
    pool: &sqlx::PgPool,
    guild_id: &str,
    member_ids: &[String],
    f: UserFilter<'_>,
) -> Result<Vec<UserRow>, AppError> {
    // `updated_at` is recomputed rather than aliased because Postgres does
    // not allow output-list aliases in HAVING.
    const UPDATED_AT: &str =
        "GREATEST(ku.refreshed_at, COALESCE(max(cr.last_synced_at), ku.refreshed_at))";

    let relation_having = match f.relation {
        Some(col) => format!(" AND COALESCE(bool_or(cr.{col}), false)"),
        None => String::new(),
    };

    let sql = format!(
        "SELECT ku.discord_id, \
                ku.discord_name, \
                ku.kick_username, \
                ku.kick_user_id, \
                COALESCE(bool_or(cr.is_follower),   false) AS is_follower, \
                COALESCE(bool_or(cr.is_subscriber), false) AS is_subscriber, \
                COALESCE(bool_or(cr.is_vip),        false) AS is_vip, \
                COALESCE(bool_or(cr.is_og),         false) AS is_og, \
                COALESCE(bool_or(cr.is_moderator),  false) AS is_moderator, \
                COALESCE(max(cr.sub_months_cumulative), 0) AS sub_months_cumulative, \
                COALESCE(max(cr.sub_streak_months),    0) AS sub_streak_months, \
                COALESCE(sum(cr.gifted_subs_given),    0)::int AS gifted_subs_given, \
                min(cr.followed_at)  AS followed_at, \
                max(cr.last_seen_at) AS last_seen_at, \
                ku.linked_at, \
                {UPDATED_AT} AS updated_at \
         FROM kick_users ku \
         LEFT JOIN guild_broadcasters gb ON gb.guild_id = $1 \
         LEFT JOIN channel_relations cr \
                ON cr.kick_user_id = ku.kick_user_id \
               AND cr.kick_channel_id = gb.kick_channel_id \
         WHERE ku.discord_id = ANY($2) \
           AND ($3::text IS NULL OR ku.discord_id > $3) \
           AND ($6::text IS NULL OR ku.discord_id = $6) \
         GROUP BY ku.discord_id, ku.discord_name, ku.kick_username, \
                  ku.kick_user_id, ku.linked_at, ku.refreshed_at \
         HAVING ($4::timestamptz IS NULL OR {UPDATED_AT} >= $4){relation_having} \
         ORDER BY ku.discord_id ASC \
         LIMIT $5"
    );

    let rows = sqlx::query_as::<_, UserRow>(&sql)
        .bind(guild_id)
        .bind(member_ids)
        .bind(f.after)
        .bind(f.updated_since)
        .bind(f.limit)
        .bind(f.only_discord_id)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_filter_rejects_anything_off_the_allowlist() {
        assert_eq!(parse_relation(None).unwrap(), None);
        assert_eq!(
            parse_relation(Some("subscriber")).unwrap(),
            Some("is_subscriber")
        );
        assert_eq!(parse_relation(Some("og")).unwrap(), Some("is_og"));
        // The whole point: no caller string can become SQL.
        for bad in ["is_subscriber", "1=1", "true) OR (1=1", "", "SUBSCRIBER"] {
            assert!(
                parse_relation(Some(bad)).is_err(),
                "`{bad}` must not be accepted"
            );
        }
    }

    #[test]
    fn updated_since_requires_rfc3339() {
        assert!(parse_updated_since(None).unwrap().is_none());
        assert!(parse_updated_since(Some("2026-07-27T00:00:00Z"))
            .unwrap()
            .is_some());
        // Offsets are normalised to UTC so the DB comparison is unambiguous.
        let off = parse_updated_since(Some("2026-07-27T02:00:00+02:00"))
            .unwrap()
            .unwrap();
        assert_eq!(off.to_rfc3339(), "2026-07-27T00:00:00+00:00");
        for bad in ["yesterday", "2026-07-27", "1753574400", ""] {
            assert!(parse_updated_since(Some(bad)).is_err(), "`{bad}` must fail");
        }
    }

    /// Exercise the hand-written listing SQL against a real Postgres.
    ///
    /// This query is the one thing here that unit tests genuinely cannot
    /// cover from the outside: the `GROUP BY` / `HAVING` split, the
    /// recomputed `updated_at` expression, the nullable `$3`/`$4`/`$6` casts,
    /// and every bind's type are all checked by the server, not the
    /// compiler. A typo in any of them is a runtime 500 that ships happily.
    ///
    /// Skips when `DATABASE_URL` is unset so CI without a database still
    /// passes. Reads only — seeds nothing, deletes nothing.
    #[tokio::test]
    async fn listing_sql_is_accepted_by_postgres() {
        // `main` loads .env via dotenvy; the test harness does not, so without
        // this the check would quietly skip on a machine that does have a
        // database — passing while testing nothing.
        dotenvy::dotenv().ok();
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping live-schema check");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("database unreachable — skipping live-schema check");
            return;
        };

        let members = vec!["1".to_string(), "2".to_string()];
        let cases: Vec<(&str, UserFilter)> = vec![
            (
                "bare list",
                UserFilter {
                    after: None,
                    updated_since: None,
                    relation: None,
                    only_discord_id: None,
                    limit: 10,
                },
            ),
            (
                "every optional predicate at once",
                UserFilter {
                    after: Some("1"),
                    updated_since: Some(Utc::now()),
                    relation: Some("is_subscriber"),
                    only_discord_id: Some("2"),
                    limit: 1,
                },
            ),
        ];
        for (name, f) in cases {
            let got = fetch_users(&pool, "0", &members, f).await;
            assert!(got.is_ok(), "{name}: {:?}", got.err());
        }

        // Every branch of `relation` must produce valid SQL, not just the
        // one the first case happened to use.
        for rel in ["follower", "subscriber", "vip", "og", "moderator"] {
            let col = parse_relation(Some(rel)).unwrap();
            let got = fetch_users(
                &pool,
                "0",
                &members,
                UserFilter {
                    after: None,
                    updated_since: None,
                    relation: col,
                    only_discord_id: None,
                    limit: 1,
                },
            )
            .await;
            assert!(got.is_ok(), "relation={rel}: {:?}", got.err());
        }
    }

    #[test]
    fn limit_is_clamped_both_ways() {
        let clamp = |n: Option<i64>| n.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        assert_eq!(clamp(None), DEFAULT_LIMIT);
        assert_eq!(clamp(Some(0)), 1);
        assert_eq!(clamp(Some(-5)), 1, "negative must not reach LIMIT");
        assert_eq!(clamp(Some(10_000)), MAX_LIMIT);
        assert_eq!(clamp(Some(250)), 250);
    }
}
