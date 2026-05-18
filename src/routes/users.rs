//! Public "all users" listing — every linked viewer with any relation to a
//! channel connected to this guild. Shows username + follower/sub/VIP/mod
//! flags and counts, so admins can see who's in their server at a glance.
//!
//! Gated by `guild_settings.view_permission`:
//!   * 'disabled' — nobody (page renders an explanatory notice)
//!   * 'managers' — Manage-Server only
//!   * 'members'  — any member of the guild
//!
//! Only viewers who linked their Kick account appear (we only have a
//! username for linked users, and surfacing only opted-in members is the
//! privacy-respecting default). Convention 36: on 401 the page renders an
//! in-page "Login with Discord" prompt — it never auto-redirects.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::auth::{extract_bearer, guild_members, guild_permission, require_guild_admin};
use crate::services::csrf;
use crate::AppState;

const USERS_PAGE: &str = include_str!("../../templates/users.html");

pub async fn users_page(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
) -> impl IntoResponse {
    let html = USERS_PAGE
        .replace("{{BASE_URL}}", &state.config.base_url)
        .replace("{{GUILD_ID}}", &guild_id);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

#[allow(clippy::type_complexity)]
pub async fn users_data(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(guild_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let view_permission: String =
        sqlx::query_scalar("SELECT view_permission FROM guild_settings WHERE guild_id = $1")
            .bind(&guild_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "managers".to_string());

    if view_permission == "disabled" {
        return Err(AppError::Forbidden(
            "The user list is disabled for this server.".into(),
        ));
    }

    let perm = guild_permission(&state, &jar, &guild_id).await?;
    if !perm.is_member {
        return Err(AppError::Forbidden(
            "You're not a member of this server.".into(),
        ));
    }
    if view_permission == "managers" && !perm.is_manager {
        return Err(AppError::Forbidden(
            "This list is visible to server managers only.".into(),
        ));
    }

    // "Who is in this guild" comes from the Auth Gateway, NOT from a local
    // table and NOT from the incidental presence of a `channel_relations`
    // row. A member who linked their Kick account must appear the instant
    // they link — before any broadcaster is connected and before any
    // follow/sub webhook lands — with the relationship columns simply blank.
    // This is the membership-centric pattern the reference plugin uses
    // (Genshin-Player-Role `players_data`) and BLUEPRINT §16.3 prescribes;
    // one user-cookie call returns both the member filter and the guild name.
    let (member_ids, guild_name) = guild_members(&state, &jar, &guild_id).await?;

    // One row per linked viewer who is a current member of this guild.
    // `channel_relations` is LEFT-joined and scoped to the broadcasters this
    // guild has connected, then collapsed (OR / max / sum) so a viewer linked
    // to several of the guild's channels appears once. A viewer with no
    // relation row at all still appears, with all flags false / counts zero
    // (hence the COALESCE around the bool_or aggregates — with the LEFT JOIN
    // they can now be NULL).
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            i64,
            bool,
            bool,
            bool,
            bool,
            i32,
            i32,
            i32,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT ku.discord_id, \
                ku.discord_name, \
                ku.kick_username, \
                ku.kick_user_id, \
                COALESCE(bool_or(cr.is_follower),   false) AS is_follower, \
                COALESCE(bool_or(cr.is_subscriber), false) AS is_subscriber, \
                COALESCE(bool_or(cr.is_vip),        false) AS is_vip, \
                COALESCE(bool_or(cr.is_moderator),  false) AS is_moderator, \
                COALESCE(max(cr.sub_months_cumulative), 0) AS sub_months, \
                COALESCE(max(cr.sub_streak_months),    0) AS sub_streak, \
                COALESCE(sum(cr.gifted_subs_given),    0)::int AS gifted, \
                min(cr.followed_at)           AS followed_at, \
                max(cr.last_seen_at)          AS last_seen_at, \
                ku.linked_at \
         FROM kick_users ku \
         LEFT JOIN guild_broadcasters gb ON gb.guild_id = $1 \
         LEFT JOIN channel_relations cr \
                ON cr.kick_user_id = ku.kick_user_id \
               AND cr.kick_channel_id = gb.kick_channel_id \
         WHERE ku.discord_id = ANY($2) \
         GROUP BY ku.discord_id, ku.discord_name, ku.kick_username, ku.kick_user_id, ku.linked_at \
         ORDER BY ku.kick_username ASC \
         LIMIT 1000",
    )
    .bind(&guild_id)
    .bind(&member_ids)
    .fetch_all(&state.pool)
    .await?;

    let users = rows
        .into_iter()
        .map(
            |(
                discord_id,
                discord_name,
                username,
                kick_user_id,
                is_follower,
                is_subscriber,
                is_vip,
                is_moderator,
                sub_months,
                sub_streak,
                gifted,
                followed_at,
                last_seen_at,
                linked_at,
            )| {
                json!({
                    "discord_id": discord_id,
                    "discord_name": discord_name,
                    "username": username,
                    "kick_user_id": kick_user_id,
                    "is_follower": is_follower,
                    "is_subscriber": is_subscriber,
                    "is_vip": is_vip,
                    "is_moderator": is_moderator,
                    "sub_months": sub_months,
                    "sub_streak": sub_streak,
                    "gifted": gifted,
                    "followed_at": followed_at.map(|x| x.to_rfc3339()),
                    "last_seen_at": last_seen_at.map(|x| x.to_rfc3339()),
                    "linked_at": linked_at.to_rfc3339(),
                })
            },
        )
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "guild_id": guild_id,
        "guild_name": guild_name,
        "count": users.len(),
        "users": users,
    })))
}

// ---------------------------------------------------------------------
// POST /admin/{guild_id}/view-permission  (manager-only)
// ---------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ViewPermBody {
    pub view_permission: String,
}

pub async fn set_view_permission(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(guild_id): Path<String>,
    Json(body): Json<ViewPermBody>,
) -> Result<Json<Value>, AppError> {
    if extract_bearer(&headers).is_none() {
        csrf::verify_origin(&headers, &state.allowed_origins)?;
    }
    require_guild_admin(&state, &jar, &headers, &guild_id).await?;

    let vp = match body.view_permission.as_str() {
        "disabled" | "managers" | "members" => body.view_permission.as_str(),
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown view_permission '{other}' (expected disabled|managers|members)."
            )))
        }
    };

    sqlx::query(
        "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (guild_id) DO UPDATE SET view_permission = EXCLUDED.view_permission, \
                                              updated_at = now()",
    )
    .bind(&guild_id)
    .bind(vp)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({ "success": true, "view_permission": vp })))
}
