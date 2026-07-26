//! Human- and machine-readable documentation for the `/api/v1` surface.
//!
//! Both are public and credential-less by design. A third-party developer is
//! usually handed a key and a base URL and nothing else; making them
//! authenticate just to find out what the endpoints *are* wastes everybody's
//! time, and neither response reveals anything about any guild — they are
//! static descriptions of the contract.
//!
//! Two representations of the same thing:
//!   * `GET /api/v1/docs`         — the page a developer reads.
//!   * `GET /api/v1/openapi.json` — the spec their tooling reads (Postman,
//!     client generators, contract tests).
//!
//! Keep them in step when the contract changes. The JSON payload shapes in
//! the HTML examples and the OpenAPI schemas both describe
//! `routes::api_v1::UserRow::to_json`.

use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::services::api_key::{RATE_BURST, RATE_PER_MINUTE, SCOPE_USERS_READ, TOKEN_PREFIX};
use crate::AppState;

const DOCS_PAGE: &str = include_str!("../../templates/api_docs.html");

/// Page size defaults, mirrored from `routes::api_v1` so the documented
/// numbers and the enforced ones cannot drift apart.
use super::api_v1::{DEFAULT_LIMIT, MAX_LIMIT};

// ---------------------------------------------------------------------
// GET /api/v1/docs
// ---------------------------------------------------------------------

pub async fn page(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    let html = DOCS_PAGE.replace("{{BASE_URL}}", &state.config.base_url);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // Public, static, and identical for every reader — let it cache.
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        html,
    )
}

// ---------------------------------------------------------------------
// GET /api/v1/openapi.json
// ---------------------------------------------------------------------

/// Hand-written rather than derived from the handlers. That is a deliberate
/// trade: no proc-macro layer over every route, at the cost of having to
/// update this when the contract changes. It is a third-party contract, so
/// changes should be rare and considered anyway.
pub async fn openapi(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    let base = &state.config.base_url;
    let spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Kick Channel Role API",
            "version": "1.0.0",
            "summary": "Read-only access to one Discord server's linked Kick accounts.",
            "description": format!(
                "Every API key is scoped to exactly one Discord server, which is why no \
                 endpoint takes a server id — the key carries it.\n\n\
                 Keys are minted by a member with Manage Server from the plugin's role \
                 settings in the RoleLogic dashboard. Server-to-server only: browsers on \
                 third-party origins are blocked by CORS so keys stay out of frontend \
                 bundles.\n\nFull guide: {base}/api/v1/docs"
            ),
        },
        "servers": [ { "url": format!("{base}/api/v1") } ],
        "security": [ { "apiKey": [] } ],
        "tags": [
            { "name": "Key", "description": "Credential introspection." },
            { "name": "Users", "description": "Linked members of the server." },
        ],
        "paths": {
            "/whoami": {
                "get": {
                    "tags": ["Key"],
                    "operationId": "whoami",
                    "summary": "Confirm a key and see which server it points at",
                    "responses": {
                        "200": {
                            "description": "The key is valid.",
                            "content": { "application/json": { "schema": {
                                "type": "object",
                                "required": ["guild", "key"],
                                "properties": {
                                    "guild": { "$ref": "#/components/schemas/Guild" },
                                    "key": {
                                        "type": "object",
                                        "properties": {
                                            "label": { "type": "string" },
                                            "scopes": {
                                                "type": "array",
                                                "items": { "type": "string" },
                                            },
                                        },
                                    },
                                },
                            } } },
                        },
                        "401": { "$ref": "#/components/responses/Unauthorized" },
                        "429": { "$ref": "#/components/responses/RateLimited" },
                    },
                },
            },
            "/users": {
                "get": {
                    "tags": ["Users"],
                    "operationId": "listUsers",
                    "summary": "List linked users, cursor-paginated",
                    "description":
                        "Ordered by an immutable unique id so the cursor stays stable \
                         while records change. Keep calling with cursor=page.next_cursor \
                         until page.has_more is false.",
                    "parameters": [
                        {
                            "name": "limit", "in": "query", "required": false,
                            "description": "Page size. Out-of-range values are clamped, not rejected.",
                            "schema": {
                                "type": "integer", "minimum": 1,
                                "maximum": MAX_LIMIT, "default": DEFAULT_LIMIT,
                            },
                        },
                        {
                            "name": "cursor", "in": "query", "required": false,
                            "description": "Opaque. Pass back page.next_cursor verbatim.",
                            "schema": { "type": "string" },
                        },
                        {
                            "name": "updated_since", "in": "query", "required": false,
                            "description":
                                "RFC 3339 instant. Only users whose record changed at or \
                                 after it. Note that removals are not reported this way — \
                                 do a periodic full pass to detect them.",
                            "schema": { "type": "string", "format": "date-time" },
                            "example": "2026-07-27T00:00:00Z",
                        },
                        {
                            "name": "relation", "in": "query", "required": false,
                            "description": "Return only users holding this relation.",
                            "schema": {
                                "type": "string",
                                "enum": ["follower", "subscriber", "vip", "og", "moderator"],
                            },
                        },
                    ],
                    "responses": {
                        "200": {
                            "description": "A page of linked users.",
                            "content": { "application/json": { "schema": {
                                "type": "object",
                                "required": ["guild", "users", "page"],
                                "properties": {
                                    "guild": { "$ref": "#/components/schemas/Guild" },
                                    "users": {
                                        "type": "array",
                                        "items": { "$ref": "#/components/schemas/User" },
                                    },
                                    "page": { "$ref": "#/components/schemas/Page" },
                                },
                            } } },
                        },
                        "400": { "$ref": "#/components/responses/BadRequest" },
                        "401": { "$ref": "#/components/responses/Unauthorized" },
                        "429": { "$ref": "#/components/responses/RateLimited" },
                        "500": { "$ref": "#/components/responses/ServerError" },
                    },
                },
            },
            "/users/{discord_id}": {
                "get": {
                    "tags": ["Users"],
                    "operationId": "getUser",
                    "summary": "Look up one member",
                    "parameters": [ {
                        "name": "discord_id", "in": "path", "required": true,
                        "description": "Discord snowflake, as a string.",
                        "schema": { "type": "string" },
                        "example": "273645509182736451",
                    } ],
                    "responses": {
                        "200": {
                            "description": "The member is linked and visible to this key.",
                            "content": { "application/json": { "schema": {
                                "type": "object",
                                "required": ["guild", "user"],
                                "properties": {
                                    "guild": { "$ref": "#/components/schemas/Guild" },
                                    "user": { "$ref": "#/components/schemas/User" },
                                },
                            } } },
                        },
                        "401": { "$ref": "#/components/responses/Unauthorized" },
                        "404": {
                            "description":
                                "Nothing to report about this person. Deliberately does not \
                                 distinguish not-a-member from never-linked from opted-out, \
                                 which would leak the server's membership list.",
                            "content": { "application/json": {
                                "schema": { "$ref": "#/components/schemas/Error" },
                            } },
                        },
                        "429": { "$ref": "#/components/responses/RateLimited" },
                        "500": { "$ref": "#/components/responses/ServerError" },
                    },
                },
            },
        },
        "components": {
            "securitySchemes": {
                "apiKey": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": format!("{TOKEN_PREFIX}<43 random characters>"),
                    "description": format!(
                        "Guild-scoped API key, sent as `Authorization: Bearer {TOKEN_PREFIX}…`. \
                         There is no query-parameter form: query strings leak into logs, \
                         history and Referer headers. Scope: `{SCOPE_USERS_READ}`."
                    ),
                },
            },
            "schemas": {
                "Guild": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string", "description": "Discord snowflake." },
                        "name": {
                            "type": ["string", "null"],
                            "description": "Null when the name isn't cached yet; not an error.",
                        },
                    },
                },
                "Page": {
                    "type": "object",
                    "required": ["limit", "count", "has_more"],
                    "properties": {
                        "limit": { "type": "integer" },
                        "count": { "type": "integer", "description": "Users in this page." },
                        "has_more": { "type": "boolean" },
                        "next_cursor": {
                            "type": ["string", "null"],
                            "description": "Null on the last page.",
                        },
                    },
                },
                "User": {
                    "type": "object",
                    "required": [
                        "discord_id", "kick_user_id", "kick_username",
                        "linked_at", "updated_at", "relation",
                    ],
                    "properties": {
                        "discord_id": {
                            "type": "string",
                            "description":
                                "Discord snowflake. Always a string — it exceeds 53 bits, so \
                                 parsing as a JSON number loses precision.",
                        },
                        "discord_name": { "type": ["string", "null"] },
                        "kick_user_id": {
                            "type": "integer",
                            "description": "Stable across renames. Key your records on this.",
                        },
                        "kick_username": {
                            "type": "string",
                            "description": "Current username; can change.",
                        },
                        "linked_at": { "type": "string", "format": "date-time" },
                        "updated_at": {
                            "type": "string", "format": "date-time",
                            "description": "Feed this back as `updated_since`.",
                        },
                        "relation": { "$ref": "#/components/schemas/Relation" },
                    },
                },
                "Relation": {
                    "type": "object",
                    "description":
                        "Collapsed across every channel the server has connected: booleans are \
                         OR-ed, months and streak take the highest value, gifted subs are \
                         summed. One row per person, never one per channel.",
                    "properties": {
                        "is_follower": { "type": "boolean" },
                        "is_subscriber": { "type": "boolean" },
                        "is_vip": { "type": "boolean" },
                        "is_og": {
                            "type": "boolean",
                            "description":
                                "Per-channel badge granted by the broadcaster — not account age.",
                        },
                        "is_moderator": { "type": "boolean" },
                        "sub_months_cumulative": { "type": "integer" },
                        "sub_streak_months": { "type": "integer" },
                        "gifted_subs_given": { "type": "integer" },
                        "followed_at": { "type": ["string", "null"], "format": "date-time" },
                        "last_seen_at": { "type": ["string", "null"], "format": "date-time" },
                    },
                },
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": { "type": "string" },
                        "code": { "type": "string" },
                        "retry_after": {
                            "type": "integer",
                            "description": "Seconds. Present on 429.",
                        },
                    },
                },
            },
            "responses": {
                "BadRequest": {
                    "description": "A parameter was malformed. Retrying will not help.",
                    "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Error" },
                    } },
                },
                "Unauthorized": {
                    "description": "Missing, unknown, or revoked key.",
                    "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Error" },
                    } },
                },
                "RateLimited": {
                    "description": format!(
                        "Over the quota ({RATE_PER_MINUTE} requests/minute per key, burst \
                         {RATE_BURST})."
                    ),
                    "headers": {
                        "Retry-After": {
                            "description": "Seconds to wait before retrying.",
                            "schema": { "type": "integer" },
                        },
                    },
                    "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Error" },
                    } },
                },
                "ServerError": {
                    "description":
                        "Temporary server-side problem. Retry with backoff. This NEVER means \
                         the server has no linked users — a failed upstream lookup returns an \
                         error rather than an empty list precisely so the two are \
                         distinguishable. Keep your last good snapshot.",
                    "content": { "application/json": {
                        "schema": { "$ref": "#/components/schemas/Error" },
                    } },
                },
            },
        },
    });

    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        Json::<Value>(spec),
    )
}
