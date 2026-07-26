# Kick-Channel-Role

A RoleLogic plugin that grants Discord roles based on a member's relationship
to a Kick.com channel — follower / subscriber / VIP / mod / OG, with cumulative
sub-months, gift counts, account-age, regex matches, plus per-channel ephemeral
targets (live status, current category) for "Live Now"-style roles.

Conditions compose as a **DNF rule tree** (OR of AND-groups), so admins can
express rules like *"(subscriber AND ≥3 months) OR VIP OR (follower AND
followed-for ≥30 days)"* without nesting.

Written in Rust (axum, sqlx, tokio). Stateless HTTP tier + N durable
job-polling workers + Kick webhook ingestor. Designed for multi-region public
deploy, modeled directly on [Form-Respondent-Role](../Form-Respondent-Role/).

> **Status: feature-complete (phases 1–11).** Implemented end to end:
> RoleLogic contract (iframe UI mode); Kick OAuth 2.1 + PKCE for broadcaster
> connect and viewer verification; AES-256-GCM at-rest encryption of Kick
> tokens; the DNF rule engine (18 condition targets, 11 operators, OR-of-AND
> groups) with both a Rust evaluator and a pushdown SQL builder; durable job
> queue + per-player / per-role-link / per-channel sync workers; Kick webhook
> ingestor (HMAC-verified, idempotent) with auto-subscribe on connect;
> live-state poller + 6h reconcile safety net; the iframe rule-builder UI
> (dual-mode auth, postMessage protocol, optimistic locking,
> refresh-without-clobber); optional public users list; guild-scoped API keys
> + read-only `/api/v1` machine API. 82 unit tests (two run against a live
> Postgres when `DATABASE_URL` is set); `cargo clippy -D warnings` clean.
>
> The Kick API specifics (endpoint hosts, scope names, event names, webhook
> header/signature shape, user-object fields) are coded to Kick's published
> conventions but marked `TODO(kick-docs)` where they must be reconciled
> against the live API on first integration. Mechanics around them
> (verify → dedupe → apply → enqueue, PKCE, token refresh) are spec-stable.

---

## Quick start (local)

You need Docker. Postgres + the plugin start together in `compose.yml`.

```bash
cp .env.example .env
# Fill in: POSTGRES_PASSWORD, SESSION_SECRET, INTERNAL_API_KEY, BASE_URL.
# Suggested generators:
#   openssl rand -base64 24    # POSTGRES_PASSWORD
#   openssl rand -base64 48    # SESSION_SECRET
#   openssl rand -hex 32       # INTERNAL_API_KEY
docker compose up --build
```

Then visit `http://localhost:8094/kick-channel-role/health` — should
return `{"status":"healthy"}`. Once Phase 3 lands, broadcaster connection
lives at `/kick-channel-role/admin/{guild_id}/broadcasters` and member
verification at `/kick-channel-role/verify`.

The Auth Gateway it talks to (cookie minting, guild-membership lookup) is a
separate service. Point `AUTH_GATEWAY_URL` at it and share `INTERNAL_API_KEY`.

## Configuration

All config lives in env vars. See [`.env.example`](.env.example) for the
full list with comments. Required:

| Var | What |
| --- | --- |
| `DATABASE_URL` | `postgres://…` |
| `SESSION_SECRET` | HMAC key for `rl_session` + iframe-session + (Phase 3) Kick-token KEK |
| `BASE_URL` | Public-facing plugin URL (https in prod, no trailing slash) |
| `INTERNAL_API_KEY` | Shared secret for plugin → Auth Gateway calls |
| `POSTGRES_PASSWORD` | Used by both the DB container and `DATABASE_URL` |

Optional but commonly set: `AUTH_GATEWAY_URL`, `ROLELOGIC_API_URL`,
`RL_DASHBOARD_ORIGIN`, `KICK_CLIENT_ID`, `KICK_CLIENT_SECRET`,
`KICK_WEBHOOK_SECRET`, `DB_MAX_CONNECTIONS`, `WORKER_CONCURRENCY`.

## Repo layout

```
src/
  main.rs              # Router, middleware stack, worker spawn, signal handler
  config.rs            # AppConfig from env (incl. KickConfig)
  db.rs                # Pool + migrations (001–009)
  error.rs             # AppError + sqlx-error → HTTP-status classifier
  schema.rs            # RoleLogic iframe /config builder
  models/
    condition.rs       # ConditionTarget / Operator / TargetKind
    rule.rs            # RuleTree (DNF: OR of AND-groups)
    facts.rs           # POD (viewer × channel) facts for evaluation
  routes/
    plugin.rs          # POST /register, GET/POST/DELETE /config
    admin.rs           # broadcaster CRUD + iframe role-config + save/preview
    oauth.rs           # Kick OAuth callbacks (broadcaster + viewer)
    verify.rs          # member verification flow
    webhooks.rs        # Kick webhook ingestor
    users.rs           # public linked-users list + view-permission setting
    api_v1.rs          # read-only machine API (Bearer kck_… , guild from key)
    api_keys.rs        # manager CRUD for those keys (create/list/revoke)
    health.rs          # /health, /ready, /favicon.ico
  services/
    api_key.rs         # guild-scoped API keys: mint/hash/authenticate/quota
    rolelogic.rs       # RoleLogic API client (PUT/POST/DELETE users)
    auth_gateway.rs    # Auth Gateway /auth/internal/* (sync workers)
    auth.rs            # cookie+manager / guild-permission helpers
    kick.rs            # Kick API client (OAuth/PKCE, Helix-eq, webhooks)
    crypto.rs          # HKDF + AES-256-GCM token-at-rest encryption
    broadcaster_token.rs # decrypt → refresh → re-persist access tokens
    condition_eval.rs  # sync Rust rule evaluator (Convention 5)
    rule_sql.rs        # SQL WHERE pushdown for bulk per-role-link sync
    rule_validator.rs  # save-time rule-tree validation
    jobs.rs            # durable queue (enqueue/claim/retry/DLQ/reap)
    sync.rs            # per-player / per-role-link / per-channel sync
    session.rs         # rl_session cookie verify
    rl_token.rs        # rl_token JWT + iframe-session token
    csrf.rs            # Origin allowlist check
    security_headers.rs# CSP/HSTS/nosniff/Referrer-Policy middleware
  tasks/
    job_listener.rs    # LISTEN jobs_pending → wake workers
    job_worker.rs      # FOR UPDATE SKIP LOCKED dispatch loop
    live_poll.rs       # 60s live-state refresh while broadcasting
    reconcile.rs       # 6h webhook-loss safety net + GC
    shutdown.rs        # tokio broadcast-based shutdown
migrations/            # 001–012, applied in numeric order on startup
templates/             # iframe rule builder, verify, users list, oauth-done
```

## Public API (`/api/v1`)

A server manager can hand another service read-only access to their server's
linked Kick accounts, as JSON, without that service ever holding a user's
login.

**Why a key and not the session cookie.** `rl_session` is a whole-account
browser credential — every server, every plugin — with a short TTL, no
per-integration revocation and no audit trail. It also can't work
server-to-server at all: `/users/{guild}/data` *forwards* the caller's cookie
to the Auth Gateway to resolve guild membership, and a machine has no cookie
to forward. The API instead resolves membership through the gateway's
server-to-server endpoint (`/auth/internal/guild_member_ids`), same source of
truth and same per-plugin opt-out filter.

**Keys** are minted from the plugin's role settings in the RoleLogic
dashboard (Manage Server required). Each is scoped to one server, carries the
`users:read` scope, and is stored only as a SHA-256 hash — the raw value is
shown once and can never be retrieved. Revoking takes effect on the next
request. Max 10 live keys per server.

No endpoint takes a `guild_id`: the key carries it, so there is no cross-guild
check that can be forgotten.

```bash
BASE=https://your-host/kick-channel-role
KEY=kck_…

# Discovery document — no auth, describes the whole contract.
curl -s $BASE/api/v1

# Confirm a key and see which server it points at.
curl -s -H "Authorization: Bearer $KEY" $BASE/api/v1/whoami

# Linked members. Cursor-paginated; ordered by Discord ID so the cursor is
# stable even if someone renames mid-scan.
curl -s -H "Authorization: Bearer $KEY" \
  "$BASE/api/v1/users?limit=200&relation=subscriber"

# Incremental poll — only what changed.
curl -s -H "Authorization: Bearer $KEY" \
  "$BASE/api/v1/users?updated_since=2026-07-27T00:00:00Z"

# One member: "does this person qualify?" without paging the server.
curl -s -H "Authorization: Bearer $KEY" $BASE/api/v1/users/123456789012345678
```

Query params on `/users`: `limit` (1–500, default 100), `cursor` (pass back
`page.next_cursor`), `updated_since` (RFC 3339), `relation`
(`follower|subscriber|vip|og|moderator`).

Notes for integrators:

- **Not gated on the users-page visibility setting.** That knob controls which
  humans may browse the HTML page; a key is a separate, explicit grant. A UI
  toggle must not silently break a running integration — revoke the key
  instead.
- **Server-to-server only.** The CORS allowlist covers the dashboard origins,
  not arbitrary sites, so a browser on a third-party origin cannot call this.
  That is deliberate: it keeps keys out of frontend bundles.
- **Rate limit** 120 req/min per key, burst 30. `429` responses carry
  `Retry-After`. The per-IP limiter (5/s, burst 20) sits underneath and will
  trip first for a bursty single-host caller.
- **Opted-out members are absent**, exactly as they are from role sync.
- `404` on single-user lookup means "we have nothing to tell you about this
  person" — not a member, never linked, or opted out are deliberately
  indistinguishable.

## Development

Quick commands:

```bash
cargo build               # debug build
cargo check               # type-check only
cargo test                # all unit tests
cargo clippy --no-deps --all-targets -- -D warnings
cargo fmt --all --check
docker compose up --build # full local stack
```
