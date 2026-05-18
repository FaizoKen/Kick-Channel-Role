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
> refresh-without-clobber); optional public users list. 71 unit
> tests; `cargo clippy -D warnings` clean.
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
    health.rs          # /health, /ready, /favicon.ico
  services/
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
migrations/            # 001–009, applied in numeric order on startup
templates/             # iframe rule builder, verify, users list, oauth-done
```

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
