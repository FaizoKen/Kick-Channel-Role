# Kick-Channel-Role — Operations Runbook

Production target: multi-region public service behind Cloudflare Tunnel,
single Postgres (pgBouncer in transaction-pool mode), N stateless replicas.

## Deploy

1. Provision Postgres. Run migrations as a separate step before swapping
   replicas: `kick-channel-role migrate` (applies 001–009 and exits 0).
2. Deploy stateless replicas behind the LB.
   - The LB **must** rewrite `X-Forwarded-For` to the real client IP
     (Cloudflare Tunnel does this) — the per-IP rate limiter is spoofable
     otherwise.
   - LB liveness → `/kick-channel-role/health` (503 when DB down).
   - LB traffic gate → `/kick-channel-role/ready` (503 on SIGTERM drain).
3. Add the Cloudflare Tunnel ingress rule **before** the catch-all:
   `path: ^/kick-channel-role(/.*)?$  →  http://localhost:8094`.
4. Set `RL_DASHBOARD_ORIGIN` so the iframe role-config page can be embedded.
5. Register the Kick app (see README + the in-repo setup notes); the four
   redirect URIs must be HTTPS and byte-exact.

## Health & readiness

| Endpoint | Meaning |
| --- | --- |
| `GET /kick-channel-role/health` | 200 healthy / 503 if DB unreachable |
| `GET /kick-channel-role/ready` | 200 ready / 503 draining (post-SIGTERM) |

## Job queue (DLQ replay)

Background work is a durable `jobs` table (`player_sync`, `config_sync`,
`channel_sync`). Lifecycle: `pending → in_progress → completed | dead`.

- **Inspect the DLQ:**
  `SELECT id, kind, attempts, last_error, completed_at FROM jobs WHERE status='dead' ORDER BY completed_at DESC LIMIT 50;`
- **Replay one dead job:**
  `UPDATE jobs SET status='pending', attempts=0, next_run_at=now(), last_error=NULL WHERE id=$ID;`
  Workers wake on the `jobs_pending` NOTIFY; no restart needed.
- **Stuck in_progress** (worker crashed mid-claim): the reaper auto-revives
  rows whose `locked_at` is older than 45m. To force-revive sooner:
  `UPDATE jobs SET status='pending', locked_by=NULL, locked_at=NULL WHERE status='in_progress' AND locked_at < now() - interval '5 minutes';`

## Common incidents

**Roles not updating after a sub/follow on Kick**
1. Did the webhook arrive? `SELECT * FROM webhook_deliveries ORDER BY received_at DESC LIMIT 20;`
   - Empty → Kick isn't delivering. Check the app's webhook URL in the Kick
     developer portal and that `KICK_WEBHOOK_SECRET` matches.
2. Webhook arrived but no role change → check `jobs` for a failed
   `player_sync`/`channel_sync` and its `last_error`.
3. Regardless of webhooks, the **reconcile worker** rebuilds membership
   facts every 6h and fans out `channel_sync`. To force it, restart a
   replica (reconcile runs ~90s after boot).

**`auth_gateway … returned 401`** — `INTERNAL_API_KEY` doesn't match the
Auth Gateway's value. Sync workers can't scope by guild until fixed
(Convention 39/40); roles are *not* cleared on this failure (errors bubble,
worker retries).

**`Kick did not return a refresh_token`** on connect — the Kick app isn't
configured as a confidential client / the offline scope wasn't granted.
Re-run the connect flow after fixing the app registration.

**Iframe shows "Cannot load configuration"** — the `rl_token` failed one of
the six checks (Convention 43). Most common: clock skew (>60s) or the role
link was deleted upstream (Convention 47 — the local row self-cleans on the
next sync; reopen the plugin tab).

**Role flickers for every member** — should not happen: a failed guild-member
fetch bubbles and the sync aborts without clearing (Convention 40). If you
see it, check for a `sync_for_role_link` path that swallowed an error.

## Token / secret rotation

- **`KICK_WEBHOOK_SECRET`**: rotating it invalidates Kick's stored signing
  secret. You must re-subscribe every channel's events (re-run connect, or a
  future `resubscribe` admin action). Until then, deliveries fail signature
  verification and are rejected.
- **`SESSION_SECRET`**: this is the KEK root for broadcaster OAuth tokens
  (`services/crypto.rs`). Rotating it makes every `*_token_enc` blob
  undecryptable → every broadcaster must reconnect. Plan a `migrate_kek`
  step before rotating in production.
- **`INTERNAL_API_KEY`**: rotate in lockstep with the Auth Gateway.

## Scaling notes

- `WORKER_CONCURRENCY` scales sync throughput linearly until DB-pool
  saturation. Budget `replicas * DB_MAX_CONNECTIONS ≤ pgBouncer pool`.
- `live_poll` costs **zero** Kick calls when nobody is live (partial index
  on `WHERE is_live`). While live it's one channel-info call/min/channel.
- `reconcile` is the heavy job (list followers/subs/vips/mods per channel
  every 6h). At high channel counts, consider sharding reconcile by
  `kick_channel_id % replica_count`.

## Verifying the contract with curl

```bash
PFX=https://test-plugin-rolelogic.faizo.net/kick-channel-role
curl -s $PFX/health
curl -s -X POST -H 'Authorization: Token rl_test' -H 'Content-Type: application/json' \
  -d '{"guild_id":"G","role_id":"R"}' $PFX/register          # {"success":true}
curl -s -H 'Authorization: Token rl_test' $PFX/config        # iframe ui_mode payload
curl -s -X DELETE -H 'Authorization: Token rl_test' -H 'Content-Type: application/json' \
  -d '{"guild_id":"G","role_id":"R"}' $PFX/config            # {"success":true}

# Member-facing combined verify page data source (public, no auth). Feeds the
# "follow / subscribe on Kick" step. Empty list = guild has no channel connected.
curl -s "$PFX/verify/channels?guild=<GUILD_ID>"             # {"channels":[{"kick_slug":...}]}
```
