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

**"I linked my Kick account but never got the role"** — the classic report,
and almost always a member who **already followed before linking**.

Kick's public API cannot answer "does user X follow channel Y": no follower
list, no per-user lookup, no follow flag on any event. The only official
signal is `channel.followed`, which fires *only on a fresh follow*. Someone
who followed last month and links today generates no event at all, so
`is_follower` stays false. (This is why the folklore workaround is "unfollow
and follow again" — that recreates the transition.)

The **follow probe** exists to fix exactly this and runs automatically at
link time and on "Re-check now". To diagnose:

```sql
-- Has this member been probed, and what did it conclude?
SELECT b.kick_slug, cr.is_follower, cr.followed_at,
       cr.follow_probed_at, cr.follow_confirmed_at, cr.follow_probe_misses
  FROM channel_relations cr
  JOIN broadcasters b USING (kick_channel_id)
  JOIN kick_users ku USING (kick_user_id)
 WHERE ku.discord_id = '<discord_id>';
```

- `follow_probed_at` NULL → no probe has landed. Check `jobs` for a
  `follow_probe` row (`payload->>'discord_id'`) and its `last_error`, and
  confirm `KICK_FOLLOW_PROBE_ENABLED` isn't false. Members in this state are
  picked up automatically by the backfill (below) — they don't have to
  revisit the verify page.
- `follow_probed_at` set but `is_follower` false → Kick genuinely reported no
  follow. Have them follow the channel; the webhook handles the rest.
- Repeated `follow probe returned no usable answer` warnings in the logs →
  the undocumented endpoint is blocked or changed shape. Nothing breaks:
  webhooks still work and the verify page guides members through a re-follow.
  Nobody loses a role — a probe that can't answer never writes.

**Roles not updating after a sub/follow on Kick**
1. Did the webhook arrive? `SELECT * FROM webhook_deliveries ORDER BY received_at DESC LIMIT 20;`
   - Empty → Kick isn't delivering. Check the app's webhook URL in the Kick
     developer portal and that the subscriptions exist
     (`SELECT * FROM webhook_subscriptions;`).
2. Webhook arrived but no role change → check `jobs` for a failed
   `player_sync`/`channel_sync` and its `last_error`.
3. The **reconcile worker** runs every 6h: it refreshes channel live state,
   expires lapsed subs, self-heals webhook subscriptions and enqueues the
   follow sweep. Note it does **not** rebuild per-viewer membership — it
   can't, since Kick exposes no list endpoints. Recovering a viewer's
   relationship is the follow probe's job, not this worker's. To force a
   cycle, restart a replica (reconcile runs ~90s after boot).

**Backfilling members who linked before the probe shipped**

Nothing to run — the reconcile worker drains this automatically. Every cycle
(~90s after boot, then every 6h) it enqueues probes for up to 500 viewers
whose relationships have never been successfully read, oldest attempt first.
Rows leave the backlog as soon as one probe answers in either direction, so
the work stops on its own; failed probes are retried after 24h.

Watch it drain:

```sql
-- Remaining backlog. Should fall to 0 and stay there.
SELECT count(*) FILTER (WHERE follow_probed_at IS NULL)        AS never_probed,
       count(*) FILTER (WHERE follow_probed_at IS NOT NULL)    AS probed,
       count(*) FILTER (WHERE is_follower)                     AS followers
  FROM channel_relations;
```

Log line: `follow backfill enqueued probes for never-checked viewers`
(with `count`). If `never_probed` stalls above 0 while that line keeps
appearing, probes are being attempted but never answered — see the
"no usable answer" note above; run at `RUST_LOG=kick_channel_role=debug` and
grep `follow probe unavailable` for the reason.

To force a pass without waiting 6h, restart a replica.

**A member lost their follower role unexpectedly** — check
`follow_probe_misses` and `follow_confirmed_at` above. Removal requires
`KICK_UNFOLLOW_CONFIRMATIONS` (default 3) separate probes, each at least 6h
apart, all reporting "not following"; errors and unreachable responses never
count. If they insist they still follow, that's a probe accuracy bug — set
`KICK_FOLLOW_PROBE_ENABLED=false` to stop removals immediately, then
investigate.

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

**A guild's API integration suddenly gets 401s** — the key was revoked, or
someone re-minted and swapped the wrong value in. Confirm which:

```sql
SELECT id, label, prefix, created_by, created_at, last_used_at, revoked_at, revoked_by
  FROM guild_api_keys WHERE guild_id = '<guild>' ORDER BY created_at DESC;
```

Revoked rows are kept on purpose, so `revoked_by` / `revoked_at` answer "who
turned this off and when". There is no un-revoke and no way to recover the
token — we only store its SHA-256. The fix is always: mint a new key in the
dashboard, paste it into the integration.

**"Which key pulled our member list?"** — `last_used_at` (coarse: written at
most once a minute per key) says a key is live. For what it actually read,
run the app at `RUST_LOG=kick_channel_role=debug` and look for
`api/v1 users listed` lines carrying `key_id`, `guild_id` and `returned`.
Match `key_id` back to the table above. Tokens are never logged; only the
public `prefix` appears, in the `API key created` / `API key revoked` lines.

**Suspected key leak** — revoke it in the dashboard (effective on the very
next request; there is no cached auth decision to expire), then check
`last_used_at` against when the guild says their integration last ran. A gap
means someone else was using it.

## Token / secret rotation

- **`KICK_WEBHOOK_SECRET`**: rotating it invalidates Kick's stored signing
  secret. You must re-subscribe every channel's events (re-run connect, or a
  future `resubscribe` admin action). Until then, deliveries fail signature
  verification and are rejected.
- **`SESSION_SECRET`**: this is the KEK root for broadcaster OAuth tokens
  (`services/crypto.rs`). Rotating it makes every `*_token_enc` blob
  undecryptable → every broadcaster must reconnect. Plan a `migrate_kek`
  step before rotating in production.
- **`INTERNAL_API_KEY`**: rotate in lockstep with the Auth Gateway. Note this
  is the *master* server-to-server credential across every guild — never hand
  it to a guild owner who wants API access. Mint them a `kck_…` guild key
  instead; that is the whole reason it exists.
- **Guild `kck_…` API keys**: self-service, per guild, no operator action.
  Rotation is mint-new → swap → revoke-old, and the 10-key ceiling leaves
  room for that overlap.

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
