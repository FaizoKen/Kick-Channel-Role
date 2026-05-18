-- Durable background-job queue.
--
-- Workers (Phase 7+) claim rows with `FOR UPDATE SKIP LOCKED` so N replicas
-- drain in parallel without double-processing. NOTIFY/LISTEN on
-- `jobs_pending` wakes idle workers sub-second; the poll timer is a safety
-- net for missed notifications under pgBouncer transaction-pool mode.
--
-- `kind` discriminates the payload shape:
--   * 'player_sync'   → {"discord_id": "..."}
--   * 'config_sync'   → {"guild_id": "...", "role_id": "..."}
--   * 'channel_sync'  → {"kick_channel_id": 123}   (per-channel state refresh)
--   * 'webhook'       → {"url": "...", "payload": {...}}   (outbound)
--
-- Lifecycle: pending → in_progress → (completed | pending-with-backoff | dead).

CREATE TABLE IF NOT EXISTS jobs (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 8,
    next_run_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    locked_by       TEXT,
    locked_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    CONSTRAINT jobs_status_check
        CHECK (status IN ('pending','in_progress','completed','dead'))
);

-- Hot path: workers poll for pending rows ordered by next_run_at. Partial
-- index keeps the working set tiny even when there are many completed rows.
CREATE INDEX IF NOT EXISTS idx_jobs_pending_next_run
    ON jobs (next_run_at)
    WHERE status = 'pending';

-- For operator dashboards / DLQ replay tooling.
CREATE INDEX IF NOT EXISTS idx_jobs_dead_recent
    ON jobs (completed_at DESC)
    WHERE status = 'dead';

-- Detect stuck-in-progress rows (worker crashed after claiming but before
-- finishing). The reaper task flips these back to pending after a TTL.
CREATE INDEX IF NOT EXISTS idx_jobs_locked
    ON jobs (locked_at)
    WHERE status = 'in_progress';
