-- Follow-probe bookkeeping.
--
-- Background: Kick's *public* API exposes no way to ask "does user X follow
-- channel Y" — there is no follower list, no per-user relationship endpoint,
-- and no follow flag on any webhook payload. The only official signal is the
-- `channel.followed` event, which fires solely on a fresh follow *transition*.
--
-- Consequence (the bug this migration supports fixing): anyone who already
-- followed before they linked their Kick account — or before the broadcaster
-- connected the channel — never produced that event, so `is_follower` stayed
-- false forever and they never got the role. The only workaround members
-- found was to unfollow and re-follow.
--
-- The follow probe reads Kick's undocumented channel user-card endpoint to
-- recover that state. Because it is undocumented it can fail or disappear at
-- any time, so we record *how confident* we are rather than trusting a single
-- read:
--
--   follow_probed_at      last time a probe returned a usable answer
--   follow_confirmed_at   last time a probe positively confirmed a follow
--   follow_missed_at      last time a "not following" answer was *counted*
--   follow_probe_misses   consecutive counted "not following" answers
--   follow_probe_attempted_at  last time a probe was *tried*, answer or not
--
-- `follow_probe_attempted_at` is the only one written on a failed probe, and
-- it holds no opinion about the relationship — it exists so the backfill can
-- walk the never-successfully-probed backlog fairly. Without it, a permanently
-- unreachable row would be re-picked every cycle and starve everything behind
-- it; with it, the backfill orders by "least recently attempted" and drains.
--
-- `follow_probed_at` and `follow_missed_at` are deliberately separate.  The
-- first orders the sweep and must advance on every usable probe, or the sweep
-- would re-pick the same row forever.  The second gates how fast misses can
-- accumulate: two probes minutes apart are one observation, not two, so a
-- member mashing "Re-check now" can never talk us into revoking their role.
--
-- A positive answer applies immediately (it can only ever grant). A negative
-- answer only removes the follow after `KICK_UNFOLLOW_CONFIRMATIONS` separate
-- usable probes agree, spaced over time — Kick sends no unfollow event, so a
-- negative is the only way to ever clear a stale follow, but a single bad read
-- must never strip somebody's role. Probes that error, time out, get
-- challenged, or return an unrecognisable body are "unavailable" and touch
-- none of these columns.
--
-- This is the same lesson migration 011 / the reconcile worker already
-- learned the hard way: never reset facts to defaults on a fetch failure.

ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS follow_probed_at TIMESTAMPTZ;

ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS follow_confirmed_at TIMESTAMPTZ;

ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS follow_missed_at TIMESTAMPTZ;

ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS follow_probe_misses SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS follow_probe_attempted_at TIMESTAMPTZ;

-- Backfill: every follow we already know about came from a `channel.followed`
-- webhook, which is authoritative. Treat it as confirmed at its follow time so
-- the staleness sweep doesn't immediately start counting misses against rows
-- that were never probed.
UPDATE channel_relations
   SET follow_confirmed_at = COALESCE(followed_at, last_synced_at)
 WHERE is_follower
   AND follow_confirmed_at IS NULL;

-- Sweep ordering: "least recently probed first", NULLs (never probed) first.
-- Partial index — the sweep only ever walks rows belonging to linked viewers
-- of connected channels, and the hot case is picking the next batch.
CREATE INDEX IF NOT EXISTS idx_channel_relations_probe_due
    ON channel_relations (follow_probed_at NULLS FIRST);

-- Backfill ordering: the never-successfully-probed backlog, oldest attempt
-- first. Partial index because that set shrinks to nothing as the backlog
-- drains — after which this index costs almost nothing and the backfill query
-- stops matching rows entirely.
CREATE INDEX IF NOT EXISTS idx_channel_relations_backfill_due
    ON channel_relations (follow_probe_attempted_at NULLS FIRST)
    WHERE follow_probed_at IS NULL;
