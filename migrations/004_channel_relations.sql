-- Channel_relations: the denormalized facts table that every rule
-- evaluation reads from. One row per (channel, viewer) pair.
--
-- Convention 6: every condition target that filters via SQL has its own
-- column here so `build_rule_where` can emit straight `WHERE cr.is_subscriber`
-- predicates instead of JSONB extraction. JSONB is only used for fields
-- without their own column (none for now, but reserved for future flexibility).
--
-- Rows are created/updated by:
--   * webhook_ingestor (Phase 8) on Kick push events
--   * reconcile_worker (Phase 9) every 6h via broadcaster-token Helix calls
--   * player_sync_worker on demand when a viewer's role eligibility is reevaluated
--
-- A row may exist with all-false / all-zero columns if the viewer is known
-- (linked) but has no relationship to the channel yet — that's the
-- "no relation" state, distinct from "row missing" (= never evaluated).

CREATE TABLE IF NOT EXISTS channel_relations (
    kick_channel_id        BIGINT NOT NULL REFERENCES broadcasters (kick_channel_id) ON DELETE CASCADE,
    kick_user_id           BIGINT NOT NULL,

    -- Follower facts
    is_follower            BOOLEAN NOT NULL DEFAULT FALSE,
    followed_at            TIMESTAMPTZ,

    -- Subscription facts
    is_subscriber          BOOLEAN NOT NULL DEFAULT FALSE,
    subscribed_at          TIMESTAMPTZ,
    sub_months_cumulative  INTEGER NOT NULL DEFAULT 0,
    sub_streak_months      INTEGER NOT NULL DEFAULT 0,
    sub_is_gift            BOOLEAN NOT NULL DEFAULT FALSE,
    gifted_subs_given      INTEGER NOT NULL DEFAULT 0,

    -- Role facts
    is_vip                 BOOLEAN NOT NULL DEFAULT FALSE,
    is_moderator           BOOLEAN NOT NULL DEFAULT FALSE,

    -- Activity facts (channel-scoped). chat_messages_30d is a sliding-window
    -- counter maintained by the webhook ingestor; the reconcile worker re-
    -- computes it from the chat-stats endpoint (Phase 9) if Kick exposes one.
    kicks_donated          INTEGER NOT NULL DEFAULT 0,
    chat_messages_30d      INTEGER NOT NULL DEFAULT 0,
    last_seen_at           TIMESTAMPTZ,

    last_synced_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kick_channel_id, kick_user_id)
);

-- Reverse lookup: when a viewer's link is updated, we re-evaluate every
-- channel they're known to.
CREATE INDEX IF NOT EXISTS idx_channel_relations_user
    ON channel_relations (kick_user_id);

-- Partial indexes for hot booleans (Convention 6). The bulk-sync SQL is
-- shape `WHERE cr.kick_channel_id = $1 AND cr.is_follower [AND …]`, so
-- per-channel filters scoped to the hot boolean are the right shape.
CREATE INDEX IF NOT EXISTS idx_channel_relations_followers
    ON channel_relations (kick_channel_id)
    WHERE is_follower;
CREATE INDEX IF NOT EXISTS idx_channel_relations_subs
    ON channel_relations (kick_channel_id)
    WHERE is_subscriber;
CREATE INDEX IF NOT EXISTS idx_channel_relations_vip
    ON channel_relations (kick_channel_id)
    WHERE is_vip;
CREATE INDEX IF NOT EXISTS idx_channel_relations_mod
    ON channel_relations (kick_channel_id)
    WHERE is_moderator;
