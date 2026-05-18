-- Kick_users: linked Discord ↔ Kick identity. Populated by the viewer
-- OAuth callback (Phase 4); one row per verified Discord member.
--
-- `kick_user_id` is UNIQUE because a Kick account can be linked to at most
-- one Discord account at a time. Re-linking from a second Discord ID would
-- raise a unique-violation; the handler must explicitly DELETE the old row.
-- This prevents a "sub-sharing" exploit where one Kick subscription grants
-- a role to multiple Discord accounts.
--
-- `kick_created_at` and `is_og` are denormalized off the user object so the
-- account_age_days and is_og condition targets evaluate without a Kick API
-- round-trip. They're refreshed on every successful link / re-link.

CREATE TABLE IF NOT EXISTS kick_users (
    discord_id        TEXT PRIMARY KEY,
    kick_user_id      BIGINT UNIQUE NOT NULL,
    kick_username     TEXT NOT NULL,
    kick_created_at   TIMESTAMPTZ NOT NULL,
    country_code      TEXT,
    is_og             BOOLEAN NOT NULL DEFAULT FALSE,
    linked_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    refreshed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Reverse lookup: webhook handlers receive Kick user IDs and need to find
-- the Discord ID to enqueue player_sync for.
CREATE INDEX IF NOT EXISTS idx_kick_users_kick_id
    ON kick_users (kick_user_id);
