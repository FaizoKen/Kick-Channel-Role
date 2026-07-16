-- OG is a per-channel chat badge on Kick (the broadcaster grants it, like
-- VIP) — NOT an account-level "early adopter" attribute. The original schema
-- put `is_og` on kick_users and populated it from a user-ID threshold
-- heuristic, which granted "OG" roles to anyone with an old Kick account
-- (bug report: "OG gives the role to subscribers"). The channel-scoped truth
-- lives here and is populated from `chat.message.sent` webhook badges.
--
-- `kick_users.is_og` is intentionally left in place (expand→contract); no
-- code reads it after this deploy and a later migration may drop it.
--
-- `sub_expires_at` records the expiry Kick reports on subscription events.
-- Kick sends no "subscription cancelled/expired" webhook and has no
-- list-subscribers endpoint, so the reconcile worker uses this timestamp
-- (plus a grace window) to flip `is_subscriber` off when a sub lapses.

ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS is_og BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE channel_relations
    ADD COLUMN IF NOT EXISTS sub_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_channel_relations_og
    ON channel_relations (kick_channel_id)
    WHERE is_og;
