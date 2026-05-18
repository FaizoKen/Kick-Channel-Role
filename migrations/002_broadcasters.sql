-- Broadcasters: one row per Kick channel an admin has connected. A single
-- guild can connect multiple channels; a single channel can be referenced
-- by many role_links across many guilds (admins of multiple servers can
-- bind to the same streamer).
--
-- access_token_enc / refresh_token_enc are AES-256-GCM ciphertexts whose
-- key is HKDF-derived from SESSION_SECRET (see services/crypto.rs, Phase 3).
-- Storing them encrypted means a DB dump alone can't be used to impersonate
-- the broadcaster against Kick's API.
--
-- `is_live` / `current_category` / `viewer_count` are denormalized for fast
-- per-channel ephemeral-target evaluation (Convention 6). They're updated
-- by the live_poll worker (Phase 9) and `stream.online`/`offline` webhooks.

CREATE TABLE IF NOT EXISTS broadcasters (
    kick_channel_id     BIGINT PRIMARY KEY,
    kick_slug           TEXT NOT NULL,
    display_name        TEXT NOT NULL,

    -- OAuth state. token_expires_at is the access-token expiry; we refresh
    -- on access if within ~5 minutes of it (services/kick.rs, Phase 3).
    access_token_enc    BYTEA NOT NULL,
    refresh_token_enc   BYTEA NOT NULL,
    token_expires_at    TIMESTAMPTZ NOT NULL,
    token_scopes        TEXT[] NOT NULL DEFAULT '{}',

    -- Denormalized live state (Convention 6).
    is_live             BOOLEAN NOT NULL DEFAULT FALSE,
    current_category    TEXT,
    viewer_count        INTEGER NOT NULL DEFAULT 0,
    live_started_at     TIMESTAMPTZ,
    last_live_at        TIMESTAMPTZ,

    last_synced_at      TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Slug lookups are used by the connect flow (admin pastes a Kick channel
-- URL → we resolve the slug to a channel_id) and by webhook ingestion when
-- the payload identifies the channel by slug.
CREATE UNIQUE INDEX IF NOT EXISTS idx_broadcasters_slug
    ON broadcasters (lower(kick_slug));

-- Live-poll worker scans this every cycle while at least one broadcaster
-- is live; the partial index keeps the scan cheap when nobody is.
CREATE INDEX IF NOT EXISTS idx_broadcasters_live
    ON broadcasters (kick_channel_id)
    WHERE is_live;
