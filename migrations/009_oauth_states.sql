-- Server-side PKCE state for Kick OAuth flows. Convention 37 explicitly
-- permits oauth_states for a plugin's *secondary* OAuth (not Discord).
--
-- Rows live for ~10 minutes, then expire. Cleanup task GCs expired rows
-- periodically; the partial index keeps the working set tiny.

CREATE TABLE IF NOT EXISTS kick_oauth_states (
    state           TEXT PRIMARY KEY,
    code_verifier   TEXT NOT NULL,
    flow            TEXT NOT NULL CHECK (flow IN ('broadcaster','viewer')),
    discord_id      TEXT NOT NULL,
    guild_id        TEXT,
    return_to       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kick_oauth_states_expires
    ON kick_oauth_states (expires_at);
