-- Guild-scoped API keys for the read-only public JSON API (`/api/v1/*`).
--
-- Why a key table instead of reusing the `rl_session` cookie: a session
-- cookie is a *whole-account* credential (every guild, every plugin) with a
-- short TTL, no per-integration revocation, and no audit trail — and the
-- cookie-authed users endpoint physically cannot work server-to-server
-- because it forwards the caller's cookie to the Auth Gateway. A key issued
-- by a manager is scoped to exactly one guild, revocable on its own, and
-- carries its own usage record.
--
-- `token_hash` is SHA-256 of the raw token. The raw value is shown to the
-- creating manager exactly once and never stored, so a database leak does
-- not yield usable credentials. Lookup is by hash (an indexed equality
-- probe), which is safe here because the token is 256 bits of CSPRNG output
-- — unlike a password, it is not guessable, so no KDF or constant-time
-- compare is warranted.
--
-- `prefix` is the first few characters of the raw token, kept in clear so
-- the management UI can show "kck_3f9a…" and an operator can correlate a log
-- line with a row without being able to reconstruct the secret.
--
-- `scopes` is future-proofing: today every key is minted `{users:read}`, but
-- the column exists so a later write-capable or narrower scope does not need
-- a migration + backfill. Convention 6 (own column, not JSONB) applies.

CREATE TABLE IF NOT EXISTS guild_api_keys (
    id            BIGSERIAL PRIMARY KEY,
    guild_id      TEXT NOT NULL,
    token_hash    BYTEA NOT NULL,
    prefix        TEXT NOT NULL,
    label         TEXT NOT NULL,
    scopes        TEXT[] NOT NULL DEFAULT ARRAY['users:read']::TEXT[],
    -- Discord ID of the manager who created / revoked the key. Audit only;
    -- the key keeps working if that person later loses Manage Server, which
    -- is deliberate — an integration must not break because one admin left.
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Coarse "last seen" for the UI. Written at most once a minute per key
    -- (see services::api_key::touch_last_used) so a hot integration doesn't
    -- turn every read into a write.
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT
);

-- Authentication path: exactly one indexed probe per request.
CREATE UNIQUE INDEX IF NOT EXISTS idx_guild_api_keys_hash
    ON guild_api_keys (token_hash);

-- Management UI lists the live keys for one guild.
CREATE INDEX IF NOT EXISTS idx_guild_api_keys_guild_live
    ON guild_api_keys (guild_id)
    WHERE revoked_at IS NULL;
