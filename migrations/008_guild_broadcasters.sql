-- A channel can be connected by multiple guilds (each via its own OAuth
-- consent). `broadcasters` rows are globally keyed by kick_channel_id; this
-- join table records which guilds have opted into using that channel.
--
-- Disconnect-from-a-guild only DELETEs the join row. The broadcaster row
-- (with its OAuth tokens) survives as long as at least one other guild is
-- still using it. When the last guild disconnects, a cleanup task can GC
-- the orphaned broadcaster.

CREATE TABLE IF NOT EXISTS guild_broadcasters (
    guild_id                TEXT NOT NULL,
    kick_channel_id         BIGINT NOT NULL REFERENCES broadcasters (kick_channel_id) ON DELETE CASCADE,
    connected_by_discord_id TEXT,
    connected_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, kick_channel_id)
);

CREATE INDEX IF NOT EXISTS idx_guild_broadcasters_guild
    ON guild_broadcasters (guild_id);
