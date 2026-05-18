-- Capture the Discord display name at link time so the public users page can
-- show "DiscordName (kickslug)" without an Auth Gateway per-user lookup.
-- The display name lives in the `rl_session` cookie payload — we just grab it
-- in the viewer-OAuth callback and persist alongside kick_user_id.
--
-- Nullable: rows linked before this migration ran won't have a value until
-- the user re-links or their session is refreshed through a code path that
-- writes the column. The users page falls back to discord_id when null.

ALTER TABLE kick_users
    ADD COLUMN IF NOT EXISTS discord_name TEXT;
