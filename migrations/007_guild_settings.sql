-- Per-guild settings (Convention 33). Server-wide knobs live here, NOT on
-- role_links rows, so two role links in the same guild can't drift apart on
-- "settings for this server."
--
-- `view_permission` controls who can view the optional public users list
-- (Phase 10): 'managers' (default, manage-server only), 'members' (any
-- member of the guild), or 'disabled' to hide entirely.

CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id         TEXT PRIMARY KEY,
    view_permission  TEXT NOT NULL DEFAULT 'managers',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
