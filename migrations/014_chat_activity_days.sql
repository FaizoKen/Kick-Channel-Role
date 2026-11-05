-- Chat messages per (channel, viewer, UTC day), so the "Chat messages (last
-- 30d)" condition really counts the last 30 days.
--
-- Until now `channel_relations.chat_messages_30d` was only ever incremented
-- (webhooks::apply_event on `chat.message.sent`) and nothing aged it, so it
-- was an all-time count since the channel was connected. Now each message
-- also lands in today's bucket here, and the reconcile worker recomputes the
-- column from the last 30 buckets every cycle and drops older ones.
--
-- Seeding: the running totals go into today's bucket once, when the table is
-- created, so no member's count (or a role that depends on it) drops on
-- deploy; they age out 30 days later like any other day's messages. Every
-- migration re-runs on each start (db::run_migrations), so the create and the
-- seed sit behind one existence check — a second run must not seed again, or
-- every count would double.

DO $$
BEGIN
    IF to_regclass('chat_activity_days') IS NULL THEN
        CREATE TABLE chat_activity_days (
            kick_channel_id BIGINT  NOT NULL REFERENCES broadcasters (kick_channel_id) ON DELETE CASCADE,
            kick_user_id    BIGINT  NOT NULL,
            day             DATE    NOT NULL,
            messages        INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (kick_channel_id, kick_user_id, day)
        );

        INSERT INTO chat_activity_days (kick_channel_id, kick_user_id, day, messages)
        SELECT kick_channel_id, kick_user_id, (now() AT TIME ZONE 'UTC')::date, chat_messages_30d
          FROM channel_relations
         WHERE chat_messages_30d > 0;
    END IF;
END $$;

-- The reconcile worker's cleanup deletes by day.
CREATE INDEX IF NOT EXISTS idx_chat_activity_days_day ON chat_activity_days (day);
