-- Webhook bookkeeping.
--
-- `webhook_subscriptions` tracks the EventSub-style subscriptions we've
-- registered with Kick per (channel, event_type). Stored so we can:
--   * idempotently re-register on broadcaster connect / secret rotation
--   * clean up on disconnect (best-effort DELETE against Kick's API)
--   * verify a received event corresponds to a subscription we own
--
-- `webhook_deliveries` is a short-retention idempotency log so duplicate
-- deliveries (Kick retries on 5xx + the occasional double-fire) don't
-- double-apply state changes. Rows older than ~24h are GC'd by a cleanup
-- task (Phase 11); the partial index keeps the working set tiny.

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id                  BIGSERIAL PRIMARY KEY,
    kick_channel_id     BIGINT NOT NULL REFERENCES broadcasters (kick_channel_id) ON DELETE CASCADE,
    event_type          TEXT NOT NULL,
    kick_subscription_id TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kick_channel_id, event_type)
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    message_id      TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_received
    ON webhook_deliveries (received_at);
