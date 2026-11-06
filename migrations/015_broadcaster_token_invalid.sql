-- When Kick stops accepting a channel's sign-in.
--
-- A broadcaster's refresh token can be revoked on Kick's side (the streamer
-- removes the app, changes their password, Kick resets sessions). Kick then
-- answers every refresh with `invalid_grant`, which is final for that token.
-- Until now the reconcile worker kept retrying it every cycle, logged a
-- warning each time, and gave up on the whole channel before expiring lapsed
-- subscriptions. Now the first `invalid_grant` stamps this column, nothing
-- calls Kick's token endpoint for the channel again, the role settings ask
-- the admin to reconnect, and reconnecting (the broadcaster OAuth upsert)
-- clears it. Webhook subscriptions often keep delivering meanwhile, so the
-- channel's facts keep updating from events.
ALTER TABLE broadcasters
    ADD COLUMN IF NOT EXISTS token_invalid_at TIMESTAMPTZ;
