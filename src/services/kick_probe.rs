//! Follow probe: recover a viewer's *existing* relationship to a channel.
//!
//! # Why this exists
//!
//! Kick's public API (docs.kick.com) has no endpoint that answers "does user X
//! follow channel Y". There is no follower list, no per-user relationship
//! lookup, and no follow flag on any webhook payload. The only official signal
//! is the `channel.followed` event — and that fires **only on a fresh follow
//! transition**.
//!
//! So a viewer who already followed before linking their Kick account (or
//! before the broadcaster connected the channel) never generated an event.
//! [`crate::routes::webhooks`] never saw them, `is_follower` stayed false, and
//! they never got the role no matter how long they waited. The only workaround
//! members discovered was to unfollow and re-follow — which is exactly the
//! transition the webhook needs.
//!
//! This module closes that gap by reading Kick's *undocumented* channel
//! user-card endpoint — the one behind clicking a username in Kick chat:
//!
//! ```text
//! GET https://kick.com/api/v2/channels/{slug}/users/{username}
//! ```
//!
//! It returns `following_since`, `subscribed_for` and the viewer's channel
//! badges, which is precisely the state the public API withholds.
//!
//! # Trust model
//!
//! Undocumented means it can change shape, start returning a bot challenge, or
//! vanish — without notice. Every design choice here follows from that:
//!
//! * The probe is **strictly additive**. Webhooks remain the authoritative,
//!   always-on source; the probe only fills in what they structurally cannot
//!   see. Turning it off (`KICK_FOLLOW_PROBE_ENABLED=false`) degrades the
//!   plugin to its previous behaviour, never below it.
//! * It reports three states, not two. "Not following" and "I couldn't tell"
//!   are different answers, and only the first is evidence. See
//!   [`ProbeOutcome`].
//! * A response only counts as usable if it still looks like the user card we
//!   expect — specifically, the `following_since` key must be *present* (null
//!   is fine, that means "not following"). If Kick ever drops that field, the
//!   probe fails safe to [`ProbeOutcome::Unavailable`] and goes quiet rather
//!   than silently deciding nobody follows anything. That failure mode would
//!   strip roles from every member at once, so it is worth the strictness.
//! * Requests are rate-limited well below anything that could look like
//!   scraping, and identify themselves honestly in the User-Agent.
//!
//! Applying an outcome to the database — including the multi-confirmation rule
//! before a follow is ever removed — lives in
//! [`crate::services::follow_sync`], not here. This module does I/O and
//! parsing only.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use governor::{Quota, RateLimiter};
use serde_json::Value;

/// Identifies us to Kick. Deliberately honest: this is an undocumented
/// endpoint being used for a legitimate purpose, and a plugin that lies about
/// who it is in order to slip past bot protection is a plugin that deserves to
/// be blocked. If Kick would rather we didn't call this, they can tell us
/// apart from a browser and we'll get `Unavailable` — which the caller already
/// handles.
const USER_AGENT: &str = concat!(
    "RoleLogic-KickChannelRole/",
    env!("CARGO_PKG_VERSION"),
    " (+https://rolelogic.faizo.net; Discord role sync)"
);

/// Verification runs this inline-ish (via a job the verify page waits on), so
/// a slow probe must not leave a member staring at a spinner. Short timeout;
/// a miss just falls back to the guided re-follow path.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// What a single probe learned. The three-way split is the whole point: the
/// caller must be able to distinguish "Kick says they don't follow" from
/// "Kick didn't tell me", because only the former may ever remove a role.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// Kick returned a well-formed user card. Trustworthy in both directions.
    Usable(CardFacts),
    /// No usable answer — network error, non-200, bot challenge, unparseable
    /// body, or a card missing the fields we rely on. Carries a short reason
    /// for logging. **Never** evidence of anything; callers must leave stored
    /// facts untouched.
    Unavailable(String),
}

/// Facts read off a channel user card. Only `is_following` is treated as
/// authoritative in both directions; the rest are applied set-only (they can
/// grant, never revoke) because the subscription lifecycle and the chat-badge
/// snapshot are owned by the webhook ingestor and the expiry sweep.
#[derive(Debug, Clone, Default)]
pub struct CardFacts {
    pub is_following: bool,
    /// When the follow started, if Kick gave a parseable timestamp. This also
    /// backfills the "FOLLOWED" column on the public users page, which shows
    /// `—` for every pre-existing follower today.
    pub following_since: Option<DateTime<Utc>>,
    /// Months subscribed, per the card. 0 when absent or not subscribed.
    pub subscribed_for_months: i64,
    pub is_subscriber: bool,
    pub is_vip: bool,
    pub is_moderator: bool,
    pub is_og: bool,
}

/// Rate-limited client for the undocumented endpoint. Separate from
/// [`crate::services::kick::KickClient`] on purpose — different host, no
/// credentials, far more conservative budget, and it must be independently
/// disableable.
#[derive(Clone)]
pub struct FollowProbe {
    http: reqwest::Client,
    base: String,
    limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
}

impl FollowProbe {
    /// `base` is the site origin (default `https://kick.com`), `rpm` the
    /// request budget per minute across this replica.
    pub fn new(base: String, rpm: u32) -> Self {
        let http = reqwest::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("Failed to build follow-probe HTTP client");
        let quota = Quota::per_minute(NonZeroU32::new(rpm.max(1)).unwrap());
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            limiter: Arc::new(RateLimiter::direct(quota)),
        }
    }

    /// Look up `username`'s relationship to channel `slug`.
    ///
    /// Both are path segments on an undocumented endpoint, so they are
    /// percent-encoded and pre-validated rather than interpolated raw.
    pub async fn probe(&self, slug: &str, username: &str) -> ProbeOutcome {
        if !is_safe_segment(slug) || !is_safe_segment(username) {
            return ProbeOutcome::Unavailable("slug/username not URL-safe".into());
        }

        // Kick's channel slugs and usernames differ in case/underscore rules;
        // the card endpoint keys off the channel slug and the *username*.
        let url = format!(
            "{}/api/v2/channels/{}/users/{}",
            self.base,
            urlencoding::encode(slug),
            urlencoding::encode(username)
        );

        self.limiter.until_ready().await;

        let resp = match self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return ProbeOutcome::Unavailable(format!("request failed: {e}")),
        };

        let status = resp.status();
        if !status.is_success() {
            // Note 404 lands here deliberately. It *might* mean "no
            // relationship", but it might equally mean the endpoint moved or
            // the slug is stale — and we cannot tell the two apart. Treating
            // it as "not following" would let a Kick-side path change quietly
            // revoke roles, so it counts as no answer at all.
            return ProbeOutcome::Unavailable(format!("http {status}"));
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => return ProbeOutcome::Unavailable(format!("body read failed: {e}")),
        };

        parse_card(&body)
    }
}

/// Parse a user-card body into facts, or explain why it isn't usable.
///
/// Split out from the request so the recognition rules are directly testable
/// against real and adversarial payloads.
fn parse_card(body: &str) -> ProbeOutcome {
    let json: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        // A bot-protection interstitial is HTML with a 200. Not an answer.
        Err(e) => return ProbeOutcome::Unavailable(format!("non-JSON body: {e}")),
    };

    // Some Kick responses nest under `data`; accept either shape.
    let card = json.get("data").filter(|d| d.is_object()).unwrap_or(&json);

    let Some(obj) = card.as_object() else {
        return ProbeOutcome::Unavailable("body was not a JSON object".into());
    };

    // The load-bearing recognition check. `following_since` present-and-null
    // is a real "not following" answer; `following_since` *absent* means this
    // is not the card we think it is, and guessing would mean revoking roles
    // en masse. Fail safe instead.
    if !obj.contains_key("following_since") {
        return ProbeOutcome::Unavailable("card missing `following_since` field".into());
    }

    let following_since = obj.get("following_since").and_then(parse_kick_timestamp);
    let is_following = obj
        .get("following_since")
        .map(|v| !v.is_null())
        .unwrap_or(false);

    let subscribed_for_months = obj
        .get("subscribed_for")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0)
        .max(0);

    // Badges mirror what `chat.message.sent` carries, so the same three
    // channel badges are recoverable here for someone who has never spoken.
    let badges = obj.get("badges").and_then(Value::as_array);
    let has_badge = |name: &str| {
        badges.is_some_and(|arr| {
            arr.iter().any(|b| {
                b.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.eq_ignore_ascii_case(name))
            })
        })
    };

    ProbeOutcome::Usable(CardFacts {
        is_following,
        following_since,
        subscribed_for_months,
        is_subscriber: has_badge("subscriber") || has_badge("founder") || subscribed_for_months > 0,
        is_vip: has_badge("vip"),
        // `is_moderator` also appears as a top-level flag on the card.
        is_moderator: has_badge("moderator")
            || obj
                .get("is_moderator")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        is_og: has_badge("og"),
    })
}

/// Kick has been inconsistent about timestamp formatting on the site API
/// (RFC3339 with and without fractional seconds, and a bare `YYYY-MM-DD
/// HH:MM:SS` in UTC). Try each; a timestamp we can't parse is not a reason to
/// discard an otherwise good answer — the caller falls back to `now()`.
fn parse_kick_timestamp(v: &Value) -> Option<DateTime<Utc>> {
    let s = v.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    None
}

/// Guard against path traversal / injection through a stored slug or username
/// before it reaches a URL. Kick identifiers are conservative already; this
/// just makes the assumption explicit and enforced.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(body: &str) -> CardFacts {
        match parse_card(body) {
            ProbeOutcome::Usable(f) => f,
            ProbeOutcome::Unavailable(r) => panic!("expected usable, got unavailable: {r}"),
        }
    }

    fn unavailable_reason(body: &str) -> String {
        match parse_card(body) {
            ProbeOutcome::Unavailable(r) => r,
            ProbeOutcome::Usable(f) => panic!("expected unavailable, got {f:?}"),
        }
    }

    #[test]
    fn existing_follower_is_recovered_with_follow_date() {
        // The exact case from the bug report: linked, follows already, never
        // produced a `channel.followed` webhook.
        let f = facts(
            r#"{"id":123,"username":"CarefreeZTMGG","slug":"carefreeztmgg",
                "following_since":"2025-11-02 18:04:11","subscribed_for":0,"badges":[]}"#,
        );
        assert!(f.is_following);
        assert_eq!(
            f.following_since.map(|d| d.to_rfc3339()),
            Some("2025-11-02T18:04:11+00:00".to_string())
        );
        assert!(!f.is_subscriber);
    }

    #[test]
    fn null_following_since_is_a_real_negative() {
        let f = facts(r#"{"id":1,"username":"x","following_since":null,"badges":[]}"#);
        assert!(!f.is_following);
        assert!(f.following_since.is_none());
    }

    #[test]
    fn rfc3339_timestamps_parse() {
        let f = facts(r#"{"following_since":"2026-01-15T09:30:00.123456Z"}"#);
        assert!(f.is_following);
        assert!(f.following_since.is_some());
    }

    #[test]
    fn unparseable_timestamp_still_counts_as_following() {
        // Better to know they follow and lose the date than to drop the fact.
        let f = facts(r#"{"following_since":"last tuesday"}"#);
        assert!(f.is_following);
        assert!(f.following_since.is_none());
    }

    #[test]
    fn badges_and_sub_months_are_read() {
        let f = facts(
            r#"{"following_since":"2024-01-01 00:00:00","subscribed_for":7,
                "is_moderator":true,
                "badges":[{"type":"vip"},{"type":"og"},{"type":"subscriber","count":7}]}"#,
        );
        assert_eq!(f.subscribed_for_months, 7);
        assert!(f.is_subscriber && f.is_vip && f.is_og && f.is_moderator);
    }

    #[test]
    fn data_wrapped_card_is_accepted() {
        let f = facts(r#"{"data":{"following_since":"2024-01-01 00:00:00"}}"#);
        assert!(f.is_following);
    }

    // --- fail-safe behaviour: none of these may read as "not following" ---

    #[test]
    fn missing_following_since_is_unavailable_not_a_negative() {
        // The dangerous case. If Kick renames the field, treating the card as
        // a negative would revoke every follower role at once.
        let r = unavailable_reason(r#"{"id":1,"username":"x","badges":[]}"#);
        assert!(r.contains("following_since"), "got: {r}");
    }

    #[test]
    fn bot_challenge_html_is_unavailable() {
        let r = unavailable_reason("<!DOCTYPE html><html>Just a moment…</html>");
        assert!(r.contains("non-JSON"), "got: {r}");
    }

    #[test]
    fn json_error_blob_is_unavailable() {
        let r = unavailable_reason(r#"{"error":"not found"}"#);
        assert!(r.contains("following_since"), "got: {r}");
    }

    #[test]
    fn non_object_body_is_unavailable() {
        assert!(matches!(parse_card("[]"), ProbeOutcome::Unavailable(_)));
    }

    #[test]
    fn hostile_identifiers_are_rejected_before_the_request() {
        assert!(!is_safe_segment("../../admin"));
        assert!(!is_safe_segment("a/b"));
        assert!(!is_safe_segment(""));
        assert!(!is_safe_segment(&"x".repeat(65)));
        assert!(is_safe_segment("itztmgg"));
        assert!(is_safe_segment("TMGGchurros530"));
        assert!(is_safe_segment("Faizo_Ken"));
        assert!(is_safe_segment("faizo-ken"));
    }
}
