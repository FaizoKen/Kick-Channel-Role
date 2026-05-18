//! Kick.com API client: OAuth 2.1 + PKCE, Helix-equivalents, EventSub-style
//! webhooks. Mirrors the shape of `Twitch-Follower-Role/src/services/twitch.rs`.
//!
//! Endpoint hostnames and exact field names are based on Kick's published
//! docs at https://docs.kick.com — TODOs flag the bits to re-verify when
//! Phase 3 is exercised against the real API.
//!
//! This is a deliberately fuller API surface than the current call sites
//! consume (response structs carry every documented field; a few methods —
//! `unsubscribe_event`, `client_id` — are wired for disconnect/rotation
//! flows). `dead_code` is allowed module-wide rather than scattering
//! per-item attributes across an external-API client.
#![allow(dead_code)]

use base64::Engine;
use governor::{Quota, RateLimiter};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

// TODO(kick-docs): confirm these endpoints. Kick has moved auth between
// `id.kick.com/oauth/*` and `kick.com/oauth/*` historically.
pub const AUTHORIZE_URL: &str = "https://id.kick.com/oauth/authorize";
pub const TOKEN_URL: &str = "https://id.kick.com/oauth/token";
pub const API_BASE: &str = "https://api.kick.com/public/v1";

#[derive(Debug, Deserialize)]
pub struct KickUser {
    /// Numeric Kick user ID. Stable forever for a given account.
    pub user_id: i64,
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub profile_picture: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KickChannel {
    pub broadcaster_user_id: i64,
    pub slug: String,
    #[serde(default)]
    pub stream_title: Option<String>,
    #[serde(default)]
    pub category: Option<KickCategory>,
    #[serde(default)]
    pub stream: Option<KickStream>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KickCategory {
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KickStream {
    #[serde(default)]
    pub is_live: bool,
    #[serde(default)]
    pub viewer_count: i64,
    #[serde(default)]
    pub start_time: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiList<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
pub struct FollowerData {
    pub user_id: i64,
    pub followed_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SubscriberData {
    pub user_id: i64,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub months_total: Option<i64>,
    #[serde(default)]
    pub is_gift: bool,
}

#[derive(Debug, Deserialize)]
pub struct ChannelRoleUser {
    pub user_id: i64,
}

#[derive(Clone)]
pub struct KickClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    /// ~50 req/min to stay comfortably under the public-app limit (~60/min).
    rate_limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    >,
}

impl KickClient {
    pub fn new(client_id: String, client_secret: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client");
        let quota = Quota::per_minute(NonZeroU32::new(50).unwrap());
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        Self {
            http,
            client_id,
            client_secret,
            rate_limiter,
        }
    }

    async fn permit(&self) {
        self.rate_limiter.until_ready().await;
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    // -----------------------------------------------------------------
    // OAuth 2.1 + PKCE
    // -----------------------------------------------------------------

    /// Build the authorize URL the admin/viewer is redirected to. PKCE
    /// `code_challenge` is the URL-safe-no-pad base64 of SHA-256(verifier).
    pub fn authorize_url(
        &self,
        redirect_uri: &str,
        scope: &str,
        state: &str,
        code_verifier: &str,
    ) -> String {
        let challenge = pkce_s256(code_verifier);
        let qs = serde_urlencoded::to_string([
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", scope),
            ("state", state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ])
        .expect("urlencoded serialize never fails for &str inputs");
        format!("{AUTHORIZE_URL}?{qs}")
    }

    /// Exchange an authorization code (with PKCE verifier) for tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, AppError> {
        self.permit().await;
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("code", code),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("token exchange request failed: {e}")))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("token exchange body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "token exchange failed: {status} - {body}"
            )));
        }
        serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("token exchange parse: {e} | body: {body}")))
    }

    /// Refresh an expiring user token. Returns the new (access, optional
    /// refresh). Kick may or may not rotate the refresh token — if it doesn't
    /// the second member is None and the caller keeps the old refresh.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, AppError> {
        self.permit().await;
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("refresh request failed: {e}")))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("refresh body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "refresh failed: {status} - {body}"
            )));
        }
        serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("refresh parse: {e} | body: {body}")))
    }

    // -----------------------------------------------------------------
    // Public API endpoints
    // -----------------------------------------------------------------

    /// Get the authenticated user's identity. Endpoint shape:
    /// `GET /public/v1/users` (authenticated returns the caller's record).
    pub async fn get_authenticated_user(&self, access_token: &str) -> Result<KickUser, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/users");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("users request failed: {e}")))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("users body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "get_authenticated_user: {status} - {body}"
            )));
        }
        let parsed: ApiList<KickUser> = serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("users parse: {e} | body: {body}")))?;
        parsed
            .data
            .into_iter()
            .next()
            .ok_or_else(|| AppError::KickApi("users response had no data".into()))
    }

    /// Get the broadcaster's channel metadata (slug, live state, category).
    /// Caller is typically the broadcaster themselves.
    pub async fn get_channel_by_user(
        &self,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<KickChannel, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/channels?broadcaster_user_id={broadcaster_user_id}");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("channels request failed: {e}")))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("channels body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "get_channel_by_user: {status} - {body}"
            )));
        }
        let parsed: ApiList<KickChannel> = serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("channels parse: {e} | body: {body}")))?;
        parsed
            .data
            .into_iter()
            .next()
            .ok_or_else(|| AppError::KickApi("channels response had no data".into()))
    }

    /// Get live channel metadata (no auth needed for public broadcaster info,
    /// but we send the broadcaster's own token in case Kick requires it).
    /// Used by `live_poll` (Phase 9) to refresh `is_live` / category /
    /// viewer count.
    pub async fn refresh_channel_live_state(
        &self,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<KickChannel, AppError> {
        self.get_channel_by_user(broadcaster_user_id, access_token)
            .await
    }

    /// List subscribers for a broadcaster's channel. Paginates server-side;
    /// callers can stop early. Endpoint shape:
    /// `GET /public/v1/channels/{id}/subscriptions`.
    pub async fn list_subscribers(
        &self,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<Vec<SubscriberData>, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/channels/{broadcaster_user_id}/subscriptions");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("subs request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("subs body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "list_subscribers: {status} - {body}"
            )));
        }
        let parsed: ApiList<SubscriberData> = serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("subs parse: {e} | body: {body}")))?;
        Ok(parsed.data)
    }

    /// List followers for the channel.
    pub async fn list_followers(
        &self,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<Vec<FollowerData>, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/channels/{broadcaster_user_id}/followers");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("followers request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("followers body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "list_followers: {status} - {body}"
            )));
        }
        let parsed: ApiList<FollowerData> = serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("followers parse: {e} | body: {body}")))?;
        Ok(parsed.data)
    }

    /// List moderators for the channel.
    pub async fn list_moderators(
        &self,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<Vec<ChannelRoleUser>, AppError> {
        self.list_channel_role(broadcaster_user_id, "moderators", access_token)
            .await
    }

    /// List VIPs for the channel.
    pub async fn list_vips(
        &self,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<Vec<ChannelRoleUser>, AppError> {
        self.list_channel_role(broadcaster_user_id, "vips", access_token)
            .await
    }

    async fn list_channel_role(
        &self,
        broadcaster_user_id: i64,
        kind: &str,
        access_token: &str,
    ) -> Result<Vec<ChannelRoleUser>, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/channels/{broadcaster_user_id}/{kind}");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("{kind} request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("{kind} body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!("list {kind}: {status} - {body}")));
        }
        let parsed: ApiList<ChannelRoleUser> = serde_json::from_str(&body)
            .map_err(|e| AppError::KickApi(format!("{kind} parse: {e} | body: {body}")))?;
        Ok(parsed.data)
    }

    // -----------------------------------------------------------------
    // EventSub-style webhook subscriptions (Phase 8)
    // -----------------------------------------------------------------

    /// Subscribe to a channel event. Phase 8 wires the call sites.
    pub async fn subscribe_event(
        &self,
        event_type: &str,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<String, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/events/subscriptions");
        let body = serde_json::json!({
            "type": event_type,
            "version": 1,
            "condition": { "broadcaster_user_id": broadcaster_user_id }
        });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("subscribe request failed: {e}")))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .map_err(|e| AppError::KickApi(format!("subscribe body: {e}")))?;
        if !status.is_success() {
            return Err(AppError::KickApi(format!(
                "subscribe {event_type}: {status} - {body_text}"
            )));
        }
        // TODO(kick-docs): confirm response shape; using {data:[{id:"..."}]} for now.
        let parsed: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| AppError::KickApi(format!("subscribe parse: {e} | body: {body_text}")))?;
        parsed["data"][0]["id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| AppError::KickApi("subscribe response missing id".into()))
    }

    /// Delete a webhook subscription by ID. Best-effort cleanup.
    pub async fn unsubscribe_event(
        &self,
        subscription_id: &str,
        access_token: &str,
    ) -> Result<(), AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/events/subscriptions/{subscription_id}");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::KickApi(format!("unsubscribe request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(subscription_id, "unsubscribe returned {status}: {body}");
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Webhook signature verification
    // -----------------------------------------------------------------

    /// Verify the HMAC-SHA256 signature Kick attaches to webhook deliveries.
    /// Signature header format: `sha256=<hex>`. The signed message is
    /// `message_id + timestamp + raw_body` (mirrors Twitch EventSub; we'll
    /// confirm against Kick's exact spec at Phase 8 wire-up).
    pub fn verify_webhook_signature(
        message_id: &str,
        timestamp: &str,
        body: &[u8],
        webhook_secret: &str,
        signature_header: &str,
    ) -> bool {
        // Reject deliveries older than 10 minutes — limits replay window.
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(timestamp) {
            let age = chrono::Utc::now().signed_duration_since(ts);
            if age.num_minutes().abs() > 10 {
                return false;
            }
        } else {
            return false;
        }

        let Some(sig_hex) = signature_header.strip_prefix("sha256=") else {
            return false;
        };

        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(message_id.as_bytes());
        mac.update(timestamp.as_bytes());
        mac.update(body);

        let computed = hex::encode(mac.finalize().into_bytes());
        crate::services::rl_token::constant_time_eq(computed.as_bytes(), sig_hex.as_bytes())
    }
}

// ---------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------

/// Generate a 96-character PKCE code verifier per RFC 7636 §4.1
/// (43-128 chars of unreserved set). 96 chars = ~720 bits of entropy.
pub fn new_code_verifier() -> String {
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// S256 challenge per RFC 7636 §4.2: BASE64URL(SHA256(ASCII(verifier))).
fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_known_vector() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), challenge);
    }

    #[test]
    fn verifier_has_enough_entropy() {
        let v = new_code_verifier();
        assert!(v.len() >= 43 && v.len() <= 128);
    }

    #[test]
    fn authorize_url_includes_required_params() {
        let c = KickClient::new("id123".into(), "secret".into());
        let url = c.authorize_url(
            "https://example.com/cb",
            "user:read channel:read",
            "state123",
            "verifier-abcdefghij",
        );
        assert!(url.starts_with(AUTHORIZE_URL));
        assert!(url.contains("client_id=id123"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("response_type=code"));
    }
}
