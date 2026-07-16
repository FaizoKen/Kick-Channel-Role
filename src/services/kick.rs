//! Kick.com API client: OAuth 2.1 + PKCE, public API calls, webhook
//! subscriptions and signature verification.
//!
//! Endpoint paths, request/response shapes, and the webhook signing scheme
//! follow Kick's published docs at https://docs.kick.com:
//!   * events: POST/DELETE `/public/v1/events/subscriptions`
//!     (`{broadcaster_user_id, events:[{name,version}], method:"webhook"}`)
//!   * webhook signatures: RSA-SHA256 (PKCS#1 v1.5) over
//!     `"{message_id}.{timestamp}.{raw_body}"`, base64 signature, public key
//!     served at GET `/public/v1/public-key`.
//!
//! Note Kick's public API has NO list endpoints for a channel's followers /
//! subscribers / VIPs / moderators — those facts can only be accumulated
//! from webhook events (incl. `chat.message.sent` badges).
//!
//! This is a deliberately fuller API surface than the current call sites
//! consume (response structs carry every documented field; a few methods —
//! `unsubscribe_event`, `client_id` — are wired for disconnect/rotation
//! flows). `dead_code` is allowed module-wide rather than scattering
//! per-item attributes across an external-API client.
#![allow(dead_code)]

use base64::Engine;
use governor::{Quota, RateLimiter};
use rand::RngCore;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::error::AppError;

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

    // -----------------------------------------------------------------
    // Webhook event subscriptions
    // -----------------------------------------------------------------

    /// Subscribe to a channel event via webhook. Request/response shapes per
    /// docs.kick.com "Subscribe to Events":
    /// `POST /public/v1/events/subscriptions` with
    /// `{broadcaster_user_id, events:[{name, version}], method:"webhook"}`,
    /// response `{data:[{name, subscription_id, version, error}]}`.
    pub async fn subscribe_event(
        &self,
        event_type: &str,
        broadcaster_user_id: i64,
        access_token: &str,
    ) -> Result<String, AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/events/subscriptions");
        let body = serde_json::json!({
            "broadcaster_user_id": broadcaster_user_id,
            "events": [{ "name": event_type, "version": 1 }],
            "method": "webhook",
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
        let parsed: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|e| AppError::KickApi(format!("subscribe parse: {e} | body: {body_text}")))?;
        let entry = &parsed["data"][0];
        // Per-event failures come back 200 with a non-empty `error` string.
        if let Some(err) = entry["error"].as_str().filter(|s| !s.is_empty()) {
            return Err(AppError::KickApi(format!(
                "subscribe {event_type} rejected: {err}"
            )));
        }
        entry["subscription_id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| AppError::KickApi("subscribe response missing subscription_id".into()))
    }

    /// Delete a webhook subscription by ID. Best-effort cleanup.
    /// `DELETE /public/v1/events/subscriptions?id=<subscription_id>`.
    pub async fn unsubscribe_event(
        &self,
        subscription_id: &str,
        access_token: &str,
    ) -> Result<(), AppError> {
        self.permit().await;
        let url = format!("{API_BASE}/events/subscriptions");
        let resp = self
            .http
            .delete(&url)
            .query(&[("id", subscription_id)])
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
}

// ---------------------------------------------------------------------
// Webhook signature verification (module-level: no client credentials
// involved — Kick signs with its own key pair)
// ---------------------------------------------------------------------

/// Fetch Kick's webhook-signing public key. Response shape:
/// `{ "data": { "public_key": "-----BEGIN PUBLIC KEY-----…" } }`.
/// No authentication required.
pub async fn fetch_public_key(http: &reqwest::Client) -> Result<RsaPublicKey, AppError> {
    let url = format!("{API_BASE}/public-key");
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::KickApi(format!("public-key request failed: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| AppError::KickApi(format!("public-key body: {e}")))?;
    if !status.is_success() {
        return Err(AppError::KickApi(format!(
            "fetch_public_key: {status} - {body}"
        )));
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| AppError::KickApi(format!("public-key parse: {e} | body: {body}")))?;
    let pem = parsed["data"]["public_key"]
        .as_str()
        .ok_or_else(|| AppError::KickApi("public-key response missing data.public_key".into()))?;
    RsaPublicKey::from_public_key_pem(pem)
        .map_err(|e| AppError::KickApi(format!("public-key PEM parse: {e}")))
}

/// Verify the signature Kick attaches to webhook deliveries.
/// Per docs.kick.com "Webhook Security": the signed message is
/// `"{message_id}.{timestamp}.{raw_body}"` (dot-separated), signed with
/// Kick's RSA private key (PKCS#1 v1.5, SHA-256); the header carries the
/// base64-encoded signature.
pub fn verify_webhook_signature(
    public_key: &RsaPublicKey,
    message_id: &str,
    timestamp: &str,
    body: &[u8],
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

    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(signature_header.trim())
    else {
        return false;
    };

    let mut message = Vec::with_capacity(message_id.len() + timestamp.len() + body.len() + 2);
    message.extend_from_slice(message_id.as_bytes());
    message.push(b'.');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);

    let digest = Sha256::digest(&message);
    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
        .is_ok()
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
    fn webhook_signature_roundtrip() {
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let pub_key = priv_key.to_public_key();

        let id = "msg-1";
        let ts = chrono::Utc::now().to_rfc3339();
        let body: &[u8] = br#"{"hello":"world"}"#;

        let mut message = Vec::new();
        message.extend_from_slice(id.as_bytes());
        message.push(b'.');
        message.extend_from_slice(ts.as_bytes());
        message.push(b'.');
        message.extend_from_slice(body);
        let digest = Sha256::digest(&message);
        let sig = priv_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .expect("sign");
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);

        assert!(verify_webhook_signature(&pub_key, id, &ts, body, &sig_b64));
        // Tampered message id fails.
        assert!(!verify_webhook_signature(
            &pub_key, "msg-2", &ts, body, &sig_b64
        ));
        // Stale timestamp fails even with a valid signature over it.
        let old_ts = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert!(!verify_webhook_signature(
            &pub_key, id, &old_ts, body, &sig_b64
        ));
        // Garbage base64 fails.
        assert!(!verify_webhook_signature(&pub_key, id, &ts, body, "!!!"));
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
