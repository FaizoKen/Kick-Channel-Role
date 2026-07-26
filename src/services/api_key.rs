//! Guild-scoped API keys for the read-only public JSON API (`/api/v1/*`).
//!
//! A server manager mints a key from the role-config page; an external
//! service then calls `/api/v1/*` with `Authorization: Bearer kck_…`. The key
//! *is* the guild binding — no endpoint takes a `guild_id` from the caller,
//! so there is no confused-deputy check to get wrong.
//!
//! This is deliberately NOT the `rl_session` cookie and NOT the `ifs:` iframe
//! token:
//!   * `rl_session` is a whole-account browser credential with a short TTL,
//!     no per-integration revocation, and no audit trail. The cookie-authed
//!     users endpoint also forwards that cookie to the Auth Gateway, so it
//!     cannot work server-to-server at all.
//!   * `ifs:` is a short-lived stateless JWT — right for a browser session,
//!     wrong for a long-lived machine credential that must be revocable the
//!     instant a manager clicks "Revoke".
//!
//! Storage: only SHA-256 of the token. The raw value is returned exactly
//! once, at creation. Because the token is 256 bits of CSPRNG output (not a
//! human-chosen password) an indexed equality probe on the hash is the
//! correct lookup — no KDF, no constant-time compare needed.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::http::HeaderMap;
use base64::Engine;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::AppState;

/// Human-visible prefix on every token. Makes a leaked key attributable to
/// this plugin at a glance and lets us reject a replayed `ifs:` iframe token
/// before it ever reaches the database.
pub const TOKEN_PREFIX: &str = "kck_";

/// Read the guild's linked-user list. The only scope that exists today;
/// the column is plural so adding a second one is not a migration.
pub const SCOPE_USERS_READ: &str = "users:read";

/// How many live keys one guild may hold. Generous enough for several
/// integrations plus a rotation overlap, low enough that a compromised
/// manager account can't quietly mint hundreds.
pub const MAX_ACTIVE_KEYS_PER_GUILD: i64 = 10;

/// Characters of the raw token kept in clear for display (`kck_` + 8).
const PREFIX_DISPLAY_LEN: usize = 12;

/// Sustained requests per minute per key, and the burst a caller may spend
/// at once. Sized for a polling integration (once a minute is ample given
/// `updated_since`), with headroom for a paginated full backfill.
pub const RATE_PER_MINUTE: u32 = 120;
pub const RATE_BURST: u32 = 30;

/// Per-key limiter. In-process, so with N replicas the effective ceiling is
/// N × the quota — that is fine here: this exists to stop one integration
/// from monopolising the pool, not to bill anyone. The per-IP `GovernorLayer`
/// in `main` still applies underneath.
pub type KeyRateLimiter = RateLimiter<i64, DefaultKeyedStateStore<i64>, DefaultClock>;

pub fn new_rate_limiter() -> KeyRateLimiter {
    let quota = Quota::per_minute(
        NonZeroU32::new(RATE_PER_MINUTE).expect("RATE_PER_MINUTE is a non-zero constant"),
    )
    .allow_burst(NonZeroU32::new(RATE_BURST).expect("RATE_BURST is a non-zero constant"));
    RateLimiter::keyed(quota)
}

/// A freshly minted key. `raw` is the only copy that will ever exist — it is
/// returned to the creating manager and then dropped.
pub struct Minted {
    pub raw: String,
    pub hash: Vec<u8>,
    pub prefix: String,
}

pub fn mint() -> Minted {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let raw = format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let prefix = raw.chars().take(PREFIX_DISPLAY_LEN).collect::<String>();
    let hash = hash_token(&raw);
    Minted { raw, hash, prefix }
}

pub fn hash_token(raw: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    h.finalize().to_vec()
}

/// The one row `authenticate` reads. Kept separate from [`ApiKeyContext`]
/// because `revoked_at` is a gate, not something handlers should see.
#[derive(sqlx::FromRow)]
struct KeyLookup {
    id: i64,
    guild_id: String,
    label: String,
    scopes: Vec<String>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The authenticated caller behind an `/api/v1/*` request.
pub struct ApiKeyContext {
    pub key_id: i64,
    pub guild_id: String,
    pub label: String,
    pub scopes: Vec<String>,
}

impl ApiKeyContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Pull `Authorization: Bearer <token>` off the request.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

const MISSING: &str =
    "Missing API key. Send `Authorization: Bearer kck_…` — mint one from the plugin's \
     role settings in the RoleLogic dashboard.";
const REJECTED: &str = "Invalid or revoked API key.";

/// Authenticate an `/api/v1/*` request and assert it carries `required_scope`.
///
/// Every failure that could reveal whether a given token exists returns the
/// same opaque message — a caller learns "this key does not work", never
/// "this key exists but was revoked" or "belongs to another guild".
pub async fn authenticate(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<ApiKeyContext, AppError> {
    let raw = extract_bearer(headers).ok_or_else(|| AppError::UnauthorizedWith(MISSING.into()))?;

    // Reject anything that isn't shaped like one of our keys before touching
    // the database. This is what stops an `ifs:` iframe-session token (or an
    // `rl_session` cookie value pasted into the header) from being replayed
    // against the machine API.
    if !raw.starts_with(TOKEN_PREFIX) {
        return Err(AppError::UnauthorizedWith(REJECTED.into()));
    }

    let hash = hash_token(&raw);
    let row = lookup_key(&state.pool, &hash).await?;

    let KeyLookup {
        id: key_id,
        guild_id,
        label,
        scopes,
        revoked_at,
    } = row.ok_or_else(|| AppError::UnauthorizedWith(REJECTED.into()))?;
    if revoked_at.is_some() {
        return Err(AppError::UnauthorizedWith(REJECTED.into()));
    }

    // Rate-limit by key identity, not by IP: a legitimate integration behind
    // a NAT and an abusive one behind the same NAT must not share a bucket.
    if let Err(not_until) = state.api_rate_limiter.check_key(&key_id) {
        let retry_after = not_until
            .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()))
            .as_secs()
            .max(1);
        return Err(AppError::RateLimited { retry_after });
    }

    let ctx = ApiKeyContext {
        key_id,
        guild_id,
        label,
        scopes,
    };
    if !ctx.has_scope(required_scope) {
        return Err(AppError::Forbidden(format!(
            "This API key does not carry the `{required_scope}` scope."
        )));
    }

    touch_last_used(&state.pool, key_id).await;
    Ok(ctx)
}

/// Split out of [`authenticate`] so the query can be run against a real
/// database in tests without constructing an `AppState`.
async fn lookup_key(pool: &sqlx::PgPool, hash: &[u8]) -> Result<Option<KeyLookup>, AppError> {
    let row = sqlx::query_as::<_, KeyLookup>(
        "SELECT id, guild_id, label, scopes, revoked_at \
           FROM guild_api_keys WHERE token_hash = $1",
    )
    .bind(hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record coarse usage. The `WHERE` clause makes Postgres skip the write
/// unless a minute has passed, so a caller polling hard doesn't turn every
/// read into a row update. Failure is logged and swallowed — an audit
/// timestamp is never worth failing a successful read over.
async fn touch_last_used(pool: &sqlx::PgPool, key_id: i64) {
    let res = sqlx::query(
        "UPDATE guild_api_keys SET last_used_at = now() \
          WHERE id = $1 \
            AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
    )
    .bind(key_id)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(key_id, "failed to record api key usage: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_tokens_are_prefixed_unique_and_hashed() {
        let a = mint();
        let b = mint();
        assert!(a.raw.starts_with(TOKEN_PREFIX));
        assert_ne!(a.raw, b.raw, "two mints must not collide");
        assert_eq!(a.hash, hash_token(&a.raw));
        assert_ne!(a.hash, b.hash);
        // 32 raw bytes -> 43 base64url chars, plus the 4-char prefix.
        assert_eq!(a.raw.len(), TOKEN_PREFIX.len() + 43);
        assert_eq!(a.hash.len(), 32, "SHA-256 digest");
    }

    #[test]
    fn display_prefix_reveals_nothing_usable() {
        let m = mint();
        assert_eq!(m.prefix.len(), PREFIX_DISPLAY_LEN);
        assert!(m.raw.starts_with(&m.prefix));
        assert!(
            m.raw.len() > m.prefix.len() * 3,
            "most of the secret is withheld"
        );
    }

    #[test]
    fn bearer_extraction_is_strict() {
        let mut h = HeaderMap::new();
        assert_eq!(extract_bearer(&h), None);
        h.insert("authorization", "kck_nobearer".parse().unwrap());
        assert_eq!(extract_bearer(&h), None, "scheme is required");
        h.insert("authorization", "Bearer   ".parse().unwrap());
        assert_eq!(extract_bearer(&h), None, "empty token rejected");
        h.insert("authorization", "Bearer kck_abc ".parse().unwrap());
        assert_eq!(extract_bearer(&h).as_deref(), Some("kck_abc"));
    }

    /// Full credential lifecycle against a real Postgres: mint → store →
    /// look up → touch → revoke → refuse. Skips when `DATABASE_URL` is unset.
    ///
    /// Everything it writes is removed in the same test, and the guild id is
    /// a namespaced sentinel that no real Discord snowflake can collide with.
    #[tokio::test]
    async fn key_lifecycle_round_trips_through_postgres() {
        // See the note in routes::api_v1's live test — the harness does not
        // load .env, so without this the check skips itself into a green tick.
        dotenvy::dotenv().ok();
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL unset — skipping key lifecycle check");
            return;
        };
        let Ok(pool) = sqlx::PgPool::connect(&url).await else {
            eprintln!("database unreachable — skipping key lifecycle check");
            return;
        };
        let guild = "test-key-lifecycle";

        let minted = mint();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO guild_api_keys (guild_id, token_hash, prefix, label, scopes, created_by) \
             VALUES ($1, $2, $3, 'lifecycle test', $4, 'tester') RETURNING id",
        )
        .bind(guild)
        .bind(&minted.hash)
        .bind(&minted.prefix)
        .bind(vec![SCOPE_USERS_READ.to_string()])
        .fetch_one(&pool)
        .await
        .expect("insert key");

        // Presenting the raw token finds exactly this row, with the scope
        // array surviving the TEXT[] round trip.
        let found = lookup_key(&pool, &minted.hash)
            .await
            .expect("lookup")
            .expect("key should be found");
        assert_eq!(found.id, id);
        assert_eq!(found.guild_id, guild);
        assert_eq!(found.scopes, vec![SCOPE_USERS_READ.to_string()]);
        assert!(found.revoked_at.is_none());

        // A different token must not match — the hash is the whole identity.
        assert!(lookup_key(&pool, &mint().hash).await.unwrap().is_none());

        // First touch writes; the immediate second one is suppressed by the
        // one-minute guard, which is what keeps a hot poller from turning
        // every read into a write.
        touch_last_used(&pool, id).await;
        let first: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT last_used_at FROM guild_api_keys WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(first.is_some(), "first use must be recorded");
        touch_last_used(&pool, id).await;
        let second: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT last_used_at FROM guild_api_keys WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(first, second, "second touch within a minute must not write");

        // Revocation is visible to the very next lookup — no cached decision.
        sqlx::query("UPDATE guild_api_keys SET revoked_at = now() WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let revoked = lookup_key(&pool, &minted.hash).await.unwrap().unwrap();
        assert!(
            revoked.revoked_at.is_some(),
            "authenticate() refuses on this flag"
        );

        sqlx::query("DELETE FROM guild_api_keys WHERE guild_id = $1")
            .bind(guild)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The per-key bucket must be exactly that — per key. Tested directly
    /// rather than over HTTP because the per-IP `GovernorLayer` (burst 20)
    /// trips before this one (burst 30) for any single-host caller, so an
    /// end-to-end burst can never isolate this behaviour. This limiter earns
    /// its keep for a key used from several hosts, and as the sustained-rate
    /// ceiling (2/s) beneath the per-IP layer's looser 5/s.
    #[test]
    fn rate_limiter_is_per_key_and_bounded_by_burst() {
        let rl = new_rate_limiter();
        // The whole burst is spendable. (The loop runs in microseconds, so
        // GCRA replenishment is not a factor.)
        for cell in 0..RATE_BURST {
            assert!(rl.check_key(&1).is_ok(), "burst cell {cell} should pass");
        }
        assert!(rl.check_key(&1).is_err(), "burst must be bounded");
        // A second key is untouched — one integration cannot spend another's
        // quota, which is the entire reason this isn't keyed on IP.
        assert!(rl.check_key(&2).is_ok(), "keys must not share a bucket");
    }

    #[test]
    fn scope_check_is_exact() {
        let ctx = ApiKeyContext {
            key_id: 1,
            guild_id: "g".into(),
            label: "l".into(),
            scopes: vec![SCOPE_USERS_READ.to_string()],
        };
        assert!(ctx.has_scope(SCOPE_USERS_READ));
        assert!(!ctx.has_scope("users:write"));
        assert!(!ctx.has_scope("users"));
    }
}
