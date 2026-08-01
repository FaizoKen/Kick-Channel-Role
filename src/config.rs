use std::env;

#[derive(Clone, Debug)]
pub struct DbPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

impl DbPoolConfig {
    fn from_env() -> Self {
        Self {
            max_connections: env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            min_connections: env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            acquire_timeout_secs: env::var("DB_ACQUIRE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            idle_timeout_secs: env::var("DB_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KickConfig {
    /// Kick application client_id (public). `None` until the operator
    /// registers an app at https://kick.com/settings/developer.
    pub client_id: Option<String>,
    /// Kick application client_secret. Phase 3+: used in the OAuth 2.1 +
    /// PKCE flow for both broadcaster and viewer.
    pub client_secret: Option<String>,

    /// Enable the follow probe (`KICK_FOLLOW_PROBE_ENABLED`, default on).
    ///
    /// The probe reads Kick's undocumented channel user-card endpoint to
    /// recover follows that predate a member's link — state the *public* API
    /// exposes no way to query. See [`crate::services::kick_probe`]. Set to
    /// `false` to fall back to webhook-only behaviour if Kick ever objects or
    /// the endpoint starts misbehaving; nothing else needs redeploying.
    pub follow_probe_enabled: bool,
    /// Origin the probe calls (`KICK_PROBE_BASE_URL`). Overridable so tests
    /// and staging can point at a stub instead of the live site.
    pub follow_probe_base_url: String,
    /// Probe request budget per minute, per replica (`KICK_PROBE_RPM`).
    /// Deliberately low: this is an undocumented endpoint being used
    /// considerately, not a data-collection pipeline.
    pub follow_probe_rpm: u32,
    /// How many separately-spaced "not following" answers must agree before a
    /// stored follow is removed (`KICK_UNFOLLOW_CONFIRMATIONS`, default 3).
    /// Kick emits no unfollow event, so probes are the only way to ever clear
    /// a stale follow — but a single bad read must never cost a member their
    /// role, hence the confirmation count. Raise it to be even more cautious;
    /// values below 1 are clamped to 1.
    pub unfollow_confirmations: i16,
}

impl KickConfig {
    fn from_env() -> Self {
        Self {
            client_id: env::var("KICK_CLIENT_ID")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            client_secret: env::var("KICK_CLIENT_SECRET")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            follow_probe_enabled: env::var("KICK_FOLLOW_PROBE_ENABLED")
                .ok()
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            follow_probe_base_url: env::var("KICK_PROBE_BASE_URL")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://kick.com".to_string()),
            follow_probe_rpm: env::var("KICK_PROBE_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(20),
            unfollow_confirmations: env::var("KICK_UNFOLLOW_CONFIRMATIONS")
                .ok()
                .and_then(|v| v.parse::<i16>().ok())
                .map(|n| n.max(1))
                .unwrap_or(3),
        }
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub session_secret: String,
    pub base_url: String,
    pub listen_addr: String,
    /// Base URL of the Auth Gateway (no trailing slash, no `/auth` suffix).
    /// Prod: usually the same origin as `BASE_URL` (derived if unset).
    /// Local dev: set explicitly to e.g. http://localhost:8090.
    pub auth_gateway_url: String,
    /// Shared secret for plugin → gateway /auth/internal/* calls
    /// (sent in the `X-Internal-Key` header).
    pub internal_api_key: String,
    /// Origin allowed to embed this plugin in an iframe. Used to build the
    /// `Content-Security-Policy: frame-ancestors …` header on the role-config
    /// page. Unset → falls back to the production dashboard origin.
    pub rl_dashboard_origin: Option<String>,
    /// Base URL of the RoleLogic API used by `RoleLogicClient`. No trailing slash.
    /// Override per environment (prod, staging, DR region) via `ROLELOGIC_API_URL`.
    pub rolelogic_api_url: String,
    /// How many job-polling worker tasks to spawn (Phase 7+). Each task
    /// claims a batch via `FOR UPDATE SKIP LOCKED`.
    pub worker_concurrency: u32,
    /// DB connection pool sizing + timeouts.
    pub db_pool: DbPoolConfig,
    /// Kick OAuth + webhook credentials. All fields are optional in Phase 1;
    /// later phases will require specific subsets and fail loudly if missing.
    pub kick: KickConfig,
}

/// Extract the origin (scheme://host[:port]) from BASE_URL, dropping any path prefix.
pub(crate) fn derive_origin(base_url: &str) -> String {
    if let Some(scheme_end) = base_url.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(path_slash) = base_url[after_scheme..].find('/') {
            return base_url[..after_scheme + path_slash].to_string();
        }
    }
    base_url.to_string()
}

impl AppConfig {
    pub fn from_env() -> Self {
        let base_url = env::var("BASE_URL").expect("BASE_URL must be set");
        let auth_gateway_url = env::var("AUTH_GATEWAY_URL")
            .ok()
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| derive_origin(&base_url));

        Self {
            database_url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            session_secret: env::var("SESSION_SECRET").expect("SESSION_SECRET must be set"),
            base_url,
            listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8094".to_string()),
            auth_gateway_url,
            internal_api_key: env::var("INTERNAL_API_KEY")
                .expect("INTERNAL_API_KEY must be set (must match the Auth Gateway's value)"),
            rl_dashboard_origin: env::var("RL_DASHBOARD_ORIGIN")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| Some("https://rolelogic.faizo.net".to_string())),
            rolelogic_api_url: env::var("ROLELOGIC_API_URL")
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "https://api-rolelogic.faizo.net".to_string()),
            worker_concurrency: env::var("WORKER_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
            db_pool: DbPoolConfig::from_env(),
            kick: KickConfig::from_env(),
        }
    }
}
