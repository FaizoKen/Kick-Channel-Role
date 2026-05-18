use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

use crate::config::DbPoolConfig;

/// How long an individual pooled connection may live before being recycled.
/// Caps how long pgBouncer's server-side mapping persists and limits the
/// blast radius of a leaked-but-still-pooled connection.
const POOL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

pub async fn create_pool(database_url: &str, cfg: &DbPoolConfig) -> PgPool {
    // Disable sqlx's prepared-statement cache. We deploy pgBouncer in
    // transaction-pool mode in front of Postgres; under that mode the
    // backend a connection is mapped to changes between transactions, which
    // makes session-scoped prepared statements unsafe (the next backend
    // wouldn't know about them and queries would fail with
    // `prepared statement "sqlx_s_…" does not exist`).
    let connect_options = PgConnectOptions::from_str(database_url)
        .expect("invalid DATABASE_URL")
        .statement_cache_capacity(0);

    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .max_lifetime(POOL_MAX_LIFETIME)
        .test_before_acquire(false)
        .connect_with(connect_options)
        .await
        .expect("Failed to connect to PostgreSQL")
}

/// Migrations are applied in order on startup. They are idempotent
/// (`CREATE … IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, etc.) so a replica
/// that finds them already applied is a no-op. New migrations MUST follow
/// the expand→contract pattern (additive first; breaking column drops in a
/// follow-up) so blue/green deploys never run two app versions against an
/// incompatible schema.
///
/// Convention 21: when you add a migration file, add the matching entry here.
/// The app will NOT discover new migration files automatically.
pub async fn run_migrations(pool: &PgPool) {
    let migrations: &[(&str, &str)] = &[
        ("001", include_str!("../migrations/001_initial_schema.sql")),
        ("002", include_str!("../migrations/002_broadcasters.sql")),
        ("003", include_str!("../migrations/003_kick_users.sql")),
        (
            "004",
            include_str!("../migrations/004_channel_relations.sql"),
        ),
        ("005", include_str!("../migrations/005_webhooks.sql")),
        ("006", include_str!("../migrations/006_jobs.sql")),
        ("007", include_str!("../migrations/007_guild_settings.sql")),
        (
            "008",
            include_str!("../migrations/008_guild_broadcasters.sql"),
        ),
        ("009", include_str!("../migrations/009_oauth_states.sql")),
        (
            "010",
            include_str!("../migrations/010_kick_users_discord_name.sql"),
        ),
    ];
    for (id, sql) in migrations {
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("Migration {id} failed: {e}"));
    }
    tracing::info!("Applied {} migrations", migrations.len());
}
