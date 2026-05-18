use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::Router;
use sqlx::PgPool;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::GovernorLayer;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

mod config;
mod db;
mod error;
mod models;
mod routes;
mod schema;
mod services;
mod tasks;

use services::rolelogic::RoleLogicClient;
use services::security_headers;
use tasks::shutdown::Shutdown;

pub struct AppState {
    pub pool: PgPool,
    pub config: config::AppConfig,
    #[allow(dead_code)] // wired up in Phase 2 (POST /register handler)
    pub rl_client: RoleLogicClient,
    #[allow(dead_code)] // wired up in Phase 3+ (Kick API client, Auth Gateway calls)
    pub http: reqwest::Client,
    /// Origins permitted to issue cookie-authenticated state-changing
    /// requests. Source of truth for both the `CorsLayer` allowlist and the
    /// per-handler `csrf::verify_origin` check.
    pub allowed_origins: Vec<String>,
    /// Flips to `true` when graceful shutdown starts. `/ready` reads it so
    /// load balancers can drain replicas before they stop accepting.
    pub draining: AtomicBool,
    /// Per-replica wake signal driven by `tasks::job_listener` on every
    /// `NOTIFY jobs_pending`. Workers `select!` on this so a job inserted by
    /// any replica wakes every worker within ~ms.
    pub jobs_notify: Arc<tokio::sync::Notify>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            // Default: app at INFO, everything else (notably `tower_http`,
            // which fires a structured log per request) at WARN. Operators
            // can re-enable per-request lines with
            // `RUST_LOG=…,tower_http=info`.
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kick_channel_role=info,tower_http=warn".into()),
        )
        .init();

    // `migrate` subcommand: apply migrations and exit. Lets blue-green
    // deploys run migrations as a separate step before swapping replicas.
    let migrate_only = std::env::args().nth(1).as_deref() == Some("migrate");

    let app_config = config::AppConfig::from_env();
    let listen_addr = app_config.listen_addr.clone();

    let pool = db::create_pool(&app_config.database_url, &app_config.db_pool).await;
    db::run_migrations(&pool).await;
    tracing::info!("Database connected and migrations applied");

    if migrate_only {
        tracing::info!("`migrate` subcommand done; exiting without starting the server");
        return;
    }

    let rl_client = RoleLogicClient::new(app_config.rolelogic_api_url.clone());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to build HTTP client");

    // Compute once: origins that can drive cookie-authenticated state changes.
    // The CorsLayer mirror is built from this same list below.
    let mut allowed_origins = vec![config::derive_origin(&app_config.base_url)];
    if let Some(dash) = app_config.rl_dashboard_origin.as_deref() {
        allowed_origins.push(dash.to_string());
    }

    let worker_concurrency = app_config.worker_concurrency.max(1);

    let state = Arc::new(AppState {
        pool,
        config: app_config,
        rl_client,
        http,
        allowed_origins,
        draining: AtomicBool::new(false),
        jobs_notify: Arc::new(tokio::sync::Notify::new()),
    });

    // Single shutdown signal multiplexed to axum + every worker. A SIGTERM
    // listener fires `trigger()`; everyone drains and we join below.
    let shutdown = Shutdown::new();

    // One LISTEN jobs_pending task per replica relays Postgres NOTIFYs into
    // `state.jobs_notify` so workers wake on enqueue instead of poll.
    let listener_handle = tokio::spawn(tasks::job_listener::run(
        state.pool.clone(),
        Arc::clone(&state.jobs_notify),
        shutdown.subscribe(),
    ));

    let mut worker_handles: Vec<tokio::task::JoinHandle<()>> =
        Vec::with_capacity(worker_concurrency as usize);
    for i in 0..worker_concurrency {
        worker_handles.push(tokio::spawn(tasks::job_worker::run(
            Arc::clone(&state),
            shutdown.subscribe(),
            format!("job-worker-{i}"),
        )));
    }
    tracing::info!(workers = worker_concurrency, "Job workers started");

    // Periodic worker: reconcile (6h) — rebuilds follower/sub facts and is
    // the webhook-loss safety net. (No live poller: no rule depends on the
    // channel's live state anymore.)
    let reconcile_handle = tokio::spawn(tasks::reconcile::run(
        Arc::clone(&state),
        shutdown.subscribe(),
    ));

    // All routes nested under the plugin's path prefix (Convention 23).
    let plugin_routes = Router::new()
        // RoleLogic plugin contract
        .route("/register", post(routes::plugin::register))
        .route("/config", get(routes::plugin::get_config))
        .route("/config", post(routes::plugin::post_config))
        .route("/config", delete(routes::plugin::delete_config))
        // Admin — broadcaster CRUD
        .route(
            "/admin/{guild_id}/broadcasters",
            get(routes::admin::broadcaster_list),
        )
        .route(
            "/admin/{guild_id}/broadcasters/connect",
            post(routes::admin::broadcaster_connect),
        )
        .route(
            "/admin/{guild_id}/broadcasters/{kick_channel_id}",
            delete(routes::admin::broadcaster_disconnect),
        )
        // Admin — iframe role-config (deep-linked from RoleLogic dashboard)
        .route(
            "/admin/{guild_id}/role/{role_id}",
            get(routes::admin::role_config_page),
        )
        .route(
            "/admin/{guild_id}/role/{role_id}/data",
            get(routes::admin::role_config_data),
        )
        .route(
            "/admin/{guild_id}/role/{role_id}/save",
            post(routes::admin::role_config_save),
        )
        .route(
            "/admin/{guild_id}/role/{role_id}/preview",
            get(routes::admin::role_config_preview).post(routes::admin::role_config_preview_edit),
        )
        // Kick OAuth callbacks
        .route(
            "/oauth/kick/broadcaster/callback",
            get(routes::oauth::broadcaster_callback),
        )
        .route(
            "/oauth/kick/viewer/callback",
            get(routes::oauth::viewer_callback),
        )
        // Per-guild settings (users-list visibility)
        .route(
            "/admin/{guild_id}/view-permission",
            post(routes::users::set_view_permission),
        )
        // Public all-users listing (every linked viewer with a relation)
        .route("/users/{guild_id}", get(routes::users::users_page))
        .route("/users/{guild_id}/data", get(routes::users::users_data))
        // Kick webhook ingestor (single app-wide URL)
        .route("/webhooks/kick", post(routes::webhooks::kick_webhook))
        // Member verification
        .route("/verify", get(routes::verify::verify_page))
        .route("/verify/status", get(routes::verify::verify_status))
        .route("/verify/login", post(routes::verify::verify_login))
        .route("/verify/kick", post(routes::verify::verify_kick))
        // Health & static
        .route("/favicon.ico", get(routes::health::favicon))
        .route("/health", get(routes::health::health))
        .route("/ready", get(routes::health::ready));

    // -------- Middleware stack --------
    //
    // Outermost (declared last) runs first on requests / last on responses.

    // CORS: explicit allowlist of origins that may invoke our endpoints
    // cross-origin. `allow_credentials(true)` requires explicit origins
    // (no wildcard).
    let cors_origins: Vec<HeaderValue> = state
        .allowed_origins
        .iter()
        .map(|o| {
            HeaderValue::from_str(o)
                .expect("allowed origin contains characters not valid in a HeaderValue")
        })
        .collect();
    let cors_layer = CorsLayer::new()
        .allow_origin(cors_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-rl-preview"),
        ])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600));

    // Per-IP rate limiter. Burst of 20 absorbs UI bursts; sustained 5/sec is
    // far higher than any legitimate human usage but low enough to choke
    // floods. Per-route tightening (e.g. webhook ingestor) is a later phase.
    //
    // SmartIpKeyExtractor pulls the client IP from `Forwarded` / `X-Forwarded-For`
    // / `X-Real-IP`. **The reverse proxy in front of this service MUST overwrite
    // these headers with the real client IP** (Cloudflare Tunnel and most LBs do
    // this by default) — otherwise an attacker can spoof per-IP buckets.
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(20)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build governor config"),
    );
    let governor_limiter = governor_config.limiter().clone();
    // GC dead IP buckets every 5 s; caps worst-case footprint under a
    // rotating-IP flood by 12× vs the default 60 s.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    let sensitive_request_headers = SetSensitiveRequestHeadersLayer::new([
        header::AUTHORIZATION,
        header::COOKIE,
        HeaderName::from_static("x-internal-key"),
    ]);

    let request_id_header = HeaderName::from_static("x-request-id");

    let app = Router::new()
        .nest("/kick-channel-role", plugin_routes)
        .layer(DefaultBodyLimit::max(256 * 1024))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(sensitive_request_headers)
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(cors_layer)
        .layer(GovernorLayer {
            config: governor_config,
        })
        .layer(middleware::from_fn(security_headers::baseline))
        .layer(CompressionLayer::new().br(true).gzip(true))
        .with_state(Arc::clone(&state));

    tracing::info!("Server starting on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .expect("Failed to bind listener");

    // Spawn the OS signal listener so SIGTERM/SIGINT fires shutdown for
    // BOTH the HTTP server and (future) workers through one source of truth.
    let shutdown_for_signal = shutdown.clone();
    let state_for_signal = Arc::clone(&state);
    tokio::spawn(async move {
        tasks::shutdown::wait_for_signal().await;
        state_for_signal.draining.store(true, Ordering::SeqCst);
        tracing::info!("Shutdown signal received; draining HTTP");
        shutdown_for_signal.trigger();
    });

    let mut server_shutdown = shutdown.subscribe();
    // `into_make_service_with_connect_info::<SocketAddr>()` is required for
    // `SmartIpKeyExtractor` to fall back to the peer address when the request
    // has no forwarded-for header (e.g. direct LAN calls from RoleLogic).
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        server_shutdown.wait().await;
    })
    .await
    {
        tracing::error!("Server error: {e}");
    }

    tracing::info!("HTTP drained; waiting for workers to finish in-flight jobs");
    for h in worker_handles {
        if let Err(e) = h.await {
            tracing::error!("Worker join failed: {e}");
        }
    }
    if let Err(e) = listener_handle.await {
        tracing::error!("Job listener join failed: {e}");
    }
    for (name, h) in [("reconcile", reconcile_handle)] {
        if let Err(e) = h.await {
            tracing::error!("{name} join failed: {e}");
        }
    }

    tracing::info!("Server stopped");
}
