//! CDSIP API Server — Entry Point
//!
//! Closed Defensive Security Intelligence Platform
//! Strictly defensive. Policy-gated. Audit-logged. Evidence-driven.

pub mod config;
pub mod errors;
pub mod extractors;
pub mod routes;
pub mod server;

use config::AppConfig;
use tracing_subscriber::{fmt, EnvFilter};

pub async fn run_server() -> anyhow::Result<()> {
    // Load .env file if present (development)
    let _ = dotenvy::dotenv();

    // Initialize structured logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("cdsip_api=info,tower_http=info")),
        )
        .json()
        .init();

    tracing::info!("=== CDSIP API Server ===");
    tracing::info!("Closed Defensive Security Intelligence Platform");

    // Load and validate configuration
    let config = AppConfig::from_env();
    config.validate_security();

    let host = config.host.clone();
    let port = config.port;

    // Build application state
    let state = server::build_app_state(config).await;

    // Seed admin user on first startup
    if let Err(e) = routes::auth::seed_admin_user(&state).await {
        tracing::warn!(error = %e, "Failed to seed admin user (may already exist)");
    }

    // Build router
    let app = server::build_router(state);

    // Start server
    let addr = format!("{host}:{port}");
    tracing::info!(address = %addr, "Starting CDSIP API server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
