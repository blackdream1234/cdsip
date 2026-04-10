//! Server setup — Axum router, middleware, state initialization.

use axum::routing::{get, post};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;

use cdsip_audit_core::storage::AuditStorage;
use cdsip_audit_core::AuditLogger;
use cdsip_policy_engine::PolicyGovernor;
use cdsip_risk_engine::RiskCalculator;
use cdsip_tool_broker::ToolBroker;
use cdsip_tool_broker::nmap::runner::NmapConfig;

use crate::config::AppConfig;
use crate::extractors::AppState;
use crate::routes;

/// Build the complete application state.
pub async fn build_app_state(config: AppConfig) -> AppState {
    // Database pool
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    tracing::info!("Database connection established");

    // Audit logger
    let audit_storage = AuditStorage::new(pool.clone());
    let audit_logger = AuditLogger::new(audit_storage, config.environment.clone());

    // Policy governor
    let policy_governor = PolicyGovernor::new(pool.clone());

    // Risk calculator
    let risk_calculator = RiskCalculator::new(pool.clone());

    // Tool broker with Nmap
    let nmap_config = NmapConfig {
        binary_path: config.nmap_binary_path.clone(),
        timeout_secs: config.nmap_timeout_secs,
        artifact_dir: "/app/artifacts".to_string(),
    };

    let tool_broker = Arc::new(ToolBroker::new(
        pool.clone(),
        PolicyGovernor::new(pool.clone()),
        nmap_config,
    ));

    AppState {
        pool,
        config: Arc::new(config),
        audit_logger,
        policy_governor,
        tool_broker,
        risk_calculator,
    }
}

/// Build the Axum router with all routes and middleware.
pub fn build_router(state: AppState) -> Router {
    let api_routes = Router::new()
        // Health
        .route("/health", get(routes::health::health_check))
        // Auth
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/me", get(routes::auth::me))
        // Assets
        .route("/assets", get(routes::assets::list_assets).post(routes::assets::create_asset))
        .route("/assets/{id}", get(routes::assets::get_asset).put(routes::assets::update_asset))
        .route("/assets/{id}/risk", get(routes::risk::get_asset_risk))
        // Scans
        .route("/scan-targets", get(routes::scans::list_targets).post(routes::scans::create_target))
        .route("/scan-jobs", get(routes::scans::list_jobs).post(routes::scans::create_job))
        .route("/scan-jobs/{id}/run", post(routes::scans::trigger_run))
        .route("/scan-runs", get(routes::scans::list_runs))
        .route("/scan-runs/{id}", get(routes::scans::get_run))
        .route("/scan-runs/{id}/findings", get(routes::scans::get_run_findings))
        // Incidents
        .route("/incidents", get(routes::incidents::list_incidents).post(routes::incidents::create_incident))
        .route("/incidents/{id}", get(routes::incidents::get_incident).put(routes::incidents::update_incident))
        .route("/incidents/{id}/evidence", post(routes::incidents::link_evidence))
        // Policies
        .route("/policies", get(routes::policies::list_policies).post(routes::policies::create_policy))
        .route("/policies/{id}", get(routes::policies::get_policy))
        .route("/policies/{id}/rules", post(routes::policies::add_rule))
        .route("/approvals", get(routes::policies::list_approvals))
        .route("/approvals/{id}/decide", post(routes::policies::decide_approval))
        // Audit
        .route("/audit", get(routes::audit::list_audit_events))
        .route("/audit/{id}", get(routes::audit::get_audit_event))
        // Risk
        .route("/risk/calculate/{asset_id}", post(routes::risk::calculate_risk))
        .route("/risk/scores", get(routes::risk::list_risk_scores));

    Router::new()
        .nest("/api/v1", api_routes)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
