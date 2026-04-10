//! Shared application state and extractors.

pub mod auth;

use axum::extract::FromRef;
use cdsip_audit_core::AuditLogger;
use cdsip_policy_engine::PolicyGovernor;
use cdsip_risk_engine::RiskCalculator;
use cdsip_tool_broker::ToolBroker;
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::AppConfig;

/// Application state shared across all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
    pub audit_logger: AuditLogger,
    pub policy_governor: PolicyGovernor,
    pub tool_broker: Arc<ToolBroker>,
    pub risk_calculator: RiskCalculator,
}
