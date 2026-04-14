use axum::{extract::State, Json};
use serde::Serialize;
use sqlx::Row;

use crate::extractors::AppState;

#[derive(Serialize)]
pub struct SystemStatus {
    pub audit_immutable_trigger_active: bool,
    pub policy_engine_status: String,
    pub tool_broker_status: String,
    pub autonomous_mode_allowed: bool,
    pub environment: String,
}

pub async fn system_status(State(state): State<AppState>) -> Json<SystemStatus> {
    // Verify triggers genuinely exist on audit_events
    let trigger_query = r#"
        SELECT count(*) as count 
        FROM pg_trigger 
        WHERE tgname IN ('trg_audit_no_delete', 'trg_audit_no_update') 
        AND tgrelid = 'audit_events'::regclass;
    "#;

    let trigger_count: i64 = sqlx::query(trigger_query)
        .fetch_one(&state.pool)
        .await
        .map(|row| row.get("count"))
        .unwrap_or(0);

    let audit_immutable = trigger_count == 2;

    Json(SystemStatus {
        audit_immutable_trigger_active: audit_immutable,
        policy_engine_status: "active".to_string(), // Currently deterministic as compiled middleware
        tool_broker_status: "active".to_string(),
        autonomous_mode_allowed: false, // Per core defensive requirement
        environment: state.config.environment.clone(),
    })
}
