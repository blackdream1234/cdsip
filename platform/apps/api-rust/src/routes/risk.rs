//! Risk scoring routes.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use cdsip_domain_models::risk::RiskScore;
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::{AuthUser, require_write};

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// POST /api/v1/risk/calculate/:asset_id
pub async fn calculate_risk(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(asset_id): Path<Uuid>,
) -> Result<Json<RiskScore>, AppError> {
    require_write(&auth)?;

    let input = state.risk_calculator.gather_input(asset_id).await?;
    let score = state.risk_calculator.calculate(&input).await?;

    let audit_event = state.audit_logger.builder("risk.calculate", "risk_score", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(asset_id)
        .details(serde_json::json!({"score": score.score, "severity": score.severity_band}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(score))
}

/// GET /api/v1/risk/scores
pub async fn list_risk_scores(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<RiskScore>>, AppError> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let scores = state.risk_calculator.get_all_latest(limit, offset).await?;
    Ok(Json(scores))
}

/// GET /api/v1/assets/:id/risk
pub async fn get_asset_risk(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(asset_id): Path<Uuid>,
) -> Result<Json<Option<RiskScore>>, AppError> {
    let score = state.risk_calculator.get_latest(asset_id).await?;
    Ok(Json(score))
}
