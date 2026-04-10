//! Audit log routes — read-only for admin and auditor roles.

use axum::extract::{Path, Query, State};
use axum::Json;
use uuid::Uuid;

use cdsip_domain_models::audit::{AuditEvent, AuditQuery};
use cdsip_domain_models::risk::PaginatedResponse;
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::{AuthUser, require_audit_access};

/// GET /api/v1/audit
pub async fn list_audit_events(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AuditQuery>,
) -> Result<Json<PaginatedResponse<AuditEvent>>, AppError> {
    require_audit_access(&auth)?;

    let events = state.audit_logger.query(&params).await?;
    let total = state.audit_logger.count(&params).await?;

    Ok(Json(PaginatedResponse {
        items: events,
        total,
        limit: params.limit.unwrap_or(50),
        offset: params.offset.unwrap_or(0),
    }))
}

/// GET /api/v1/audit/:id
pub async fn get_audit_event(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<AuditEvent>, AppError> {
    require_audit_access(&auth)?;

    let event = state.audit_logger.get_by_id(id).await?
        .ok_or_else(|| AppError::NotFound(format!("Audit event {id} not found")))?;

    Ok(Json(event))
}
