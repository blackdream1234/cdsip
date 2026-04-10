//! Incident routes.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use cdsip_domain_models::incident::*;
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::{AuthUser, require_write};

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub status: Option<String>,
    pub severity: Option<String>,
}

/// GET /api/v1/incidents
pub async fn list_incidents(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Incident>>, AppError> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let incidents = sqlx::query_as::<_, Incident>(
        r#"
        SELECT * FROM incidents
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR severity = $2)
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(&params.status)
    .bind(&params.severity)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(incidents))
}

/// GET /api/v1/incidents/:id
pub async fn get_incident(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Incident>, AppError> {
    let incident = sqlx::query_as::<_, Incident>(
        "SELECT * FROM incidents WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Incident {id} not found")))?;

    Ok(Json(incident))
}

/// POST /api/v1/incidents
pub async fn create_incident(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateIncidentRequest>,
) -> Result<Json<Incident>, AppError> {
    require_write(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let id = Uuid::now_v7();
    let incident = sqlx::query_as::<_, Incident>(
        r#"
        INSERT INTO incidents (id, title, severity, summary, created_by, assigned_to)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&req.title)
    .bind(req.severity.to_string())
    .bind(&req.summary)
    .bind(auth.user_id)
    .bind(req.assigned_to)
    .fetch_one(&state.pool)
    .await?;

    let audit_event = state.audit_logger.builder("incident.create", "incident", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .details(serde_json::json!({"title": req.title, "severity": req.severity.to_string()}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(incident))
}

/// PUT /api/v1/incidents/:id
pub async fn update_incident(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIncidentRequest>,
) -> Result<Json<Incident>, AppError> {
    require_write(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let incident = sqlx::query_as::<_, Incident>(
        r#"
        UPDATE incidents SET
            title = COALESCE($1, title),
            status = COALESCE($2, status),
            severity = COALESCE($3, severity),
            summary = COALESCE($4, summary),
            assigned_to = COALESCE($5, assigned_to),
            resolved_at = CASE WHEN $2 IN ('resolved', 'closed') THEN NOW() ELSE resolved_at END
        WHERE id = $6
        RETURNING *
        "#,
    )
    .bind(&req.title)
    .bind(req.status.map(|s| s.to_string()))
    .bind(req.severity.map(|s| s.to_string()))
    .bind(&req.summary)
    .bind(req.assigned_to)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Incident {id} not found")))?;

    let audit_event = state.audit_logger.builder("incident.update", "incident", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(incident))
}

/// POST /api/v1/incidents/:id/evidence
pub async fn link_evidence(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<LinkEvidenceRequest>,
) -> Result<Json<IncidentEvidence>, AppError> {
    require_write(&auth)?;

    let link_id = Uuid::now_v7();
    let link = sqlx::query_as::<_, IncidentEvidence>(
        r#"
        INSERT INTO incident_evidence (id, incident_id, evidence_id, relationship_type, added_by)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(link_id)
    .bind(id)
    .bind(req.evidence_id)
    .bind(&req.relationship_type)
    .bind(auth.user_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(link))
}
