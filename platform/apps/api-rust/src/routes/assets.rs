//! Asset management routes.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use cdsip_domain_models::asset::{Asset, CreateAssetRequest, UpdateAssetRequest};
use cdsip_domain_models::risk::PaginatedResponse;
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::{AuthUser, require_write};

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub environment: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
}

/// GET /api/v1/assets
pub async fn list_assets(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<PaginatedResponse<Asset>>, AppError> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let assets = sqlx::query_as::<_, Asset>(
        r#"
        SELECT * FROM assets
        WHERE ($1::text IS NULL OR environment = $1)
          AND ($2::text IS NULL OR status = $2)
          AND ($3::text IS NULL OR ip_address LIKE '%' || $3 || '%' OR hostname LIKE '%' || $3 || '%')
        ORDER BY criticality DESC, last_seen DESC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(&params.environment)
    .bind(&params.status)
    .bind(&params.search)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    let total: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM assets
        WHERE ($1::text IS NULL OR environment = $1)
          AND ($2::text IS NULL OR status = $2)
          AND ($3::text IS NULL OR ip_address LIKE '%' || $3 || '%' OR hostname LIKE '%' || $3 || '%')
        "#,
    )
    .bind(&params.environment)
    .bind(&params.status)
    .bind(&params.search)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(PaginatedResponse {
        items: assets,
        total: total.0,
        limit,
        offset,
    }))
}

/// GET /api/v1/assets/:id
pub async fn get_asset(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, AppError> {
    let asset = sqlx::query_as::<_, Asset>(
        "SELECT * FROM assets WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Asset {id} not found")))?;

    Ok(Json(asset))
}

/// POST /api/v1/assets
pub async fn create_asset(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateAssetRequest>,
) -> Result<Json<Asset>, AppError> {
    require_write(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let id = Uuid::now_v7();
    let status = req.status.map(|s| s.to_string()).unwrap_or_else(|| "active".to_string());

    let asset = sqlx::query_as::<_, Asset>(
        r#"
        INSERT INTO assets (id, ip_address, hostname, mac_address, os_fingerprint, owner, criticality, environment, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&req.ip_address)
    .bind(&req.hostname)
    .bind(&req.mac_address)
    .bind(&req.os_fingerprint)
    .bind(&req.owner)
    .bind(req.criticality)
    .bind(req.environment.to_string())
    .bind(&status)
    .fetch_one(&state.pool)
    .await?;

    // Audit event
    let audit_event = state.audit_logger.builder("asset.create", "asset", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .details(serde_json::json!({"ip_address": req.ip_address}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(asset))
}

/// PUT /api/v1/assets/:id
pub async fn update_asset(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAssetRequest>,
) -> Result<Json<Asset>, AppError> {
    require_write(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    // Verify asset exists
    let existing = sqlx::query_as::<_, Asset>("SELECT * FROM assets WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Asset {id} not found")))?;

    let asset = sqlx::query_as::<_, Asset>(
        r#"
        UPDATE assets SET
            hostname = COALESCE($1, hostname),
            mac_address = COALESCE($2, mac_address),
            os_fingerprint = COALESCE($3, os_fingerprint),
            owner = COALESCE($4, owner),
            criticality = COALESCE($5, criticality),
            environment = COALESCE($6, environment),
            status = COALESCE($7, status)
        WHERE id = $8
        RETURNING *
        "#,
    )
    .bind(&req.hostname)
    .bind(&req.mac_address)
    .bind(&req.os_fingerprint)
    .bind(&req.owner)
    .bind(req.criticality)
    .bind(req.environment.map(|e| e.to_string()))
    .bind(req.status.map(|s| s.to_string()))
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    // Audit event
    let audit_event = state.audit_logger.builder("asset.update", "asset", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(asset))
}
