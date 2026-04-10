//! Scan routes — targets, jobs, runs, findings.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use cdsip_domain_models::scan::*;
use cdsip_domain_models::risk::PaginatedResponse;
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::{AuthUser, require_write};

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// GET /api/v1/scan-targets
pub async fn list_targets(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ScanTarget>>, AppError> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let targets = sqlx::query_as::<_, ScanTarget>(
        "SELECT * FROM scan_targets ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(targets))
}

/// POST /api/v1/scan-targets
pub async fn create_target(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateScanTargetRequest>,
) -> Result<Json<ScanTarget>, AppError> {
    require_write(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let id = Uuid::now_v7();
    let target = sqlx::query_as::<_, ScanTarget>(
        r#"
        INSERT INTO scan_targets (id, network_id, target_spec, description)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(req.network_id)
    .bind(&req.target_spec)
    .bind(&req.description)
    .fetch_one(&state.pool)
    .await?;

    let audit_event = state.audit_logger.builder("scan_target.create", "scan_target", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .details(serde_json::json!({"target_spec": req.target_spec}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(target))
}

/// GET /api/v1/scan-jobs
pub async fn list_jobs(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ScanJob>>, AppError> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let jobs = sqlx::query_as::<_, ScanJob>(
        "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(jobs))
}

/// POST /api/v1/scan-jobs
pub async fn create_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateScanJobRequest>,
) -> Result<Json<ScanJob>, AppError> {
    require_write(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let id = Uuid::now_v7();
    let job = sqlx::query_as::<_, ScanJob>(
        r#"
        INSERT INTO scan_jobs (id, name, scan_target_id, profile, schedule_cron, created_by, environment)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.scan_target_id)
    .bind(req.profile.to_string())
    .bind(&req.schedule_cron)
    .bind(auth.user_id)
    .bind(&req.environment)
    .fetch_one(&state.pool)
    .await?;

    let audit_event = state.audit_logger.builder("scan_job.create", "scan_job", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .details(serde_json::json!({"name": req.name, "profile": req.profile.to_string()}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(job))
}

/// POST /api/v1/scan-jobs/:id/run — Trigger a scan run through the Tool Broker
pub async fn trigger_run(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(job_id): Path<Uuid>,
) -> Result<Json<ScanRun>, AppError> {
    require_write(&auth)?;

    // Get the job
    let job = sqlx::query_as::<_, ScanJob>("SELECT * FROM scan_jobs WHERE id = $1")
        .bind(job_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Scan job {job_id} not found")))?;

    // Get the target
    let target = sqlx::query_as::<_, ScanTarget>(
        "SELECT * FROM scan_targets WHERE id = $1",
    )
    .bind(job.scan_target_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Scan target not found".to_string()))?;

    // Create scan run record
    let run_id = Uuid::now_v7();
    let run = sqlx::query_as::<_, ScanRun>(
        r#"
        INSERT INTO scan_runs (id, scan_job_id, status, started_at)
        VALUES ($1, $2, 'running', NOW())
        RETURNING *
        "#,
    )
    .bind(run_id)
    .bind(job_id)
    .fetch_one(&state.pool)
    .await?;

    // Execute through Tool Broker (async — fire and forget for V1)
    let broker = state.tool_broker.clone();
    let pool = state.pool.clone();
    let actor_id = auth.user_id;
    let actor_role = auth.role.clone();
    let environment = job.environment.clone();
    let profile = job.profile.clone();
    let target_spec = target.target_spec.clone();

    tokio::spawn(async move {
        let params = serde_json::json!({
            "profile": profile,
            "target": target_spec,
        });

        let result = broker
            .execute("nmap", params, actor_id, &actor_role, &environment, Uuid::now_v7())
            .await;

        match result {
            Ok(output) => {
                // Update scan run as completed
                let _ = sqlx::query(
                    "UPDATE scan_runs SET status = 'completed', completed_at = NOW(), findings_count = $1 WHERE id = $2",
                )
                .bind(output.data.get("total_ports").and_then(|v| v.as_i64()).unwrap_or(0) as i32)
                .bind(run_id)
                .execute(&pool)
                .await;

                tracing::info!(run_id = %run_id, "Scan run completed successfully");
            }
            Err(e) => {
                let _ = sqlx::query(
                    "UPDATE scan_runs SET status = 'failed', completed_at = NOW(), error_message = $1 WHERE id = $2",
                )
                .bind(e.to_string())
                .bind(run_id)
                .execute(&pool)
                .await;

                tracing::error!(run_id = %run_id, error = %e, "Scan run failed");
            }
        }
    });

    Ok(Json(run))
}

/// GET /api/v1/scan-runs
pub async fn list_runs(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ScanRun>>, AppError> {
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0);

    let runs = sqlx::query_as::<_, ScanRun>(
        "SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(runs))
}

/// GET /api/v1/scan-runs/:id
pub async fn get_run(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanRun>, AppError> {
    let run = sqlx::query_as::<_, ScanRun>(
        "SELECT * FROM scan_runs WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Scan run {id} not found")))?;

    Ok(Json(run))
}

/// GET /api/v1/scan-runs/:id/findings
pub async fn get_run_findings(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ScanFinding>>, AppError> {
    let findings = sqlx::query_as::<_, ScanFinding>(
        "SELECT * FROM scan_findings WHERE scan_run_id = $1 ORDER BY severity DESC, port ASC",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(findings))
}
