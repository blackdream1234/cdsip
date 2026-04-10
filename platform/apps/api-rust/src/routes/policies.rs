//! Policy management routes.

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;
use validator::Validate;

use cdsip_domain_models::policy::*;
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::{AuthUser, require_admin};

/// GET /api/v1/policies
pub async fn list_policies(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<Json<Vec<Policy>>, AppError> {
    let policies = state.policy_governor.list_policies().await?;
    Ok(Json(policies))
}

/// GET /api/v1/policies/:id
pub async fn get_policy(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let policy = state.policy_governor.get_policy(id).await?
        .ok_or_else(|| AppError::NotFound(format!("Policy {id} not found")))?;
    let rules = state.policy_governor.get_rules(id).await?;

    Ok(Json(serde_json::json!({
        "policy": policy,
        "rules": rules,
    })))
}

/// POST /api/v1/policies
pub async fn create_policy(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<Policy>, AppError> {
    require_admin(&auth)?;
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let policy = state.policy_governor.create_policy(&req, auth.user_id).await?;

    let audit_event = state.audit_logger.builder("policy.create", "policy", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(policy.id)
        .details(serde_json::json!({"name": req.name}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(policy))
}

/// POST /api/v1/policies/:id/rules
pub async fn add_rule(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(policy_id): Path<Uuid>,
    Json(req): Json<CreatePolicyRuleRequest>,
) -> Result<Json<PolicyRule>, AppError> {
    require_admin(&auth)?;

    let rule = state.policy_governor.add_rule(policy_id, &req).await?;

    let audit_event = state.audit_logger.builder("policy_rule.create", "policy_rule", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(rule.id)
        .details(serde_json::json!({"policy_id": policy_id, "rule_type": req.rule_type}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(rule))
}

/// GET /api/v1/approvals
pub async fn list_approvals(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Approval>>, AppError> {
    // Analysts can see their own + admins see all
    let approvals = state.policy_governor.list_pending_approvals().await?;
    Ok(Json(approvals))
}

/// POST /api/v1/approvals/:id/decide
pub async fn decide_approval(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<ApprovalDecisionRequest>,
) -> Result<Json<Approval>, AppError> {
    require_admin(&auth)?;

    let approval = state.policy_governor
        .decide_approval(id, auth.user_id, req.approved, req.reason.as_deref())
        .await?;

    let audit_event = state.audit_logger.builder("approval.decide", "approval", Uuid::now_v7())
        .actor(auth.user_id, &auth.role)
        .resource_id(id)
        .details(serde_json::json!({"approved": req.approved, "reason": req.reason}))
        .build();
    state.audit_logger.log(audit_event).await?;

    Ok(Json(approval))
}
