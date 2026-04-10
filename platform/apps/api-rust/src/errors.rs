//! Structured API error types and responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Application-level error type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            AppError::Validation(msg) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error", msg.clone()),
            AppError::PolicyDenied(msg) => (StatusCode::FORBIDDEN, "policy_denied", msg.clone()),
            AppError::Internal(msg) => {
                tracing::error!(error = %msg, "Internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An internal error occurred".to_string())
            }
            AppError::Database(e) => {
                tracing::error!(error = %e, "Database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An internal error occurred".to_string())
            }
        };

        let body = json!({
            "error": {
                "type": error_type,
                "message": message,
            }
        });

        (status, Json(body)).into_response()
    }
}

impl From<cdsip_policy_engine::PolicyError> for AppError {
    fn from(e: cdsip_policy_engine::PolicyError) -> Self {
        AppError::Internal(format!("Policy engine error: {e}"))
    }
}

impl From<cdsip_tool_broker::ToolError> for AppError {
    fn from(e: cdsip_tool_broker::ToolError) -> Self {
        match e {
            cdsip_tool_broker::ToolError::PolicyDenied(msg) => AppError::PolicyDenied(msg),
            cdsip_tool_broker::ToolError::InvalidInput(msg) => AppError::Validation(msg),
            cdsip_tool_broker::ToolError::UnauthorizedTarget(msg) => AppError::Forbidden(msg),
            cdsip_tool_broker::ToolError::NotFound(msg) => AppError::NotFound(msg),
            other => AppError::Internal(other.to_string()),
        }
    }
}

impl From<cdsip_risk_engine::RiskError> for AppError {
    fn from(e: cdsip_risk_engine::RiskError) -> Self {
        match e {
            cdsip_risk_engine::RiskError::AssetNotFound(id) => AppError::NotFound(format!("Asset {id} not found")),
            other => AppError::Internal(other.to_string()),
        }
    }
}

impl From<cdsip_audit_core::AuditError> for AppError {
    fn from(e: cdsip_audit_core::AuditError) -> Self {
        AppError::Internal(format!("Audit error: {e}"))
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AppError::Unauthorized(format!("Token error: {e}"))
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(e: argon2::password_hash::Error) -> Self {
        AppError::Internal(format!("Password hashing error: {e}"))
    }
}
