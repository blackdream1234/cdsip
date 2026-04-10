//! Tool broker error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Tool not found: {0}")]
    NotFound(String),

    #[error("Tool execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Tool execution timed out after {0} seconds")]
    Timeout(u64),

    #[error("Input validation failed: {0}")]
    InvalidInput(String),

    #[error("Target not authorized: {0}")]
    UnauthorizedTarget(String),

    #[error("Policy denied execution: {0}")]
    PolicyDenied(String),

    #[error("Output parsing failed: {0}")]
    ParseError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Policy error: {0}")]
    PolicyError(#[from] cdsip_policy_engine::PolicyError),
}
