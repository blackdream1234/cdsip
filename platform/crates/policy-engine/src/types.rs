//! Policy engine error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy evaluation failed: {0}")]
    EvaluationError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Invalid policy configuration: {0}")]
    ConfigError(String),

    #[error("Policy not found: {0}")]
    NotFound(String),
}
