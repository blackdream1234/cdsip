//! Risk engine error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RiskError {
    #[error("Risk calculation failed: {0}")]
    CalculationError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Asset not found: {0}")]
    AssetNotFound(uuid::Uuid),
}
