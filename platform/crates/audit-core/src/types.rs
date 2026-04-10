//! Audit error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Failed to store audit event: {0}")]
    StorageError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
