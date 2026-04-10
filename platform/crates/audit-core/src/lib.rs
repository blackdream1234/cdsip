//! CDSIP Audit Core
//!
//! Provides append-only audit logging for the platform.
//! Audit events are NEVER updated or deleted at the application level.

pub mod logger;
pub mod storage;
pub mod types;

pub use logger::AuditLogger;
pub use types::AuditError;
