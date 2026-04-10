//! CDSIP Domain Models
//!
//! Pure data types and domain entities for the Closed Defensive Security
//! Intelligence Platform. This crate contains NO business logic — only
//! type definitions, enums, validation, and serialization.
//!
//! All other crates depend on this one for shared type contracts.

pub mod asset;
pub mod audit;
pub mod evidence;
pub mod incident;
pub mod policy;
pub mod risk;
pub mod scan;
pub mod user;

/// Common ID type used across all entities.
pub type EntityId = uuid::Uuid;

/// Re-export commonly used types.
pub mod prelude {
    pub use super::asset::{Asset, AssetCriticality, AssetStatus, AssetTag, Network};
    pub use super::audit::AuditEvent;
    pub use super::evidence::{EvidenceObject, EvidenceType};
    pub use super::incident::{Incident, IncidentSeverity, IncidentStatus};
    pub use super::policy::{
        Approval, ApprovalStatus, Policy, PolicyAction, PolicyDecision, PolicyRequest, PolicyRule,
    };
    pub use super::risk::{RiskScore, SeverityBand};
    pub use super::scan::{
        Port, ScanFinding, ScanJob, ScanProfile, ScanRun, ScanRunStatus, ScanTarget, Service,
    };
    pub use super::user::{Role, Session, User};
    pub use super::EntityId;
}
