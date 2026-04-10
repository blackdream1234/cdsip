//! Incident domain models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

/// Incident severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentSeverity::Info => write!(f, "info"),
            IncidentSeverity::Low => write!(f, "low"),
            IncidentSeverity::Medium => write!(f, "medium"),
            IncidentSeverity::High => write!(f, "high"),
            IncidentSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Incident lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    Closed,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentStatus::Open => write!(f, "open"),
            IncidentStatus::Investigating => write!(f, "investigating"),
            IncidentStatus::Contained => write!(f, "contained"),
            IncidentStatus::Resolved => write!(f, "resolved"),
            IncidentStatus::Closed => write!(f, "closed"),
        }
    }
}

/// A security incident.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Incident {
    pub id: Uuid,
    pub title: String,
    pub status: String,
    pub severity: String,
    pub summary: Option<String>,
    pub created_by: Uuid,
    pub assigned_to: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// DTO for creating an incident.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateIncidentRequest {
    #[validate(length(min = 1, max = 256))]
    pub title: String,
    pub severity: IncidentSeverity,
    #[validate(length(max = 4096))]
    pub summary: Option<String>,
    pub assigned_to: Option<Uuid>,
}

/// DTO for updating an incident.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateIncidentRequest {
    #[validate(length(min = 1, max = 256))]
    pub title: Option<String>,
    pub status: Option<IncidentStatus>,
    pub severity: Option<IncidentSeverity>,
    #[validate(length(max = 4096))]
    pub summary: Option<String>,
    pub assigned_to: Option<Uuid>,
}

/// Evidence linked to an incident.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IncidentEvidence {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub evidence_id: Uuid,
    pub relationship_type: String,
    pub added_by: Uuid,
    pub created_at: DateTime<Utc>,
}

/// DTO for linking evidence to an incident.
#[derive(Debug, Clone, Deserialize)]
pub struct LinkEvidenceRequest {
    pub evidence_id: Uuid,
    pub relationship_type: String,
}
