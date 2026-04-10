//! Evidence object domain models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Types of evidence that can be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    ScanFinding,
    PolicyViolation,
    NetworkObservation,
    ManualNote,
    ToolOutput,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceType::ScanFinding => write!(f, "scan_finding"),
            EvidenceType::PolicyViolation => write!(f, "policy_violation"),
            EvidenceType::NetworkObservation => write!(f, "network_observation"),
            EvidenceType::ManualNote => write!(f, "manual_note"),
            EvidenceType::ToolOutput => write!(f, "tool_output"),
        }
    }
}

/// Sensitivity classification for evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl std::fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sensitivity::Public => write!(f, "public"),
            Sensitivity::Internal => write!(f, "internal"),
            Sensitivity::Confidential => write!(f, "confidential"),
            Sensitivity::Restricted => write!(f, "restricted"),
        }
    }
}

/// An evidence object — immutable record linked to incidents and findings.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EvidenceObject {
    pub id: Uuid,
    pub evidence_type: String,
    pub source: String,
    pub source_id: Option<Uuid>,
    pub data: serde_json::Value,
    pub hash: String,
    pub sensitivity: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

/// DTO for creating evidence.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateEvidenceRequest {
    pub evidence_type: EvidenceType,
    pub source: String,
    pub source_id: Option<Uuid>,
    pub data: serde_json::Value,
    pub sensitivity: Sensitivity,
}
