//! Risk scoring domain models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Severity bands mapped from numeric risk scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBand {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityBand {
    /// Map a 0–100 score to a severity band.
    pub fn from_score(score: f64) -> Self {
        match score as i64 {
            0..=19 => SeverityBand::Info,
            20..=39 => SeverityBand::Low,
            40..=59 => SeverityBand::Medium,
            60..=79 => SeverityBand::High,
            _ => SeverityBand::Critical,
        }
    }
}

impl std::fmt::Display for SeverityBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeverityBand::Info => write!(f, "info"),
            SeverityBand::Low => write!(f, "low"),
            SeverityBand::Medium => write!(f, "medium"),
            SeverityBand::High => write!(f, "high"),
            SeverityBand::Critical => write!(f, "critical"),
        }
    }
}

/// Individual risk factor contributing to the overall score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name (e.g., "asset_criticality", "open_ports").
    pub name: String,
    /// Weight of this factor in the overall score (0.0 - 1.0).
    pub weight: f64,
    /// Raw value of this factor.
    pub value: f64,
    /// Weighted contribution to the score.
    pub contribution: f64,
    /// Human-readable description of why this factor matters.
    pub description: String,
}

/// A risk score for an asset — fully explainable.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RiskScore {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub score: f64,
    pub severity_band: String,
    pub factors: serde_json::Value,
    pub rationale: String,
    pub calculated_at: DateTime<Utc>,
    pub calculated_by: String,
    pub created_at: DateTime<Utc>,
}

/// Input data for risk calculation — gathered from various sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskInput {
    pub asset_id: Uuid,
    pub asset_criticality: i32,
    pub open_port_count: i32,
    pub risky_service_count: i32,
    pub new_ports_since_last_scan: i32,
    pub service_changes_since_last_scan: i32,
    pub failed_policy_requests: i32,
    pub high_severity_findings: i32,
    pub days_since_last_scan: i32,
}

/// Paginated list response wrapper.
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Dashboard statistics.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub total_assets: i64,
    pub critical_assets: i64,
    pub active_incidents: i64,
    pub recent_scan_runs: i64,
    pub high_risk_assets: i64,
    pub policy_denials_24h: i64,
    pub audit_events_24h: i64,
}
