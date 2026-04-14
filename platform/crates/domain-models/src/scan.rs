//! Scan domain models — targets, jobs, runs, findings, services, ports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

/// Approved scan profiles — no arbitrary flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfile {
    /// Basic host discovery (-sn)
    HostDiscovery,
    /// Safe TCP port scan (-sT --top-ports 1000)
    SafeTcpScan,
    /// Service/version detection (-sV --version-intensity 5)
    ServiceDetection,
}

impl ScanProfile {
    /// Returns the Nmap flags for this profile.
    /// These are the ONLY allowed flag sets.
    pub fn nmap_flags(&self) -> &[&str] {
        match self {
            ScanProfile::HostDiscovery => &["-sn", "-n", "--max-retries", "2"],
            ScanProfile::SafeTcpScan => &[
                "-sT",
                "--top-ports",
                "1000",
                "-n",
                "--max-retries",
                "2",
                "--host-timeout",
                "300s",
            ],
            ScanProfile::ServiceDetection => &[
                "-sV",
                "--version-intensity",
                "5",
                "--top-ports",
                "1000",
                "-n",
                "--max-retries",
                "2",
                "--host-timeout",
                "300s",
            ],
        }
    }

    /// Human-readable description for audit/UI.
    pub fn description(&self) -> &str {
        match self {
            ScanProfile::HostDiscovery => "Basic host discovery (ping sweep)",
            ScanProfile::SafeTcpScan => "Safe TCP connect scan (top 1000 ports)",
            ScanProfile::ServiceDetection => "Service/version detection (top 1000 ports)",
        }
    }
}

impl std::fmt::Display for ScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanProfile::HostDiscovery => write!(f, "host_discovery"),
            ScanProfile::SafeTcpScan => write!(f, "safe_tcp_scan"),
            ScanProfile::ServiceDetection => write!(f, "service_detection"),
        }
    }
}

/// Scan run status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ScanRunStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// A target specification eligible for scanning.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanTarget {
    pub id: Uuid,
    pub network_id: Option<Uuid>,
    pub target_spec: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// DTO for creating a scan target.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateScanTargetRequest {
    pub network_id: Option<Uuid>,
    #[validate(length(min = 1, max = 255))]
    pub target_spec: String,
    pub description: Option<String>,
}

/// A scan job definition (can be scheduled or one-shot).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanJob {
    pub id: Uuid,
    pub name: String,
    pub scan_target_id: Uuid,
    pub profile: String,
    pub schedule_cron: Option<String>,
    pub is_active: bool,
    pub created_by: Uuid,
    pub approved_by: Option<Uuid>,
    pub environment: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DTO for creating a scan job.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateScanJobRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    pub scan_target_id: Uuid,
    pub profile: ScanProfile,
    pub schedule_cron: Option<String>,
    pub environment: String,
}

/// A single scan execution.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanRun {
    pub id: Uuid,
    pub scan_job_id: Uuid,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub findings_count: i32,
    pub raw_artifact_path: Option<String>,
    pub error_message: Option<String>,
    pub execution_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A single finding from a scan run.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanFinding {
    pub id: Uuid,
    pub scan_run_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub ip_address: String,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub state: String,
    pub severity: String,
    pub confidence: f64,
    pub raw_data: Option<serde_json::Value>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Port record for an asset.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Port {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub port_number: i32,
    pub protocol: String,
    pub state: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Service record for an asset.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Service {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub port: i32,
    pub protocol: String,
    pub service_name: String,
    pub service_version: Option<String>,
    pub state: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Diff between two scan runs.
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiff {
    pub previous_run_id: Uuid,
    pub current_run_id: Uuid,
    pub new_ports: Vec<ScanFinding>,
    pub closed_ports: Vec<ScanFinding>,
    pub changed_services: Vec<ServiceChange>,
    pub new_hosts: Vec<String>,
    pub disappeared_hosts: Vec<String>,
}

/// A service change between two scans.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceChange {
    pub ip_address: String,
    pub port: i32,
    pub previous_service: Option<String>,
    pub current_service: Option<String>,
    pub previous_version: Option<String>,
    pub current_version: Option<String>,
}
