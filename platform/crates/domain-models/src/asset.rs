//! Asset, Network, and Tag domain models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

/// Asset criticality level (1 = lowest, 5 = highest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssetCriticality {
    Minimal = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl AssetCriticality {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::Minimal),
            2 => Some(Self::Low),
            3 => Some(Self::Medium),
            4 => Some(Self::High),
            5 => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

/// Asset environment classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Production,
    Staging,
    Lab,
    Development,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Production => write!(f, "production"),
            Environment::Staging => write!(f, "staging"),
            Environment::Lab => write!(f, "lab"),
            Environment::Development => write!(f, "development"),
        }
    }
}

/// Asset operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    Active,
    Inactive,
    Decommissioned,
    Unknown,
}

impl std::fmt::Display for AssetStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetStatus::Active => write!(f, "active"),
            AssetStatus::Inactive => write!(f, "inactive"),
            AssetStatus::Decommissioned => write!(f, "decommissioned"),
            AssetStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// A discovered or registered asset (host, device, endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Asset {
    pub id: Uuid,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub os_fingerprint: Option<String>,
    pub owner: Option<String>,
    pub criticality: i32,
    pub environment: String,
    pub status: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DTO for creating a new asset.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetRequest {
    #[validate(length(min = 1, max = 45))]
    pub ip_address: String,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(length(max = 17))]
    pub mac_address: Option<String>,
    pub os_fingerprint: Option<String>,
    #[validate(length(max = 128))]
    pub owner: Option<String>,
    #[validate(range(min = 1, max = 5))]
    pub criticality: i32,
    pub environment: Environment,
    pub status: Option<AssetStatus>,
}

/// DTO for updating an asset.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateAssetRequest {
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(length(max = 17))]
    pub mac_address: Option<String>,
    pub os_fingerprint: Option<String>,
    #[validate(length(max = 128))]
    pub owner: Option<String>,
    #[validate(range(min = 1, max = 5))]
    pub criticality: Option<i32>,
    pub environment: Option<Environment>,
    pub status: Option<AssetStatus>,
}

/// Tag attached to an asset for flexible categorization.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetTag {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub key: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
}

/// A network range that can be used for targeting scans.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Network {
    pub id: Uuid,
    pub name: String,
    pub cidr: String,
    pub environment: String,
    pub description: Option<String>,
    pub is_scan_allowed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DTO for creating a network.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateNetworkRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    #[validate(length(min = 1, max = 43))]
    pub cidr: String,
    pub environment: Environment,
    pub description: Option<String>,
    pub is_scan_allowed: bool,
}
