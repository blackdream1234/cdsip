//! User, Role, and Session domain models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

/// User roles — strictly enumerated, no dynamic role creation in V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    SecurityAnalyst,
    Auditor,
    ReadOnly,
}

impl Role {
    /// Returns true if this role can mutate data.
    pub fn can_write(&self) -> bool {
        matches!(self, Role::Admin | Role::SecurityAnalyst)
    }

    /// Returns true if this role can manage policies.
    pub fn can_manage_policies(&self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Returns true if this role can approve actions.
    pub fn can_approve(&self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Returns true if this role can view audit logs.
    pub fn can_view_audit(&self) -> bool {
        matches!(self, Role::Admin | Role::Auditor)
    }

    /// Returns true if this role can manage users.
    pub fn can_manage_users(&self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Returns true if this role can request scans.
    pub fn can_request_scans(&self) -> bool {
        matches!(self, Role::Admin | Role::SecurityAnalyst)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::SecurityAnalyst => write!(f, "security_analyst"),
            Role::Auditor => write!(f, "auditor"),
            Role::ReadOnly => write!(f, "read_only"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Role::Admin),
            "security_analyst" => Ok(Role::SecurityAnalyst),
            "auditor" => Ok(Role::Auditor),
            "read_only" => Ok(Role::ReadOnly),
            _ => Err(format!("Unknown role: {s}")),
        }
    }
}

/// A platform user.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DTO for creating a new user — input validation applied.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 12, max = 128))]
    pub password: String,
    pub role: Role,
}

/// DTO for login.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1))]
    pub username: String,
    #[validate(length(min = 1))]
    pub password: String,
}

/// Public user info — never exposes password_hash.
#[derive(Debug, Clone, Serialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            role: u.role,
            is_active: u.is_active,
            created_at: u.created_at,
        }
    }
}

/// Auth token response.
#[derive(Debug, Clone, Serialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// JWT claims embedded in access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: Uuid,
}

/// Session record for token tracking/revocation.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}
