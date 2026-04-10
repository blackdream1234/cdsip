//! Policy and approval domain models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

/// Policy actions — the outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    RequireApproval,
    Escalate,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyAction::Allow => write!(f, "allow"),
            PolicyAction::Deny => write!(f, "deny"),
            PolicyAction::RequireApproval => write!(f, "require_approval"),
            PolicyAction::Escalate => write!(f, "escalate"),
        }
    }
}

/// A policy request — submitted to the Policy Governor for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// Who is requesting.
    pub actor_id: Uuid,
    /// What role they have.
    pub actor_role: String,
    /// What action is being requested.
    pub action: String,
    /// What resource type (e.g., "scan", "asset", "incident").
    pub resource_type: String,
    /// Specific resource ID if known.
    pub resource_id: Option<Uuid>,
    /// Target specification (e.g., IP range for scans).
    pub target: Option<String>,
    /// Environment context.
    pub environment: String,
    /// Additional context for rule evaluation.
    pub context: serde_json::Value,
}

/// The Policy Governor's decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Unique ID for this decision (for audit trail).
    pub decision_id: Uuid,
    /// The action taken.
    pub action: PolicyAction,
    /// Which policy matched (if any).
    pub matched_policy_id: Option<Uuid>,
    /// Which rule matched (if any).
    pub matched_rule_id: Option<Uuid>,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
    /// If RequireApproval, the approval ID to track.
    pub approval_id: Option<Uuid>,
}

/// A policy definition.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub environment_scope: String,
    pub is_active: bool,
    pub version: i32,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DTO for creating a policy.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    #[validate(length(max = 1024))]
    pub description: Option<String>,
    pub environment_scope: String,
}

/// DTO for updating a policy.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdatePolicyRequest {
    #[validate(length(min = 1, max = 128))]
    pub name: Option<String>,
    #[validate(length(max = 1024))]
    pub description: Option<String>,
    pub environment_scope: Option<String>,
    pub is_active: Option<bool>,
}

/// A rule within a policy.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PolicyRule {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub action: String,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

/// DTO for creating a policy rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePolicyRuleRequest {
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub action: PolicyAction,
    pub priority: i32,
}

/// Approval status for queued actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalStatus::Pending => write!(f, "pending"),
            ApprovalStatus::Approved => write!(f, "approved"),
            ApprovalStatus::Denied => write!(f, "denied"),
            ApprovalStatus::Expired => write!(f, "expired"),
        }
    }
}

/// An approval record — tracks pending/decided requests.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Approval {
    pub id: Uuid,
    pub policy_rule_id: Option<Uuid>,
    pub requested_by: Uuid,
    pub approved_by: Option<Uuid>,
    pub status: String,
    pub request_data: serde_json::Value,
    pub decision_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// DTO for deciding on an approval.
#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub approved: bool,
    pub reason: Option<String>,
}
