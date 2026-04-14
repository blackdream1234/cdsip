//! Audit event domain models — append-only, immutable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// An audit event — immutable record of a platform action.
/// These records must NEVER be updated or deleted at the application level.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
    pub actor_role: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub request_id: Uuid,
    pub correlation_id: Option<Uuid>,
    pub policy_decision: Option<String>,
    pub policy_decision_id: Option<Uuid>,
    pub environment: String,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Builder for creating audit events — enforces required fields.
#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    action: String,
    resource_type: String,
    request_id: Uuid,
    environment: String,
    actor_id: Option<Uuid>,
    actor_role: Option<String>,
    resource_id: Option<Uuid>,
    correlation_id: Option<Uuid>,
    policy_decision: Option<String>,
    policy_decision_id: Option<Uuid>,
    details: serde_json::Value,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl AuditEventBuilder {
    /// Create a new builder with required fields.
    pub fn new(action: impl Into<String>, resource_type: impl Into<String>, request_id: Uuid, environment: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource_type: resource_type.into(),
            request_id,
            environment: environment.into(),
            actor_id: None,
            actor_role: None,
            resource_id: None,
            correlation_id: None,
            policy_decision: None,
            policy_decision_id: None,
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
        }
    }

    pub fn actor(mut self, id: Uuid, role: impl Into<String>) -> Self {
        self.actor_id = Some(id);
        self.actor_role = Some(role.into());
        self
    }

    pub fn resource_id(mut self, id: Uuid) -> Self {
        self.resource_id = Some(id);
        self
    }

    pub fn correlation_id(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }

    pub fn policy_decision(mut self, decision: impl Into<String>) -> Self {
        self.policy_decision = Some(decision.into());
        self
    }

    pub fn policy_decision_id(mut self, id: Uuid) -> Self {
        self.policy_decision_id = Some(id);
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Build the immutable AuditEvent.
    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: Uuid::now_v7(),
            timestamp: Utc::now(),
            actor_id: self.actor_id,
            actor_role: self.actor_role,
            action: self.action,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            request_id: self.request_id,
            correlation_id: self.correlation_id,
            policy_decision: self.policy_decision,
            policy_decision_id: self.policy_decision_id,
            environment: self.environment,
            details: self.details,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
        }
    }
}

/// Query parameters for audit log listing.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditQuery {
    pub actor_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Tool execution record — linked to audit events.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ToolExecution {
    pub id: Uuid,
    pub tool_id: String,
    pub tool_version: String,
    pub requested_by: Uuid,
    pub approved_by: Option<Uuid>,
    pub policy_decision_id: Option<Uuid>,
    pub scan_run_id: Option<Uuid>,
    pub input_params: serde_json::Value,
    pub output_summary: Option<serde_json::Value>,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub environment: String,
    pub audit_event_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
