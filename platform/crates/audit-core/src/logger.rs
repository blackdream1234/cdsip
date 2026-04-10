//! Audit logger — the primary interface for producing audit events.

use cdsip_domain_models::audit::{AuditEvent, AuditEventBuilder, AuditQuery};
use tracing::{info, error};
use uuid::Uuid;

use crate::storage::AuditStorage;
use crate::types::AuditError;

/// AuditLogger provides a high-level interface for recording and querying
/// immutable audit events. All sensitive platform operations MUST go
/// through this logger.
#[derive(Debug, Clone)]
pub struct AuditLogger {
    storage: AuditStorage,
    environment: String,
}

impl AuditLogger {
    pub fn new(storage: AuditStorage, environment: String) -> Self {
        Self {
            storage,
            environment,
        }
    }

    /// Log an audit event. This is the primary entry point.
    /// Events are stored immutably — once logged, they cannot be modified.
    pub async fn log(&self, event: AuditEvent) -> Result<(), AuditError> {
        info!(
            audit_event_id = %event.id,
            action = %event.action,
            resource_type = %event.resource_type,
            actor_id = ?event.actor_id,
            "Audit event recorded"
        );

        if let Err(e) = self.storage.insert(&event).await {
            // Audit failures are critical — log aggressively but don't crash
            error!(
                audit_event_id = %event.id,
                error = %e,
                "CRITICAL: Failed to store audit event"
            );
            return Err(e);
        }

        Ok(())
    }

    /// Create a builder with the current environment pre-set.
    pub fn builder(
        &self,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        request_id: Uuid,
    ) -> AuditEventBuilder {
        AuditEventBuilder::new(action, resource_type, request_id, &self.environment)
    }

    /// Log a login event.
    pub async fn log_login(
        &self,
        user_id: Uuid,
        role: &str,
        request_id: Uuid,
        ip_address: Option<&str>,
        success: bool,
    ) -> Result<(), AuditError> {
        let event = self
            .builder("auth.login", "session", request_id)
            .actor(user_id, role)
            .details(serde_json::json!({ "success": success }))
            .ip_address(ip_address.unwrap_or("unknown"))
            .build();

        self.log(event).await
    }

    /// Log a logout event.
    pub async fn log_logout(
        &self,
        user_id: Uuid,
        role: &str,
        request_id: Uuid,
    ) -> Result<(), AuditError> {
        let event = self
            .builder("auth.logout", "session", request_id)
            .actor(user_id, role)
            .build();

        self.log(event).await
    }

    /// Log a policy decision.
    pub async fn log_policy_decision(
        &self,
        actor_id: Uuid,
        actor_role: &str,
        action: &str,
        resource_type: &str,
        resource_id: Option<Uuid>,
        decision: &str,
        reason: &str,
        request_id: Uuid,
    ) -> Result<(), AuditError> {
        let mut builder = self
            .builder(format!("policy.{action}"), resource_type, request_id)
            .actor(actor_id, actor_role)
            .policy_decision(decision)
            .details(serde_json::json!({ "reason": reason }));

        if let Some(rid) = resource_id {
            builder = builder.resource_id(rid);
        }

        self.log(builder.build()).await
    }

    /// Query audit events.
    pub async fn query(&self, params: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError> {
        self.storage.query(params).await
    }

    /// Count audit events.
    pub async fn count(&self, params: &AuditQuery) -> Result<i64, AuditError> {
        self.storage.count(params).await
    }

    /// Get single audit event by ID.
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<AuditEvent>, AuditError> {
        self.storage.get_by_id(id).await
    }
}
