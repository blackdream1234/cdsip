//! Audit event storage — PostgreSQL adapter.
//!
//! All operations are INSERT-only. No UPDATE or DELETE methods exist.

use cdsip_domain_models::audit::{AuditEvent, AuditQuery};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::AuditError;

/// PostgreSQL storage backend for audit events.
#[derive(Debug, Clone)]
pub struct AuditStorage {
    pool: PgPool,
}

impl AuditStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a single audit event. This is append-only.
    pub async fn insert(&self, event: &AuditEvent) -> Result<(), AuditError> {
        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, timestamp, actor_id, actor_role, action,
                resource_type, resource_id, request_id, correlation_id,
                policy_decision, policy_decision_id, environment, details, ip_address, user_agent
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            "#,
        )
        .bind(event.id)
        .bind(event.timestamp)
        .bind(event.actor_id)
        .bind(&event.actor_role)
        .bind(&event.action)
        .bind(&event.resource_type)
        .bind(event.resource_id)
        .bind(event.request_id)
        .bind(event.correlation_id)
        .bind(&event.policy_decision)
        .bind(event.policy_decision_id)
        .bind(&event.environment)
        .bind(&event.details)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Query audit events with filters. Read-only.
    pub async fn query(&self, params: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError> {
        let limit = params.limit.unwrap_or(50).min(200);
        let offset = params.offset.unwrap_or(0);

        let events = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, timestamp, actor_id, actor_role, action,
                   resource_type, resource_id, request_id, correlation_id,
                   policy_decision, policy_decision_id, environment, details, ip_address, user_agent
            FROM audit_events
            WHERE ($1::uuid IS NULL OR actor_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::text IS NULL OR resource_type = $3)
              AND ($4::uuid IS NULL OR resource_id = $4)
              AND ($5::timestamptz IS NULL OR timestamp >= $5)
              AND ($6::timestamptz IS NULL OR timestamp <= $6)
            ORDER BY timestamp DESC
            LIMIT $7 OFFSET $8
            "#,
        )
        .bind(params.actor_id)
        .bind(&params.action)
        .bind(&params.resource_type)
        .bind(params.resource_id)
        .bind(params.from)
        .bind(params.to)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Count audit events matching query (for pagination).
    pub async fn count(&self, params: &AuditQuery) -> Result<i64, AuditError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM audit_events
            WHERE ($1::uuid IS NULL OR actor_id = $1)
              AND ($2::text IS NULL OR action = $2)
              AND ($3::text IS NULL OR resource_type = $3)
              AND ($4::uuid IS NULL OR resource_id = $4)
              AND ($5::timestamptz IS NULL OR timestamp >= $5)
              AND ($6::timestamptz IS NULL OR timestamp <= $6)
            "#,
        )
        .bind(params.actor_id)
        .bind(&params.action)
        .bind(&params.resource_type)
        .bind(params.resource_id)
        .bind(params.from)
        .bind(params.to)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }

    /// Get a single audit event by ID. Read-only.
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<AuditEvent>, AuditError> {
        let event = sqlx::query_as::<_, AuditEvent>(
            r#"
            SELECT id, timestamp, actor_id, actor_role, action,
                   resource_type, resource_id, request_id, correlation_id,
                   policy_decision, policy_decision_id, environment, details, ip_address, user_agent
            FROM audit_events
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(event)
    }
}
