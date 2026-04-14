//! Tool Broker — the single controlled gateway for all tool execution.
//!
//! All tool execution requests flow through this broker:
//! 1. Validate tool exists
//! 2. Validate input parameters
//! 3. Check policy authorization
//! 4. Execute tool
//! 5. Record execution
//! 6. Return normalized results

use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn, error};
use serde_json::Value;

use cdsip_domain_models::audit::ToolExecution;
use cdsip_domain_models::policy::{PolicyAction, PolicyRequest};
use cdsip_policy_engine::PolicyGovernor;

use crate::executor::ToolOutput;
use crate::registry::{ToolDefinition, ToolRegistry};
use crate::nmap::NmapExecutor;
use crate::nmap::runner::NmapConfig;
use crate::types::ToolError;

/// The Tool Broker is the ONLY entry point for executing external tools.
pub struct ToolBroker {
    registry: Arc<RwLock<ToolRegistry>>,
    policy_governor: PolicyGovernor,
    pool: PgPool,
}

impl ToolBroker {
    /// Create a new ToolBroker and register default tools.
    pub fn new(pool: PgPool, policy_governor: PolicyGovernor, nmap_config: NmapConfig) -> Self {
        let mut registry = ToolRegistry::new();

        // Register Nmap tool
        let nmap_def = ToolDefinition {
            tool_id: "nmap".to_string(),
            name: "Nmap Scanner".to_string(),
            version: "1.0.0".to_string(),
            description: "Controlled network port and service scanner".to_string(),
            allowed_environments: vec![
                "lab".to_string(),
                "development".to_string(),
                "staging".to_string(),
                "production".to_string(),
            ],
            allowed_roles: vec!["admin".to_string(), "security_analyst".to_string()],
            timeout_secs: nmap_config.timeout_secs,
            max_concurrent: 2,
        };

        let nmap_executor = Arc::new(NmapExecutor::new(nmap_config));
        registry.register(nmap_def, nmap_executor);

        Self {
            registry: Arc::new(RwLock::new(registry)),
            policy_governor,
            pool,
        }
    }

    /// Execute a tool through the broker pipeline.
    ///
    /// This enforces the full security pipeline:
    /// input validation → policy check → execution → audit
    pub async fn execute(
        &self,
        tool_id: &str,
        params: Value,
        actor_id: Uuid,
        actor_role: &str,
        environment: &str,
        request_id: Uuid,
        execution_id: Uuid,
    ) -> Result<ToolOutput, ToolError> {
        let registry = self.registry.read().await;

        // 1. Check tool exists
        let definition = registry
            .get_definition(tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;

        // 2. Check environment is allowed for this tool
        if !definition.allowed_environments.contains(&environment.to_string()) {
            return Err(ToolError::UnauthorizedTarget(format!(
                "Tool '{tool_id}' not allowed in environment '{environment}'"
            )));
        }

        // 3. Check role is allowed for this tool
        if !definition.allowed_roles.contains(&actor_role.to_string()) {
            return Err(ToolError::PolicyDenied(format!(
                "Role '{actor_role}' not allowed to use tool '{tool_id}'"
            )));
        }

        // 4. Get executor and validate input
        let executor = registry
            .get_executor(tool_id)
            .ok_or_else(|| ToolError::NotFound(format!("Executor not found for '{tool_id}'")))?;

        executor.validate_input(&params)?;

        // 5. Policy check via Governor
        let target = params.get("target").and_then(|v| v.as_str()).map(String::from);

        let policy_request = PolicyRequest {
            actor_id,
            actor_role: actor_role.to_string(),
            action: format!("tool.execute.{tool_id}"),
            resource_type: "tool_execution".to_string(),
            resource_id: None,
            target,
            environment: environment.to_string(),
            request_id,
            context: serde_json::json!({
                "tool_id": tool_id,
                "params": params,
            }),
        };

        let policy_decision = self.policy_governor.evaluate(&policy_request).await?;

        match policy_decision.action {
            PolicyAction::Deny => {
                warn!(
                    tool_id = tool_id,
                    actor_id = %actor_id,
                    reason = %policy_decision.reason,
                    "Tool execution denied by policy"
                );
                return Err(ToolError::PolicyDenied(policy_decision.reason));
            }
            PolicyAction::RequireApproval => {
                info!(
                    tool_id = tool_id,
                    approval_id = ?policy_decision.approval_id,
                    "Tool execution queued for approval"
                );
                return Err(ToolError::PolicyDenied(format!(
                    "Approval required. Approval ID: {:?}",
                    policy_decision.approval_id
                )));
            }
            PolicyAction::Escalate => {
                return Err(ToolError::PolicyDenied(
                    "Action escalated — requires higher authority".to_string(),
                ));
            }
            PolicyAction::Allow => {
                info!(
                    tool_id = tool_id,
                    decision_id = %policy_decision.decision_id,
                    "Policy approved tool execution"
                );
            }
        }

        // 6. Record execution start
        self.record_execution_start(
            execution_id,
            tool_id,
            &definition.version,
            actor_id,
            &params,
            environment,
            policy_decision.decision_id,
        )
        .await?;

        // 7. Execute the tool
        let result = executor.execute(&params).await;

        // 8. Record execution result
        match &result {
            Ok(output) => {
                self.record_execution_complete(
                    execution_id,
                    "completed",
                    Some(&serde_json::json!({"summary": output.summary})),
                )
                .await?;
            }
            Err(e) => {
                self.record_execution_complete(
                    execution_id,
                    "failed",
                    Some(&serde_json::json!({"error": e.to_string()})),
                )
                .await?;
            }
        }

        result
    }

    /// Record tool execution start in database.
    async fn record_execution_start(
        &self,
        id: Uuid,
        tool_id: &str,
        tool_version: &str,
        requested_by: Uuid,
        input_params: &Value,
        environment: &str,
        policy_decision_id: Uuid,
    ) -> Result<(), ToolError> {
        sqlx::query(
            r#"
            INSERT INTO tool_executions (id, tool_id, tool_version, requested_by, input_params, status, started_at, environment, policy_decision_id)
            VALUES ($1, $2, $3, $4, $5, 'running', NOW(), $6, $7)
            "#,
        )
        .bind(id)
        .bind(tool_id)
        .bind(tool_version)
        .bind(requested_by)
        .bind(input_params)
        .bind(environment)
        .bind(policy_decision_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Record tool execution completion in database.
    async fn record_execution_complete(
        &self,
        id: Uuid,
        status: &str,
        output_summary: Option<&Value>,
    ) -> Result<(), ToolError> {
        sqlx::query(
            r#"
            UPDATE tool_executions
            SET status = $1, output_summary = $2, completed_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(status)
        .bind(output_summary)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
