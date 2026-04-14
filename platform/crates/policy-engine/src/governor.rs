//! Policy Governor — the top-level policy enforcement interface.
//!
//! Every sensitive action in the platform MUST pass through the Governor.
//! It wraps the evaluator, handles approval workflows, and produces
//! audit-ready decision records.

use cdsip_domain_models::policy::{
    Approval, PolicyAction, PolicyDecision, PolicyRequest,
    Policy, PolicyRule, CreatePolicyRequest, CreatePolicyRuleRequest,
};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn, error};

use crate::evaluator::PolicyEvaluator;
use crate::types::PolicyError;

/// The Policy Governor is the single authority for all policy decisions.
/// It is the ONLY path through which sensitive actions can be authorized.
#[derive(Debug, Clone)]
pub struct PolicyGovernor {
    evaluator: PolicyEvaluator,
    pool: PgPool,
}

impl PolicyGovernor {
    pub fn new(pool: PgPool) -> Self {
        Self {
            evaluator: PolicyEvaluator::new(pool.clone()),
            pool,
        }
    }

    /// Evaluate a policy request and return a decision.
    /// This is the primary entry point for all policy checks.
    ///
    /// If the decision is RequireApproval, an approval record is created
    /// and the approval_id is returned in the decision.
    pub async fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        let mut decision = self.evaluator.evaluate(request).await?;

        // If approval is required, create an approval record
        if decision.action == PolicyAction::RequireApproval {
            let approval_id = self.create_approval(request, &decision).await?;
            decision.approval_id = Some(approval_id);

            info!(
                decision_id = %decision.decision_id,
                approval_id = %approval_id,
                "Approval required — queued for review"
            );
        }

        // Insert decision into DB natively to guarantee complete traceability
        sqlx::query(
            r#"
            INSERT INTO policy_decisions 
                (id, outcome, matched_rule_ids, rationale, actor_id, environment, request_id, timestamp)
            VALUES 
                ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(decision.decision_id)
        .bind(decision.action.to_string())
        .bind(&decision.matched_rule_ids)
        .bind(&decision.reason)
        .bind(decision.actor_id)
        .bind(&decision.environment)
        .bind(decision.request_id)
        .bind(decision.decided_at)
        .execute(&self.pool)
        .await?;

        Ok(decision)
    }

    /// Check if an action is allowed (convenience method).
    /// Returns true only if the decision is Allow.
    pub async fn is_allowed(&self, request: &PolicyRequest) -> Result<bool, PolicyError> {
        let decision = self.evaluate(request).await?;
        Ok(decision.action == PolicyAction::Allow)
    }

    /// Create an approval record for actions requiring review.
    async fn create_approval(
        &self,
        request: &PolicyRequest,
        decision: &PolicyDecision,
    ) -> Result<Uuid, PolicyError> {
        let approval_id = Uuid::now_v7();
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        sqlx::query(
            r#"
            INSERT INTO approvals (id, policy_rule_id, requested_by, status, request_data, expires_at)
            VALUES ($1, $2, $3, 'pending', $4, $5)
            "#,
        )
        .bind(approval_id)
        .bind(decision.matched_rule_ids.first().copied())
        .bind(request.actor_id)
        .bind(serde_json::to_value(request).map_err(|e| PolicyError::EvaluationError(e.to_string()))?)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(approval_id)
    }

    /// Process an approval decision (approve or deny a pending request).
    pub async fn decide_approval(
        &self,
        approval_id: Uuid,
        approver_id: Uuid,
        approved: bool,
        reason: Option<&str>,
    ) -> Result<Approval, PolicyError> {
        let status = if approved { "approved" } else { "denied" };

        let approval = sqlx::query_as::<_, Approval>(
            r#"
            UPDATE approvals
            SET approved_by = $1,
                status = $2,
                decision_reason = $3,
                decided_at = NOW()
            WHERE id = $4 AND status = 'pending'
            RETURNING id, policy_rule_id, requested_by, approved_by, status,
                      request_data, decision_reason, created_at, decided_at, expires_at
            "#,
        )
        .bind(approver_id)
        .bind(status)
        .bind(reason)
        .bind(approval_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| PolicyError::NotFound(format!("Pending approval {approval_id} not found")))?;

        info!(
            approval_id = %approval_id,
            status = status,
            approver_id = %approver_id,
            "Approval decision recorded"
        );

        Ok(approval)
    }

    /// List all policies.
    pub async fn list_policies(&self) -> Result<Vec<Policy>, PolicyError> {
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(policies)
    }

    /// Get a policy decision by ID.
    pub async fn get_policy_decision(&self, decision_id: Uuid) -> Result<Option<PolicyDecision>, PolicyError> {
        let decision = sqlx::query_as::<_, PolicyDecision>(
            r#"
            SELECT 
                id as decision_id, 
                outcome as action, 
                matched_rule_ids, 
                '{}'::uuid[] as matched_policy_ids, 
                rationale as reason, 
                actor_id, 
                environment, 
                request_id, 
                timestamp as decided_at, 
                NULL::uuid as approval_id 
            FROM policy_decisions 
            WHERE id = $1
            "#,
        )
        .bind(decision_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(decision)
    }

    /// Get a policy by ID.
    pub async fn get_policy(&self, id: Uuid) -> Result<Option<Policy>, PolicyError> {
        let policy = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(policy)
    }

    /// Create a new policy.
    pub async fn create_policy(
        &self,
        req: &CreatePolicyRequest,
        created_by: Uuid,
    ) -> Result<Policy, PolicyError> {
        let id = Uuid::now_v7();

        let policy = sqlx::query_as::<_, Policy>(
            r#"
            INSERT INTO policies (id, name, description, environment_scope, created_by)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.environment_scope)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;

        info!(policy_id = %id, name = %req.name, "Policy created");

        Ok(policy)
    }

    /// Add a rule to a policy.
    pub async fn add_rule(
        &self,
        policy_id: Uuid,
        req: &CreatePolicyRuleRequest,
    ) -> Result<PolicyRule, PolicyError> {
        let id = Uuid::now_v7();

        let rule = sqlx::query_as::<_, PolicyRule>(
            r#"
            INSERT INTO policy_rules (id, policy_id, rule_type, conditions, action, priority)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(policy_id)
        .bind(&req.rule_type)
        .bind(&req.conditions)
        .bind(req.action.to_string())
        .bind(req.priority)
        .fetch_one(&self.pool)
        .await?;

        info!(
            rule_id = %id,
            policy_id = %policy_id,
            rule_type = %req.rule_type,
            "Policy rule created"
        );

        Ok(rule)
    }

    /// Get rules for a specific policy.
    pub async fn get_rules(&self, policy_id: Uuid) -> Result<Vec<PolicyRule>, PolicyError> {
        let rules = sqlx::query_as::<_, PolicyRule>(
            "SELECT * FROM policy_rules WHERE policy_id = $1 ORDER BY priority DESC",
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rules)
    }

    /// List pending approvals.
    pub async fn list_pending_approvals(&self) -> Result<Vec<Approval>, PolicyError> {
        let approvals = sqlx::query_as::<_, Approval>(
            r#"
            SELECT * FROM approvals
            WHERE status = 'pending' AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(approvals)
    }

    /// Expire stale approvals.
    pub async fn expire_stale_approvals(&self) -> Result<u64, PolicyError> {
        let result = sqlx::query(
            r#"
            UPDATE approvals
            SET status = 'expired', decided_at = NOW()
            WHERE status = 'pending' AND expires_at <= NOW()
            "#,
        )
        .execute(&self.pool)
        .await?;

        let count = result.rows_affected();
        if count > 0 {
            warn!(count = count, "Expired stale approvals");
        }

        Ok(count)
    }
}
