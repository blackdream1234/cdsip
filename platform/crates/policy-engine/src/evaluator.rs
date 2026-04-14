 //! Policy evaluator — loads rules from DB and evaluates requests.

use cdsip_domain_models::policy::{PolicyRule, PolicyRequest, PolicyDecision, PolicyAction};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn};

use crate::rules::RuleEvaluator;
use crate::types::PolicyError;

/// Loads active policy rules from the database and evaluates requests
/// against them in priority order.
#[derive(Debug, Clone)]
pub struct PolicyEvaluator {
    pool: PgPool,
}

impl PolicyEvaluator {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Load all active policy rules, optionally filtered by environment scope.
    /// Rules are returned sorted by priority DESC (highest priority first).
    pub async fn load_rules(&self, environment: &str) -> Result<Vec<PolicyRule>, PolicyError> {
        let rules = sqlx::query_as::<_, PolicyRule>(
            r#"
            SELECT pr.id, pr.policy_id, pr.rule_type, pr.conditions, pr.action, pr.priority, pr.created_at
            FROM policy_rules pr
            JOIN policies p ON pr.policy_id = p.id
            WHERE p.is_active = true
              AND (p.environment_scope = $1 OR p.environment_scope = 'all')
            ORDER BY pr.priority DESC
            "#,
        )
        .bind(environment)
        .fetch_all(&self.pool)
        .await?;

        Ok(rules)
    }

    /// Evaluate a policy request against all active rules.
    /// Returns the decision from the highest-priority matching rule.
    /// If no rule matches, returns DENY (secure default).
    pub async fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision, PolicyError> {
        let rules = self.load_rules(&request.environment).await?;

        info!(
            actor_id = %request.actor_id,
            action = %request.action,
            resource_type = %request.resource_type,
            environment = %request.environment,
            rules_count = rules.len(),
            "Evaluating policy request"
        );

        for rule in &rules {
            if RuleEvaluator::matches(rule, request) {
                let action = RuleEvaluator::parse_action(&rule.action);

                let decision = PolicyDecision {
                    decision_id: Uuid::now_v7(),
                    action,
                    matched_policy_ids: vec![rule.policy_id],
                    matched_rule_ids: vec![rule.id],
                    reason: format!(
                        "Matched rule '{}' (type: {}, priority: {})",
                        rule.id, rule.rule_type, rule.priority
                    ),
                    actor_id: Some(request.actor_id),
                    environment: request.environment.clone(),
                    request_id: request.request_id,
                    decided_at: Utc::now(),
                    approval_id: None,
                };

                info!(
                    decision_id = %decision.decision_id,
                    action = %decision.action,
                    rule_id = %rule.id,
                    "Policy decision made"
                );

                return Ok(decision);
            }
        }

        // No rule matched — default DENY
        warn!(
            actor_id = %request.actor_id,
            action = %request.action,
            "No policy rule matched — defaulting to DENY"
        );

        Ok(PolicyDecision {
            decision_id: Uuid::now_v7(),
            action: PolicyAction::Deny,
            matched_policy_ids: vec![],
            matched_rule_ids: vec![],
            reason: "No matching policy rule found. Default action is DENY.".to_string(),
            actor_id: Some(request.actor_id),
            environment: request.environment.clone(),
            request_id: request.request_id,
            decided_at: Utc::now(),
            approval_id: None,
        })
    }
}
