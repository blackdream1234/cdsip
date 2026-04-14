//! Policy rule matching and condition evaluation.

use cdsip_domain_models::policy::{PolicyAction, PolicyRequest, PolicyRule};
use serde_json::Value;
use tracing::debug;

/// Evaluates whether a single policy rule matches a given request.
pub struct RuleEvaluator;

impl RuleEvaluator {
    /// Check if a rule's conditions match the request.
    /// Returns true if all conditions in the rule are satisfied.
    pub fn matches(rule: &PolicyRule, request: &PolicyRequest) -> bool {
        let conditions = &rule.conditions;

        // Match-all rule (catch-all)
        if conditions.get("match") == Some(&Value::String("all".to_string())) {
            debug!(rule_id = %rule.id, "Catch-all rule matched");
            return true;
        }

        let mut all_match = true;

        // Check role condition
        if let Some(Value::Array(allowed_roles)) = conditions.get("roles") {
            let role_matches = allowed_roles.iter().any(|r| {
                r.as_str()
                    .is_some_and(|role_str| role_str == request.actor_role)
            });
            if !role_matches {
                debug!(
                    rule_id = %rule.id,
                    actor_role = %request.actor_role,
                    "Role condition not met"
                );
                all_match = false;
            }
        }

        // Check environment condition
        if let Some(Value::String(env)) = conditions.get("environment") {
            if env != &request.environment {
                debug!(
                    rule_id = %rule.id,
                    request_env = %request.environment,
                    rule_env = %env,
                    "Environment condition not met"
                );
                all_match = false;
            }
        }

        // Check action condition
        if let Some(Value::String(action)) = conditions.get("action") {
            if action != &request.action {
                debug!(
                    rule_id = %rule.id,
                    request_action = %request.action,
                    rule_action = %action,
                    "Action condition not met"
                );
                all_match = false;
            }
        }

        // Check resource_type condition
        if let Some(Value::String(resource_type)) = conditions.get("resource_type") {
            if resource_type != &request.resource_type {
                all_match = false;
            }
        }

        // Check target allowlist
        if let Some(Value::Array(allowed_targets)) = conditions.get("allowed_targets") {
            if let Some(ref target) = request.target {
                let target_allowed = allowed_targets.iter().any(|t| {
                    t.as_str().is_some_and(|allowed| {
                        Self::target_matches(target, allowed)
                    })
                });
                if !target_allowed {
                    debug!(
                        rule_id = %rule.id,
                        target = %target,
                        "Target not in allowlist"
                    );
                    all_match = false;
                }
            }
        }

        all_match
    }

    /// Check if a target specification matches an allowed target pattern.
    /// Supports exact match and CIDR-prefix matching.
    fn target_matches(target: &str, allowed: &str) -> bool {
        // Exact match
        if target == allowed {
            return true;
        }

        // CIDR prefix match: if allowed is a CIDR, check if target starts with the network part
        if allowed.contains('/') {
            if let Some(network) = allowed.split('/').next() {
                // Simple prefix check — in production use proper CIDR math
                if let Some(prefix) = network.rfind('.') {
                    let network_prefix = &network[..prefix];
                    if target.starts_with(network_prefix) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Parse a PolicyAction from its database string representation.
    pub fn parse_action(action_str: &str) -> PolicyAction {
        match action_str {
            "allow" => PolicyAction::Allow,
            "deny" => PolicyAction::Deny,
            "require_approval" => PolicyAction::RequireApproval,
            "escalate" => PolicyAction::Escalate,
            _ => PolicyAction::Deny, // Unknown actions default to deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use chrono::Utc;

    fn make_rule(conditions: Value, action: &str, priority: i32) -> PolicyRule {
        PolicyRule {
            id: Uuid::now_v7(),
            policy_id: Uuid::now_v7(),
            rule_type: "test".to_string(),
            conditions,
            action: action.to_string(),
            priority,
            created_at: Utc::now(),
        }
    }

    fn make_request(action: &str, role: &str, env: &str) -> PolicyRequest {
        PolicyRequest {
            actor_id: Uuid::now_v7(),
            actor_role: role.to_string(),
            action: action.to_string(),
            resource_type: "scan".to_string(),
            resource_id: None,
            target: Some("192.168.100.10".to_string()),
            environment: env.to_string(),
            context: serde_json::json!({}),
        }
    }

    #[test]
    fn test_catch_all_matches_everything() {
        let rule = make_rule(serde_json::json!({"match": "all"}), "deny", -1000);
        let request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &request));
    }

    #[test]
    fn test_role_match() {
        let rule = make_rule(
            serde_json::json!({"roles": ["admin", "security_analyst"], "action": "scan.execute"}),
            "allow",
            100,
        );
        let request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &request));

        let request_readonly = make_request("scan.execute", "read_only", "lab");
        assert!(!RuleEvaluator::matches(&rule, &request_readonly));
    }

    #[test]
    fn test_environment_match() {
        let rule = make_rule(
            serde_json::json!({"environment": "lab", "action": "scan.execute"}),
            "allow",
            100,
        );
        let lab_request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &lab_request));

        let prod_request = make_request("scan.execute", "admin", "production");
        assert!(!RuleEvaluator::matches(&rule, &prod_request));
    }

    #[test]
    fn test_action_mismatch() {
        let rule = make_rule(
            serde_json::json!({"action": "scan.execute", "roles": ["admin"]}),
            "allow",
            100,
        );
        let request = make_request("asset.delete", "admin", "lab");
        assert!(!RuleEvaluator::matches(&rule, &request));
    }

    #[test]
    fn test_unknown_action_defaults_to_deny() {
        assert_eq!(RuleEvaluator::parse_action("unknown"), PolicyAction::Deny);
        assert_eq!(RuleEvaluator::parse_action("allow"), PolicyAction::Allow);
        assert_eq!(
            RuleEvaluator::parse_action("require_approval"),
            PolicyAction::RequireApproval,
        );
    }

    #[test]
    fn test_target_allowlist_exact_match() {
        let rule = make_rule(
            serde_json::json!({
                "roles": ["admin"],
                "action": "scan.execute",
                "allowed_targets": ["192.168.100.10", "10.0.1.5"]
            }),
            "allow",
            100,
        );
        let request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &request));
    }

    #[test]
    fn test_target_not_in_allowlist() {
        let rule = make_rule(
            serde_json::json!({
                "roles": ["admin"],
                "action": "scan.execute",
                "allowed_targets": ["10.0.1.5", "10.0.1.6"]
            }),
            "allow",
            100,
        );
        let request = make_request("scan.execute", "admin", "lab");
        assert!(!RuleEvaluator::matches(&rule, &request));
    }

    #[test]
    fn test_cidr_prefix_match() {
        let rule = make_rule(
            serde_json::json!({
                "action": "scan.execute",
                "allowed_targets": ["192.168.100.0/24"]
            }),
            "allow",
            100,
        );
        let request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &request));
    }

    #[test]
    fn test_resource_type_match() {
        let rule = make_rule(
            serde_json::json!({
                "resource_type": "scan",
                "action": "scan.execute"
            }),
            "allow",
            100,
        );
        let request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &request));

        let rule_incident = make_rule(
            serde_json::json!({
                "resource_type": "incident",
                "action": "scan.execute"
            }),
            "allow",
            100,
        );
        assert!(!RuleEvaluator::matches(&rule_incident, &request));
    }

    #[test]
    fn test_multiple_conditions_all_must_match() {
        let rule = make_rule(
            serde_json::json!({
                "roles": ["admin"],
                "environment": "lab",
                "action": "scan.execute",
                "resource_type": "scan",
                "allowed_targets": ["192.168.100.0/24"]
            }),
            "allow",
            100,
        );

        // All match
        let request = make_request("scan.execute", "admin", "lab");
        assert!(RuleEvaluator::matches(&rule, &request));

        // Wrong role
        let bad_role = make_request("scan.execute", "read_only", "lab");
        assert!(!RuleEvaluator::matches(&rule, &bad_role));

        // Wrong env
        let bad_env = make_request("scan.execute", "admin", "production");
        assert!(!RuleEvaluator::matches(&rule, &bad_env));

        // Wrong action
        let bad_action = make_request("asset.create", "admin", "lab");
        assert!(!RuleEvaluator::matches(&rule, &bad_action));
    }

    #[test]
    fn test_parse_all_actions() {
        assert_eq!(RuleEvaluator::parse_action("allow"), PolicyAction::Allow);
        assert_eq!(RuleEvaluator::parse_action("deny"), PolicyAction::Deny);
        assert_eq!(RuleEvaluator::parse_action("require_approval"), PolicyAction::RequireApproval);
        assert_eq!(RuleEvaluator::parse_action("escalate"), PolicyAction::Escalate);
        assert_eq!(RuleEvaluator::parse_action(""), PolicyAction::Deny);
        assert_eq!(RuleEvaluator::parse_action("DROP TABLE"), PolicyAction::Deny);
    }
}
