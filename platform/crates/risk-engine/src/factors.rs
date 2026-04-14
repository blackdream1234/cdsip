//! Risk factor definitions and weights.
//!
//! Each factor has a name, weight, and scoring function.
//! The total score is a weighted sum, clamped to 0-100.

use cdsip_domain_models::risk::RiskFactor;
use cdsip_domain_models::risk::RiskInput;

/// Known risky services that increase risk score when exposed.
const RISKY_SERVICES: &[&str] = &[
    "telnet", "ftp", "rlogin", "rsh", "rexec",
    "mysql", "mssql", "postgres", "mongodb", "redis",
    "smb", "rdp", "vnc", "snmp",
];

/// Calculate risk factors from input data.
/// Each factor produces a 0.0-1.0 value and a human-readable description.
pub fn calculate_factors(input: &RiskInput) -> Vec<RiskFactor> {
    let mut factors = Vec::new();

    // Factor 1: Asset criticality (weight: 0.25)
    let criticality_value = (input.asset_criticality as f64 - 1.0) / 4.0; // normalize 1-5 to 0-1
    factors.push(RiskFactor {
        name: "asset_criticality".to_string(),
        weight: 0.25,
        value: criticality_value,
        contribution: criticality_value * 0.25,
        description: format!(
            "Asset criticality level {} of 5",
            input.asset_criticality
        ),
    });

    // Factor 2: Open ports (weight: 0.15)
    let port_value = (input.open_port_count as f64 / 50.0).min(1.0);
    factors.push(RiskFactor {
        name: "open_ports".to_string(),
        weight: 0.15,
        value: port_value,
        contribution: port_value * 0.15,
        description: format!(
            "{} open ports detected (normalized: {:.2})",
            input.open_port_count, port_value
        ),
    });

    // Factor 3: Risky services (weight: 0.20)
    let risky_value = (input.risky_service_count as f64 / 5.0).min(1.0);
    factors.push(RiskFactor {
        name: "risky_services".to_string(),
        weight: 0.20,
        value: risky_value,
        contribution: risky_value * 0.20,
        description: format!(
            "{} risky services exposed (telnet, ftp, database, rdp, etc.)",
            input.risky_service_count
        ),
    });

    // Factor 4: New ports since last scan (weight: 0.10)
    let new_ports_value = (input.new_ports_since_last_scan as f64 / 10.0).min(1.0);
    factors.push(RiskFactor {
        name: "new_ports".to_string(),
        weight: 0.10,
        value: new_ports_value,
        contribution: new_ports_value * 0.10,
        description: format!(
            "{} newly opened ports since last scan",
            input.new_ports_since_last_scan
        ),
    });

    // Factor 5: Service changes (weight: 0.10)
    let changes_value = (input.service_changes_since_last_scan as f64 / 5.0).min(1.0);
    factors.push(RiskFactor {
        name: "service_changes".to_string(),
        weight: 0.10,
        value: changes_value,
        contribution: changes_value * 0.10,
        description: format!(
            "{} service changes since last scan",
            input.service_changes_since_last_scan
        ),
    });

    // Factor 6: Failed policy requests (weight: 0.05)
    let policy_value = (input.failed_policy_requests as f64 / 10.0).min(1.0);
    factors.push(RiskFactor {
        name: "policy_violations".to_string(),
        weight: 0.05,
        value: policy_value,
        contribution: policy_value * 0.05,
        description: format!(
            "{} failed/denied policy requests related to this asset",
            input.failed_policy_requests
        ),
    });

    // Factor 7: High severity findings (weight: 0.10)
    let findings_value = (input.high_severity_findings as f64 / 10.0).min(1.0);
    factors.push(RiskFactor {
        name: "high_severity_findings".to_string(),
        weight: 0.10,
        value: findings_value,
        contribution: findings_value * 0.10,
        description: format!(
            "{} high/critical severity findings",
            input.high_severity_findings
        ),
    });

    // Factor 8: Scan staleness (weight: 0.05)
    let staleness_value = (input.days_since_last_scan as f64 / 30.0).min(1.0);
    factors.push(RiskFactor {
        name: "scan_staleness".to_string(),
        weight: 0.05,
        value: staleness_value,
        contribution: staleness_value * 0.05,
        description: format!(
            "{} days since last scan (stale > 30 days)",
            input.days_since_last_scan
        ),
    });

    factors
}

/// Check if a service name is considered risky.
pub fn is_risky_service(service_name: &str) -> bool {
    let lower = service_name.to_lowercase();
    RISKY_SERVICES.iter().any(|&s| lower.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_input(criticality: i32, ports: i32, risky: i32) -> RiskInput {
        RiskInput {
            asset_id: Uuid::now_v7(),
            asset_criticality: criticality,
            open_port_count: ports,
            risky_service_count: risky,
            new_ports_since_last_scan: 0,
            service_changes_since_last_scan: 0,
            failed_policy_requests: 0,
            high_severity_findings: 0,
            days_since_last_scan: 0,
        }
    }

    #[test]
    fn test_low_risk_asset() {
        let input = make_input(1, 2, 0);
        let factors = calculate_factors(&input);
        let total: f64 = factors.iter().map(|f| f.contribution).sum();
        assert!(total * 100.0 < 20.0, "Low-risk asset should score below 20");
    }

    #[test]
    fn test_high_risk_asset() {
        let input = RiskInput {
            asset_id: Uuid::now_v7(),
            asset_criticality: 5,
            open_port_count: 40,
            risky_service_count: 4,
            new_ports_since_last_scan: 8,
            service_changes_since_last_scan: 3,
            failed_policy_requests: 5,
            high_severity_findings: 7,
            days_since_last_scan: 25,
        };
        let factors = calculate_factors(&input);
        let total: f64 = factors.iter().map(|f| f.contribution).sum();
        assert!(total * 100.0 > 60.0, "High-risk asset should score above 60");
    }

    #[test]
    fn test_weights_sum_to_one() {
        let input = make_input(3, 10, 1);
        let factors = calculate_factors(&input);
        let total_weight: f64 = factors.iter().map(|f| f.weight).sum();
        assert!((total_weight - 1.0).abs() < f64::EPSILON, "Weights must sum to 1.0");
    }

    #[test]
    fn test_risky_services() {
        assert!(is_risky_service("telnet"));
        assert!(is_risky_service("MySQL"));
        assert!(is_risky_service("redis"));
        assert!(!is_risky_service("nginx"));
        assert!(!is_risky_service("http"));
    }

    #[test]
    fn test_maximum_risk_bounds() {
        let input = RiskInput {
            asset_id: Uuid::now_v7(),
            asset_criticality: 5,
            open_port_count: 500, // beyond max clamps at 1.0 (50)
            risky_service_count: 50, // beyond max clamps at 1.0 (5)
            new_ports_since_last_scan: 100, // beyond max clamps at 1.0 (10)
            service_changes_since_last_scan: 50, // beyond max clamps at 1.0 (5)
            failed_policy_requests: 100, // beyond max clamps at 1.0 (10)
            high_severity_findings: 100, // beyond max clamps at 1.0 (10)
            days_since_last_scan: 300, // beyond max clamps at 1.0 (30)
        };
        let factors = calculate_factors(&input);
        let total: f64 = factors.iter().map(|f| f.contribution).sum();
        
        // Due to floats, it might be 0.999999
        assert!((total - 1.0).abs() < f64::EPSILON, "Maximum risk must clamp perfectly to 1.0 (100)");

        for f in factors {
            assert!(f.value <= 1.0, "Factor {} exceeded 1.0", f.name);
        }
    }
}
