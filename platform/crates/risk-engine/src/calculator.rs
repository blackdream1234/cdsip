//! Risk calculator — computes asset risk scores from factor inputs.

use cdsip_domain_models::risk::{RiskInput, RiskScore, SeverityBand, RiskFactor};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;

use crate::factors::calculate_factors;
use crate::types::RiskError;

/// The RiskCalculator computes transparent, explainable risk scores.
#[derive(Debug, Clone)]
pub struct RiskCalculator {
    pool: PgPool,
}

impl RiskCalculator {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Calculate risk score for an asset based on provided input data.
    /// Returns a fully explainable RiskScore with factor breakdown.
    pub async fn calculate(&self, input: &RiskInput) -> Result<RiskScore, RiskError> {
        let factors = calculate_factors(input);

        // Sum weighted contributions
        let raw_score: f64 = factors.iter().map(|f| f.contribution).sum();

        // Scale to 0-100 and clamp
        let score = (raw_score * 100.0).clamp(0.0, 100.0);
        let severity_band = SeverityBand::from_score(score);

        // Build rationale from factors
        let rationale = self.build_rationale(&factors, score, &severity_band);

        let risk_score = RiskScore {
            id: Uuid::now_v7(),
            asset_id: input.asset_id,
            score,
            severity_band: severity_band.to_string(),
            factors: serde_json::to_value(&factors)
                .unwrap_or_else(|_| serde_json::json!([])),
            rationale,
            calculated_at: Utc::now(),
            calculated_by: "risk_engine_v1".to_string(),
            created_at: Utc::now(),
        };

        // Store the score
        self.store(&risk_score).await?;

        info!(
            asset_id = %input.asset_id,
            score = score,
            severity = %severity_band,
            "Risk score calculated"
        );

        Ok(risk_score)
    }

    /// Build a human-readable rationale from factors.
    fn build_rationale(&self, factors: &[RiskFactor], score: f64, severity: &SeverityBand) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Risk score: {:.1}/100 ({})",
            score, severity
        ));
        lines.push(String::new());

        // Sort factors by contribution (highest first)
        let mut sorted_factors = factors.to_vec();
        sorted_factors.sort_by(|a, b| b.contribution.partial_cmp(&a.contribution).unwrap());

        lines.push("Contributing factors (highest impact first):".to_string());
        for factor in &sorted_factors {
            if factor.contribution > 0.0 {
                lines.push(format!(
                    "  - {}: {:.1}% contribution — {}",
                    factor.name,
                    factor.contribution * 100.0,
                    factor.description
                ));
            }
        }

        lines.join("\n")
    }

    /// Store a risk score in the database.
    async fn store(&self, score: &RiskScore) -> Result<(), RiskError> {
        sqlx::query(
            r#"
            INSERT INTO risk_scores (id, asset_id, score, severity_band, factors, rationale, calculated_at, calculated_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(score.id)
        .bind(score.asset_id)
        .bind(score.score)
        .bind(&score.severity_band)
        .bind(&score.factors)
        .bind(&score.rationale)
        .bind(score.calculated_at)
        .bind(&score.calculated_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get the latest risk score for an asset.
    pub async fn get_latest(&self, asset_id: Uuid) -> Result<Option<RiskScore>, RiskError> {
        let score = sqlx::query_as::<_, RiskScore>(
            r#"
            SELECT * FROM risk_scores
            WHERE asset_id = $1
            ORDER BY calculated_at DESC
            LIMIT 1
            "#,
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(score)
    }

    /// Get risk score history for an asset.
    pub async fn get_history(
        &self,
        asset_id: Uuid,
        limit: i64,
    ) -> Result<Vec<RiskScore>, RiskError> {
        let scores = sqlx::query_as::<_, RiskScore>(
            r#"
            SELECT * FROM risk_scores
            WHERE asset_id = $1
            ORDER BY calculated_at DESC
            LIMIT $2
            "#,
        )
        .bind(asset_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(scores)
    }

    /// Get all latest risk scores (one per asset), sorted by score descending.
    pub async fn get_all_latest(&self, limit: i64, offset: i64) -> Result<Vec<RiskScore>, RiskError> {
        let scores = sqlx::query_as::<_, RiskScore>(
            r#"
            SELECT DISTINCT ON (asset_id) *
            FROM risk_scores
            ORDER BY asset_id, calculated_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(scores)
    }

    /// Gather risk input data from the database for an asset.
    /// This queries multiple tables to build the RiskInput.
    pub async fn gather_input(&self, asset_id: Uuid) -> Result<RiskInput, RiskError> {
        // Get asset criticality
        let criticality: (i32,) = sqlx::query_as(
            "SELECT criticality FROM assets WHERE id = $1",
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RiskError::AssetNotFound(asset_id))?;

        // Count open ports
        let open_ports: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ports WHERE asset_id = $1 AND state = 'open'",
        )
        .bind(asset_id)
        .fetch_one(&self.pool)
        .await?;

        // Count risky services
        let risky_services: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM services
            WHERE asset_id = $1 AND state = 'open'
              AND LOWER(service_name) IN ('telnet', 'ftp', 'rlogin', 'rsh', 'rexec',
                  'mysql', 'mssql', 'postgres', 'mongodb', 'redis', 'smb', 'rdp', 'vnc', 'snmp')
            "#,
        )
        .bind(asset_id)
        .fetch_one(&self.pool)
        .await?;

        // Count high severity findings
        let high_findings: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM scan_findings
            WHERE asset_id = $1 AND severity IN ('high', 'critical')
            "#,
        )
        .bind(asset_id)
        .fetch_one(&self.pool)
        .await?;

        // Days since last scan
        let last_scan: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
            r#"
            SELECT MAX(sf.created_at) FROM scan_findings sf
            WHERE sf.asset_id = $1
            "#,
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?;

        let days_since_last = last_scan
            .and_then(|r| Some((Utc::now() - r.0).num_days() as i32))
            .unwrap_or(365); // No scan ever = very stale

        Ok(RiskInput {
            asset_id,
            asset_criticality: criticality.0,
            open_port_count: open_ports.0 as i32,
            risky_service_count: risky_services.0 as i32,
            new_ports_since_last_scan: 0, // TODO: compute from scan diff
            service_changes_since_last_scan: 0, // TODO: compute from scan diff
            failed_policy_requests: 0, // TODO: query audit events
            high_severity_findings: high_findings.0 as i32,
            days_since_last_scan: days_since_last,
        })
    }
}
