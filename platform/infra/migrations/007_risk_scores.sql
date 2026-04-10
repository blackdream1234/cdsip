-- =============================================================================
-- Migration 007: Risk Scores
-- CDSIP — Closed Defensive Security Intelligence Platform
-- =============================================================================

CREATE TABLE risk_scores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    score           DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 100),
    severity_band   VARCHAR(16) NOT NULL
                    CHECK (severity_band IN ('critical', 'high', 'medium', 'low', 'info')),
    factors         JSONB NOT NULL DEFAULT '{}',
    rationale       TEXT NOT NULL,
    calculated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    calculated_by   VARCHAR(64) NOT NULL DEFAULT 'risk_engine_v1',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_risk_scores_asset ON risk_scores(asset_id);
CREATE INDEX idx_risk_scores_severity ON risk_scores(severity_band);
CREATE INDEX idx_risk_scores_calculated ON risk_scores(calculated_at DESC);
CREATE INDEX idx_risk_scores_score ON risk_scores(score DESC);
