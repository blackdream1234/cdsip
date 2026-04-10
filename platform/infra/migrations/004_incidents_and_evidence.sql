-- =============================================================================
-- Migration 004: Incidents and Evidence
-- CDSIP — Closed Defensive Security Intelligence Platform
-- =============================================================================

CREATE TABLE evidence_objects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_type   VARCHAR(32) NOT NULL
                    CHECK (evidence_type IN (
                        'scan_finding', 'policy_violation', 'network_observation',
                        'manual_note', 'tool_output'
                    )),
    source          VARCHAR(128) NOT NULL,
    source_id       UUID,
    data            JSONB NOT NULL DEFAULT '{}',
    hash            VARCHAR(128) NOT NULL,
    sensitivity     VARCHAR(32) NOT NULL DEFAULT 'internal'
                    CHECK (sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_evidence_type ON evidence_objects(evidence_type);
CREATE INDEX idx_evidence_source ON evidence_objects(source);
CREATE INDEX idx_evidence_source_id ON evidence_objects(source_id);
CREATE INDEX idx_evidence_sensitivity ON evidence_objects(sensitivity);
CREATE INDEX idx_evidence_created_at ON evidence_objects(created_at DESC);

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(256) NOT NULL,
    status          VARCHAR(32) NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium'
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    summary         TEXT,
    created_by      UUID NOT NULL REFERENCES users(id),
    assigned_to     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_created_by ON incidents(created_by);
CREATE INDEX idx_incidents_assigned_to ON incidents(assigned_to);
CREATE INDEX idx_incidents_created_at ON incidents(created_at DESC);

CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE incident_evidence (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id         UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    evidence_id         UUID NOT NULL REFERENCES evidence_objects(id) ON DELETE RESTRICT,
    relationship_type   VARCHAR(64) NOT NULL DEFAULT 'related',
    added_by            UUID NOT NULL REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(incident_id, evidence_id)
);

CREATE INDEX idx_incident_evidence_incident ON incident_evidence(incident_id);
CREATE INDEX idx_incident_evidence_evidence ON incident_evidence(evidence_id);
