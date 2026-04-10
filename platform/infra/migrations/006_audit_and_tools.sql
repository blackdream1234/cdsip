-- =============================================================================
-- Migration 006: Audit Events and Tool Executions
-- CDSIP — Closed Defensive Security Intelligence Platform
-- =============================================================================
-- CRITICAL: audit_events is APPEND-ONLY.
-- No UPDATE or DELETE operations should ever target this table.
-- Application-level enforcement is primary; this migration adds a safety trigger.
-- =============================================================================

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_role      VARCHAR(32),
    action          VARCHAR(128) NOT NULL,
    resource_type   VARCHAR(64) NOT NULL,
    resource_id     UUID,
    request_id      UUID NOT NULL,
    correlation_id  UUID,
    policy_decision VARCHAR(32),
    environment     VARCHAR(32) NOT NULL DEFAULT 'development',
    details         JSONB NOT NULL DEFAULT '{}',
    ip_address      VARCHAR(45),
    user_agent      TEXT
);

-- Performance indexes for common query patterns
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_actor ON audit_events(actor_id);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id);
CREATE INDEX idx_audit_request ON audit_events(request_id);
CREATE INDEX idx_audit_correlation ON audit_events(correlation_id);

-- Safety trigger: prevent UPDATE and DELETE on audit_events
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events table is append-only. UPDATE and DELETE operations are forbidden.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_mutation();

CREATE TRIGGER trg_audit_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_mutation();

-- Tool executions — tracks every tool invocation with full provenance
CREATE TABLE tool_executions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_id             VARCHAR(64) NOT NULL,
    tool_version        VARCHAR(32) NOT NULL,
    requested_by        UUID NOT NULL REFERENCES users(id),
    approved_by         UUID REFERENCES users(id),
    policy_decision_id  UUID,
    scan_run_id         UUID REFERENCES scan_runs(id) ON DELETE SET NULL,
    input_params        JSONB NOT NULL DEFAULT '{}',
    output_summary      JSONB,
    status              VARCHAR(32) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    environment         VARCHAR(32) NOT NULL DEFAULT 'development',
    audit_event_id      UUID,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tool_exec_tool ON tool_executions(tool_id);
CREATE INDEX idx_tool_exec_requested_by ON tool_executions(requested_by);
CREATE INDEX idx_tool_exec_scan_run ON tool_executions(scan_run_id);
CREATE INDEX idx_tool_exec_status ON tool_executions(status);
CREATE INDEX idx_tool_exec_created ON tool_executions(created_at DESC);
