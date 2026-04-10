-- =============================================================================
-- Migration 003: Scans — Targets, Jobs, Runs, Findings, Services, Ports
-- CDSIP — Closed Defensive Security Intelligence Platform
-- =============================================================================

CREATE TABLE scan_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      UUID REFERENCES networks(id) ON DELETE SET NULL,
    target_spec     VARCHAR(255) NOT NULL,
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_targets_network_id ON scan_targets(network_id);
CREATE INDEX idx_scan_targets_active ON scan_targets(is_active);

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128) NOT NULL,
    scan_target_id  UUID NOT NULL REFERENCES scan_targets(id) ON DELETE RESTRICT,
    profile         VARCHAR(64) NOT NULL
                    CHECK (profile IN ('host_discovery', 'safe_tcp_scan', 'service_detection')),
    schedule_cron   VARCHAR(128),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID NOT NULL REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    environment     VARCHAR(32) NOT NULL DEFAULT 'development'
                    CHECK (environment IN ('production', 'staging', 'lab', 'development')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_jobs_target ON scan_jobs(scan_target_id);
CREATE INDEX idx_scan_jobs_created_by ON scan_jobs(created_by);
CREATE INDEX idx_scan_jobs_active ON scan_jobs(is_active);

CREATE TRIGGER trg_scan_jobs_updated_at
    BEFORE UPDATE ON scan_jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE scan_runs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id         UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE RESTRICT,
    status              VARCHAR(32) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    findings_count      INTEGER NOT NULL DEFAULT 0,
    raw_artifact_path   TEXT,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_runs_job ON scan_runs(scan_job_id);
CREATE INDEX idx_scan_runs_status ON scan_runs(status);
CREATE INDEX idx_scan_runs_created_at ON scan_runs(created_at DESC);

CREATE TABLE scan_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id     UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    asset_id        UUID REFERENCES assets(id) ON DELETE SET NULL,
    ip_address      VARCHAR(45) NOT NULL,
    port            INTEGER,
    protocol        VARCHAR(16),
    service_name    VARCHAR(128),
    service_version VARCHAR(256),
    state           VARCHAR(32) NOT NULL DEFAULT 'unknown'
                    CHECK (state IN ('open', 'closed', 'filtered', 'unknown')),
    severity        VARCHAR(16) NOT NULL DEFAULT 'info'
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    raw_data        JSONB,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_findings_run ON scan_findings(scan_run_id);
CREATE INDEX idx_scan_findings_asset ON scan_findings(asset_id);
CREATE INDEX idx_scan_findings_ip ON scan_findings(ip_address);
CREATE INDEX idx_scan_findings_severity ON scan_findings(severity);
CREATE INDEX idx_scan_findings_port ON scan_findings(port);

CREATE TABLE services (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    protocol        VARCHAR(16) NOT NULL DEFAULT 'tcp',
    service_name    VARCHAR(128) NOT NULL,
    service_version VARCHAR(256),
    state           VARCHAR(32) NOT NULL DEFAULT 'open',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port, protocol)
);

CREATE INDEX idx_services_asset ON services(asset_id);

CREATE TRIGGER trg_services_updated_at
    BEFORE UPDATE ON services
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE ports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port_number     INTEGER NOT NULL,
    protocol        VARCHAR(16) NOT NULL DEFAULT 'tcp',
    state           VARCHAR(32) NOT NULL DEFAULT 'open',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, port_number, protocol)
);

CREATE INDEX idx_ports_asset ON ports(asset_id);

CREATE TRIGGER trg_ports_updated_at
    BEFORE UPDATE ON ports
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
