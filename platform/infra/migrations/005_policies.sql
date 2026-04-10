-- =============================================================================
-- Migration 005: Policies, Rules, and Approvals
-- CDSIP — Closed Defensive Security Intelligence Platform
-- =============================================================================

CREATE TABLE policies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(128) NOT NULL,
    description         TEXT,
    environment_scope   VARCHAR(32) NOT NULL DEFAULT 'all'
                        CHECK (environment_scope IN ('production', 'staging', 'lab', 'development', 'all')),
    is_active           BOOLEAN NOT NULL DEFAULT true,
    version             INTEGER NOT NULL DEFAULT 1,
    created_by          UUID NOT NULL REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_active ON policies(is_active);
CREATE INDEX idx_policies_environment ON policies(environment_scope);

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE policy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    rule_type       VARCHAR(64) NOT NULL,
    conditions      JSONB NOT NULL DEFAULT '{}',
    action          VARCHAR(32) NOT NULL DEFAULT 'deny'
                    CHECK (action IN ('allow', 'deny', 'require_approval', 'escalate')),
    priority        INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_rules_policy ON policy_rules(policy_id);
CREATE INDEX idx_policy_rules_type ON policy_rules(rule_type);
CREATE INDEX idx_policy_rules_priority ON policy_rules(priority DESC);

CREATE TABLE approvals (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_rule_id      UUID REFERENCES policy_rules(id) ON DELETE SET NULL,
    requested_by        UUID NOT NULL REFERENCES users(id),
    approved_by         UUID REFERENCES users(id),
    status              VARCHAR(32) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    request_data        JSONB NOT NULL DEFAULT '{}',
    decision_reason     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at          TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours')
);

CREATE INDEX idx_approvals_status ON approvals(status);
CREATE INDEX idx_approvals_requested_by ON approvals(requested_by);
CREATE INDEX idx_approvals_expires ON approvals(expires_at);
