-- Create Policy Decisions trace table
CREATE TABLE IF NOT EXISTS policy_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    outcome VARCHAR(32) NOT NULL,
    matched_rule_ids UUID[] DEFAULT '{}',
    rationale TEXT NOT NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    environment VARCHAR(32) NOT NULL,
    request_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policy_decision_req ON policy_decisions(request_id);
CREATE INDEX idx_policy_decision_actor ON policy_decisions(actor_id);
CREATE INDEX idx_policy_decision_time ON policy_decisions("timestamp" DESC);

-- Link audit events to policy decisions explicitly
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS policy_decision_id UUID REFERENCES policy_decisions(id) ON DELETE SET NULL;
