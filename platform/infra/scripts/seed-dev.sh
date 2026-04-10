#!/usr/bin/env bash
# =============================================================================
# CDSIP Development Seed Script
# Creates initial admin user and sample data for local development.
# =============================================================================
set -euo pipefail

PGHOST="${PGHOST:-localhost}"
PGUSER="${PGUSER:-cdsip}"
PGDATABASE="${PGDATABASE:-cdsip}"

ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@cdsip.local}"
# Password hash for "admin_dev_password" using argon2id
# In production this is set via environment variable and hashed by the application
ADMIN_HASH='$argon2id$v=19$m=19456,t=2,p=1$placeholder_dev_only$placeholder_hash_dev'

echo "=== CDSIP Development Seed ==="

# Insert admin user (idempotent)
psql -h "${PGHOST}" -U "${PGUSER}" -d "${PGDATABASE}" <<EOSQL
INSERT INTO users (id, username, email, password_hash, role, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '${ADMIN_USERNAME}',
    '${ADMIN_EMAIL}',
    '${ADMIN_HASH}',
    'admin',
    true
)
ON CONFLICT (username) DO NOTHING;

-- Sample analyst user
INSERT INTO users (id, username, email, password_hash, role, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    'analyst',
    'analyst@cdsip.local',
    '${ADMIN_HASH}',
    'security_analyst',
    true
)
ON CONFLICT (username) DO NOTHING;

-- Sample auditor user
INSERT INTO users (id, username, email, password_hash, role, is_active)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    'auditor',
    'auditor@cdsip.local',
    '${ADMIN_HASH}',
    'auditor',
    true
)
ON CONFLICT (username) DO NOTHING;

-- Sample network (lab only)
INSERT INTO networks (id, name, cidr, environment, description, is_scan_allowed)
VALUES (
    '10000000-0000-0000-0000-000000000001',
    'Lab Network',
    '192.168.100.0/24',
    'lab',
    'Internal lab network for testing and scanning',
    true
)
ON CONFLICT DO NOTHING;

-- Sample scan target
INSERT INTO scan_targets (id, network_id, target_spec, description, is_active)
VALUES (
    '20000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001',
    '192.168.100.0/24',
    'Full lab network scan target',
    true
)
ON CONFLICT DO NOTHING;

-- Default deny-all policy
INSERT INTO policies (id, name, description, environment_scope, is_active, version, created_by)
VALUES (
    '30000000-0000-0000-0000-000000000001',
    'Default Deny All',
    'Base policy: deny all actions unless explicitly allowed by a higher-priority rule.',
    'all',
    true,
    1,
    '00000000-0000-0000-0000-000000000001'
)
ON CONFLICT DO NOTHING;

-- Deny-all rule (lowest priority)
INSERT INTO policy_rules (id, policy_id, rule_type, conditions, action, priority)
VALUES (
    '40000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000001',
    'catch_all',
    '{"match": "all"}',
    'deny',
    -1000
)
ON CONFLICT DO NOTHING;

-- Allow lab scans for admins and analysts
INSERT INTO policies (id, name, description, environment_scope, is_active, version, created_by)
VALUES (
    '30000000-0000-0000-0000-000000000002',
    'Allow Lab Scans',
    'Allow scan execution on lab networks for admin and security_analyst roles.',
    'lab',
    true,
    1,
    '00000000-0000-0000-0000-000000000001'
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_rules (id, policy_id, rule_type, conditions, action, priority)
VALUES (
    '40000000-0000-0000-0000-000000000002',
    '30000000-0000-0000-0000-000000000002',
    'scan_execution',
    '{"roles": ["admin", "security_analyst"], "environment": "lab", "action": "scan.execute"}',
    'allow',
    100
)
ON CONFLICT DO NOTHING;

-- Production scans require admin approval
INSERT INTO policies (id, name, description, environment_scope, is_active, version, created_by)
VALUES (
    '30000000-0000-0000-0000-000000000003',
    'Production Scan Approval Required',
    'Scans targeting production environment require admin approval.',
    'production',
    true,
    1,
    '00000000-0000-0000-0000-000000000001'
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_rules (id, policy_id, rule_type, conditions, action, priority)
VALUES (
    '40000000-0000-0000-0000-000000000003',
    '30000000-0000-0000-0000-000000000003',
    'scan_execution',
    '{"roles": ["admin", "security_analyst"], "environment": "production", "action": "scan.execute"}',
    'require_approval',
    200
)
ON CONFLICT DO NOTHING;
EOSQL

echo "=== Seed complete. ==="
echo "  Admin: ${ADMIN_USERNAME} / ${ADMIN_EMAIL}"
echo "  Analyst: analyst / analyst@cdsip.local"
echo "  Auditor: auditor / auditor@cdsip.local"
echo "  NOTE: Passwords will be set by the API on first startup or via the seed-password tool."
