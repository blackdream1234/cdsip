-- =============================================================================
-- Migration 002: Assets, Networks, and Tags
-- CDSIP — Closed Defensive Security Intelligence Platform
-- =============================================================================

CREATE TABLE networks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128) NOT NULL,
    cidr            VARCHAR(43) NOT NULL,
    environment     VARCHAR(32) NOT NULL DEFAULT 'development'
                    CHECK (environment IN ('production', 'staging', 'lab', 'development')),
    description     TEXT,
    is_scan_allowed BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_networks_environment ON networks(environment);
CREATE INDEX idx_networks_cidr ON networks(cidr);

CREATE TRIGGER trg_networks_updated_at
    BEFORE UPDATE ON networks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address      VARCHAR(45) NOT NULL,
    hostname        VARCHAR(255),
    mac_address     VARCHAR(17),
    os_fingerprint  TEXT,
    owner           VARCHAR(128),
    criticality     INTEGER NOT NULL DEFAULT 1
                    CHECK (criticality BETWEEN 1 AND 5),
    environment     VARCHAR(32) NOT NULL DEFAULT 'development'
                    CHECK (environment IN ('production', 'staging', 'lab', 'development')),
    status          VARCHAR(32) NOT NULL DEFAULT 'unknown'
                    CHECK (status IN ('active', 'inactive', 'decommissioned', 'unknown')),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_assets_ip_address ON assets(ip_address);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_environment ON assets(environment);
CREATE INDEX idx_assets_criticality ON assets(criticality);
CREATE INDEX idx_assets_status ON assets(status);

CREATE TRIGGER trg_assets_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE asset_tags (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    key             VARCHAR(64) NOT NULL,
    value           VARCHAR(256) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, key)
);

CREATE INDEX idx_asset_tags_asset_id ON asset_tags(asset_id);
CREATE INDEX idx_asset_tags_key ON asset_tags(key);
