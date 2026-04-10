#!/usr/bin/env bash
# =============================================================================
# CDSIP Database Initialization Script
# Runs all migrations in order, idempotently.
# =============================================================================
set -euo pipefail

MIGRATIONS_DIR="/migrations"

echo "=== CDSIP Database Migrator ==="
echo "Waiting for PostgreSQL to be ready..."

until pg_isready -h "${PGHOST}" -U "${PGUSER}" -d "${PGDATABASE}" > /dev/null 2>&1; do
    echo "  PostgreSQL not ready, retrying in 2s..."
    sleep 2
done

echo "PostgreSQL is ready."

# Create migration tracking table if it doesn't exist
psql -h "${PGHOST}" -U "${PGUSER}" -d "${PGDATABASE}" <<'EOSQL'
CREATE TABLE IF NOT EXISTS _migrations (
    id          SERIAL PRIMARY KEY,
    filename    VARCHAR(255) NOT NULL UNIQUE,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum    VARCHAR(64) NOT NULL
);
EOSQL

echo "Migration tracking table ready."

# Run each migration file in order
MIGRATION_COUNT=0
for migration_file in $(ls "${MIGRATIONS_DIR}"/*.sql 2>/dev/null | sort); do
    filename=$(basename "${migration_file}")
    checksum=$(sha256sum "${migration_file}" | awk '{print $1}')

    # Check if already applied
    already_applied=$(psql -h "${PGHOST}" -U "${PGUSER}" -d "${PGDATABASE}" -tAc \
        "SELECT COUNT(*) FROM _migrations WHERE filename = '${filename}'")

    if [ "${already_applied}" -gt 0 ]; then
        echo "  SKIP: ${filename} (already applied)"
        continue
    fi

    echo "  APPLYING: ${filename}..."
    psql -h "${PGHOST}" -U "${PGUSER}" -d "${PGDATABASE}" -f "${migration_file}"

    # Record migration
    psql -h "${PGHOST}" -U "${PGUSER}" -d "${PGDATABASE}" -c \
        "INSERT INTO _migrations (filename, checksum) VALUES ('${filename}', '${checksum}')"

    echo "  DONE: ${filename}"
    MIGRATION_COUNT=$((MIGRATION_COUNT + 1))
done

echo "=== Migration complete. Applied ${MIGRATION_COUNT} new migration(s). ==="
