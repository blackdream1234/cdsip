ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS execution_id UUID;
CREATE INDEX IF NOT EXISTS idx_scan_runs_execution_id ON scan_runs(execution_id);
