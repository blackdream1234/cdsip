/**
 * CDSIP API Client
 * All API interactions go through this module.
 * No direct fetch calls from components.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

interface ApiOptions {
  method?: string;
  body?: unknown;
  token?: string;
}

class ApiError extends Error {
  status: number;
  type: string;

  constructor(status: number, type: string, message: string) {
    super(message);
    this.status = status;
    this.type = type;
  }
}

async function request<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const { method = 'GET', body, token } = options;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new ApiError(
      res.status,
      errorData?.error?.type || 'unknown',
      errorData?.error?.message || `Request failed: ${res.status}`
    );
  }

  return res.json();
}

// Auth
export const auth = {
  login: (username: string, password: string) =>
    request<{ access_token: string; token_type: string; expires_in: number }>(
      '/auth/login',
      { method: 'POST', body: { username, password } }
    ),
  logout: (token: string) =>
    request('/auth/logout', { method: 'POST', token }),
  me: (token: string) =>
    request<{ id: string; username: string; email: string; role: string }>(
      '/auth/me',
      { token }
    ),
};

// Assets
export const assets = {
  list: (token: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<{ items: Asset[]; total: number }>(`/assets${qs}`, { token });
  },
  get: (token: string, id: string) =>
    request<Asset>(`/assets/${id}`, { token }),
  create: (token: string, data: Partial<Asset>) =>
    request<Asset>('/assets', { method: 'POST', body: data, token }),
};

// Scans
export const scans = {
  listTargets: (token: string) =>
    request<ScanTarget[]>('/scan-targets', { token }),
  listJobs: (token: string) =>
    request<ScanJob[]>('/scan-jobs', { token }),
  listRuns: (token: string) =>
    request<ScanRun[]>('/scan-runs', { token }),
  triggerRun: (token: string, jobId: string) =>
    request<ScanRun>(`/scan-jobs/${jobId}/run`, { method: 'POST', token }),
  getRunFindings: (token: string, runId: string) =>
    request<ScanFinding[]>(`/scan-runs/${runId}/findings`, { token }),
};

// Incidents
export const incidents = {
  list: (token: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<Incident[]>(`/incidents${qs}`, { token });
  },
  get: (token: string, id: string) =>
    request<Incident>(`/incidents/${id}`, { token }),
  create: (token: string, data: Partial<Incident>) =>
    request<Incident>('/incidents', { method: 'POST', body: data, token }),
};

// Policies
export const policies = {
  list: (token: string) =>
    request<Policy[]>('/policies', { token }),
  get: (token: string, id: string) =>
    request<{ policy: Policy; rules: PolicyRule[] }>(`/policies/${id}`, { token }),
  listApprovals: (token: string) =>
    request<Approval[]>('/approvals', { token }),
};

// Audit
export const audit = {
  list: (token: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<{ items: AuditEvent[]; total: number }>(`/audit${qs}`, { token });
  },
};

// Risk
export const risk = {
  calculate: (token: string, assetId: string) =>
    request<RiskScore>(`/risk/calculate/${assetId}`, { method: 'POST', token }),
  listScores: (token: string) =>
    request<RiskScore[]>('/risk/scores', { token }),
};

// Types
export interface Asset {
  id: string;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  os_fingerprint: string | null;
  owner: string | null;
  criticality: number;
  environment: string;
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface ScanTarget {
  id: string;
  network_id: string | null;
  target_spec: string;
  description: string | null;
  is_active: boolean;
}

export interface ScanJob {
  id: string;
  name: string;
  scan_target_id: string;
  profile: string;
  schedule_cron: string | null;
  is_active: boolean;
  created_by: string;
  environment: string;
}

export interface ScanRun {
  id: string;
  scan_job_id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  error_message: string | null;
}

export interface ScanFinding {
  id: string;
  scan_run_id: string;
  ip_address: string;
  port: number | null;
  protocol: string | null;
  service_name: string | null;
  service_version: string | null;
  state: string;
  severity: string;
}

export interface Incident {
  id: string;
  title: string;
  status: string;
  severity: string;
  summary: string | null;
  created_by: string;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string | null;
  environment_scope: string;
  is_active: boolean;
  version: number;
}

export interface PolicyRule {
  id: string;
  policy_id: string;
  rule_type: string;
  conditions: Record<string, unknown>;
  action: string;
  priority: number;
}

export interface Approval {
  id: string;
  requested_by: string;
  status: string;
  request_data: Record<string, unknown>;
  created_at: string;
  expires_at: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor_id: string | null;
  actor_role: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  request_id: string;
  policy_decision: string | null;
  environment: string;
  details: Record<string, unknown>;
}

export interface RiskScore {
  id: string;
  asset_id: string;
  score: number;
  severity_band: string;
  rationale: string;
  calculated_at: string;
}
