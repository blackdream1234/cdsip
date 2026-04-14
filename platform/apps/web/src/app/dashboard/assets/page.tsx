"use client";

import { useEffect, useState } from "react";

interface AssetRow {
  id: string;
  ip_address: string;
  hostname: string | null;
  os_fingerprint: string | null;
  criticality: number;
  environment: string;
  status: string;
  last_seen: string;
  risk_score: number | null;
}

const demoAssets: AssetRow[] = [
  { id: "a1", ip_address: "10.0.1.10", hostname: "srv-web-01", os_fingerprint: "Linux 5.15", criticality: 4, environment: "production", status: "active", last_seen: "2 min ago", risk_score: 62 },
  { id: "a2", ip_address: "10.0.1.11", hostname: "srv-db-01", os_fingerprint: "Linux 5.15", criticality: 5, environment: "production", status: "active", last_seen: "5 min ago", risk_score: 73 },
  { id: "a3", ip_address: "10.0.1.20", hostname: "srv-api-01", os_fingerprint: "Linux 6.1", criticality: 4, environment: "production", status: "active", last_seen: "1 min ago", risk_score: 41 },
  { id: "a4", ip_address: "10.0.100.5", hostname: "lab-test-01", os_fingerprint: "Ubuntu 24.04", criticality: 2, environment: "lab", status: "active", last_seen: "10 min ago", risk_score: 28 },
  { id: "a5", ip_address: "10.0.100.6", hostname: "lab-scan-target", os_fingerprint: "Debian 12", criticality: 1, environment: "lab", status: "active", last_seen: "15 min ago", risk_score: 12 },
  { id: "a6", ip_address: "10.0.2.50", hostname: "staging-web", os_fingerprint: "Alpine 3.19", criticality: 3, environment: "staging", status: "active", last_seen: "30 min ago", risk_score: 35 },
  { id: "a7", ip_address: "10.0.1.99", hostname: "legacy-app", os_fingerprint: "CentOS 7", criticality: 3, environment: "production", status: "inactive", last_seen: "2 days ago", risk_score: 82 },
  { id: "a8", ip_address: "10.0.100.10", hostname: "dev-workstation", os_fingerprint: "Windows 11", criticality: 2, environment: "development", status: "active", last_seen: "1 hr ago", risk_score: 19 },
];

function riskColor(score: number | null): string {
  if (score === null) return "var(--text-muted)";
  if (score >= 80) return "var(--severity-critical)";
  if (score >= 60) return "var(--severity-high)";
  if (score >= 40) return "var(--severity-medium)";
  if (score >= 20) return "var(--severity-low)";
  return "var(--severity-info)";
}

function criticalityLabel(c: number): string {
  return ["", "Minimal", "Low", "Medium", "High", "Critical"][c] || "?";
}

function envBadge(env: string) {
  const colors: Record<string, string> = {
    production: "var(--severity-critical)",
    staging: "var(--accent-yellow)",
    lab: "var(--accent-green)",
    development: "var(--accent-blue)",
  };
  return (
    <span style={{
      padding: "0.125rem 0.5rem",
      borderRadius: "9999px",
      fontSize: "0.7rem",
      fontWeight: 500,
      background: `${colors[env] || "var(--text-muted)"}15`,
      color: colors[env] || "var(--text-muted)",
      border: `1px solid ${colors[env] || "var(--text-muted)"}30`,
    }}>
      {env}
    </span>
  );
}

export default function AssetsPage() {
  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState("all");
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!mounted) return null;

  const filtered = demoAssets.filter((a) => {
    const matchesSearch = !search || a.ip_address.includes(search) || a.hostname?.toLowerCase().includes(search.toLowerCase());
    const matchesEnv = envFilter === "all" || a.environment === envFilter;
    return matchesSearch && matchesEnv;
  });

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.25rem" }}>Asset Inventory</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
            {filtered.length} assets tracked · Criticality-sorted
          </p>
        </div>
        <button className="btn btn-primary">+ Register Asset</button>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem" }}>
        <input
          type="text"
          placeholder="Search by IP or hostname..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: "300px" }}
        />
        <select value={envFilter} onChange={(e) => setEnvFilter(e.target.value)}>
          <option value="all">All Environments</option>
          <option value="production">Production</option>
          <option value="staging">Staging</option>
          <option value="lab">Lab</option>
          <option value="development">Development</option>
        </select>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Hostname</th>
              <th>OS</th>
              <th>Criticality</th>
              <th>Environment</th>
              <th>Status</th>
              <th>Risk Score</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((asset) => (
              <tr key={asset.id} style={{ cursor: "pointer" }}>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.825rem", color: "var(--accent-cyan)" }}>
                  {asset.ip_address}
                </td>
                <td>{asset.hostname || "—"}</td>
                <td style={{ fontSize: "0.8rem" }}>{asset.os_fingerprint || "—"}</td>
                <td>
                  <span style={{
                    color: asset.criticality >= 4 ? "var(--severity-high)" : asset.criticality >= 3 ? "var(--severity-medium)" : "var(--text-secondary)",
                    fontWeight: asset.criticality >= 4 ? 600 : 400,
                  }}>
                    {criticalityLabel(asset.criticality)}
                  </span>
                </td>
                <td>{envBadge(asset.environment)}</td>
                <td>
                  <span style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "0.375rem",
                    fontSize: "0.8rem",
                  }}>
                    <span style={{
                      width: "6px",
                      height: "6px",
                      borderRadius: "50%",
                      background: asset.status === "active" ? "var(--accent-green)" : "var(--text-muted)",
                    }} />
                    {asset.status}
                  </span>
                </td>
                <td>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontWeight: 600,
                    color: riskColor(asset.risk_score),
                  }}>
                    {asset.risk_score ?? "—"}
                  </span>
                </td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{asset.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
            No assets match your filters.
          </div>
        )}
      </div>
    </div>
  );
}
