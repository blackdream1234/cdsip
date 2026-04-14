"use client";

import { useEffect, useState } from "react";

interface IncidentRow {
  id: string;
  code: string;
  title: string;
  severity: string;
  status: string;
  assigned_to: string | null;
  evidence_count: number;
  created_at: string;
  updated_at: string;
}

const demoIncidents: IncidentRow[] = [
  { id: "i1", code: "INC-007", title: "Unauthorized SSH access attempt on srv-db-01", severity: "high", status: "investigating", assigned_to: "analyst_jones", evidence_count: 3, created_at: "8 min ago", updated_at: "2 min ago" },
  { id: "i2", code: "INC-006", title: "Unexpected port 8443 opened on production web server", severity: "medium", status: "investigating", assigned_to: "analyst_chen", evidence_count: 2, created_at: "1 hr ago", updated_at: "15 min ago" },
  { id: "i3", code: "INC-005", title: "Telnet service detected on legacy-app (CentOS 7)", severity: "critical", status: "open", assigned_to: null, evidence_count: 1, created_at: "3 hr ago", updated_at: "3 hr ago" },
  { id: "i4", code: "INC-004", title: "MySQL exposed without authentication on lab host", severity: "high", status: "resolved", assigned_to: "analyst_jones", evidence_count: 4, created_at: "1 day ago", updated_at: "6 hr ago" },
  { id: "i5", code: "INC-003", title: "New hosts appeared in production subnet without registration", severity: "medium", status: "resolved", assigned_to: "analyst_chen", evidence_count: 2, created_at: "2 days ago", updated_at: "1 day ago" },
  { id: "i6", code: "INC-002", title: "Failed login attempts exceeding threshold on API server", severity: "low", status: "closed", assigned_to: "analyst_jones", evidence_count: 1, created_at: "3 days ago", updated_at: "2 days ago" },
  { id: "i7", code: "INC-001", title: "Routine: Outdated OpenSSH version on staging server", severity: "low", status: "closed", assigned_to: "analyst_chen", evidence_count: 1, created_at: "1 week ago", updated_at: "4 days ago" },
];

function severityBadge(severity: string) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

function statusStyle(status: string) {
  const colors: Record<string, string> = {
    open: "var(--severity-critical)",
    investigating: "var(--accent-yellow)",
    resolved: "var(--accent-green)",
    closed: "var(--text-muted)",
  };
  return { color: colors[status] || "var(--text-muted)", fontWeight: 500 as const, fontSize: "0.825rem" };
}

export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState("all");
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;

  const filtered = demoIncidents.filter((i) => statusFilter === "all" || i.status === statusFilter);
  const openCount = demoIncidents.filter((i) => i.status === "open" || i.status === "investigating").length;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.25rem" }}>Incidents</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
            {openCount} active · Evidence-linked · Audit-logged
          </p>
        </div>
        <button className="btn btn-primary">+ Create Incident</button>
      </div>

      {/* Status filter tabs */}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
        {["all", "open", "investigating", "resolved", "closed"].map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className="btn"
            style={{
              background: statusFilter === s ? "rgba(59, 130, 246, 0.15)" : "transparent",
              color: statusFilter === s ? "var(--accent-blue)" : "var(--text-muted)",
              border: `1px solid ${statusFilter === s ? "rgba(59, 130, 246, 0.3)" : "var(--border-primary)"}`,
              fontSize: "0.8rem",
              textTransform: "capitalize",
            }}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Title</th>
              <th>Status</th>
              <th>Assigned</th>
              <th>Evidence</th>
              <th>Created</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((inc) => (
              <tr key={inc.id} style={{ cursor: "pointer" }}>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.825rem", fontWeight: 600, color: "var(--accent-cyan)" }}>
                  {inc.code}
                </td>
                <td>{severityBadge(inc.severity)}</td>
                <td style={{ maxWidth: "350px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {inc.title}
                </td>
                <td><span style={statusStyle(inc.status)}>{inc.status}</span></td>
                <td style={{ fontSize: "0.8rem", color: inc.assigned_to ? "var(--text-secondary)" : "var(--severity-critical)" }}>
                  {inc.assigned_to || "Unassigned"}
                </td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace" }}>{inc.evidence_count}</td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{inc.created_at}</td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{inc.updated_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
