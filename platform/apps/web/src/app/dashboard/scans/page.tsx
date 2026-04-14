"use client";

import { useEffect, useState } from "react";

interface ScanRunRow {
  id: string;
  job_name: string;
  profile: string;
  target: string;
  environment: string;
  status: string;
  started_at: string;
  duration: string;
  findings: number;
  triggered_by: string;
}

const demoRuns: ScanRunRow[] = [
  { id: "r1", job_name: "Lab Discovery", profile: "host_discovery", target: "10.0.100.0/24", environment: "lab", status: "completed", started_at: "2 min ago", duration: "12s", findings: 8, triggered_by: "analyst_jones" },
  { id: "r2", job_name: "DMZ Service Scan", profile: "service_detection", target: "10.0.2.0/24", environment: "staging", status: "completed", started_at: "15 min ago", duration: "45s", findings: 23, triggered_by: "analyst_chen" },
  { id: "r3", job_name: "Prod TCP Scan", profile: "safe_tcp_scan", target: "10.0.1.0/24", environment: "production", status: "running", started_at: "1 min ago", duration: "—", findings: 0, triggered_by: "admin" },
  { id: "r4", job_name: "Lab Full Scan", profile: "service_detection", target: "10.0.100.5", environment: "lab", status: "completed", started_at: "1 hr ago", duration: "1m 12s", findings: 14, triggered_by: "analyst_jones" },
  { id: "r5", job_name: "Staging Check", profile: "safe_tcp_scan", target: "10.0.2.50", environment: "staging", status: "failed", started_at: "2 hr ago", duration: "5m 00s", findings: 0, triggered_by: "analyst_chen" },
  { id: "r6", job_name: "Lab Discovery", profile: "host_discovery", target: "10.0.100.0/24", environment: "lab", status: "completed", started_at: "3 hr ago", duration: "9s", findings: 6, triggered_by: "system" },
];

function statusBadge(status: string) {
  const map: Record<string, { bg: string; color: string }> = {
    completed: { bg: "rgba(16, 185, 129, 0.15)", color: "var(--accent-green)" },
    running: { bg: "rgba(59, 130, 246, 0.15)", color: "var(--accent-blue)" },
    failed: { bg: "rgba(239, 68, 68, 0.15)", color: "var(--severity-critical)" },
    queued: { bg: "rgba(148, 163, 184, 0.15)", color: "var(--text-muted)" },
  };
  const s = map[status] || map.queued;
  return (
    <span style={{
      padding: "0.125rem 0.5rem",
      borderRadius: "9999px",
      fontSize: "0.75rem",
      fontWeight: 500,
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.color}30`,
      display: "inline-flex",
      alignItems: "center",
      gap: "0.375rem",
    }}>
      {status === "running" && <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: s.color }} className="pulse-dot" />}
      {status}
    </span>
  );
}

function profileLabel(p: string) {
  const map: Record<string, string> = {
    host_discovery: "Host Discovery",
    safe_tcp_scan: "Safe TCP",
    service_detection: "Service Detection",
  };
  return map[p] || p;
}

export default function ScansPage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.25rem" }}>Scans</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
            Policy-gated scan execution · {demoRuns.filter(r => r.status === "running").length} running
          </p>
        </div>
        <button className="btn btn-primary">+ New Scan Job</button>
      </div>

      {/* Profile cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
        {[
          { name: "Host Discovery", desc: "Ping sweep — identify live hosts", flags: "-sn -PE -PP", color: "var(--accent-blue)" },
          { name: "Safe TCP Scan", desc: "Connect scan — top 1000 ports", flags: "-sT --top-ports 1000", color: "var(--accent-cyan)" },
          { name: "Service Detection", desc: "Version detection — moderate intensity", flags: "-sV --version-intensity 5", color: "var(--accent-purple)" },
        ].map((p) => (
          <div key={p.name} className="card" style={{ borderLeft: `3px solid ${p.color}` }}>
            <div style={{ fontSize: "0.9rem", fontWeight: 600, marginBottom: "0.25rem" }}>{p.name}</div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>{p.desc}</div>
            <code style={{ fontSize: "0.7rem", color: p.color, fontFamily: "'JetBrains Mono', monospace" }}>{p.flags}</code>
          </div>
        ))}
      </div>

      {/* Scan runs */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "1rem 1.25rem", borderBottom: "1px solid var(--border-primary)" }}>
          <h2 style={{ fontSize: "0.9rem", fontWeight: 600 }}>Scan Runs</h2>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Job</th>
              <th>Profile</th>
              <th>Target</th>
              <th>Env</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Findings</th>
              <th>Triggered By</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {demoRuns.map((run) => (
              <tr key={run.id} style={{ cursor: "pointer" }}>
                <td style={{ fontWeight: 500 }}>{run.job_name}</td>
                <td style={{ fontSize: "0.8rem" }}>{profileLabel(run.profile)}</td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem", color: "var(--accent-cyan)" }}>{run.target}</td>
                <td style={{ fontSize: "0.8rem" }}>{run.environment}</td>
                <td>{statusBadge(run.status)}</td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem" }}>{run.duration}</td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: run.findings > 0 ? 600 : 400, color: run.findings > 0 ? "var(--accent-yellow)" : "var(--text-muted)" }}>
                  {run.findings}
                </td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{run.triggered_by}</td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{run.started_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
