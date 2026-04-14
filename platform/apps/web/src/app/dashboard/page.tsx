"use client";

import { useEffect, useState } from "react";

interface StatCard {
  label: string;
  value: string;
  change: string;
  changeType: "up" | "down" | "neutral";
  color: string;
}

interface RecentEvent {
  id: string;
  time: string;
  action: string;
  actor: string;
  detail: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
}

// Demo data — will be replaced with API calls when backend is running
const stats: StatCard[] = [
  { label: "Total Assets", value: "247", change: "+12", changeType: "up", color: "var(--accent-blue)" },
  { label: "Active Scans", value: "3", change: "running", changeType: "neutral", color: "var(--accent-cyan)" },
  { label: "Open Incidents", value: "7", change: "+2", changeType: "up", color: "var(--accent-yellow)" },
  { label: "Critical Risks", value: "4", change: "-1", changeType: "down", color: "var(--severity-critical)" },
  { label: "Pending Approvals", value: "2", change: "action needed", changeType: "neutral", color: "var(--accent-purple)" },
  { label: "Policy Rules", value: "18", change: "all active", changeType: "neutral", color: "var(--accent-green)" },
];

const recentEvents: RecentEvent[] = [
  { id: "1", time: "2 min ago", action: "scan.complete", actor: "system", detail: "Host discovery scan completed — 12 hosts found (lab)", severity: "info" },
  { id: "2", time: "8 min ago", action: "incident.create", actor: "analyst_jones", detail: "INC-007: Unauthorized SSH access attempt on 10.0.1.42", severity: "high" },
  { id: "3", time: "15 min ago", action: "policy.deny", actor: "system", detail: "Tool execution denied — target 192.168.200.0/24 not in allowlist", severity: "critical" },
  { id: "4", time: "22 min ago", action: "risk.calculate", actor: "analyst_chen", detail: "Risk recalculated for asset srv-db-01: 73/100 (High)", severity: "medium" },
  { id: "5", time: "35 min ago", action: "approval.decide", actor: "admin", detail: "Production scan approved for network prod-dmz", severity: "low" },
  { id: "6", time: "1 hr ago", action: "auth.login", actor: "analyst_jones", detail: "Successful login from 10.0.0.100", severity: "info" },
  { id: "7", time: "2 hr ago", action: "asset.discover", actor: "system", detail: "3 new assets discovered in lab-net-01 (10.0.100.0/24)", severity: "info" },
];

const riskDistribution = [
  { band: "Critical", count: 4, color: "var(--severity-critical)", width: "16%" },
  { band: "High", count: 12, color: "var(--severity-high)", width: "48%" },
  { band: "Medium", count: 31, color: "var(--severity-medium)", width: "100%" },
  { band: "Low", count: 18, color: "var(--severity-low)", width: "58%" },
  { band: "Info", count: 6, color: "var(--severity-info)", width: "19%" },
];

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

export default function DashboardPage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  if (!mounted) return null;

  return (
    <div>
      <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.25rem" }}>
        Security Overview
      </h1>
      <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "1.5rem" }}>
        Real-time defensive posture at a glance
      </p>

      {/* Stats Grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
        gap: "1rem",
        marginBottom: "1.5rem",
      }}>
        {stats.map((stat) => (
          <div key={stat.label} className="card" style={{ position: "relative", overflow: "hidden" }}>
            <div style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: "3px",
              height: "100%",
              background: stat.color,
              borderRadius: "3px 0 0 3px",
            }} />
            <div style={{ paddingLeft: "0.5rem" }}>
              <div style={{
                fontSize: "0.75rem",
                color: "var(--text-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                marginBottom: "0.5rem",
              }}>
                {stat.label}
              </div>
              <div style={{
                display: "flex",
                alignItems: "baseline",
                gap: "0.5rem",
              }}>
                <span className="stat-value" style={{ color: stat.color }}>{stat.value}</span>
                <span style={{
                  fontSize: "0.75rem",
                  color: stat.changeType === "up" ? "var(--accent-green)" :
                    stat.changeType === "down" ? "var(--severity-critical)" :
                    "var(--text-muted)",
                }}>
                  {stat.change}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "1.5rem" }}>
        {/* Recent Activity */}
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{
            padding: "1rem 1.25rem",
            borderBottom: "1px solid var(--border-primary)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}>
            <h2 style={{ fontSize: "0.9rem", fontWeight: 600 }}>Recent Activity</h2>
            <span style={{
              fontSize: "0.7rem",
              color: "var(--text-muted)",
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              Immutable Audit Trail
            </span>
          </div>
          <div style={{ maxHeight: "400px", overflowY: "auto" }}>
            {recentEvents.map((event) => (
              <div key={event.id} style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "0.75rem",
                padding: "0.75rem 1.25rem",
                borderBottom: "1px solid var(--border-primary)",
                transition: "background 0.1s ease",
              }}>
                <SeverityBadge severity={event.severity} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.25rem" }}>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem", color: "var(--accent-cyan)" }}>
                      {event.action}
                    </span>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>{event.time}</span>
                  </div>
                  <div style={{ fontSize: "0.825rem", color: "var(--text-secondary)" }}>
                    {event.detail}
                  </div>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: "0.125rem" }}>
                    by {event.actor}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          {/* Risk Distribution */}
          <div className="card">
            <h2 style={{ fontSize: "0.9rem", fontWeight: 600, marginBottom: "1rem" }}>Risk Distribution</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {riskDistribution.map((band) => (
                <div key={band.band}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.25rem" }}>
                    <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>{band.band}</span>
                    <span style={{ fontSize: "0.8rem", fontWeight: 600, color: band.color, fontFamily: "'JetBrains Mono', monospace" }}>
                      {band.count}
                    </span>
                  </div>
                  <div style={{
                    height: "6px",
                    background: "var(--border-primary)",
                    borderRadius: "3px",
                    overflow: "hidden",
                  }}>
                    <div style={{
                      height: "100%",
                      width: band.width,
                      background: band.color,
                      borderRadius: "3px",
                      transition: "width 0.5s ease",
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Security Posture */}
          <div className="card">
            <h2 style={{ fontSize: "0.9rem", fontWeight: 600, marginBottom: "1rem" }}>Security Posture</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {[
                { label: "Policy Enforcement", status: "Active", ok: true },
                { label: "Audit Logging", status: "Append-Only", ok: true },
                { label: "Tool Broker", status: "Gated", ok: true },
                { label: "Default Policy", status: "DENY", ok: true },
                { label: "Autonomous Mode", status: "DISABLED", ok: true },
              ].map((item) => (
                <div key={item.label} style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "0.5rem 0",
                  borderBottom: "1px solid var(--border-primary)",
                }}>
                  <span style={{ fontSize: "0.825rem", color: "var(--text-secondary)" }}>{item.label}</span>
                  <span style={{
                    fontSize: "0.75rem",
                    fontWeight: 600,
                    color: item.ok ? "var(--accent-green)" : "var(--severity-critical)",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
