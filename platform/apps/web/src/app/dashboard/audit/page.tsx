"use client";

import { useEffect, useState } from "react";

interface AuditRow {
  id: string;
  timestamp: string;
  actor: string;
  role: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  environment: string;
  policy_decision: string | null;
  policy_decision_id: string | null;
  request_id: string;
}

const demoAudit: AuditRow[] = [
  { id: "e1", timestamp: "10:42:18.031", actor: "system", role: "system", action: "scan.complete", resource_type: "scan_run", resource_id: "r1", environment: "lab", policy_decision: "allow", policy_decision_id: null, request_id: "req-a1b2c3" },
  { id: "e2", timestamp: "10:34:22.847", actor: "analyst_jones", role: "security_analyst", action: "incident.create", resource_type: "incident", resource_id: "inc-007", environment: "production", policy_decision: "allow", policy_decision_id: null, request_id: "req-d4e5f6" },
  { id: "e3", timestamp: "10:27:01.193", actor: "analyst_chen", role: "security_analyst", action: "tool.execute.nmap", resource_type: "tool_execution", resource_id: null, environment: "production", policy_decision: "deny", policy_decision_id: null, request_id: "req-g7h8i9" },
  { id: "e4", timestamp: "10:19:44.556", actor: "analyst_chen", role: "security_analyst", action: "risk.calculate", resource_type: "risk_score", resource_id: "a2", environment: "production", policy_decision: "allow", policy_decision_id: null, request_id: "req-j0k1l2" },
  { id: "e5", timestamp: "10:07:11.882", actor: "admin", role: "admin", action: "approval.decide", resource_type: "approval", resource_id: "apr-001", environment: "production", policy_decision: null, policy_decision_id: null, request_id: "req-m3n4o5" },
  { id: "e6", timestamp: "09:42:33.214", actor: "analyst_jones", role: "security_analyst", action: "auth.login", resource_type: "session", resource_id: null, environment: "development", policy_decision: null, policy_decision_id: null, request_id: "req-p6q7r8" },
  { id: "e7", timestamp: "09:15:02.771", actor: "system", role: "system", action: "scan.start", resource_type: "scan_run", resource_id: "r3", environment: "lab", policy_decision: "allow", policy_decision_id: null, request_id: "req-s9t0u1" },
  { id: "e8", timestamp: "08:55:48.103", actor: "analyst_chen", role: "security_analyst", action: "asset.update", resource_type: "asset", resource_id: "a7", environment: "production", policy_decision: "allow", policy_decision_id: null, request_id: "req-v2w3x4" },
  { id: "e9", timestamp: "08:30:15.667", actor: "admin", role: "admin", action: "policy.rule.create", resource_type: "policy_rule", resource_id: "r4", environment: "production", policy_decision: null, policy_decision_id: null, request_id: "req-y5z6a7" },
  { id: "e10", timestamp: "08:12:00.001", actor: "system", role: "system", action: "system.startup", resource_type: "system", resource_id: null, environment: "development", policy_decision: null, policy_decision_id: null, request_id: "req-b8c9d0" },
];

function decisionBadge(decision: string | null) {
  if (!decision) return <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>—</span>;
  const colors: Record<string, string> = {
    allow: "var(--accent-green)",
    deny: "var(--severity-critical)",
    require_approval: "var(--accent-yellow)",
  };
  
  const badge = (
    <span style={{
      padding: "0.125rem 0.375rem",
      borderRadius: "4px",
      fontSize: "0.7rem",
      fontWeight: 600,
      background: `${colors[decision] || "var(--text-muted)"}15`,
      color: colors[decision] || "var(--text-muted)",
      fontFamily: "'JetBrains Mono', monospace",
      textTransform: "uppercase",
    }}>
      {decision}
    </span>
  );
  
  return badge;
}

export default function AuditPage() {
  const [mounted, setMounted] = useState(false);
  const [sysStatus, setSysStatus] = useState<any>(null);
  const [events, setEvents] = useState<any[]>(demoAudit);

  useEffect(() => {
    setMounted(true);
    const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
    fetch(`${API_BASE}/api/v1/system/status`)
      .then(r => r.json())
      .then(data => setSysStatus(data))
      .catch(e => console.error(e));

    fetch(`${API_BASE}/api/v1/audit`)
      .then(r => r.json())
      .then(data => {
        if (data && data.length > 0) {
          // Format timestamps correctly if actual API succeeds
          setEvents(data.map((d: any) => ({
            ...d,
            actor: d.actor_id || "system",
            role: d.actor_role || "system"
          })));
        }
      })
      .catch(e => console.error(e));
  }, []);

  if (!mounted) return null;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.25rem" }}>Audit Log</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
            Append-only logs · Backend Verifiable
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          {sysStatus?.audit_immutable_trigger_active ? (
            <span style={{
              padding: "0.25rem 0.625rem",
              borderRadius: "4px",
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--severity-critical)",
              fontSize: "0.7rem",
              fontWeight: 600,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              UPDATE/DELETE VERIFIED BLOCKED
            </span>
          ) : (
            <span style={{
              padding: "0.25rem 0.625rem",
              borderRadius: "4px",
              background: "rgba(234, 179, 8, 0.1)",
              border: "1px solid rgba(234, 179, 8, 0.3)",
              color: "var(--accent-yellow)",
              fontSize: "0.7rem",
              fontWeight: 600,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              UNVERIFIED TAMPER PROTECTION
            </span>
          )}
        </div>
      </div>

      {sysStatus?.audit_immutable_trigger_active ? (
        <div style={{
          background: "rgba(16, 185, 129, 0.05)",
          border: "1px solid rgba(16, 185, 129, 0.2)",
          borderRadius: "0.5rem",
          padding: "0.75rem 1rem",
          marginBottom: "1rem",
          display: "flex",
          alignItems: "center",
          gap: "0.5rem",
          fontSize: "0.8rem",
          color: "var(--accent-green)",
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span>Audit trail integrity verified via active PostgreSQL database triggers.</span>
        </div>
      ) : (
        <div style={{
          background: "rgba(234, 179, 8, 0.05)",
          border: "1px solid rgba(234, 179, 8, 0.2)",
          borderRadius: "0.5rem",
          padding: "0.75rem 1rem",
          marginBottom: "1rem",
          display: "flex",
          alignItems: "center",
          gap: "0.5rem",
          fontSize: "0.8rem",
          color: "var(--accent-yellow)",
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
          <span>Backend verification pending. Checking DB triggers...</span>
        </div>
      )}

      {/* Events table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Actor</th>
              <th>Role</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Env</th>
              <th>Policy</th>
              <th>Request ID</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id}>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                  {typeof event.timestamp === 'string' && event.timestamp.length > 15 ? new Date(event.timestamp).toLocaleTimeString() : event.timestamp}
                </td>
                <td style={{ fontWeight: 500 }}>{event.actor}</td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{event.role}</td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem", color: "var(--accent-cyan)" }}>
                  {event.action}
                </td>
                <td style={{ fontSize: "0.8rem" }}>
                  <span style={{ color: "var(--text-muted)" }}>{event.resource_type}</span>
                  {event.resource_id && (
                    <span style={{ color: "var(--accent-blue)", marginLeft: "0.25rem", fontFamily: "'JetBrains Mono', monospace", fontSize: "0.75rem" }}>
                      {event.resource_id}
                    </span>
                  )}
                </td>
                <td style={{ fontSize: "0.8rem" }}>{event.environment}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {decisionBadge(event.policy_decision)}
                    {event.policy_decision_id && (
                      <span title={`Linked Decision ID: ${event.policy_decision_id}`} style={{ cursor: 'pointer', color: 'var(--accent-blue)' }}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                      </span>
                    )}
                  </div>
                </td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.7rem", color: "var(--text-muted)" }}>
                  {event.request_id}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
