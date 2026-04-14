"use client";

import { useEffect, useState } from "react";

interface PolicyRow {
  id: string;
  name: string;
  description: string;
  environment_scope: string;
  is_active: boolean;
  rules_count: number;
  version: number;
}

interface RuleRow {
  id: string;
  policy: string;
  rule_type: string;
  action: string;
  priority: number;
  conditions_summary: string;
}

const demoPolicies: PolicyRow[] = [
  { id: "p1", name: "Default Deny-All", description: "Catch-all rule. Denies any action not explicitly allowed.", environment_scope: "all", is_active: true, rules_count: 1, version: 1 },
  { id: "p2", name: "Lab Allow", description: "Allows scans and most actions in the lab environment for analysts.", environment_scope: "lab", is_active: true, rules_count: 3, version: 2 },
  { id: "p3", name: "Production Approval Required", description: "All scan and tool actions in production require admin approval.", environment_scope: "production", is_active: true, rules_count: 2, version: 1 },
  { id: "p4", name: "Staging Read-Only Analysts", description: "Analysts can view but not modify staging assets.", environment_scope: "staging", is_active: true, rules_count: 2, version: 1 },
];

const demoRules: RuleRow[] = [
  { id: "r1", policy: "Lab Allow", rule_type: "allow_scan", action: "allow", priority: 100, conditions_summary: "roles: [admin, analyst] · env: lab · action: scan.*" },
  { id: "r2", policy: "Lab Allow", rule_type: "allow_asset", action: "allow", priority: 90, conditions_summary: "roles: [admin, analyst] · env: lab · action: asset.*" },
  { id: "r3", policy: "Lab Allow", rule_type: "allow_incident", action: "allow", priority: 80, conditions_summary: "roles: [admin, analyst] · env: lab · action: incident.*" },
  { id: "r4", policy: "Production Approval Required", rule_type: "require_approval_scan", action: "require_approval", priority: 200, conditions_summary: "env: production · action: tool.execute.*" },
  { id: "r5", policy: "Production Approval Required", rule_type: "allow_read_only", action: "allow", priority: 150, conditions_summary: "env: production · action: *.list, *.get" },
  { id: "r6", policy: "Default Deny-All", rule_type: "catch_all", action: "deny", priority: -1000, conditions_summary: "match: all (catch-all)" },
];

function actionBadge(action: string) {
  const styles: Record<string, { bg: string; color: string }> = {
    allow: { bg: "rgba(16, 185, 129, 0.15)", color: "var(--accent-green)" },
    deny: { bg: "rgba(239, 68, 68, 0.15)", color: "var(--severity-critical)" },
    require_approval: { bg: "rgba(245, 158, 11, 0.15)", color: "var(--accent-yellow)" },
    escalate: { bg: "rgba(139, 92, 246, 0.15)", color: "var(--accent-purple)" },
  };
  const s = styles[action] || styles.deny;
  return (
    <span style={{
      padding: "0.125rem 0.5rem",
      borderRadius: "9999px",
      fontSize: "0.75rem",
      fontWeight: 600,
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.color}30`,
      textTransform: "uppercase",
    }}>
      {action.replace("_", " ")}
    </span>
  );
}

export default function PoliciesPage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  if (!mounted) return null;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700, marginBottom: "0.25rem" }}>Policy Governor</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
            Deny-by-default · {demoPolicies.filter(p => p.is_active).length} active policies · {demoRules.length} rules
          </p>
        </div>
        <button className="btn btn-primary">+ Create Policy</button>
      </div>

      {/* Policies */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "1rem", marginBottom: "2rem" }}>
        {demoPolicies.map((policy) => (
          <div key={policy.id} className="card" style={{ cursor: "pointer" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
              <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{policy.name}</span>
              <span style={{
                width: "8px",
                height: "8px",
                borderRadius: "50%",
                background: policy.is_active ? "var(--accent-green)" : "var(--text-muted)",
                marginTop: "0.375rem",
              }} />
            </div>
            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.75rem", lineHeight: 1.4 }}>
              {policy.description}
            </p>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "var(--text-muted)" }}>
              <span>Scope: <strong style={{ color: "var(--text-secondary)" }}>{policy.environment_scope}</strong></span>
              <span>{policy.rules_count} rules · v{policy.version}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Rules table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "1rem 1.25rem", borderBottom: "1px solid var(--border-primary)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2 style={{ fontSize: "0.9rem", fontWeight: 600 }}>Policy Rules (Priority Sorted)</h2>
          <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
            Default: DENY if no match
          </span>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Policy</th>
              <th>Type</th>
              <th>Action</th>
              <th>Conditions</th>
            </tr>
          </thead>
          <tbody>
            {demoRules.sort((a, b) => b.priority - a.priority).map((rule) => (
              <tr key={rule.id}>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>{rule.priority}</td>
                <td style={{ fontWeight: 500 }}>{rule.policy}</td>
                <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem", color: "var(--accent-cyan)" }}>{rule.rule_type}</td>
                <td>{actionBadge(rule.action)}</td>
                <td style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>{rule.conditions_summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
