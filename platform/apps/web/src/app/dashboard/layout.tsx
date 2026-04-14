"use client";

import Sidebar from "@/components/Sidebar";
import { ReactNode, useEffect, useState } from "react";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  const [sysStatus, setSysStatus] = useState<any>(null);

  useEffect(() => {
    const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
    fetch(`${API_BASE}/api/v1/system/status`)
      .then(r => r.json())
      .then(data => setSysStatus(data))
      .catch(e => console.error(e));
  }, []);

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar />
      <main style={{
        flex: 1,
        marginLeft: '240px',
        padding: '1.5rem 2rem',
        minHeight: '100vh',
      }}>
        {/* Top bar */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.5rem',
          paddingBottom: '1rem',
          borderBottom: '1px solid var(--border-primary)',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
          }}>
            {!sysStatus?.autonomous_mode_allowed ? (
              <span style={{
                padding: '0.25rem 0.625rem',
                borderRadius: '9999px',
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: 'var(--accent-green)',
                fontSize: '0.7rem',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}>
                Defensive Mode Confirmed
              </span>
            ) : (
               <span style={{
                padding: '0.25rem 0.625rem',
                borderRadius: '9999px',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: 'var(--severity-critical)',
                fontSize: '0.7rem',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}>
                AUTONOMOUS MODE ACTIVE
              </span>
            )}

            {sysStatus?.policy_engine_status === 'active' && (
              <span style={{
                padding: '0.25rem 0.625rem',
                borderRadius: '9999px',
                background: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                color: 'var(--accent-blue)',
                fontSize: '0.7rem',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
              }}>
                Policy-Gated Active
              </span>
            )}
          </div>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '1rem',
            fontSize: '0.8rem',
            color: 'var(--text-muted)',
          }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>ENV: {sysStatus?.environment || "connecting..."}</span>
          </div>
        </div>
        {children}
      </main>
    </div>
  );
}
