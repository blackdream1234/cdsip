"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data?.error?.message || "Authentication failed");
      }

      const data = await res.json();
      if (typeof window !== "undefined") {
        localStorage.setItem("cdsip_token", data.access_token);
        localStorage.setItem("cdsip_user", JSON.stringify({ username }));
      }
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "var(--bg-primary)",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Background grid */}
      <div style={{
        position: "absolute",
        inset: 0,
        backgroundImage: `
          linear-gradient(rgba(59, 130, 246, 0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(59, 130, 246, 0.03) 1px, transparent 1px)
        `,
        backgroundSize: "40px 40px",
        zIndex: 0,
      }} />

      {/* Gradient orbs */}
      <div style={{
        position: "absolute",
        width: "500px",
        height: "500px",
        borderRadius: "50%",
        background: "radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%)",
        top: "-150px",
        right: "-100px",
        zIndex: 0,
      }} />
      <div style={{
        position: "absolute",
        width: "400px",
        height: "400px",
        borderRadius: "50%",
        background: "radial-gradient(circle, rgba(6, 182, 212, 0.06) 0%, transparent 70%)",
        bottom: "-100px",
        left: "-100px",
        zIndex: 0,
      }} />

      <div style={{
        width: "420px",
        zIndex: 1,
        position: "relative",
      }}>
        {/* Logo header */}
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <div style={{
            width: "56px",
            height: "56px",
            borderRadius: "14px",
            background: "linear-gradient(135deg, var(--accent-blue), var(--accent-cyan))",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            fontWeight: 800,
            fontSize: "1.5rem",
            color: "white",
            marginBottom: "1rem",
            boxShadow: "0 0 40px rgba(59, 130, 246, 0.3)",
          }}>
            C
          </div>
          <h1 style={{
            fontSize: "1.75rem",
            fontWeight: 800,
            letterSpacing: "0.1em",
            marginBottom: "0.25rem",
            background: "linear-gradient(135deg, var(--text-primary), var(--accent-cyan))",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}>
            CDSIP
          </h1>
          <p style={{
            color: "var(--text-muted)",
            fontSize: "0.8rem",
            textTransform: "uppercase",
            letterSpacing: "0.15em",
          }}>
            Closed Defensive Security Intelligence Platform
          </p>
        </div>

        {/* Login card */}
        <div style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border-primary)",
          borderRadius: "1rem",
          padding: "2rem",
          boxShadow: "0 4px 40px rgba(0, 0, 0, 0.3)",
        }}>
          <h2 style={{
            fontSize: "1.1rem",
            fontWeight: 600,
            marginBottom: "0.25rem",
          }}>
            Command Wall Access
          </h2>
          <p style={{
            color: "var(--text-muted)",
            fontSize: "0.8rem",
            marginBottom: "1.5rem",
          }}>
            Authenticated access required. All actions are audit-logged.
          </p>

          {error && (
            <div style={{
              padding: "0.75rem 1rem",
              borderRadius: "0.5rem",
              background: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--severity-critical)",
              fontSize: "0.825rem",
              marginBottom: "1rem",
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: "1rem" }}>
              <label style={{
                display: "block",
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "var(--text-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                marginBottom: "0.375rem",
              }}>
                Username
              </label>
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoFocus
                style={{ width: "100%" }}
              />
            </div>

            <div style={{ marginBottom: "1.5rem" }}>
              <label style={{
                display: "block",
                fontSize: "0.75rem",
                fontWeight: 600,
                color: "var(--text-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                marginBottom: "0.375rem",
              }}>
                Password
              </label>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                style={{ width: "100%" }}
              />
            </div>

            <button
              id="login-submit"
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{
                width: "100%",
                padding: "0.75rem",
                fontSize: "0.9rem",
                fontWeight: 600,
                opacity: loading ? 0.7 : 1,
                cursor: loading ? "wait" : "pointer",
              }}
            >
              {loading ? "Authenticating..." : "Authenticate"}
            </button>
          </form>

          {/* Security note */}
          <div style={{
            marginTop: "1.5rem",
            padding: "0.75rem",
            borderRadius: "0.5rem",
            background: "rgba(59, 130, 246, 0.05)",
            border: "1px solid rgba(59, 130, 246, 0.15)",
          }}>
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              marginBottom: "0.375rem",
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--accent-blue)" }}>Security Notice</span>
            </div>
            <p style={{
              fontSize: "0.7rem",
              color: "var(--text-muted)",
              lineHeight: 1.5,
              margin: 0,
            }}>
              This platform operates in defensive-only mode. All login attempts, session activity, and policy decisions are permanently recorded in an immutable audit log.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div style={{
          textAlign: "center",
          marginTop: "1.5rem",
          fontSize: "0.7rem",
          color: "var(--text-muted)",
        }}>
          <span>v0.1.0 · Defensive Only · Policy-Gated · Audit-Logged</span>
        </div>
      </div>
    </div>
  );
}
