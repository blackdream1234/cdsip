# CDSIP V1 Architecture

## 1. System Overview

The Closed Defensive Security Intelligence Platform (CDSIP) is designed as a modular, policy-driven security platform. V1 focuses on foundational capabilities: asset discovery via Nmap, policy-gated execution, audit logging, risk scoring, and an analyst dashboard.

### Design Principles

- **Defensive only** — No offensive capabilities exist in the codebase
- **Deny by default** — The Policy Governor denies all actions unless an explicit allow rule matches
- **Audit everything** — Every mutation, login, policy decision, and tool execution is recorded
- **Evidence-linked** — Decisions reference concrete evidence objects
- **Explainable** — Risk scores include full factor breakdown and rationale
- **Sandboxed tools** — Tool execution goes through the Tool Broker pipeline

## 2. Component Architecture

### 2.1 Sentinel Core (Rust/Axum)

The central API server built with Axum. Responsibilities:
- HTTP routing and request handling
- JWT authentication and RBAC enforcement
- Request ID generation and correlation
- Middleware pipeline (auth → audit → handler)
- Application state management

### 2.2 Policy Governor (policy-engine crate)

First-class subsystem, not an afterthought. The Governor:
- Loads active policy rules from PostgreSQL sorted by priority
- Evaluates every sensitive request against matching rules
- Returns one of: Allow, Deny, RequireApproval, Escalate
- Creates approval records when approval is required
- Default action is always DENY when no rule matches
- Is environment-aware (production vs lab have different rules)

Rule matching evaluates:
- Actor role (is the user allowed?)
- Environment (is this the right environment?)
- Action (is this action type allowed?)
- Target (is this target in the allowlist?)
- Resource type (asset, scan, incident, etc.)

### 2.3 Tool Broker (tool-broker crate)

Single gateway for all external tool execution:

```
Request → Validate Input → Check Environment → Check Role
    → Policy Governor Evaluate → Execute Tool → Normalize Output
    → Record Execution → Return Results
```

V1 includes one tool: **Nmap**

Nmap integration:
- Only 3 approved scan profiles (host discovery, TCP scan, service detection)
- No arbitrary flags — profiles map to hardcoded flag sets
- Target validation rejects shell metacharacters
- Execution uses `tokio::process::Command` (no shell)
- Hard timeout enforcement
- XML output parsed into structured findings
- Raw XML stored as artifact for forensics

### 2.4 Audit Core (audit-core crate)

Append-only audit logging:
- No UPDATE or DELETE operations exist in the code
- Database has triggers that REJECT update/delete attempts
- Every event includes: actor, action, resource, timestamp, request ID, policy decision
- Builder pattern ensures required fields are always populated
- Events are always written, even on failure (with error details)

### 2.5 Risk Engine (risk-engine crate)

Transparent, explainable risk scoring:

**8 weighted factors** (weights sum to 1.0):
| Factor | Weight | Description |
|--------|--------|-------------|
| Asset criticality | 0.25 | How critical is this asset (1-5) |
| Risky services | 0.20 | Exposed dangerous services (telnet, RDP, etc.) |
| Open ports | 0.15 | Total open port count |
| High-severity findings | 0.10 | Critical/high scan findings |
| New ports | 0.10 | Newly opened since last scan |
| Service changes | 0.10 | Services that changed since last scan |
| Policy violations | 0.05 | Failed policy requests for this asset |
| Scan staleness | 0.05 | Days since last scan |

**Severity bands**: Info (0-19), Low (20-39), Medium (40-59), High (60-79), Critical (80-100)

### 2.6 Domain Models (domain-models crate)

Pure data types. No business logic. Used by all crates:
- Users, roles, sessions
- Assets, networks, tags
- Scans (targets, jobs, runs, findings)
- Incidents, evidence
- Policies, rules, approvals
- Audit events, tool executions
- Risk scores, factors

## 3. Data Flow

### Scan Execution Flow
```
Analyst → API → Auth Check → Policy Governor → Tool Broker
    → Nmap Executor → Parse XML → Store Findings → Update Asset
    → Calculate Risk → Audit Event
```

### Policy Evaluation Flow
```
Request → Load Active Rules (by env) → Sort by Priority DESC
    → For each rule: Check conditions → First match wins
    → No match → DEFAULT DENY
```

## 4. Database

PostgreSQL 16 with 7 migration files covering 20 tables.

Key design decisions:
- UUID v7 for all primary keys (time-ordered)
- JSONB for flexible structured data (policy conditions, risk factors, raw data)
- CHECK constraints on all enum columns
- Append-only audit_events (DB triggers prevent mutation)
- Updated_at triggers on mutable tables
- Indexes on all foreign keys and frequently queried columns

## 5. Authentication & Authorization

- Argon2id password hashing
- JWT access tokens (15 min expiry)
- HttpOnly refresh tokens (7 day expiry)
- Role-based access control at route level
- Policy Governor adds additional authorization at action level
- No client-side trust — all actions server-validated

## 6. Future Extensions (Not in V1)

The architecture supports future integration of:
- **TraceGraph** — Graph-based relationship/timeline layer
- **NetVision** — Zeek, Suricata, PCAP integration
- **HostMind** — Sysmon, osquery, Wazuh data
- **Defensive Intelligence** — AI-powered analysis (Python service)
- **MISP** — Threat intelligence sharing
- **Sigma/YARA** — Detection rule support
- **Velociraptor** — Endpoint investigation

These are accommodated by:
- Clean service boundaries
- JSONB fields for extensible data
- Evidence object abstraction
- Tool Broker plugin architecture
- Separate intelligence service
