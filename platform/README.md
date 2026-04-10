# CDSIP — Closed Defensive Security Intelligence Platform

A strictly defensive, closed, auditable, policy-driven security platform for protecting sensitive information, critical devices, and controlled environments.

## ⚠️ Security Notice

This platform is **defensive only**. It:
- ❌ NEVER behaves as an offensive autonomous agent
- ❌ NEVER generates uncontrolled attack workflows
- ❌ NEVER runs actions outside explicitly authorized environments
- ✅ ALWAYS enforces deny-by-default policy
- ✅ ALWAYS logs every action to immutable audit trail
- ✅ ALWAYS requires evidence for every decision
- ✅ ALWAYS explains its reasoning

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Command Wall (Next.js)                     │
│              Dashboard · Assets · Scans · Incidents          │
│                Policies · Audit · Risk                       │
└─────────────────┬───────────────────────────────────────────┘
                  │ REST API
┌─────────────────▼───────────────────────────────────────────┐
│                 Sentinel Core (Rust/Axum)                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  Policy   │ │   Tool   │ │  Audit   │ │   Risk   │       │
│  │ Governor  │ │  Broker  │ │   Core   │ │  Engine  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                   PostgreSQL 16                               │
│        Users · Assets · Scans · Incidents · Policies         │
│           Evidence · Audit Events · Risk Scores              │
└─────────────────────────────────────────────────────────────┘
```

## Core Modules

| Module | Purpose |
|--------|---------|
| **Sentinel Core** | Central orchestrator, auth, routing |
| **Policy Governor** | Deny-by-default policy enforcement |
| **Tool Broker** | Single controlled gateway for all tool execution |
| **Audit Core** | Append-only immutable audit trail |
| **Risk Engine** | Transparent, explainable risk scoring |
| **Evidence Vault** | Secure storage for findings and artifacts |
| **Command Wall** | Analyst dashboard and UI |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Security Core | Rust |
| Backend API | Rust (Axum) + Tokio |
| Intelligence | Python (FastAPI) — placeholder |
| Frontend | Next.js + TypeScript + Tailwind CSS |
| Database | PostgreSQL 16 |
| Auth | Argon2id + JWT |
| Dev Environment | Docker Compose |

## Quick Start

### Prerequisites
- Docker & Docker Compose
- (For local dev): Rust 1.85+, Node.js 22+, Python 3.12+

### Launch with Docker

```bash
# Clone and enter the project
cd platform

# Copy environment template
cp .env.example .env

# IMPORTANT: Edit .env and change JWT_SECRET and ADMIN_PASSWORD

# Start all services
docker compose up -d

# View logs
docker compose logs -f api
```

### Services

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | Command Wall UI |
| API | http://localhost:8080 | Rust API server |
| Intel | http://localhost:8081 | Python intelligence service |
| PostgreSQL | localhost:5432 | Database |

### Default Users (Development Only)

| Username | Role | Password |
|----------|------|----------|
| admin | admin | Set via ADMIN_PASSWORD env var |

### Local Rust Development

```bash
cd platform

# Install dependencies
cargo build

# Run tests
cargo test

# Run with clippy
cargo clippy --all-targets

# Run API server locally
cargo run --bin cdsip-api
```

### Local Frontend Development

```bash
cd apps/web

npm install
npm run dev
```

## Project Structure

```
platform/
├── apps/
│   ├── api-rust/          # Rust API server (Axum)
│   ├── intel-python/      # Python intelligence service (FastAPI)
│   └── web/               # Next.js dashboard
├── crates/
│   ├── domain-models/     # Shared data types
│   ├── audit-core/        # Immutable audit logging
│   ├── policy-engine/     # Policy Governor
│   ├── tool-broker/       # Tool execution gateway
│   └── risk-engine/       # Risk scoring
├── infra/
│   ├── docker/            # Dockerfiles
│   ├── migrations/        # PostgreSQL migrations
│   └── scripts/           # Init and seed scripts
├── docs/                  # Architecture and API docs
├── docker-compose.yml
└── .env.example
```

## RBAC Roles

| Role | Permissions |
|------|------------|
| `admin` | Full access — users, policies, approvals, scans |
| `security_analyst` | Create/manage assets, incidents, request scans |
| `auditor` | Read-only + full audit log access |
| `read_only` | Dashboard view only |

## Security Principles

1. **Deny by default** — No action allowed without explicit policy rule
2. **Closed by default** — All integrations require explicit allowlisting
3. **Append-only audit** — Audit events cannot be modified or deleted
4. **Policy-gated execution** — Every tool invocation passes through the Policy Governor
5. **Evidence-driven** — Every decision is traceable to evidence
6. **No autonomous offense** — Platform never performs offensive actions
7. **Transparent risk** — Every risk score includes factor breakdown and rationale

## License

Proprietary — All rights reserved.
