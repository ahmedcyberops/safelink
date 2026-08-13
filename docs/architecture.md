# SafeLink Architecture

## Overview

SafeLink is a monorepo containing a Next.js frontend and a FastAPI backend, orchestrated via Docker Compose with PostgreSQL and Redis.

```
safelink/
├── frontend/          # Next.js 14 application
├── backend/           # FastAPI application
├── docker/            # Docker configuration
├── docs/              # Documentation
└── docker-compose.yml # Service orchestration
```

## System Flow

```
User → Frontend → Backend API → URL Validation
                                      ↓
                               Safe HTTP Fetcher (SSRF-protected)
                                      ↓
                    ┌─────────────────┼─────────────────┐
                    ↓                 ↓                 ↓
              DNS Scanner      TLS Scanner      URL/Domain Scanner
                    ↓                 ↓                 ↓
              Phishing Heuristics  Typosquat Detection
                    ↓
              Reputation Providers
                    ↓
              Risk Scoring Engine
                    ↓
              PostgreSQL (persist) + Response
                    ↓
              Frontend Results Page
```

## Backend Architecture

### Layer Separation

| Layer | Directory | Responsibility |
|-------|-----------|---------------|
| API Routes | `app/api/` | HTTP endpoints, request validation |
| Services | `app/services/` | Business logic orchestration |
| Scanners | `app/scanners/` | Individual analysis modules |
| Security | `app/security/` | SSRF protection, safe HTTP, URL parsing |
| Models | `app/models/` | SQLAlchemy ORM models |
| Schemas | `app/schemas/` | Pydantic request/response models |
| Core | `app/core/` | Config, database, Redis, logging |

### Key Components

**SafeHTTPClient** (`app/security/safe_http.py`)
- Validates every destination against SSRF rules
- Resolves DNS and validates IPs before connecting
- Follows limited redirects with per-hop validation
- Enforces timeouts and response size limits

**RiskEngine** (`app/services/risk_engine.py`)
- Accepts structured findings with weights
- Calculates 0–100 score with configurable thresholds
- Distinguishes positive, warning, and high-risk indicators

**ScanService** (`app/services/scan_service.py`)
- Orchestrates the full scan pipeline
- Persists results to PostgreSQL
- Returns structured report

**ReputationProvider** (`app/services/reputation.py`)
- Abstract provider interface
- Mock provider for development
- VirusTotal integration (optional, requires API key)

## Frontend Architecture

### Structure

| Directory | Purpose |
|-----------|---------|
| `app/` | Next.js App Router pages |
| `components/` | Reusable UI components |
| `lib/` | API client, utilities |
| `types/` | TypeScript type definitions |

### Key Pages

- `/` — Landing page with URL scanner
- `/scan/[id]` — Security analysis report

### Design System

- Tailwind CSS with custom design tokens
- Dark/light mode via CSS class toggle
- Glass-card components with subtle gradients
- Accessible risk indicators (not color-only)
- Reduced motion support

## Database Schema

```
scans
├── id (UUID)
├── url, normalized_url
├── status, risk_score, risk_level
├── summary, recommended_action
├── report_data (JSON)
├── client_ip_hash
├── created_at, completed_at, expires_at

findings
├── id, scan_id (FK)
├── finding_id, category, severity
├── title, description, weight, evidence

redirects
├── id, scan_id (FK)
├── hop_order, url, status_code, location

reputation_results
├── id, scan_id (FK)
├── provider, status, score, details
```

## Extension Points

The architecture supports future features without rewrites:

- **New scanners** — Add modules in `app/scanners/`, register in `ScanService`
- **New reputation providers** — Implement `ReputationProvider` ABC
- **User accounts** — Models stubbed, add auth middleware
- **API keys** — Rate limiter supports per-key limits
- **Screenshot/OCR** — New scanner module, same pipeline

## Infrastructure

### Docker Services

| Service | Image | Port |
|---------|-------|------|
| frontend | Node 20 Alpine | 3000 |
| backend | Python 3.12 Slim | 8000 |
| postgres | PostgreSQL 16 Alpine | 5432 |
| redis | Redis 7 Alpine | 6379 |

All containers run as non-root users where practical.
