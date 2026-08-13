# SafeLink

**Check a link before you click it.**

SafeLink is a defensive cybersecurity platform that analyzes suspicious URLs for phishing, malware, redirects, and other security risks. It provides probabilistic risk scoring — never claiming a URL is absolutely safe.

## Features

- **URL Security Scanner** — Submit any URL for multi-layer analysis
- **Risk Scoring Engine** — Weighted 0–100 score with configurable thresholds
- **SSRF Protection** — Safe outbound fetching with DNS validation and redirect checks
- **DNS Analysis** — A, AAAA, MX, NS, CNAME record resolution
- **TLS/HTTPS Analysis** — Certificate validity, issuer, expiration
- **Redirect Chain Analysis** — Safe redirect following with per-hop validation
- **Phishing Heuristics** — Pattern detection for credential harvesting
- **Typosquatting Detection** — Brand impersonation identification
- **Reputation Checks** — Provider abstraction with mock fallback
- **Rate Limiting** — Redis-backed abuse prevention
- **Premium UI** — Dark/light mode, responsive, accessible design

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS |
| Backend | Python, FastAPI, Pydantic |
| Database | PostgreSQL |
| Cache | Redis |
| Infrastructure | Docker, Docker Compose |

## Quick Start

### Prerequisites

- Docker and Docker Compose

### Run with Docker

```bash
git clone <repo-url>
cd safelink
cp .env.example .env
docker compose up --build
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Services

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Health | http://localhost:8000/api/v1/health |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

## Environment Variables

See [`.env.example`](.env.example) for all configuration options.

Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://safelink:safelink@postgres:5432/safelink` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |
| `REPUTATION_PROVIDER` | Reputation provider (`mock` or `virustotal`) | `mock` |
| `REPUTATION_API_KEY` | API key for reputation provider | (empty) |
| `RATE_LIMIT_PER_MINUTE` | Max scans per IP per minute | `10` |
| `NEXT_PUBLIC_API_URL` | Backend URL for frontend | `http://localhost:8000` |

## API Endpoints

### `POST /api/v1/scan`

Submit a URL for security analysis.

```json
{
  "url": "https://example.com"
}
```

### `GET /api/v1/scan/{scan_id}`

Retrieve a completed scan report.

### `GET /api/v1/health`

Health check with service status.

## Development

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Tests

```bash
cd backend
pytest -v
```

## Security Model

SafeLink implements defense-in-depth for safe URL analysis:

- **SSRF Protection** — Blocks localhost, private networks, metadata endpoints, internal hostnames
- **DNS Rebinding Prevention** — Validates resolved IPs before connecting
- **Redirect Validation** — Every redirect destination re-validated
- **Request Limits** — Timeouts, size limits, redirect limits, concurrency caps
- **Rate Limiting** — Redis-backed per-IP limits
- **Secure Headers** — X-Content-Type-Options, X-Frame-Options, etc.
- **No JS Execution** — Simple HTTP analysis, no browser automation
- **Input Validation** — Pydantic schemas, URL length limits
- **Privacy** — Configurable retention, no credential logging

See [docs/security.md](docs/security.md) for details.

## Architecture

See [docs/architecture.md](docs/architecture.md) for system design.

## Documentation

- [Architecture](docs/architecture.md)
- [Security Model](docs/security.md)
- [API Reference](docs/api.md)

## Roadmap

### Phase 2
- Screenshot scanner, OCR URL extraction, QR scanner, AI-assisted explanations

### Phase 3
- Browser extension, public API, API keys, user accounts, scan history

### Phase 4
- Business dashboard, organizations, team members, analytics, subscriptions

## License

Proprietary — All rights reserved.

## Disclaimer

SafeLink provides probabilistic security analysis. No URL can be guaranteed safe. Always verify through official channels before entering sensitive information.
