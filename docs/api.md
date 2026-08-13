# SafeLink API Reference

Base URL: `http://localhost:8000/api/v1`

## Authentication

No authentication required for MVP. Rate limiting applies per IP address.

## Endpoints

### Health Check

```
GET /api/v1/health
```

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "api": "healthy",
    "redis": "healthy",
    "database": "healthy"
  }
}
```

### Create Scan

```
POST /api/v1/scan
Content-Type: application/json
```

**Request Body:**

```json
{
  "url": "https://example.com"
}
```

**Success Response (200):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "risk_score": 12,
  "risk_level": "low",
  "summary": "Risk score 12/100 (low): 2 positive security indicator(s).",
  "recommended_action": "This URL shows relatively few risk indicators...",
  "findings": [
    {
      "id": "tls_valid",
      "category": "tls",
      "severity": "positive",
      "title": "Valid HTTPS certificate",
      "description": "HTTPS is enabled with a valid certificate.",
      "weight": -5,
      "evidence": null
    }
  ],
  "positive_indicators": [],
  "url_analysis": {
    "scheme": "https",
    "host": "example.com",
    "port": 443,
    "path": "/",
    "query": "",
    "url_length": 19,
    "is_ip_host": false,
    "ip_address": null,
    "encoding_indicators": [],
    "is_shortener": false,
    "query_param_count": 0,
    "has_suspicious_path": false,
    "suspicious_path_reasons": []
  },
  "domain": {
    "domain": "example.com",
    "registrable_domain": "example.com",
    "subdomain": "",
    "tld": "com",
    "subdomain_count": 0,
    "has_excessive_subdomains": false,
    "punycode_detected": false,
    "homograph_indicators": [],
    "suspicious_tld": false
  },
  "dns": {
    "domain": "example.com",
    "status": "success",
    "records": [
      { "type": "A", "values": ["93.184.216.34"] }
    ],
    "nameservers": [],
    "error": null
  },
  "tls": {
    "https_enabled": true,
    "status": "success",
    "certificate_valid": true,
    "issuer": "DigiCert Inc",
    "tls_version": "TLSv1.3"
  },
  "redirects": [],
  "reputation": [
    {
      "provider": "mock",
      "status": "clean",
      "score": 0,
      "details": "Mock provider: no indicators found"
    }
  ],
  "typosquat": {
    "possible_typosquat": false,
    "confidence": "low",
    "matched_brand": null,
    "reason": null
  },
  "stages": [],
  "created_at": "2026-01-01T00:00:00Z",
  "completed_at": "2026-01-01T00:00:05Z",
  "error": null
}
```

**Error Responses:**

| Status | Code | Description |
|--------|------|-------------|
| 422 | `validation_error` | Invalid request body |
| 429 | `rate_limit_exceeded` | Too many requests |

**Failed Scan Response (200 with status "failed"):**

```json
{
  "scan_id": "...",
  "status": "failed",
  "summary": "URLs with embedded credentials are not allowed",
  "recommended_action": "Verify the URL is correct and try again.",
  "error": "URLs with embedded credentials are not allowed"
}
```

### Get Scan

```
GET /api/v1/scan/{scan_id}
```

**Success Response (200):** Same as Create Scan response.

**Error Response (404):**

```json
{
  "detail": {
    "error": "not_found",
    "code": "scan_not_found",
    "message": "Scan not found or has expired."
  }
}
```

## Risk Levels

| Score Range | Level |
|-------------|-------|
| 0–20 | `low` |
| 21–50 | `moderate` |
| 51–75 | `suspicious` |
| 76–100 | `high` |

Thresholds are configurable via environment variables.

## Finding Severities

| Severity | Description |
|----------|-------------|
| `positive` | Positive security indicator (reduces score) |
| `info` | Informational finding |
| `warning` | Warning indicator (increases score) |
| `high` | High-risk indicator (significantly increases score) |

## Rate Limits

Default limits per IP address:
- 10 requests per minute
- 60 requests per hour

When exceeded, the API returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 45

{
  "detail": {
    "error": "rate_limit_exceeded",
    "code": "rate_limit_exceeded",
    "message": "Too many requests. Please wait 45 seconds."
  }
}
```

## Scan Stages

When a scan is in progress, stages report their status:

| Stage | Description |
|-------|-------------|
| `url_validation` | Parsing and validating the URL |
| `domain_analysis` | Analyzing domain characteristics |
| `redirect_analysis` | Following and validating redirects |
| `dns_analysis` | Resolving DNS records |
| `tls_analysis` | Checking TLS/HTTPS configuration |
| `phishing_analysis` | Running phishing heuristics |
| `reputation_check` | Querying reputation providers |
| `risk_scoring` | Calculating final risk score |

Stage statuses: `pending`, `running`, `completed`, `failed`, `unavailable`
