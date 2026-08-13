# SafeLink Security Model

## Threat Model

SafeLink accepts user-controlled URLs and makes outbound HTTP requests to analyze them. The primary security concern is **Server-Side Request Forgery (SSRF)**, where an attacker submits a URL that causes the server to access internal resources.

## SSRF Protection

### Blocked Destinations

| Category | Examples |
|----------|---------|
| Loopback | `127.0.0.0/8`, `::1` |
| Private networks | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Link-local | `169.254.0.0/16`, `fe80::/10` |
| CGNAT | `100.64.0.0/10` |
| Multicast | All multicast ranges |
| Reserved | All reserved ranges |
| Cloud metadata | `169.254.169.254`, `100.100.100.200` |
| Internal hostnames | `*.local`, `*.internal`, `*.corp`, `localhost` |

### Protection Layers

1. **URL Parsing** — Reject unsupported schemes, embedded credentials, malformed URLs
2. **Hostname Blocklist** — Block known internal hostnames and TLD patterns
3. **IP Blocklist** — Validate IP addresses against blocked ranges
4. **IP Obfuscation Detection** — Decode decimal, octal, hex IP representations
5. **DNS Resolution Validation** — Resolve hostname and validate ALL returned IPs
6. **Redirect Validation** — Re-validate every redirect destination
7. **Request Limits** — Connect timeout (5s), total timeout (15s), max redirects (5), max response size (512KB)

### DNS Rebinding Prevention

DNS is resolved before every HTTP request. All returned IP addresses are validated against the blocklist. If any resolved IP is blocked, the request is rejected.

## Input Validation

- URL length limited to 2048 characters
- Only `http` and `https` schemes allowed
- URLs with embedded credentials rejected
- Pydantic schema validation on all API inputs
- Request body size limits enforced by FastAPI

## Rate Limiting

- Redis-backed sliding window counters
- Default: 10 requests/minute, 60 requests/hour per IP
- Returns HTTP 429 with `Retry-After` header
- Client IP extracted from `X-Forwarded-For` or direct connection

## Secure Headers

All API responses include:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store
```

## CORS

- Configurable allowed origins via environment variable
- Credentials allowed for authenticated requests (future)
- Limited to GET and POST methods

## Privacy

- URLs retained for configurable period (default 24 hours)
- Client IPs stored as SHA-256 hash (16 chars)
- No authorization headers logged
- No cookies logged
- URLs sanitized in log output
- Scan reports not indexed by search engines

## Secret Management

- All secrets via environment variables
- `.env.example` provided with placeholder values
- No secrets committed to repository
- API keys for reputation providers optional

## Container Security

- Backend runs as non-root `safelink` user
- Frontend runs as non-root `nextjs` user
- Minimal base images (Alpine, Slim)
- No unnecessary packages installed

## Known Limitations

- DNS resolution uses system resolver (not DNS-over-HTTPS)
- TLS analysis uses synchronous socket connection
- No content analysis (HTML parsing, JavaScript detection)
- Reputation limited to configured providers
- No CAPTCHA for abuse prevention
- Domain age/registrar data not available without WHOIS API
- IPv6 support depends on host network configuration

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly. Do not open public issues for security concerns.
