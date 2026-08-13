"""TLS/HTTPS certificate analysis."""

from __future__ import annotations

import asyncio
import ssl
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.logging import get_logger

logger = get_logger(__name__)

TLS_TIMEOUT = 5.0


@dataclass
class TLSAnalysisResult:
    https_enabled: bool
    status: str  # success | unavailable | not_applicable
    certificate_valid: bool | None = None
    issuer: str | None = None
    subject: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    tls_version: str | None = None
    hostname_match: bool | None = None
    error: str | None = None


def _sync_tls_check(hostname: str, port: int) -> TLSAnalysisResult:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=TLS_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                days_until_expiry = None
                cert_valid = True
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_until_expiry = (expiry - now).days
                        if days_until_expiry < 0:
                            cert_valid = False
                    except ValueError:
                        pass

                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                subject_parts = dict(x[0] for x in cert.get("subject", []))

                # Check hostname match via subjectAltName
                hostname_match = False
                san = cert.get("subjectAltName", [])
                for typ, value in san:
                    if typ == "DNS" and (
                        value == hostname
                        or value == f"*.{'.'.join(hostname.split('.')[1:])}"
                    ):
                        hostname_match = True
                        break

                return TLSAnalysisResult(
                    https_enabled=True,
                    status="success",
                    certificate_valid=cert_valid,
                    issuer=issuer_parts.get("organizationName", issuer_parts.get("commonName", "Unknown")),
                    subject=subject_parts.get("commonName", hostname),
                    not_before=not_before,
                    not_after=not_after,
                    days_until_expiry=days_until_expiry,
                    tls_version=tls_version,
                    hostname_match=hostname_match,
                )
    except ssl.SSLCertVerificationError as exc:
        return TLSAnalysisResult(
            https_enabled=True,
            status="success",
            certificate_valid=False,
            error=f"Certificate verification failed: {exc.reason if hasattr(exc, 'reason') else exc}",
        )
    except (socket.timeout, TimeoutError):
        return TLSAnalysisResult(
            https_enabled=True,
            status="unavailable",
            error="TLS connection timed out",
        )
    except Exception as exc:
        return TLSAnalysisResult(
            https_enabled=True,
            status="unavailable",
            error=f"TLS analysis failed: {type(exc).__name__}",
        )


async def analyze_tls(hostname: str, port: int, scheme: str) -> TLSAnalysisResult:
    """Analyze TLS configuration for a host."""
    if scheme != "https":
        return TLSAnalysisResult(
            https_enabled=False,
            status="not_applicable",
            error="URL does not use HTTPS",
        )

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_tls_check, hostname, port)
