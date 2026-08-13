"""DNS analysis scanner."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from app.core.logging import get_logger

logger = get_logger(__name__)

DNS_TIMEOUT = 5.0


@dataclass
class DNSRecord:
    type: str
    values: list[str] = field(default_factory=list)


@dataclass
class DNSAnalysisResult:
    domain: str
    status: str  # success | partial | unavailable | nxdomain
    records: list[DNSRecord] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    error: str | None = None


async def _query_dns(domain: str, record_type: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(
            None,
            lambda: resolver.resolve(domain, record_type, raise_on_no_answer=False),
        )
        return [str(r) for r in answers]
    except dns.resolver.NXDOMAIN:
        raise
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.Timeout:
        return []
    except Exception as exc:
        logger.debug("dns_query_failed", domain=domain, type=record_type, error=str(exc))
        return []


async def analyze_dns(domain: str) -> DNSAnalysisResult:
    """Perform safe DNS analysis for a domain."""
    result = DNSAnalysisResult(domain=domain, status="success")
    record_types = ["A", "AAAA", "MX", "NS", "CNAME"]

    try:
        for rtype in record_types:
            try:
                values = await _query_dns(domain, rtype)
                if values:
                    result.records.append(DNSRecord(type=rtype, values=values))
                    if rtype == "NS":
                        result.nameservers.extend(values)
            except dns.resolver.NXDOMAIN:
                result.status = "nxdomain"
                result.error = f"Domain {domain} does not exist (NXDOMAIN)"
                return result
    except Exception as exc:
        result.status = "unavailable"
        result.error = f"DNS analysis unavailable: {type(exc).__name__}"
        return result

    if not result.records:
        result.status = "partial"
        result.error = "No DNS records found"

    return result
