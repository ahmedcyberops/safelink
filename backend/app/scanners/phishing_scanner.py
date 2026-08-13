"""Phishing heuristic detection."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.scanners.url_scanner import DomainAnalysisResult, URLAnalysisResult
from app.security.safe_http import SafeHTTPResponse


@dataclass
class PhishingHeuristic:
    id: str
    title: str
    description: str
    severity: str  # info | warning | high
    triggered: bool
    evidence: str | None = None


@dataclass
class PhishingAnalysisResult:
    heuristics: list[PhishingHeuristic] = field(default_factory=list)
    triggered_count: int = 0


def analyze_phishing(
    url_result: URLAnalysisResult,
    domain_result: DomainAnalysisResult,
    http_response: SafeHTTPResponse | None,
) -> PhishingAnalysisResult:
    """Run phishing heuristics against URL analysis data."""
    heuristics: list[PhishingHeuristic] = []

    def add(id_: str, title: str, desc: str, severity: str, triggered: bool, evidence: str | None = None):
        heuristics.append(PhishingHeuristic(
            id=id_, title=title, description=desc,
            severity=severity, triggered=triggered, evidence=evidence,
        ))

    add(
        "ip_host",
        "IP address used as hostname",
        "The URL uses a raw IP address instead of a domain name, which is uncommon for legitimate sites.",
        "warning",
        url_result.is_ip_host,
        url_result.ip_address,
    )

    add(
        "url_shortener",
        "URL shortener detected",
        "The URL appears to use a link shortening service, which can hide the final destination.",
        "warning",
        url_result.is_shortener,
    )

    add(
        "excessive_subdomains",
        "Excessive subdomains",
        "The domain has an unusually high number of subdomains, which can indicate phishing.",
        "warning",
        domain_result.has_excessive_subdomains,
        f"{domain_result.subdomain_count} subdomains",
    )

    add(
        "suspicious_tld",
        "Suspicious top-level domain",
        "The domain uses a TLD commonly associated with abuse or low-cost registration.",
        "warning",
        domain_result.suspicious_tld,
        domain_result.tld,
    )

    add(
        "homograph",
        "Possible homograph attack",
        "The domain contains characters that resemble ASCII letters, which may indicate a homograph attack.",
        "high",
        bool(domain_result.homograph_indicators),
        "; ".join(domain_result.homograph_indicators[:3]) if domain_result.homograph_indicators else None,
    )

    add(
        "punycode",
        "Internationalized domain (Punycode)",
        "The domain uses Punycode encoding, which can hide visually similar characters.",
        "warning",
        domain_result.punycode_detected,
    )

    add(
        "long_url",
        "Unusually long URL",
        "The URL is unusually long, which can be used to hide malicious content.",
        "warning",
        url_result.url_length > 150,
        f"{url_result.url_length} characters",
    )

    add(
        "encoding",
        "URL encoding detected",
        "The URL contains encoded characters that may obscure its true destination.",
        "warning",
        bool(url_result.encoding_indicators),
        ", ".join(url_result.encoding_indicators),
    )

    add(
        "suspicious_path",
        "Suspicious URL path",
        "The URL path contains keywords commonly associated with credential harvesting.",
        "warning",
        url_result.has_suspicious_path,
        "; ".join(url_result.suspicious_path_reasons[:3]) if url_result.suspicious_path_reasons else None,
    )

    add(
        "non_standard_port",
        "Non-standard port",
        "The URL uses a port other than 80 or 443.",
        "info",
        url_result.port is not None and url_result.port not in (80, 443),
        str(url_result.port),
    )

    redirect_count = len(http_response.redirect_chain) if http_response else 0
    add(
        "multiple_redirects",
        "Multiple redirects",
        "The URL chain includes multiple redirects, which can be used to obscure the final destination.",
        "warning",
        redirect_count >= 2,
        f"{redirect_count} redirects",
    )

    login_path = url_result.has_suspicious_path
    suspicious_domain = (
        domain_result.suspicious_tld
        or domain_result.has_excessive_subdomains
        or domain_result.punycode_detected
    )
    add(
        "login_suspicious_domain",
        "Login-related path on suspicious domain",
        "The URL combines login/payment keywords with suspicious domain characteristics.",
        "high",
        login_path and suspicious_domain,
    )

    triggered = sum(1 for h in heuristics if h.triggered)
    return PhishingAnalysisResult(heuristics=heuristics, triggered_count=triggered)
