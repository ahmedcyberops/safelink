"""URL structure and domain analysis."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

import tldextract

from app.security.url_parser import ParsedURL


@dataclass
class URLAnalysisResult:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    url_length: int
    is_ip_host: bool
    ip_address: str | None
    encoding_indicators: list[str]
    is_shortener: bool
    query_param_count: int
    has_suspicious_path: bool
    suspicious_path_reasons: list[str] = field(default_factory=list)


@dataclass
class DomainAnalysisResult:
    domain: str
    registrable_domain: str
    subdomain: str
    tld: str
    subdomain_count: int
    has_excessive_subdomains: bool
    punycode_detected: bool
    homograph_indicators: list[str] = field(default_factory=list)
    suspicious_tld: bool = False
    domain_age_days: int | None = None
    registrar: str | None = None
    nameservers: list[str] = field(default_factory=list)


SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "link", "gq", "ml", "cf", "tk",
    "ga", "buzz", "sbs", "cfd", "rest", "cam", "monster",
}

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "account", "verify", "secure",
    "update", "confirm", "banking", "password", "wallet", "payment",
    "credential", "auth", "oauth", "sso",
]

HOMOGRAPH_CHARS = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u04cf": "l",  # Cyrillic ԁ -> actually different
    "\u1d00": "a",
    "\u026a": "i",
}


def analyze_url_structure(parsed: ParsedURL) -> URLAnalysisResult:
    """Analyze URL structure for suspicious patterns."""
    suspicious_reasons = []
    path_lower = parsed.path.lower()

    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path_lower:
            suspicious_reasons.append(f"Path contains '{keyword}' keyword")

    query_params = [p for p in parsed.query.split("&") if p]
    if len(query_params) > 10:
        suspicious_reasons.append(f"Excessive query parameters ({len(query_params)})")

    if parsed.url_length > 200:
        suspicious_reasons.append(f"Unusually long URL ({parsed.url_length} chars)")

    if parsed.port and parsed.port not in (80, 443):
        suspicious_reasons.append(f"Non-standard port ({parsed.port})")

    return URLAnalysisResult(
        scheme=parsed.scheme,
        host=parsed.host,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
        url_length=parsed.url_length,
        is_ip_host=parsed.is_ip_host,
        ip_address=parsed.ip_address,
        encoding_indicators=parsed.encoding_indicators,
        is_shortener=parsed.is_shortener,
        query_param_count=len(query_params),
        has_suspicious_path=bool(suspicious_reasons),
        suspicious_path_reasons=suspicious_reasons,
    )


def analyze_domain(host: str) -> DomainAnalysisResult:
    """Analyze domain characteristics."""
    extracted = tldextract.extract(host)
    registrable = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else host
    subdomain = extracted.subdomain or ""
    subdomain_parts = [s for s in subdomain.split(".") if s]

    homograph_indicators = []
    punycode_detected = host.startswith("xn--")

    for char in host:
        if char in HOMOGRAPH_CHARS:
            homograph_indicators.append(
                f"Possible homograph: '{char}' resembles '{HOMOGRAPH_CHARS[char]}'"
            )
        cat = unicodedata.category(char)
        if cat.startswith("L") and ord(char) > 127 and not punycode_detected:
            homograph_indicators.append(f"Non-ASCII character in hostname: U+{ord(char):04X}")

    return DomainAnalysisResult(
        domain=host,
        registrable_domain=registrable,
        subdomain=subdomain,
        tld=extracted.suffix or "",
        subdomain_count=len(subdomain_parts),
        has_excessive_subdomains=len(subdomain_parts) > 3,
        punycode_detected=punycode_detected,
        homograph_indicators=homograph_indicators,
        suspicious_tld=extracted.suffix.lower() in SUSPICIOUS_TLDS if extracted.suffix else False,
    )
