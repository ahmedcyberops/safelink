"""URL parsing and validation utilities."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse, urlunparse

import idna

from app.core.config import get_settings


class URLValidationError(Exception):
    """Raised when a URL fails validation."""

    def __init__(self, message: str, code: str = "invalid_url"):
        self.message = message
        self.code = code
        super().__init__(message)


@dataclass
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None
    password: str | None
    is_ip_host: bool = False
    ip_address: str | None = None
    url_length: int = 0
    has_userinfo: bool = False
    encoding_indicators: list[str] = field(default_factory=list)
    is_shortener: bool = False


# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "j.mp", "rb.gy", "cutt.ly", "shorturl.at",
    "rebrand.ly", "bl.ink", "soo.gd", "v.gd", "qr.ae",
}

SUSPICIOUS_ENCODED_PATTERNS = [
    (r"%[0-9a-fA-F]{2}", "percent_encoding"),
    (r"\\x[0-9a-fA-F]{2}", "hex_encoding"),
    (r"&#x?[0-9a-fA-F]+;", "html_entity_encoding"),
]

ALLOWED_SCHEMES = {"http", "https"}


def _decode_ip_tricks(host: str) -> str | None:
    """Attempt to decode obfuscated IP representations."""
    host = host.strip("[]")

    # Decimal IP: 2130706433 = 127.0.0.1
    if re.fullmatch(r"\d+", host):
        try:
            num = int(host)
            if 0 <= num <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(num))
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Octal IP: 0177.0.0.1
    if re.fullmatch(r"[\d.]+", host) and any(
        part.startswith("0") and len(part) > 1 for part in host.split(".")
    ):
        try:
            parts = host.split(".")
            if len(parts) == 4:
                octets = [int(p, 8) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    return ".".join(str(o) for o in octets)
        except ValueError:
            pass

    # Hex IP: 0x7f000001
    if host.lower().startswith("0x"):
        try:
            num = int(host, 16)
            if 0 <= num <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(num))
        except (ValueError, ipaddress.AddressValueError):
            pass

    return None


def _normalize_host(host: str) -> str:
    """Normalize hostname using IDNA."""
    host = host.strip().lower().rstrip(".")
    try:
        return idna.encode(host).decode("ascii")
    except idna.IDNAError:
        return host


def _detect_encoding(url: str) -> list[str]:
    indicators = []
    for pattern, name in SUSPICIOUS_ENCODED_PATTERNS:
        if re.search(pattern, url):
            indicators.append(name)
    decoded = unquote(url)
    if decoded != url:
        if "percent_encoding" not in indicators:
            indicators.append("percent_encoding")
    return indicators


def parse_url(url: str) -> ParsedURL:
    """Parse and validate a user-submitted URL."""
    settings = get_settings()

    if not url or not url.strip():
        raise URLValidationError("URL is required", "empty_url")

    url = url.strip()
    if len(url) > settings.max_url_length:
        raise URLValidationError(
            f"URL exceeds maximum length of {settings.max_url_length} characters",
            "url_too_long",
        )

    # Add scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise URLValidationError(f"Malformed URL: {exc}", "malformed_url") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(
            f"Unsupported URL scheme: {scheme}. Only http and https are allowed.",
            "unsupported_scheme",
        )

    if not parsed.hostname:
        raise URLValidationError("URL must contain a valid hostname", "missing_host")

    host = _normalize_host(parsed.hostname)
    has_userinfo = bool(parsed.username or parsed.password)

    if has_userinfo:
        raise URLValidationError(
            "URLs with embedded credentials are not allowed",
            "userinfo_not_allowed",
        )

    # Detect IP tricks
    decoded_ip = _decode_ip_tricks(host)
    is_ip_host = False
    ip_address = None

    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        is_ip_host = True
        ip_address = str(ip)
    except ValueError:
        if decoded_ip:
            is_ip_host = True
            ip_address = decoded_ip

    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    encoding_indicators = _detect_encoding(url)

    # Check for shortener
    registrable = host.split(":")[0]
    is_shortener = any(
        registrable == s or registrable.endswith(f".{s}")
        for s in SHORTENER_DOMAINS
    )

    normalized = urlunparse((
        scheme,
        f"{host}:{port}" if port not in (80, 443) else host,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",  # strip fragment
    ))

    return ParsedURL(
        original=url,
        normalized=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        fragment=parsed.fragment,
        username=parsed.username,
        password=parsed.password,
        is_ip_host=is_ip_host,
        ip_address=ip_address,
        url_length=len(url),
        has_userinfo=has_userinfo,
        encoding_indicators=encoding_indicators,
        is_shortener=is_shortener,
    )
