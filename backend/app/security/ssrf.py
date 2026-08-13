"""SSRF protection - block private/internal/reserved IP ranges."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from app.core.logging import get_logger
from app.security.url_parser import URLValidationError

logger = get_logger(__name__)

# Blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google",
    "metadata",
    "instance-data",
}

# Cloud metadata endpoints
METADATA_HOSTS = {
    "169.254.169.254",
    "100.100.100.200",  # Alibaba
    "fd00:ec2::254",
}

# Internal TLD patterns
INTERNAL_TLD_PATTERNS = [
    re.compile(r"\.local$"),
    re.compile(r"\.internal$"),
    re.compile(r"\.localhost$"),
    re.compile(r"\.corp$"),
    re.compile(r"\.lan$"),
    re.compile(r"\.home$"),
    re.compile(r"\.localdomain$"),
]


class SSRFError(Exception):
    """Raised when a destination is blocked by SSRF protection."""

    def __init__(self, message: str, code: str = "ssrf_blocked"):
        self.message = message
        self.code = code
        super().__init__(message)


@dataclass
class ResolvedHost:
    hostname: str
    ip_addresses: list[str]


def is_blocked_ip(ip_str: str) -> tuple[bool, str]:
    """Check if an IP address is in a blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address: {ip_str}"

    if ip.is_loopback:
        return True, "Loopback address blocked"
    if ip.is_private:
        return True, "Private network address blocked"
    if ip.is_link_local:
        return True, "Link-local address blocked"
    if ip.is_multicast:
        return True, "Multicast address blocked"
    if ip.is_reserved:
        return True, "Reserved address blocked"
    if ip.is_unspecified:
        return True, "Unspecified address blocked"

    # Cloud metadata
    if ip_str in METADATA_HOSTS:
        return True, "Cloud metadata endpoint blocked"

    # CGNAT range 100.64.0.0/10
    if ip.version == 4:
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if ip in cgnat:
            return True, "CGNAT address blocked"

    return False, ""


def is_blocked_hostname(hostname: str) -> tuple[bool, str]:
    """Check if a hostname should be blocked."""
    hostname = hostname.lower().strip(".")

    if hostname in BLOCKED_HOSTNAMES:
        return True, f"Blocked hostname: {hostname}"

    if hostname in METADATA_HOSTS:
        return True, "Cloud metadata endpoint blocked"

    for pattern in INTERNAL_TLD_PATTERNS:
        if pattern.search(hostname):
            return True, f"Internal hostname pattern blocked: {hostname}"

    # Block raw IP in hostname that is blocked
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        return is_blocked_ip(str(ip))
    except ValueError:
        pass

    return False, ""


async def resolve_and_validate(hostname: str, port: int = 443) -> ResolvedHost:
    """
    Resolve DNS and validate all resulting IPs against SSRF blocklist.
    Protects against DNS rebinding by validating at resolution time.
    """
    blocked, reason = is_blocked_hostname(hostname)
    if blocked:
        raise SSRFError(reason, "blocked_hostname")

    # If hostname is already an IP, validate directly
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        blocked, reason = is_blocked_ip(str(ip))
        if blocked:
            raise SSRFError(reason, "blocked_ip")
        return ResolvedHost(hostname=hostname, ip_addresses=[str(ip)])
    except ValueError:
        pass

    try:
        loop = __import__("asyncio").get_event_loop()
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            ),
        )
    except socket.gaierror as exc:
        raise URLValidationError(
            f"DNS resolution failed for {hostname}: {exc}",
            "dns_resolution_failed",
        ) from exc

    if not infos:
        raise URLValidationError(
            f"No DNS records found for {hostname}",
            "dns_no_records",
        )

    ip_addresses: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        blocked, reason = is_blocked_ip(ip_str)
        if blocked:
            raise SSRFError(
                f"Resolved IP {ip_str} for {hostname} is blocked: {reason}",
                "blocked_resolved_ip",
            )
        if ip_str not in ip_addresses:
            ip_addresses.append(ip_str)

    logger.debug("dns_resolved", hostname=hostname, ips=ip_addresses)
    return ResolvedHost(hostname=hostname, ip_addresses=ip_addresses)


def validate_redirect_destination(url: str, parsed_host: str, port: int) -> None:
    """Validate a redirect destination before following."""
    blocked, reason = is_blocked_hostname(parsed_host)
    if blocked:
        raise SSRFError(
            f"Redirect to blocked destination: {reason}",
            "blocked_redirect",
        )

    try:
        ip = ipaddress.ip_address(parsed_host.strip("[]"))
        blocked, reason = is_blocked_ip(str(ip))
        if blocked:
            raise SSRFError(
                f"Redirect to blocked IP: {reason}",
                "blocked_redirect_ip",
            )
    except ValueError:
        pass
