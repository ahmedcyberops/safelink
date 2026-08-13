"""Safe HTTP client with SSRF protection and redirect validation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.ssrf import SSRFError, resolve_and_validate, validate_redirect_destination
from app.security.url_parser import ParsedURL, URLValidationError, parse_url

logger = get_logger(__name__)

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        settings = get_settings()
        _semaphore = asyncio.Semaphore(settings.http_max_concurrent)
    return _semaphore


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None = None


@dataclass
class SafeHTTPResponse:
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    content_length: int | None
    content_type: str | None
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    error: str | None = None
    reachable: bool = True


class SafeHTTPClient:
    """HTTP client that validates every destination against SSRF rules."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def fetch(self, parsed: ParsedURL) -> SafeHTTPResponse:
        """Safely fetch a URL with redirect validation."""
        async with _get_semaphore():
            return await self._fetch_with_redirects(parsed)

    async def _fetch_with_redirects(self, parsed: ParsedURL) -> SafeHTTPResponse:
        redirect_chain: list[RedirectHop] = []
        current_url = parsed.normalized
        max_redirects = self.settings.http_max_redirects

        for hop in range(max_redirects + 1):
            try:
                current_parsed = parse_url(current_url)
            except URLValidationError as exc:
                return SafeHTTPResponse(
                    url=parsed.normalized,
                    final_url=current_url,
                    status_code=0,
                    headers={},
                    content_length=None,
                    content_type=None,
                    redirect_chain=redirect_chain,
                    error=exc.message,
                    reachable=False,
                )

            try:
                await resolve_and_validate(
                    current_parsed.host, current_parsed.port or 443
                )
            except (SSRFError, URLValidationError) as exc:
                return SafeHTTPResponse(
                    url=parsed.normalized,
                    final_url=current_url,
                    status_code=0,
                    headers={},
                    content_length=None,
                    content_type=None,
                    redirect_chain=redirect_chain,
                    error=getattr(exc, "message", str(exc)),
                    reachable=False,
                )

            try:
                response = await self._single_request(current_parsed)
            except httpx.TimeoutException:
                return SafeHTTPResponse(
                    url=parsed.normalized,
                    final_url=current_url,
                    status_code=0,
                    headers={},
                    content_length=None,
                    content_type=None,
                    redirect_chain=redirect_chain,
                    error="Connection timed out",
                    reachable=False,
                )
            except httpx.RequestError as exc:
                return SafeHTTPResponse(
                    url=parsed.normalized,
                    final_url=current_url,
                    status_code=0,
                    headers={},
                    content_length=None,
                    content_type=None,
                    redirect_chain=redirect_chain,
                    error=f"Request failed: {type(exc).__name__}",
                    reachable=False,
                )

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location", "")
                if not location:
                    break

                redirect_chain.append(RedirectHop(
                    url=current_url,
                    status_code=response.status_code,
                    location=location,
                ))

                if hop >= max_redirects:
                    return SafeHTTPResponse(
                        url=parsed.normalized,
                        final_url=current_url,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        content_length=None,
                        content_type=response.headers.get("content-type"),
                        redirect_chain=redirect_chain,
                        error=f"Too many redirects (>{max_redirects})",
                        reachable=True,
                    )

                # Resolve relative redirects
                if location.startswith("/"):
                    parsed_current = urlparse(current_url)
                    location = f"{parsed_current.scheme}://{parsed_current.netloc}{location}"
                elif not location.startswith(("http://", "https://")):
                    parsed_current = urlparse(current_url)
                    base_path = parsed_current.path.rsplit("/", 1)[0]
                    location = f"{parsed_current.scheme}://{parsed_current.netloc}{base_path}/{location}"

                try:
                    loc_parsed = parse_url(location)
                    validate_redirect_destination(
                        location, loc_parsed.host, loc_parsed.port or 443
                    )
                    await resolve_and_validate(
                        loc_parsed.host, loc_parsed.port or 443
                    )
                except (SSRFError, URLValidationError) as exc:
                    redirect_chain.append(RedirectHop(
                        url=location,
                        status_code=0,
                        location=str(getattr(exc, "message", exc)),
                    ))
                    return SafeHTTPResponse(
                        url=parsed.normalized,
                        final_url=current_url,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        content_length=None,
                        content_type=response.headers.get("content-type"),
                        redirect_chain=redirect_chain,
                        error=f"Blocked redirect: {getattr(exc, 'message', exc)}",
                        reachable=True,
                    )

                current_url = location
                continue

            # Non-redirect response
            content_length = response.headers.get("content-length")
            return SafeHTTPResponse(
                url=parsed.normalized,
                final_url=current_url,
                status_code=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                content_length=int(content_length) if content_length else len(response.content),
                content_type=response.headers.get("content-type"),
                redirect_chain=redirect_chain,
                reachable=True,
            )

        return SafeHTTPResponse(
            url=parsed.normalized,
            final_url=current_url,
            status_code=0,
            headers={},
            content_length=None,
            content_type=None,
            redirect_chain=redirect_chain,
            error="Unexpected end of redirect chain",
            reachable=False,
        )

    async def _single_request(self, parsed: ParsedURL) -> httpx.Response:
        timeout = httpx.Timeout(
            connect=self.settings.http_connect_timeout,
            read=self.settings.http_total_timeout,
            write=self.settings.http_total_timeout,
            pool=self.settings.http_total_timeout,
        )
        limits = httpx.Limits(max_connections=5)

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=False,
            verify=True,
            max_redirects=0,
        ) as client:
            response = await client.get(
                parsed.normalized,
                headers={
                    "User-Agent": "SafeLink-Scanner/1.0 (+https://safelink.local)",
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                },
            )
            # Limit response size
            if len(response.content) > self.settings.http_max_response_size:
                logger.warning(
                    "response_truncated",
                    url=parsed.normalized,
                    size=len(response.content),
                )
            return response
