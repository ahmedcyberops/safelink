"""Reputation provider abstraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ReputationResult:
    provider: str
    status: str  # clean | suspicious | malicious | unavailable
    score: int | None = None
    details: str | None = None
    categories: list[str] | None = None


class ReputationProvider(ABC):
    name: str

    @abstractmethod
    async def check(self, url: str, domain: str) -> ReputationResult:
        ...


class MockReputationProvider(ReputationProvider):
    name = "mock"

    async def check(self, url: str, domain: str) -> ReputationResult:
        """Mock provider for local development."""
        suspicious_keywords = ["phish", "malware", "evil", "hack", "steal", "fake"]
        domain_lower = domain.lower()
        for kw in suspicious_keywords:
            if kw in domain_lower:
                return ReputationResult(
                    provider=self.name,
                    status="suspicious",
                    score=65,
                    details=f"Mock provider: domain contains suspicious keyword '{kw}'",
                    categories=["phishing"],
                )
        return ReputationResult(
            provider=self.name,
            status="clean",
            score=0,
            details="Mock provider: no indicators found (development mode)",
        )


class VirusTotalProvider(ReputationProvider):
    name = "virustotal"

    async def check(self, url: str, domain: str) -> ReputationResult:
        settings = get_settings()
        if not settings.reputation_api_key:
            return ReputationResult(
                provider=self.name,
                status="unavailable",
                details="VirusTotal API key not configured",
            )
        try:
            import httpx
            import base64

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": settings.reputation_api_key}

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                )
                if resp.status_code == 404:
                    return ReputationResult(
                        provider=self.name,
                        status="clean",
                        score=0,
                        details="URL not found in VirusTotal database",
                    )
                if resp.status_code != 200:
                    return ReputationResult(
                        provider=self.name,
                        status="unavailable",
                        details=f"VirusTotal API returned status {resp.status_code}",
                    )
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                score = int((malicious * 2 + suspicious) / total * 100)

                if malicious > 0:
                    status = "malicious"
                elif suspicious > 0:
                    status = "suspicious"
                else:
                    status = "clean"

                return ReputationResult(
                    provider=self.name,
                    status=status,
                    score=score,
                    details=f"{malicious} malicious, {suspicious} suspicious of {total} engines",
                )
        except Exception as exc:
            logger.warning("virustotal_check_failed", error=str(exc))
            return ReputationResult(
                provider=self.name,
                status="unavailable",
                details=f"VirusTotal check failed: {type(exc).__name__}",
            )


def get_reputation_providers() -> list[ReputationProvider]:
    settings = get_settings()
    providers: list[ReputationProvider] = [MockReputationProvider()]
    if settings.reputation_provider == "virustotal" and settings.reputation_api_key:
        providers.append(VirusTotalProvider())
    return providers
