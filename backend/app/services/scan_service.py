"""Main scan orchestration service."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.scan import Finding as FindingModel
from app.models.scan import Redirect as RedirectModel
from app.models.scan import ReputationResultModel, Scan
from app.scanners.dns_scanner import analyze_dns
from app.scanners.phishing_scanner import analyze_phishing
from app.scanners.tls_scanner import analyze_tls
from app.scanners.typosquat_scanner import detect_typosquat
from app.scanners.url_scanner import analyze_domain, analyze_url_structure
from app.schemas.scan import (
    DNSRecordResponse,
    DNSResponse,
    DomainResponse,
    FindingResponse,
    RedirectResponse,
    ReputationResponse,
    ScanResponse,
    ScanStageResponse,
    TLSResponse,
    TyposquatResponse,
    URLAnalysisResponse,
)
from app.security.safe_http import SafeHTTPClient
from app.security.url_parser import URLValidationError, parse_url
from app.services.reputation import get_reputation_providers
from app.services.risk_engine import RiskEngine, build_findings_from_analysis

logger = get_logger(__name__)


def _to_dict(obj):
    """Convert dataclass or object to dict recursively."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.settings = get_settings()
        self.http_client = SafeHTTPClient()
        self.risk_engine = RiskEngine()

    async def create_scan(self, url: str, client_ip: str | None = None) -> Scan:
        ip_hash = None
        if client_ip:
            ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]

        retention = timedelta(hours=self.settings.scan_retention_hours)
        scan = Scan(
            url=url,
            normalized_url=url,
            status="pending",
            client_ip_hash=ip_hash,
            expires_at=datetime.now(timezone.utc) + retention,
        )
        self.db.add(scan)
        await self.db.flush()
        return scan

    async def run_scan(self, scan: Scan) -> ScanResponse:
        stages: list[ScanStageResponse] = []
        scan.status = "running"
        await self.db.flush()

        try:
            # Stage 1: URL Validation
            stages.append(ScanStageResponse(stage="url_validation", status="running"))
            try:
                parsed = parse_url(scan.url)
                scan.normalized_url = parsed.normalized
                stages[-1].status = "completed"
            except URLValidationError as exc:
                stages[-1].status = "failed"
                scan.status = "failed"
                scan.summary = exc.message
                await self.db.flush()
                return self._error_response(scan, exc.message, stages)

            # Stage 2: URL/Domain Analysis
            stages.append(ScanStageResponse(stage="domain_analysis", status="running"))
            url_result = analyze_url_structure(parsed)
            domain_result = analyze_domain(parsed.host)
            typosquat_result = detect_typosquat(parsed.host)
            stages[-1].status = "completed"

            # Stage 3: Safe HTTP Fetch + Redirects
            stages.append(ScanStageResponse(stage="redirect_analysis", status="running"))
            http_response = await self.http_client.fetch(parsed)
            stages[-1].status = "completed" if http_response.reachable else "failed"

            # Stage 4: DNS
            stages.append(ScanStageResponse(stage="dns_analysis", status="running"))
            dns_result = await analyze_dns(parsed.host)
            stages[-1].status = "completed" if dns_result.status != "unavailable" else "unavailable"

            # Stage 5: TLS
            stages.append(ScanStageResponse(stage="tls_analysis", status="running"))
            tls_result = await analyze_tls(parsed.host, parsed.port or 443, parsed.scheme)
            stages[-1].status = "completed" if tls_result.status not in ("unavailable",) else "unavailable"

            # Stage 6: Phishing heuristics
            stages.append(ScanStageResponse(stage="phishing_analysis", status="running"))
            phishing_result = analyze_phishing(url_result, domain_result, http_response)
            stages[-1].status = "completed"

            # Stage 7: Reputation
            stages.append(ScanStageResponse(stage="reputation_check", status="running"))
            reputation_results = []
            for provider in get_reputation_providers():
                rep = await provider.check(parsed.normalized, parsed.host)
                reputation_results.append(rep)
            stages[-1].status = "completed"

            # Stage 8: Risk scoring
            stages.append(ScanStageResponse(stage="risk_scoring", status="running"))
            findings = build_findings_from_analysis(
                url_result, domain_result, dns_result, tls_result,
                http_response, phishing_result, typosquat_result, reputation_results,
            )
            risk = self.risk_engine.calculate(findings)
            stages[-1].status = "completed"

            # Persist results
            scan.status = "completed"
            scan.risk_score = risk.score
            scan.risk_level = risk.level.value
            scan.summary = risk.summary
            scan.recommended_action = risk.recommended_action
            scan.completed_at = datetime.now(timezone.utc)

            report_data = self._build_report_data(
                url_result, domain_result, dns_result, tls_result,
                http_response, typosquat_result, reputation_results, risk,
            )
            scan.report_data = report_data

            # Save findings
            for f in risk.findings:
                self.db.add(FindingModel(
                    scan_id=scan.id,
                    finding_id=f.id,
                    category=f.category.value,
                    severity=f.severity.value,
                    title=f.title,
                    description=f.description,
                    weight=f.weight,
                    evidence=f.evidence,
                ))

            # Save redirects
            for i, hop in enumerate(http_response.redirect_chain):
                self.db.add(RedirectModel(
                    scan_id=scan.id,
                    hop_order=i,
                    url=hop.url,
                    status_code=hop.status_code,
                    location=hop.location,
                ))

            # Save reputation
            for rep in reputation_results:
                self.db.add(ReputationResultModel(
                    scan_id=scan.id,
                    provider=rep.provider,
                    status=rep.status,
                    score=rep.score,
                    details=rep.details,
                ))

            await self.db.flush()
            return self._build_response(scan, report_data, stages)

        except Exception as exc:
            logger.error("scan_failed", scan_id=scan.id, error=str(exc))
            scan.status = "failed"
            scan.summary = "An unexpected error occurred during scanning."
            await self.db.flush()
            return self._error_response(
                scan, "We couldn't analyze this URL. Please try again later.", stages
            )

    def _build_report_data(self, url_result, domain_result, dns_result, tls_result,
                           http_response, typosquat_result, reputation_results, risk):
        return {
            "url_analysis": _to_dict(url_result),
            "domain": _to_dict(domain_result),
            "dns": _to_dict(dns_result),
            "tls": _to_dict(tls_result),
            "redirects": [_to_dict(h) for h in http_response.redirect_chain],
            "reputation": [_to_dict(r) for r in reputation_results],
            "typosquat": _to_dict(typosquat_result),
            "findings": [
                {
                    "id": f.id, "category": f.category.value, "severity": f.severity.value,
                    "title": f.title, "description": f.description,
                    "weight": f.weight, "evidence": f.evidence,
                }
                for f in risk.findings
            ],
            "positive_indicators": [
                {
                    "id": f.id, "category": f.category.value, "severity": f.severity.value,
                    "title": f.title, "description": f.description,
                    "weight": f.weight, "evidence": f.evidence,
                }
                for f in risk.positive_indicators
            ],
        }

    def _build_response(self, scan: Scan, report: dict, stages: list) -> ScanResponse:
        dns_data = report.get("dns", {})
        dns_records = dns_data.get("records", [])

        return ScanResponse(
            scan_id=scan.id,
            status=scan.status,
            risk_score=scan.risk_score,
            risk_level=scan.risk_level,
            summary=scan.summary,
            recommended_action=scan.recommended_action,
            findings=[FindingResponse(**f) for f in report.get("findings", [])],
            positive_indicators=[FindingResponse(**f) for f in report.get("positive_indicators", [])],
            url_analysis=URLAnalysisResponse(**report["url_analysis"]) if report.get("url_analysis") else None,
            domain=DomainResponse(**report["domain"]) if report.get("domain") else None,
            dns=DNSResponse(
                domain=dns_data.get("domain", ""),
                status=dns_data.get("status", "unavailable"),
                records=[DNSRecordResponse(**r) for r in dns_records],
                nameservers=dns_data.get("nameservers", []),
                error=dns_data.get("error"),
            ) if dns_data else None,
            tls=TLSResponse(**report["tls"]) if report.get("tls") else None,
            redirects=[RedirectResponse(**r) for r in report.get("redirects", [])],
            reputation=[ReputationResponse(**r) for r in report.get("reputation", [])],
            typosquat=TyposquatResponse(**report["typosquat"]) if report.get("typosquat") else None,
            stages=stages,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        )

    def _error_response(self, scan: Scan, message: str, stages: list) -> ScanResponse:
        return ScanResponse(
            scan_id=scan.id,
            status="failed",
            summary=message,
            recommended_action="Verify the URL is correct and try again. Do not visit suspicious URLs.",
            stages=stages,
            created_at=scan.created_at,
            error=message,
        )

    async def get_scan(self, scan_id: str) -> ScanResponse | None:
        from sqlalchemy import select
        result = await self.db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return None
        if scan.report_data:
            return self._build_response(scan, scan.report_data, [])
        return ScanResponse(
            scan_id=scan.id,
            status=scan.status,
            created_at=scan.created_at,
            error=scan.summary,
        )
