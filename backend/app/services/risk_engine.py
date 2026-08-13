"""Modular risk scoring engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.core.config import get_settings


class FindingSeverity(str, Enum):
    INFO = "info"
    POSITIVE = "positive"
    WARNING = "warning"
    HIGH = "high"


class FindingCategory(str, Enum):
    URL_STRUCTURE = "url_structure"
    DOMAIN = "domain"
    DNS = "dns"
    TLS = "tls"
    REDIRECTS = "redirects"
    REPUTATION = "reputation"
    PHISHING = "phishing"
    TYPOSQUAT = "typosquat"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    SUSPICIOUS = "suspicious"
    HIGH = "high"
    UNABLE_TO_DETERMINE = "unable_to_determine"


@dataclass
class Finding:
    id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    weight: int
    evidence: str | None = None


@dataclass
class RiskScore:
    score: int
    level: RiskLevel
    findings: list[Finding]
    positive_indicators: list[Finding]
    summary: str
    recommended_action: str


SEVERITY_WEIGHTS = {
    FindingSeverity.INFO: 0,
    FindingSeverity.POSITIVE: -5,
    FindingSeverity.WARNING: 10,
    FindingSeverity.HIGH: 25,
}


class RiskEngine:
    """Calculate risk scores from structured security findings."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def calculate(self, findings: list[Finding]) -> RiskScore:
        raw_score = 0
        positive: list[Finding] = []
        warnings: list[Finding] = []
        high_risk: list[Finding] = []

        for finding in findings:
            if finding.severity == FindingSeverity.POSITIVE:
                positive.append(finding)
                raw_score += finding.weight  # negative weights
            elif finding.severity == FindingSeverity.HIGH:
                high_risk.append(finding)
                raw_score += finding.weight
            elif finding.severity == FindingSeverity.WARNING:
                warnings.append(finding)
                raw_score += finding.weight
            else:
                raw_score += finding.weight

        score = max(0, min(100, raw_score))
        level = self._score_to_level(score)
        summary = self._build_summary(score, level, warnings, high_risk, positive)
        action = self._recommended_action(level)

        return RiskScore(
            score=score,
            level=level,
            findings=findings,
            positive_indicators=positive,
            summary=summary,
            recommended_action=action,
        )

    def _score_to_level(self, score: int) -> RiskLevel:
        s = self.settings
        if score <= s.risk_threshold_low:
            return RiskLevel.LOW
        if score <= s.risk_threshold_moderate:
            return RiskLevel.MODERATE
        if score <= s.risk_threshold_suspicious:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.HIGH

    def _build_summary(
        self,
        score: int,
        level: RiskLevel,
        warnings: list[Finding],
        high_risk: list[Finding],
        positive: list[Finding],
    ) -> str:
        parts = []
        if high_risk:
            parts.append(f"{len(high_risk)} high-risk indicator(s) detected")
        if warnings:
            parts.append(f"{len(warnings)} warning(s) found")
        if positive:
            parts.append(f"{len(positive)} positive security indicator(s)")
        if not parts:
            parts.append("Limited indicators available for this URL")
        return f"Risk score {score}/100 ({level.value}): " + "; ".join(parts) + "."

    def _recommended_action(self, level: RiskLevel) -> str:
        actions = {
            RiskLevel.LOW: "This URL shows relatively few risk indicators, but no URL can be guaranteed safe. Proceed with normal caution.",
            RiskLevel.MODERATE: "Some risk indicators were found. Verify the URL through an independent source before entering sensitive information.",
            RiskLevel.SUSPICIOUS: "Multiple suspicious indicators detected. Avoid entering credentials or personal information. Verify through the official website directly.",
            RiskLevel.HIGH: "Significant risk indicators detected. Do not visit this URL or enter any personal information. Report if received unexpectedly.",
            RiskLevel.UNABLE_TO_DETERMINE: "Unable to fully analyze this URL. Treat with caution and verify through official channels.",
        }
        return actions.get(level, actions[RiskLevel.UNABLE_TO_DETERMINE])


def build_findings_from_analysis(
    url_result: Any,
    domain_result: Any,
    dns_result: Any,
    tls_result: Any,
    http_response: Any,
    phishing_result: Any,
    typosquat_result: Any,
    reputation_results: list[Any],
) -> list[Finding]:
    """Convert scanner results into weighted findings for the risk engine."""
    findings: list[Finding] = []

    # URL structure
    if url_result.is_ip_host:
        findings.append(Finding(
            id="url_ip_host", category=FindingCategory.URL_STRUCTURE,
            severity=FindingSeverity.WARNING, title="IP address hostname",
            description="URL uses a raw IP address instead of a domain name.",
            weight=15, evidence=url_result.ip_address,
        ))

    if url_result.is_shortener:
        findings.append(Finding(
            id="url_shortener", category=FindingCategory.URL_STRUCTURE,
            severity=FindingSeverity.WARNING, title="URL shortener detected",
            description="Link shortening service may hide the final destination.",
            weight=10,
        ))

    if url_result.encoding_indicators:
        findings.append(Finding(
            id="url_encoding", category=FindingCategory.URL_STRUCTURE,
            severity=FindingSeverity.WARNING, title="Encoded URL characters",
            description="URL contains encoded characters that may obscure its destination.",
            weight=8, evidence=", ".join(url_result.encoding_indicators),
        ))

    if url_result.url_length > 200:
        findings.append(Finding(
            id="url_long", category=FindingCategory.URL_STRUCTURE,
            severity=FindingSeverity.WARNING, title="Unusually long URL",
            description=f"URL is {url_result.url_length} characters long.",
            weight=5,
        ))

    # Domain
    if domain_result.has_excessive_subdomains:
        findings.append(Finding(
            id="domain_subdomains", category=FindingCategory.DOMAIN,
            severity=FindingSeverity.WARNING, title="Excessive subdomains",
            description=f"Domain has {domain_result.subdomain_count} subdomains.",
            weight=12,
        ))

    if domain_result.suspicious_tld:
        findings.append(Finding(
            id="domain_tld", category=FindingCategory.DOMAIN,
            severity=FindingSeverity.WARNING, title="Suspicious TLD",
            description=f"Domain uses TLD '.{domain_result.tld}' commonly associated with abuse.",
            weight=8, evidence=domain_result.tld,
        ))

    if domain_result.homograph_indicators:
        findings.append(Finding(
            id="domain_homograph", category=FindingCategory.DOMAIN,
            severity=FindingSeverity.HIGH, title="Possible homograph attack",
            description="Domain contains characters resembling ASCII letters.",
            weight=25, evidence="; ".join(domain_result.homograph_indicators[:2]),
        ))

    if domain_result.punycode_detected:
        findings.append(Finding(
            id="domain_punycode", category=FindingCategory.DOMAIN,
            severity=FindingSeverity.WARNING, title="Internationalized domain",
            description="Punycode-encoded domain may hide visually similar characters.",
            weight=10,
        ))

    # DNS
    if dns_result.status == "nxdomain":
        findings.append(Finding(
            id="dns_nxdomain", category=FindingCategory.DNS,
            severity=FindingSeverity.HIGH, title="Domain does not exist",
            description="DNS lookup returned NXDOMAIN — the domain does not exist.",
            weight=20,
        ))
    elif dns_result.status == "unavailable":
        findings.append(Finding(
            id="dns_unavailable", category=FindingCategory.DNS,
            severity=FindingSeverity.INFO, title="DNS analysis unavailable",
            description="Could not complete DNS analysis.", weight=0,
        ))
    elif dns_result.records:
        findings.append(Finding(
            id="dns_resolved", category=FindingCategory.DNS,
            severity=FindingSeverity.POSITIVE, title="Domain resolves in DNS",
            description="Domain has valid DNS records.", weight=-3,
        ))

    # TLS
    if tls_result.status == "success":
        if tls_result.https_enabled and tls_result.certificate_valid:
            findings.append(Finding(
                id="tls_valid", category=FindingCategory.TLS,
                severity=FindingSeverity.POSITIVE, title="Valid HTTPS certificate",
                description="HTTPS is enabled with a valid certificate. Note: HTTPS alone does not guarantee safety.",
                weight=-5,
            ))
        if tls_result.certificate_valid is False:
            findings.append(Finding(
                id="tls_invalid", category=FindingCategory.TLS,
                severity=FindingSeverity.HIGH, title="Invalid TLS certificate",
                description="TLS certificate validation failed.",
                weight=20, evidence=tls_result.error,
            ))
        if tls_result.days_until_expiry is not None and tls_result.days_until_expiry < 7:
            findings.append(Finding(
                id="tls_expiring", category=FindingCategory.TLS,
                severity=FindingSeverity.WARNING, title="Certificate expiring soon",
                description=f"Certificate expires in {tls_result.days_until_expiry} days.",
                weight=5,
            ))
    elif tls_result.status == "not_applicable":
        findings.append(Finding(
            id="tls_no_https", category=FindingCategory.TLS,
            severity=FindingSeverity.WARNING, title="No HTTPS",
            description="URL does not use HTTPS encryption.",
            weight=10,
        ))

    # Redirects
    if http_response and http_response.redirect_chain:
        count = len(http_response.redirect_chain)
        if count >= 3:
            findings.append(Finding(
                id="redirect_many", category=FindingCategory.REDIRECTS,
                severity=FindingSeverity.HIGH, title="Multiple redirects",
                description=f"URL chain includes {count} redirects.",
                weight=15,
            ))
        elif count >= 1:
            findings.append(Finding(
                id="redirect_some", category=FindingCategory.REDIRECTS,
                severity=FindingSeverity.WARNING, title="Redirects detected",
                description=f"URL chain includes {count} redirect(s).",
                weight=5,
            ))

    if http_response and not http_response.reachable:
        findings.append(Finding(
            id="http_unreachable", category=FindingCategory.URL_STRUCTURE,
            severity=FindingSeverity.INFO, title="Destination unreachable",
            description="The URL destination could not be safely reached.",
            weight=5, evidence=http_response.error,
        ))

    # Phishing heuristics
    for h in phishing_result.heuristics:
        if h.triggered and h.severity in ("warning", "high"):
            sev = FindingSeverity.HIGH if h.severity == "high" else FindingSeverity.WARNING
            weight = 20 if h.severity == "high" else 8
            findings.append(Finding(
                id=f"phishing_{h.id}", category=FindingCategory.PHISHING,
                severity=sev, title=h.title, description=h.description,
                weight=weight, evidence=h.evidence,
            ))

    # Typosquat
    if typosquat_result.possible_typosquat:
        conf_weight = {"high": 25, "medium": 15, "low": 8}
        findings.append(Finding(
            id="typosquat", category=FindingCategory.TYPOSQUAT,
            severity=FindingSeverity.HIGH if typosquat_result.confidence == "high" else FindingSeverity.WARNING,
            title="Possible typosquatting",
            description=typosquat_result.reason or "Domain may impersonate a known brand.",
            weight=conf_weight.get(typosquat_result.confidence, 10),
            evidence=typosquat_result.matched_brand,
        ))

    # Reputation
    for rep in reputation_results:
        if rep.status == "malicious":
            findings.append(Finding(
                id=f"rep_{rep.provider}_malicious", category=FindingCategory.REPUTATION,
                severity=FindingSeverity.HIGH, title=f"Flagged by {rep.provider}",
                description=rep.details or "URL/domain flagged as potentially malicious.",
                weight=30, evidence=str(rep.score),
            ))
        elif rep.status == "suspicious":
            findings.append(Finding(
                id=f"rep_{rep.provider}_suspicious", category=FindingCategory.REPUTATION,
                severity=FindingSeverity.WARNING, title=f"Suspicious per {rep.provider}",
                description=rep.details or "URL/domain flagged as suspicious.",
                weight=15, evidence=str(rep.score),
            ))
        elif rep.status == "clean":
            findings.append(Finding(
                id=f"rep_{rep.provider}_clean", category=FindingCategory.REPUTATION,
                severity=FindingSeverity.POSITIVE, title=f"Clean per {rep.provider}",
                description="No malicious indicators found.", weight=-5,
            ))

    return findings
