"""Tests for risk scoring engine."""

from app.services.risk_engine import (
    Finding,
    FindingCategory,
    FindingSeverity,
    RiskEngine,
    RiskLevel,
)


class TestRiskEngine:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_low_risk_case(self):
        findings = [
            Finding(
                id="tls_valid", category=FindingCategory.TLS,
                severity=FindingSeverity.POSITIVE, title="Valid HTTPS",
                description="HTTPS enabled", weight=-5,
            ),
            Finding(
                id="dns_resolved", category=FindingCategory.DNS,
                severity=FindingSeverity.POSITIVE, title="DNS resolves",
                description="Valid DNS", weight=-3,
            ),
        ]
        result = self.engine.calculate(findings)
        assert result.score <= 20
        assert result.level == RiskLevel.LOW

    def test_moderate_risk_case(self):
        findings = [
            Finding(
                id="url_shortener", category=FindingCategory.URL_STRUCTURE,
                severity=FindingSeverity.WARNING, title="Shortener",
                description="URL shortener", weight=10,
            ),
            Finding(
                id="redirect_some", category=FindingCategory.REDIRECTS,
                severity=FindingSeverity.WARNING, title="Redirects",
                description="Some redirects", weight=5,
            ),
            Finding(
                id="domain_tld", category=FindingCategory.DOMAIN,
                severity=FindingSeverity.WARNING, title="Suspicious TLD",
                description="Bad TLD", weight=8,
            ),
        ]
        result = self.engine.calculate(findings)
        assert 21 <= result.score <= 50
        assert result.level == RiskLevel.MODERATE

    def test_suspicious_case(self):
        findings = [
            Finding(
                id="phishing_login", category=FindingCategory.PHISHING,
                severity=FindingSeverity.HIGH, title="Login on suspicious domain",
                description="Phishing pattern", weight=20,
            ),
            Finding(
                id="redirect_many", category=FindingCategory.REDIRECTS,
                severity=FindingSeverity.HIGH, title="Many redirects",
                description="Multiple redirects", weight=15,
            ),
            Finding(
                id="domain_subdomains", category=FindingCategory.DOMAIN,
                severity=FindingSeverity.WARNING, title="Excessive subdomains",
                description="Many subdomains", weight=12,
            ),
            Finding(
                id="url_encoding", category=FindingCategory.URL_STRUCTURE,
                severity=FindingSeverity.WARNING, title="Encoded URL",
                description="Encoded chars", weight=8,
            ),
        ]
        result = self.engine.calculate(findings)
        assert 51 <= result.score <= 75
        assert result.level == RiskLevel.SUSPICIOUS

    def test_high_risk_case(self):
        findings = [
            Finding(
                id="rep_malicious", category=FindingCategory.REPUTATION,
                severity=FindingSeverity.HIGH, title="Flagged malicious",
                description="Malicious", weight=30,
            ),
            Finding(
                id="domain_homograph", category=FindingCategory.DOMAIN,
                severity=FindingSeverity.HIGH, title="Homograph",
                description="Homograph attack", weight=25,
            ),
            Finding(
                id="typosquat", category=FindingCategory.TYPOSQUAT,
                severity=FindingSeverity.HIGH, title="Typosquat",
                description="Brand impersonation", weight=25,
            ),
        ]
        result = self.engine.calculate(findings)
        assert result.score >= 76
        assert result.level == RiskLevel.HIGH

    def test_score_capped_at_100(self):
        findings = [
            Finding(
                id=f"high_{i}", category=FindingCategory.PHISHING,
                severity=FindingSeverity.HIGH, title=f"High {i}",
                description="High risk", weight=25,
            )
            for i in range(10)
        ]
        result = self.engine.calculate(findings)
        assert result.score == 100

    def test_recommended_action_exists(self):
        findings = []
        result = self.engine.calculate(findings)
        assert result.recommended_action
        assert "100% safe" not in result.recommended_action.lower()
        assert "absolutely safe" not in result.recommended_action.lower()
