"""Pydantic schemas for API request/response."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to scan")


class FindingResponse(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    description: str
    weight: int
    evidence: str | None = None


class DNSRecordResponse(BaseModel):
    type: str
    values: list[str]


class DNSResponse(BaseModel):
    domain: str
    status: str
    records: list[DNSRecordResponse] = []
    nameservers: list[str] = []
    error: str | None = None


class TLSResponse(BaseModel):
    https_enabled: bool
    status: str
    certificate_valid: bool | None = None
    issuer: str | None = None
    subject: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    tls_version: str | None = None
    hostname_match: bool | None = None
    error: str | None = None


class URLAnalysisResponse(BaseModel):
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
    suspicious_path_reasons: list[str] = []


class DomainResponse(BaseModel):
    domain: str
    registrable_domain: str
    subdomain: str
    tld: str
    subdomain_count: int
    has_excessive_subdomains: bool
    punycode_detected: bool
    homograph_indicators: list[str] = []
    suspicious_tld: bool = False


class RedirectResponse(BaseModel):
    url: str
    status_code: int
    location: str | None = None


class ReputationResponse(BaseModel):
    provider: str
    status: str
    score: int | None = None
    details: str | None = None
    categories: list[str] | None = None


class TyposquatResponse(BaseModel):
    possible_typosquat: bool
    confidence: str
    matched_brand: str | None = None
    reason: str | None = None


class ScanStageResponse(BaseModel):
    stage: str
    status: str  # pending | running | completed | failed | unavailable


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    risk_score: int | None = None
    risk_level: str | None = None
    summary: str | None = None
    recommended_action: str | None = None
    findings: list[FindingResponse] = []
    positive_indicators: list[FindingResponse] = []
    url_analysis: URLAnalysisResponse | None = None
    domain: DomainResponse | None = None
    dns: DNSResponse | None = None
    tls: TLSResponse | None = None
    redirects: list[RedirectResponse] = []
    reputation: list[ReputationResponse] = []
    typosquat: TyposquatResponse | None = None
    stages: list[ScanStageResponse] = []
    created_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class ErrorResponse(BaseModel):
    error: str
    code: str
    message: str


class HealthResponse(BaseModel):
    status: str
    version: str
    services: dict[str, str]
