'use client';

import type { ScanResult } from '@/types/scan';
import { RiskScore } from './RiskScore';
import { FindingsList } from './FindingsList';
import { DetailSection, DetailRow } from './DetailSection';
import { CopyButton, PrintButton } from './CopyButton';
import { AlertTriangle, Info } from 'lucide-react';
import Link from 'next/link';

interface ScanReportProps {
  result: ScanResult;
}

export const ScanReport = ({ result }: ScanReportProps) => {
  const reportJson = JSON.stringify(result, null, 2);

  if (result.status === 'failed') {
    return (
      <div className="mx-auto max-w-2xl animate-fade-in px-4 py-12 text-center">
        <div className="glass-card p-8">
          <AlertTriangle className="mx-auto mb-4 h-12 w-12 text-risk-suspicious" aria-hidden="true" />
          <h1 className="mb-2 text-2xl font-bold">Analysis Failed</h1>
          <p className="mb-4 text-[hsl(var(--muted-foreground))]">
            {result.error || result.summary || "We couldn't analyze this URL."}
          </p>
          <p className="mb-6 text-sm text-[hsl(var(--muted-foreground))]">
            {result.recommended_action}
          </p>
          <Link href="/" className="btn-primary">
            Scan another URL
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl animate-fade-in px-4 py-8 sm:px-6">
      {/* Header */}
      <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold sm:text-3xl">Security Analysis</h1>
          <p className="mt-1 truncate font-mono text-sm text-[hsl(var(--muted-foreground))]">
            {result.url_analysis?.host || 'Unknown URL'}
          </p>
        </div>
        <div className="flex gap-2 no-print">
          <CopyButton text={reportJson} label="Copy report" />
          <PrintButton />
        </div>
      </div>

      {/* Score + Summary */}
      <div className="mb-8 grid gap-6 lg:grid-cols-2">
        {result.risk_score != null && result.risk_level && (
          <RiskScore score={result.risk_score} level={result.risk_level} />
        )}
        <div className="glass-card flex flex-col justify-center p-6">
          <h2 className="mb-2 text-lg font-semibold">Overall Assessment</h2>
          <p className="text-sm leading-relaxed text-[hsl(var(--muted-foreground))]">
            {result.summary}
          </p>
          {result.recommended_action && (
            <div className="mt-4 flex items-start gap-2 rounded-lg bg-brand-600/10 p-3">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-brand-500" aria-hidden="true" />
              <p className="text-sm">{result.recommended_action}</p>
            </div>
          )}
          <p className="mt-4 text-xs text-[hsl(var(--muted-foreground))]">
            This analysis is probabilistic. No URL can be guaranteed safe.
          </p>
        </div>
      </div>

      {/* Findings */}
      <div className="mb-8 grid gap-6 lg:grid-cols-2">
        <FindingsList
          findings={result.findings.filter((f) => f.severity !== 'positive')}
          title="Why this URL received this score"
          emptyMessage="No warning indicators detected."
        />
        <FindingsList
          findings={result.positive_indicators}
          title="Positive security indicators"
          emptyMessage="No positive indicators found."
        />
      </div>

      {/* Technical Details */}
      <div className="space-y-6">
        {result.url_analysis && (
          <DetailSection title="URL Analysis">
            <DetailRow label="Scheme" value={result.url_analysis.scheme} />
            <DetailRow label="Host" value={result.url_analysis.host} mono />
            <DetailRow label="Port" value={result.url_analysis.port} />
            <DetailRow label="Path" value={result.url_analysis.path} mono />
            <DetailRow label="Query parameters" value={result.url_analysis.query_param_count} />
            <DetailRow label="URL length" value={`${result.url_analysis.url_length} chars`} />
            <DetailRow label="IP address host" value={result.url_analysis.is_ip_host} />
            {result.url_analysis.ip_address && (
              <DetailRow label="IP address" value={result.url_analysis.ip_address} mono />
            )}
            <DetailRow label="URL shortener" value={result.url_analysis.is_shortener} />
            {result.url_analysis.encoding_indicators.length > 0 && (
              <DetailRow
                label="Encoding indicators"
                value={result.url_analysis.encoding_indicators.join(', ')}
              />
            )}
          </DetailSection>
        )}

        {result.domain && (
          <DetailSection title="Domain Analysis">
            <DetailRow label="Domain" value={result.domain.domain} mono />
            <DetailRow label="Registrable domain" value={result.domain.registrable_domain} mono />
            <DetailRow label="Subdomain" value={result.domain.subdomain || '—'} />
            <DetailRow label="TLD" value={`.${result.domain.tld}`} />
            <DetailRow label="Subdomain count" value={result.domain.subdomain_count} />
            <DetailRow label="Excessive subdomains" value={result.domain.has_excessive_subdomains} />
            <DetailRow label="Punycode detected" value={result.domain.punycode_detected} />
            <DetailRow label="Suspicious TLD" value={result.domain.suspicious_tld} />
          </DetailSection>
        )}

        {result.dns && (
          <DetailSection title="DNS">
            <DetailRow label="Status" value={result.dns.status} />
            {result.dns.error && <DetailRow label="Error" value={result.dns.error} />}
            {result.dns.records.map((record) => (
              <DetailRow
                key={record.type}
                label={record.type}
                value={record.values.join(', ')}
                mono
              />
            ))}
            {result.dns.nameservers.length > 0 && (
              <DetailRow label="Nameservers" value={result.dns.nameservers.join(', ')} mono />
            )}
          </DetailSection>
        )}

        {result.tls && (
          <DetailSection title="TLS / HTTPS">
            <DetailRow label="HTTPS enabled" value={result.tls.https_enabled} />
            <DetailRow label="Status" value={result.tls.status} />
            {result.tls.certificate_valid != null && (
              <DetailRow label="Certificate valid" value={result.tls.certificate_valid} />
            )}
            {result.tls.issuer && <DetailRow label="Issuer" value={result.tls.issuer} />}
            {result.tls.not_after && <DetailRow label="Expires" value={result.tls.not_after} />}
            {result.tls.days_until_expiry != null && (
              <DetailRow label="Days until expiry" value={result.tls.days_until_expiry} />
            )}
            {result.tls.tls_version && <DetailRow label="TLS version" value={result.tls.tls_version} />}
            {result.tls.error && <DetailRow label="Error" value={result.tls.error} />}
          </DetailSection>
        )}

        {result.redirects.length > 0 && (
          <DetailSection title="Redirect Chain">
            {result.redirects.map((hop, i) => (
              <DetailRow
                key={i}
                label={`Hop ${i + 1} (${hop.status_code})`}
                value={hop.location || hop.url}
                mono
              />
            ))}
          </DetailSection>
        )}

        {result.reputation.length > 0 && (
          <DetailSection title="Reputation">
            {result.reputation.map((rep) => (
              <DetailRow
                key={rep.provider}
                label={rep.provider}
                value={
                  rep.status === 'unavailable'
                    ? 'Unavailable'
                    : `${rep.status}${rep.score != null ? ` (score: ${rep.score})` : ''}${rep.details ? ` — ${rep.details}` : ''}`
                }
              />
            ))}
          </DetailSection>
        )}

        {result.typosquat && (
          <DetailSection title="Typosquatting Analysis">
            <DetailRow label="Possible typosquat" value={result.typosquat.possible_typosquat} />
            <DetailRow label="Confidence" value={result.typosquat.confidence} />
            {result.typosquat.matched_brand && (
              <DetailRow label="Matched brand" value={result.typosquat.matched_brand} />
            )}
            {result.typosquat.reason && (
              <DetailRow label="Reason" value={result.typosquat.reason} />
            )}
          </DetailSection>
        )}
      </div>

      <div className="mt-8 text-center no-print">
        <Link href="/" className="btn-primary">
          Scan another URL
        </Link>
      </div>
    </div>
  );
};
