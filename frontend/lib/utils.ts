import type { RiskLevel } from '@/types/scan';

export const getRiskColor = (level: RiskLevel | string | null | undefined): string => {
  switch (level) {
    case 'low': return 'text-risk-low';
    case 'moderate': return 'text-risk-moderate';
    case 'suspicious': return 'text-risk-suspicious';
    case 'high': return 'text-risk-high';
    default: return 'text-risk-unknown';
  }
};

export const getRiskBgColor = (level: RiskLevel | string | null | undefined): string => {
  switch (level) {
    case 'low': return 'bg-risk-low/10 border-risk-low/30';
    case 'moderate': return 'bg-risk-moderate/10 border-risk-moderate/30';
    case 'suspicious': return 'bg-risk-suspicious/10 border-risk-suspicious/30';
    case 'high': return 'bg-risk-high/10 border-risk-high/30';
    default: return 'bg-risk-unknown/10 border-risk-unknown/30';
  }
};

export const getRiskLabel = (level: RiskLevel | string | null | undefined): string => {
  switch (level) {
    case 'low': return 'Low Risk';
    case 'moderate': return 'Moderate Risk';
    case 'suspicious': return 'Suspicious';
    case 'high': return 'High Risk';
    case 'unable_to_determine': return 'Unable to Determine';
    default: return 'Unknown';
  }
};

export const getSeverityIcon = (severity: string): string => {
  switch (severity) {
    case 'positive': return '✓';
    case 'warning': return '⚠';
    case 'high': return '✕';
    default: return 'ℹ';
  }
};

export const formatStageName = (stage: string): string => {
  const names: Record<string, string> = {
    url_validation: 'URL validation',
    domain_analysis: 'Domain analysis',
    redirect_analysis: 'Checking redirects',
    dns_analysis: 'DNS analysis',
    tls_analysis: 'TLS/HTTPS analysis',
    phishing_analysis: 'Phishing heuristics',
    reputation_check: 'Checking reputation',
    risk_scoring: 'Calculating risk score',
  };
  return names[stage] || stage;
};

export const copyToClipboard = async (text: string): Promise<boolean> => {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
};
