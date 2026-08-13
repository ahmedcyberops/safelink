export type RiskLevel = 'low' | 'moderate' | 'suspicious' | 'high' | 'unable_to_determine';

export type FindingSeverity = 'info' | 'positive' | 'warning' | 'high';

export interface Finding {
  id: string;
  category: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  weight: number;
  evidence?: string | null;
}

export interface DNSRecord {
  type: string;
  values: string[];
}

export interface DNSInfo {
  domain: string;
  status: string;
  records: DNSRecord[];
  nameservers: string[];
  error?: string | null;
}

export interface TLSInfo {
  https_enabled: boolean;
  status: string;
  certificate_valid?: boolean | null;
  issuer?: string | null;
  subject?: string | null;
  not_before?: string | null;
  not_after?: string | null;
  days_until_expiry?: number | null;
  tls_version?: string | null;
  hostname_match?: boolean | null;
  error?: string | null;
}

export interface URLAnalysis {
  scheme: string;
  host: string;
  port?: number | null;
  path: string;
  query: string;
  url_length: number;
  is_ip_host: boolean;
  ip_address?: string | null;
  encoding_indicators: string[];
  is_shortener: boolean;
  query_param_count: number;
  has_suspicious_path: boolean;
  suspicious_path_reasons: string[];
}

export interface DomainInfo {
  domain: string;
  registrable_domain: string;
  subdomain: string;
  tld: string;
  subdomain_count: number;
  has_excessive_subdomains: boolean;
  punycode_detected: boolean;
  homograph_indicators: string[];
  suspicious_tld: boolean;
}

export interface RedirectHop {
  url: string;
  status_code: number;
  location?: string | null;
}

export interface ReputationInfo {
  provider: string;
  status: string;
  score?: number | null;
  details?: string | null;
  categories?: string[] | null;
}

export interface TyposquatInfo {
  possible_typosquat: boolean;
  confidence: string;
  matched_brand?: string | null;
  reason?: string | null;
}

export interface ScanStage {
  stage: string;
  status: string;
}

export interface ScanResult {
  scan_id: string;
  status: string;
  risk_score?: number | null;
  risk_level?: RiskLevel | null;
  summary?: string | null;
  recommended_action?: string | null;
  findings: Finding[];
  positive_indicators: Finding[];
  url_analysis?: URLAnalysis | null;
  domain?: DomainInfo | null;
  dns?: DNSInfo | null;
  tls?: TLSInfo | null;
  redirects: RedirectHop[];
  reputation: ReputationInfo[];
  typosquat?: TyposquatInfo | null;
  stages: ScanStage[];
  created_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
}

export interface ScanError {
  error: string;
  code: string;
  message: string;
}
