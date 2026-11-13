export interface Overall {
  status: string;
  label: string;
}

export interface Validity {
  not_before: string;
  not_after: string;
  remaining_days: number | null;
  risk_level: string;
}

export interface Party {
  organization: string | null;
  common_name: string | null;
  distinguished_name: string;
}

export interface Subject {
  common_name: string | null;
  organization: string | null;
  distinguished_name: string;
}

export interface DomainMatch {
  matched: boolean;
  matched_name: string | null;
  source: string | null;
  cn: string | null;
  san_dns: string[];
  san_ip: string[];
  wildcard: boolean;
}

export interface ChainItem {
  role: string;
  role_label: string;
  common_name: string;
  status: string;
  status_label: string;
}

export interface Chain {
  status: string;
  label: string;
  openssl_error: string | null;
  items: ChainItem[];
}

export interface Tls {
  version: string | null;
  cipher_suite: string | null;
}

export interface PublicKey {
  algorithm: string;
  detail: string;
}

export interface Alert {
  level: string;
  message: string;
}

export interface CheckSuccess {
  ok: true;
  cached: boolean;
  host: string;
  display_host: string;
  resolved_ip: string;
  checked_at: string;
  elapsed_ms: number;
  overall: Overall;
  validity: Validity;
  certificate_type: string;
  certificate_type_label: string;
  certificate_type_source: string;
  issuer: Party;
  subject: Subject;
  domain_match: DomainMatch;
  chain: Chain;
  tls: Tls;
  public_key: PublicKey;
  serial_hex: string;
  fingerprint_sha256: string;
  alerts: Alert[];
}

export interface CheckFailure {
  ok: false;
  host: string;
  error: {
    code: string;
    message: string;
  };
}

export type CheckResult = CheckSuccess | CheckFailure;
