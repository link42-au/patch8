export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export type FeedSource = "nvd" | "epss" | "kev" | "ghsa" | "osv" | "msrc" | "cisco" | "euvd" | "vulnrichment";

export type FeedCadence = "high" | "medium" | "daily";

export interface Vulnerability {
  id: string;
  cve_id: string;
  description: string | null;
  published_at: string | null;
  modified_at: string | null;
  severity: Severity | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  in_kev: number;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: string | null;
  weaknesses: string[];
  references: VulnReference[];
  created_at: string;
  updated_at: string;
}

export interface VulnReference {
  url: string;
  source?: string;
  tags?: string[];
}

export interface VulnSource {
  id: string;
  vuln_id: string;
  source: FeedSource;
  source_id: string | null;
  data: Record<string, unknown>;
  ingested_at: string;
  created_at: string;
}

export interface VulnAlias {
  vuln_id: string;
  alias_type: string;
  alias_value: string;
}

export interface AffectedPackage {
  id: string;
  vuln_id: string;
  ecosystem: string;
  package_name: string;
  vulnerable_range: string | null;
  fixed_version: string | null;
  source: string;
  created_at: string;
}

export interface AffectedSoftware {
  id: string;
  vuln_id: string;
  vendor: string;
  product: string;
  version: string | null;
  version_start_including: string | null;
  version_start_excluding: string | null;
  version_end_including: string | null;
  version_end_excluding: string | null;
  cpe_uri: string | null;
  source: string;
  created_at: string;
}

export interface CweEntry {
  id: string;
  name: string;
  description: string;
  abstraction: string;
}

export interface WatchlistItem {
  id: string;
  user_id: string;
  software_name: string;
  ecosystem: string | null;
  version: string | null;
  created_at: string;
}

export interface FeedRun {
  id: string;
  source: FeedSource;
  started_at: string;
  completed_at: string | null;
  vulns_added: number;
  vulns_updated: number;
  error: string | null;
}

export interface VulnSummary {
  id: string;
  cve_id: string;
  description: string | null;
  published_at: string | null;
  severity: Severity | null;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  in_kev: number;
  kev_due_date: string | null;
  package_count: number;
  source_count: number;
}

export interface VulnDetailResponse {
  vulnerability: Vulnerability;
  sources: VulnSource[];
  aliases: VulnAlias[];
  affected_packages: AffectedPackage[];
  affected_software: AffectedSoftware[];
  cwe_details: CweEntry[];
}

export interface StatsResponse {
  total_vulns: number;
  by_severity: Record<Severity, number>;
  in_kev: number;
  high_epss: number;
  total_packages: number;
  last_updated: string | null;
  sources: { source: FeedSource; count: number; last_run: string | null }[];
}

export interface PackageSummary {
  ecosystem: string;
  package_name: string;
  vuln_count: number;
  max_severity: Severity | null;
  max_epss: number | null;
}

export const FEED_CADENCES: Record<FeedCadence, FeedSource[]> = {
  high: ["nvd"],
  medium: ["osv", "ghsa", "euvd"],
  daily: ["epss", "kev", "msrc", "vulnrichment"],
};
