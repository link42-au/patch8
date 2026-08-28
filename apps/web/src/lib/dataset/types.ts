export type P2Table = "vulnerabilities" | "affected_software" | "kev";

export interface P2ArtifactRoute {
  cve_year?: number;
  cve_bucket?: string;
  vendor_buckets?: string[];
  global?: boolean;
}

export interface P2Artifact {
  id: string;
  path: string;
  table: P2Table;
  bytes: number;
  sha256: string;
  route: P2ArtifactRoute;
}

export interface P2Manifest {
  manifest_version: 0;
  fixture_only: true;
  release_id: string;
  generated_at: string;
  rights_policy_version: "p2-synthetic-1";
  max_query_bytes: number;
  previous_release: string | null;
  artifacts: P2Artifact[];
}

export interface QueryEvidence {
  releaseId: string;
  usedFallback: boolean;
  selectedFiles: string[];
  declaredBytes: number;
}

export interface QueryResult<T> extends QueryEvidence {
  value: T;
}

export interface P2Vulnerability {
  id: string;
  cve_id: string;
  description: string;
  published_at: string;
  modified_at: string;
  severity: string;
  cvss_score: number;
  cvss_vector: string;
  cvss_version: string;
  in_kev: number;
  kev_due_date: string;
  package_count: number;
  source_count: number;
  source_id: string;
  rights_policy_version: string;
}

export interface P2Detail extends P2Vulnerability {
  vendor: string | null;
  product: string | null;
  version: string | null;
  cpe_uri: string | null;
  kev_date_added: string | null;
  kev_required_action: string | null;
}

export interface P2Product {
  vendor: string;
  product: string;
  vuln_count: number;
}

export interface P2SearchParams {
  q?: string;
  severity?: string;
  inKev?: boolean;
  vendor?: string;
  product?: string;
  limit?: number;
  offset?: number;
}

export interface P2SearchPage {
  total: number;
  limit: number;
  offset: number;
  results: P2Vulnerability[];
}

export interface P2SqlRuntime {
  registerFile(name: string, url: string): Promise<void>;
  query<T>(sql: string, params?: unknown[]): Promise<T[]>;
  close(): Promise<void>;
}
