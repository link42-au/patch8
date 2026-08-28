import type { FeedSource, PackageSummary, StatsResponse, VulnDetailResponse, VulnSummary } from "@patch8/shared";

export type { VulnDetailResponse } from "@patch8/shared";

const DATA_UNAVAILABLE = "Data adapters are not implemented in this static release.";

// ── Generic Request ──────────────────────────────────────

async function request<T>(_path: string, _init?: RequestInit): Promise<T | null> {
  throw new Error(DATA_UNAVAILABLE);
}

// ── Auth ─────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  email: string;
  name: string | null;
  role: string;
}

export const getMe = async (): Promise<AuthUser | null> => null;

// ── Stats ────────────────────────────────────────────────

export async function getStats(): Promise<StatsResponse | null> {
  return request<StatsResponse>("/api/stats");
}

// ── Vulnerabilities ──────────────────────────────────────

export interface VulnSearchParams {
  q?: string;
  severity?: string;
  in_kev?: boolean;
  epss_gt?: number;
  ecosystem?: string;
  package?: string;
  vendor?: string;
  product?: string;
  hours?: number;
  limit?: number;
  offset?: number;
}

export interface VulnSearchResponse {
  total: number;
  limit: number;
  offset: number;
  results: VulnSummary[];
}

export async function searchVulnerabilities(params: VulnSearchParams): Promise<VulnSearchResponse | null> {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.severity) sp.set("severity", params.severity);
  if (params.in_kev) sp.set("in_kev", "1");
  if (params.epss_gt !== undefined) sp.set("epss_gt", String(params.epss_gt));
  if (params.ecosystem) sp.set("ecosystem", params.ecosystem);
  if (params.package) sp.set("package", params.package);
  if (params.vendor) sp.set("vendor", params.vendor);
  if (params.product) sp.set("product", params.product);
  if (params.hours) sp.set("hours", String(params.hours));
  if (params.limit) sp.set("limit", String(params.limit));
  if (params.offset) sp.set("offset", String(params.offset));

  const qs = sp.toString();
  return request<VulnSearchResponse>(`/api/vulnerabilities${qs ? `?${qs}` : ""}`);
}

export async function getVulnerability(id: string): Promise<VulnDetailResponse | null> {
  return request<VulnDetailResponse>(`/api/vulnerabilities/${encodeURIComponent(id)}`);
}

// ── Packages ─────────────────────────────────────────────

export interface PackageSearchResponse {
  results: PackageSummary[];
}

export async function searchPackages(params: {
  q?: string;
  ecosystem?: string;
  limit?: number;
  offset?: number;
}): Promise<PackageSearchResponse | null> {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.ecosystem) sp.set("ecosystem", params.ecosystem);
  if (params.limit) sp.set("limit", String(params.limit));
  if (params.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return request<PackageSearchResponse>(`/api/packages${qs ? `?${qs}` : ""}`);
}

export interface PackageVulnResponse {
  ecosystem: string;
  package_name: string;
  results: (VulnSummary & { vulnerable_range?: string; fixed_version?: string })[];
}

export async function getPackageVulnerabilities(ecosystem: string, name: string): Promise<PackageVulnResponse | null> {
  return request<PackageVulnResponse>(
    `/api/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}/vulnerabilities`,
  );
}

// ── Software ─────────────────────────────────────────────

export interface SoftwareSummary {
  vendor: string;
  product: string;
  vuln_count: number;
  max_severity: string | null;
  max_epss: number | null;
}

export interface SoftwareSearchResponse {
  results: SoftwareSummary[];
}

export async function searchSoftware(params: {
  q?: string;
  vendor?: string;
  limit?: number;
  offset?: number;
}): Promise<SoftwareSearchResponse | null> {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.vendor) sp.set("vendor", params.vendor);
  if (params.limit) sp.set("limit", String(params.limit));
  if (params.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return request<SoftwareSearchResponse>(`/api/software${qs ? `?${qs}` : ""}`);
}

export interface VendorProductsResponse {
  vendor: string;
  results: { product: string; vuln_count: number; max_severity: string | null; max_epss: number | null }[];
}

export async function getVendorProducts(
  vendor: string,
  params?: {
    limit?: number;
    offset?: number;
  },
): Promise<VendorProductsResponse | null> {
  const sp = new URLSearchParams();
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return request<VendorProductsResponse>(`/api/software/${encodeURIComponent(vendor)}${qs ? `?${qs}` : ""}`);
}

export interface AutocompleteResult {
  vendor: string;
  product: string;
  vuln_count: number;
}

export interface AutocompleteResponse {
  results: AutocompleteResult[];
}

export async function autocompleteSoftware(q: string, limit = 10): Promise<AutocompleteResponse | null> {
  if (!q || q.length < 2) return { results: [] };
  const sp = new URLSearchParams();
  sp.set("q", q);
  sp.set("limit", String(limit));
  return request<AutocompleteResponse>(`/api/software/autocomplete?${sp.toString()}`);
}

export interface ProductVuln {
  id: string;
  cve_id: string;
  description: string | null;
  published_at: string | null;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: number;
  kev_due_date: string | null;
  version: string | null;
  version_start_including: string | null;
  version_start_excluding: string | null;
  version_end_including: string | null;
  version_end_excluding: string | null;
  cpe_uri: string | null;
  ssvc_exploitation: string | null;
}

export interface ProductVulnsResponse {
  vendor: string;
  product: string;
  results: ProductVuln[];
}

export async function getProductVulnerabilities(
  vendor: string,
  product: string,
  params?: { version?: string; limit?: number; offset?: number },
): Promise<ProductVulnsResponse | null> {
  const sp = new URLSearchParams();
  if (params?.version) sp.set("version", params.version);
  if (params?.limit) sp.set("limit", String(params.limit));
  if (params?.offset) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  return request<ProductVulnsResponse>(
    `/api/software/${encodeURIComponent(vendor)}/${encodeURIComponent(product)}/vulnerabilities${qs ? `?${qs}` : ""}`,
  );
}

export interface ProductVersion {
  version: string;
  vuln_count: number;
}

export interface ProductVersionsResponse {
  vendor: string;
  product: string;
  versions: ProductVersion[];
}

export async function getProductVersions(vendor: string, product: string): Promise<ProductVersionsResponse | null> {
  return request<ProductVersionsResponse>(
    `/api/software/${encodeURIComponent(vendor)}/${encodeURIComponent(product)}/versions`,
  );
}

export interface ProductIntelSummary {
  total_cves: number;
  in_kev: number;
  actively_exploited: number;
  poc_available: number;
  automatable: number;
  total_impact: number;
  avg_epss: number | null;
  max_epss: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  earliest_cve: string | null;
  latest_cve: string | null;
}

export interface TopRiskCve {
  cve_id: string;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: number;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  published_at: string | null;
}

export interface ProductIntelResponse {
  vendor: string;
  product: string;
  summary: ProductIntelSummary;
  top_risk: TopRiskCve[];
}

export async function getProductIntel(vendor: string, product: string): Promise<ProductIntelResponse | null> {
  return request<ProductIntelResponse>(
    `/api/software/${encodeURIComponent(vendor)}/${encodeURIComponent(product)}/intel`,
  );
}

// ── Reports ──────────────────────────────────────────────

export interface PatchTuesdayMonth {
  month: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  in_kev: number;
  actively_exploited: number;
  poc_available: number;
  max_epss: number | null;
}

export interface PatchTuesdayMonthsResponse {
  months: PatchTuesdayMonth[];
}

export interface PatchTuesdayCve {
  cve_id: string;
  description: string | null;
  published_at: string | null;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: number;
  kev_due_date: string | null;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
  products: string | null;
}

export interface PatchTuesdaySummary {
  total: number;
  critical: number;
  high: number;
  in_kev: number;
  actively_exploited: number;
  poc_available: number;
  automatable: number;
  avg_epss: number | null;
  max_epss: number | null;
}

export interface PatchTuesdayDetailResponse {
  month: string;
  summary: PatchTuesdaySummary;
  vulnerabilities: PatchTuesdayCve[];
  narrative: string | null;
}

export async function getPatchTuesdayMonths(): Promise<PatchTuesdayMonthsResponse | null> {
  return request<PatchTuesdayMonthsResponse>("/api/reports/patch-tuesday");
}

export async function getPatchTuesdayDetail(month: string): Promise<PatchTuesdayDetailResponse | null> {
  return request<PatchTuesdayDetailResponse>(`/api/reports/patch-tuesday/${month}`);
}

// ── Feeds ────────────────────────────────────────────────

export interface FeedStatus {
  source: FeedSource;
  last_started: string | null;
  last_success: string | null;
  total_added: number;
  total_updated: number;
  total_runs: number;
  error_count: number;
}

export interface FeedStatusResponse {
  feeds: FeedStatus[];
}

export async function getFeedStatus(): Promise<FeedStatusResponse | null> {
  return request<FeedStatusResponse>("/api/feeds/status");
}

// ── Watchlist ────────────────────────────────────────────

export interface WatchlistItem {
  id: string;
  user_id: string;
  software_name: string;
  ecosystem: string | null;
  version: string | null;
  created_at: string;
}

export interface WatchlistResponse {
  items: WatchlistItem[];
}

export interface WatchlistMatch {
  id: string;
  cve_id: string;
  description: string | null;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  in_kev: number;
  ecosystem: string;
  package_name: string;
  vulnerable_range: string | null;
  fixed_version: string | null;
  software_name: string;
  watchlist_item_id: string;
}

export interface WatchlistMatchResponse {
  matches: WatchlistMatch[];
}

export async function getWatchlist(): Promise<WatchlistResponse | null> {
  return request<WatchlistResponse>("/api/watchlist");
}

export async function addWatchlistItem(item: {
  software_name: string;
  ecosystem?: string;
  version?: string;
}): Promise<WatchlistItem | null> {
  return request<WatchlistItem>("/api/watchlist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(item),
  });
}

export async function removeWatchlistItem(id: string): Promise<boolean> {
  const res = await request<{ deleted: boolean }>(`/api/watchlist/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  return res?.deleted ?? false;
}

export async function getWatchlistMatches(): Promise<WatchlistMatchResponse | null> {
  return request<WatchlistMatchResponse>("/api/watchlist/matches");
}

// ── Admin ────────────────────────────────────────────────

export async function triggerFeeds(params: {
  cadence?: string;
  source?: string;
}): Promise<{ triggered: string[]; cadence: string } | null> {
  const sp = new URLSearchParams();
  if (params.cadence) sp.set("cadence", params.cadence);
  if (params.source) sp.set("source", params.source);
  const qs = sp.toString();
  return request<{ triggered: string[]; cadence: string }>(`/api/admin/trigger-feeds${qs ? `?${qs}` : ""}`, {
    method: "POST",
  });
}

export async function triggerBackfill(params: {
  source: string;
  start?: string;
  end?: string;
}): Promise<Record<string, unknown> | null> {
  const sp = new URLSearchParams();
  sp.set("source", params.source);
  if (params.start) sp.set("start", params.start);
  if (params.end) sp.set("end", params.end);
  return request<Record<string, unknown>>(`/api/admin/backfill?${sp.toString()}`, {
    method: "POST",
  });
}
