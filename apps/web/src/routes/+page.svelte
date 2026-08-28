<script lang="ts">
import { onMount } from "svelte";
import { goto } from "$app/navigation";
import { base } from "$app/paths";
import { getStats, searchVulnerabilities, getPatchTuesdayMonths } from "$lib/api";
import type { StatsResponse, VulnSummary } from "@patch8/shared";
import type { PatchTuesdayMonth } from "$lib/api";

let stats = $state<StatsResponse | null>(null);
let searchValue = $state("");
let theme = $state("light");
let statsError = $state(false);

let kevVulns = $state<VulnSummary[]>([]);
let kevLoading = $state(true);

let criticalVulns = $state<VulnSummary[]>([]);
let criticalLoading = $state(true);

let epssVulns = $state<VulnSummary[]>([]);
let epssLoading = $state(true);

let patchTuesdayMonth = $state<PatchTuesdayMonth | null>(null);
let patchTuesdayLoading = $state(true);

onMount(async () => {
  theme = document.documentElement.getAttribute("data-theme") || "light";

  const [statsResult, kevResult, criticalResult, epssResult, ptResult] = await Promise.allSettled([
    getStats(),
    searchVulnerabilities({ in_kev: true, limit: 5 }),
    searchVulnerabilities({ severity: "CRITICAL", limit: 5 }),
    searchVulnerabilities({ epss_gt: 0.9, limit: 5 }),
    getPatchTuesdayMonths(),
  ]);

  if (statsResult.status === "fulfilled" && statsResult.value) {
    stats = statsResult.value;
  } else {
    statsError = true;
  }

  if (kevResult.status === "fulfilled" && kevResult.value) {
    kevVulns = kevResult.value.results;
  }
  kevLoading = false;

  if (criticalResult.status === "fulfilled" && criticalResult.value) {
    criticalVulns = criticalResult.value.results;
  }
  criticalLoading = false;

  if (epssResult.status === "fulfilled" && epssResult.value) {
    epssVulns = epssResult.value.results;
  }
  epssLoading = false;

  if (ptResult.status === "fulfilled" && ptResult.value && ptResult.value.months.length > 0) {
    patchTuesdayMonth = ptResult.value.months[0];
  }
  patchTuesdayLoading = false;
});

function handleSearch(e: SubmitEvent) {
  e.preventDefault();
  const q = searchValue.trim();
  goto(q ? `${base}/search?q=${encodeURIComponent(q)}` : `${base}/search`);
}

function severityClass(severity: string | null): string {
  switch (severity) {
    case "CRITICAL": return "badge-critical";
    case "HIGH": return "badge-high";
    case "MEDIUM": return "badge-medium";
    case "LOW": return "badge-low";
    default: return "badge-unknown";
  }
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "—";
  const d = new Date(dateStr);
  return d.toLocaleDateString("en-AU", { day: "numeric", month: "short", year: "numeric" });
}

function formatEpss(score: number | null): string {
  if (score === null || score === undefined) return "—";
  return (score * 100).toFixed(1) + "%";
}

function truncate(text: string | null, max = 80): string {
  if (!text) return "No description";
  return text.length > max ? text.slice(0, max) + "…" : text;
}

function formatPatchTuesdayMonth(month: string): string {
  // month is "YYYY-MM" format
  const [year, mon] = month.split("-");
  const date = new Date(Number(year), Number(mon) - 1, 1);
  return date.toLocaleDateString("en-AU", { month: "long", year: "numeric" });
}
</script>

<svelte:head>
  <title>patch8 — Vulnerability Intelligence Dashboard</title>
  <meta name="description" content="Real-time vulnerability intelligence dashboard. Monitor KEV additions, critical CVEs, high EPSS exploitability, and Patch Tuesday — all in one place." />
  <meta property="og:title" content="patch8 — Vulnerability Intelligence Dashboard" />
  <meta property="og:description" content="Real-time dashboard for vulnerability analysts — KEV alerts, critical CVEs, EPSS exploitation risk, and Patch Tuesday summaries." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="patch8 — Vulnerability Intelligence Dashboard" />
  <meta name="twitter:description" content="Real-time dashboard for vulnerability analysts — KEV alerts, critical CVEs, EPSS exploitation risk, and Patch Tuesday summaries." />
  <link rel="canonical" href="https://patch8.link42.app" />
</svelte:head>

<div class="dashboard">
  <!-- Hero -->
  <div class="hero">
    <div class="hero-logo">
      <img src={theme === "dark" ? `${base}/logo-dark.svg` : `${base}/logo-light.svg`} alt="patch8" />
    </div>
    <h1 class="hero-title">patch8</h1>
    <p class="hero-tagline">Vulnerability intelligence, prioritised</p>

    <form class="search-form" onsubmit={handleSearch}>
      <input
        class="search-input"
        type="text"
        placeholder="Search CVE IDs, descriptions, or packages…"
        bind:value={searchValue}
      />
      <button class="search-btn" type="submit">Search</button>
    </form>
  </div>

  <!-- Stats bar -->
  {#if stats}
    <div class="stats-bar">
      <div class="stat-item">
        <span class="stat-number">{stats.total_vulns.toLocaleString()}</span>
        <span class="stat-label">Total CVEs</span>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <span class="stat-number stat-kev">{stats.in_kev.toLocaleString()}</span>
        <span class="stat-label">In KEV</span>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <span class="stat-number">{stats.high_epss.toLocaleString()}</span>
        <span class="stat-label">High EPSS (&gt;90%)</span>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-item">
        <span class="stat-number">{(stats.by_severity.CRITICAL ?? 0).toLocaleString()}</span>
        <span class="stat-label">Critical</span>
      </div>
      {#if stats.last_updated}
        <div class="stat-divider"></div>
        <div class="stat-item">
          <span class="stat-number stat-updated">{formatDate(stats.last_updated)}</span>
          <span class="stat-label">Last Updated</span>
        </div>
      {/if}
    </div>
  {:else if statsError}
    <p class="stats-unavailable">Stats temporarily unavailable</p>
  {/if}

  <!-- Dashboard grid -->
  <div class="dashboard-grid">

    <!-- Recent KEV Vulnerabilities -->
    <div class="card">
      <div class="card-header">
        <span class="card-icon kev-icon">⚠</span>
        <h2 class="card-title">Recent KEV Vulnerabilities</h2>
        <a href="{base}/search?in_kev=1" class="card-link">View all →</a>
      </div>
      {#if kevLoading}
        <div class="skeleton-list">
          {#each [1,2,3,4,5] as _}
            <div class="skeleton-row"></div>
          {/each}
        </div>
      {:else if kevVulns.length === 0}
        <p class="card-empty">KEV data unavailable in this static release</p>
      {:else}
        <ul class="vuln-list">
          {#each kevVulns as v}
            <li class="vuln-row">
              <a href="{base}/vulnerabilities/{v.cve_id}" class="vuln-link">
                <span class="vuln-id">{v.cve_id}</span>
                <span class="badge {severityClass(v.severity)}">{v.severity ?? "N/A"}</span>
                <span class="vuln-desc">{truncate(v.description)}</span>
                <span class="vuln-date">{formatDate(v.published_at)}</span>
              </a>
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    <!-- Critical CVEs This Week -->
    <div class="card">
      <div class="card-header">
        <span class="card-icon critical-icon">🔴</span>
        <h2 class="card-title">Critical CVEs</h2>
        <a href="{base}/search?severity=CRITICAL" class="card-link">View all →</a>
      </div>
      {#if criticalLoading}
        <div class="skeleton-list">
          {#each [1,2,3,4,5] as _}
            <div class="skeleton-row"></div>
          {/each}
        </div>
      {:else if criticalVulns.length === 0}
        <p class="card-empty">CVE data unavailable in this static release</p>
      {:else}
        <ul class="vuln-list">
          {#each criticalVulns as v}
            <li class="vuln-row">
              <a href="{base}/vulnerabilities/{v.cve_id}" class="vuln-link">
                <span class="vuln-id">{v.cve_id}</span>
                {#if v.cvss_score !== null}
                  <span class="vuln-score">CVSS {v.cvss_score.toFixed(1)}</span>
                {/if}
                <span class="vuln-desc">{truncate(v.description)}</span>
                <span class="vuln-date">{formatDate(v.published_at)}</span>
              </a>
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    <!-- High EPSS Movers -->
    <div class="card">
      <div class="card-header">
        <span class="card-icon epss-icon">📈</span>
        <h2 class="card-title">High EPSS Risk</h2>
        <a href="{base}/search?epss_gt=0.9" class="card-link">View all →</a>
      </div>
      {#if epssLoading}
        <div class="skeleton-list">
          {#each [1,2,3,4,5] as _}
            <div class="skeleton-row"></div>
          {/each}
        </div>
      {:else if epssVulns.length === 0}
        <p class="card-empty">EPSS data unavailable in this static release</p>
      {:else}
        <ul class="vuln-list">
          {#each epssVulns as v}
            <li class="vuln-row">
              <a href="{base}/vulnerabilities/{v.cve_id}" class="vuln-link">
                <span class="vuln-id">{v.cve_id}</span>
                <span class="badge {severityClass(v.severity)}">{v.severity ?? "N/A"}</span>
                <span class="epss-pill">{formatEpss(v.epss_score)} prob</span>
                <span class="vuln-desc">{truncate(v.description, 60)}</span>
              </a>
            </li>
          {/each}
        </ul>
      {/if}
    </div>

    <!-- Patch Tuesday -->
    <div class="card">
      <div class="card-header">
        <span class="card-icon pt-icon">📅</span>
        <h2 class="card-title">Patch Tuesday</h2>
        <a href="{base}/reports/patch-tuesday" class="card-link">Full report →</a>
      </div>
      {#if patchTuesdayLoading}
        <div class="skeleton-list">
          {#each [1,2,3] as _}
            <div class="skeleton-row skeleton-row-lg"></div>
          {/each}
        </div>
      {:else if !patchTuesdayMonth}
        <p class="card-empty">Patch Tuesday data unavailable in this static release</p>
      {:else}
        <div class="pt-month-label">{formatPatchTuesdayMonth(patchTuesdayMonth.month)}</div>
        <div class="pt-stats">
          <div class="pt-stat">
            <span class="pt-stat-number">{patchTuesdayMonth.total}</span>
            <span class="pt-stat-label">Total CVEs</span>
          </div>
          <div class="pt-stat">
            <span class="pt-stat-number pt-stat-critical">{patchTuesdayMonth.critical}</span>
            <span class="pt-stat-label">Critical</span>
          </div>
          <div class="pt-stat">
            <span class="pt-stat-number pt-stat-high">{patchTuesdayMonth.high}</span>
            <span class="pt-stat-label">High</span>
          </div>
          <div class="pt-stat">
            <span class="pt-stat-number pt-stat-kev">{patchTuesdayMonth.in_kev}</span>
            <span class="pt-stat-label">In KEV</span>
          </div>
        </div>
        {#if patchTuesdayMonth.actively_exploited > 0}
          <div class="pt-alert">
            <span class="pt-alert-dot"></span>
            {patchTuesdayMonth.actively_exploited} actively exploited
          </div>
        {/if}
        {#if patchTuesdayMonth.max_epss !== null}
          <div class="pt-epss">Max EPSS: <strong>{formatEpss(patchTuesdayMonth.max_epss)}</strong></div>
        {/if}
        <a href="{base}/reports/patch-tuesday/{patchTuesdayMonth.month}" class="pt-detail-link">
          View {formatPatchTuesdayMonth(patchTuesdayMonth.month)} detail →
        </a>
      {/if}
    </div>

  </div>

  <!-- Severity quick-links -->
  {#if stats}
    <div class="quick-links">
      <div class="quick-links-label">Browse by severity</div>
      <div class="quick-links-pills">
        <a href="{base}/search?severity=CRITICAL" class="filter-pill pill-critical">
          CRITICAL <span class="pill-count">{(stats.by_severity.CRITICAL ?? 0).toLocaleString()}</span>
        </a>
        <a href="{base}/search?severity=HIGH" class="filter-pill pill-high">
          HIGH <span class="pill-count">{(stats.by_severity.HIGH ?? 0).toLocaleString()}</span>
        </a>
        <a href="{base}/search?severity=MEDIUM" class="filter-pill pill-medium">
          MEDIUM <span class="pill-count">{(stats.by_severity.MEDIUM ?? 0).toLocaleString()}</span>
        </a>
        <a href="{base}/search?severity=LOW" class="filter-pill pill-low">
          LOW <span class="pill-count">{(stats.by_severity.LOW ?? 0).toLocaleString()}</span>
        </a>
      </div>
    </div>
  {/if}

  <a href="{base}/search" class="browse-all">Browse all vulnerabilities →</a>
</div>

<style>
  /* ── Layout ──────────────────────────────────────────── */

  .dashboard {
    display: flex;
    flex-direction: column;
    align-items: center;
    min-height: calc(100vh - 140px);
    padding: 48px 24px 48px;
    max-width: 1100px;
    margin: 0 auto;
    width: 100%;
    box-sizing: border-box;
  }

  /* ── Hero ────────────────────────────────────────────── */

  .hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    margin-bottom: 32px;
    width: 100%;
  }

  .hero-logo {
    width: 80px;
    height: 80px;
    margin-bottom: 16px;
  }

  .hero-logo img {
    width: 100%;
    height: 100%;
    object-fit: contain;
  }

  .hero-title {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.04em;
    margin: 0 0 4px;
  }

  .hero-tagline {
    font-size: 14px;
    color: var(--text-mid);
    margin: 0 0 24px;
  }

  .search-form {
    display: flex;
    gap: 8px;
    width: 100%;
    max-width: 560px;
  }

  .search-input {
    flex: 1;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0 16px;
    height: 44px;
    font-size: 14px;
    color: var(--text);
    outline: none;
    transition: all 0.2s;
  }

  .search-input::placeholder {
    color: var(--text-dim);
  }

  .search-input:focus {
    border-color: var(--accent-border);
    background: var(--bg-card);
    box-shadow: 0 0 0 2px var(--accent-bg);
  }

  .search-btn {
    background: var(--text);
    color: var(--text-inv);
    border: none;
    border-radius: 10px;
    padding: 0 20px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.2s;
    height: 44px;
    white-space: nowrap;
  }

  .search-btn:hover {
    opacity: 0.85;
  }

  /* ── Stats bar ───────────────────────────────────────── */

  .stats-bar {
    display: flex;
    align-items: center;
    gap: 0;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 24px;
    width: 100%;
    margin-bottom: 32px;
    flex-wrap: wrap;
    justify-content: center;
    gap: 0;
  }

  .stat-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 24px;
    min-width: 80px;
  }

  .stat-divider {
    width: 1px;
    height: 32px;
    background: var(--border);
  }

  .stat-number {
    font-size: 20px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    color: var(--text);
    line-height: 1.2;
  }

  .stat-kev {
    color: var(--red, #ef4444);
  }

  .stat-updated {
    font-size: 13px;
    font-weight: 500;
  }

  .stat-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-dim);
    margin-top: 3px;
    white-space: nowrap;
  }

  .stats-unavailable {
    font-size: 12px;
    color: var(--text-dim);
    margin: 0 0 24px;
    font-family: "Geist Mono", ui-monospace, monospace;
  }

  /* ── Dashboard grid ──────────────────────────────────── */

  .dashboard-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    width: 100%;
    margin-bottom: 32px;
  }

  /* ── Card ────────────────────────────────────────────── */

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    min-width: 0;
  }

  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 16px;
  }

  .card-icon {
    font-size: 16px;
    line-height: 1;
  }

  .kev-icon { filter: none; }

  .card-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    margin: 0;
    flex: 1;
    letter-spacing: -0.01em;
  }

  .card-link {
    font-size: 11px;
    color: var(--text-dim);
    text-decoration: none;
    white-space: nowrap;
    transition: color 0.15s;
  }

  .card-link:hover {
    color: var(--accent);
  }

  .card-empty {
    font-size: 12px;
    color: var(--text-dim);
    text-align: center;
    padding: 24px 0;
    margin: 0;
  }

  /* ── Vuln list ───────────────────────────────────────── */

  .vuln-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .vuln-row {
    border-radius: 6px;
    transition: background 0.1s;
  }

  .vuln-row:hover {
    background: var(--bg-hover);
  }

  .vuln-link {
    display: grid;
    grid-template-columns: auto auto 1fr auto;
    align-items: center;
    gap: 8px;
    padding: 8px 6px;
    text-decoration: none;
    min-width: 0;
  }

  .vuln-id {
    font-size: 12px;
    font-weight: 600;
    font-family: "Geist Mono", ui-monospace, monospace;
    color: var(--accent);
    white-space: nowrap;
  }

  .vuln-score {
    font-size: 11px;
    font-family: "Geist Mono", ui-monospace, monospace;
    color: var(--red, #ef4444);
    white-space: nowrap;
    background: var(--red-bg, rgba(239,68,68,0.08));
    border: 1px solid var(--red-border, rgba(239,68,68,0.2));
    border-radius: 4px;
    padding: 1px 5px;
  }

  .vuln-desc {
    font-size: 12px;
    color: var(--text-dim);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }

  .vuln-date {
    font-size: 11px;
    color: var(--text-dim);
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }

  /* ── Severity badges ─────────────────────────────────── */

  .badge {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.04em;
    padding: 2px 6px;
    border-radius: 4px;
    white-space: nowrap;
    border: 1px solid transparent;
  }

  .badge-critical {
    background: var(--red-bg, rgba(239,68,68,0.1));
    border-color: var(--red-border, rgba(239,68,68,0.25));
    color: var(--red, #ef4444);
  }

  .badge-high {
    background: var(--amber-bg, rgba(245,158,11,0.1));
    border-color: var(--amber-border, rgba(245,158,11,0.25));
    color: var(--amber, #f59e0b);
  }

  .badge-medium {
    background: var(--amber-bg, rgba(245,158,11,0.1));
    border-color: var(--amber-border, rgba(245,158,11,0.25));
    color: var(--amber, #f59e0b);
  }

  .badge-low {
    background: var(--green-bg, rgba(34,197,94,0.1));
    border-color: var(--green-border, rgba(34,197,94,0.25));
    color: var(--green, #22c55e);
  }

  .badge-unknown {
    background: var(--bg-subtle);
    border-color: var(--border);
    color: var(--text-dim);
  }

  /* ── EPSS pill ───────────────────────────────────────── */

  .epss-pill {
    font-size: 11px;
    font-weight: 600;
    font-family: "Geist Mono", ui-monospace, monospace;
    color: var(--accent);
    background: var(--accent-bg);
    border: 1px solid var(--accent-border);
    border-radius: 4px;
    padding: 2px 6px;
    white-space: nowrap;
  }

  /* ── Patch Tuesday card ──────────────────────────────── */

  .pt-month-label {
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 16px;
  }

  .pt-stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-bottom: 16px;
  }

  .pt-stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 6px;
  }

  .pt-stat-number {
    font-size: 18px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    color: var(--text);
    line-height: 1.2;
  }

  .pt-stat-critical { color: var(--red, #ef4444); }
  .pt-stat-high { color: var(--amber, #f59e0b); }
  .pt-stat-kev { color: var(--red, #ef4444); }

  .pt-stat-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-dim);
    margin-top: 3px;
    white-space: nowrap;
  }

  .pt-alert {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--red, #ef4444);
    margin-bottom: 8px;
  }

  .pt-alert-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--red, #ef4444);
    flex-shrink: 0;
  }

  .pt-epss {
    font-size: 12px;
    color: var(--text-dim);
    margin-bottom: 16px;
  }

  .pt-epss strong {
    color: var(--text);
    font-weight: 600;
  }

  .pt-detail-link {
    font-size: 12px;
    color: var(--accent);
    text-decoration: none;
    transition: opacity 0.15s;
  }

  .pt-detail-link:hover {
    opacity: 0.75;
  }

  /* ── Skeletons ───────────────────────────────────────── */

  .skeleton-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .skeleton-row {
    height: 32px;
    background: var(--bg-subtle);
    border-radius: 6px;
    animation: shimmer 1.4s ease-in-out infinite;
  }

  .skeleton-row-lg {
    height: 48px;
  }

  @keyframes shimmer {
    0%, 100% { opacity: 0.5; }
    50% { opacity: 1; }
  }

  /* ── Quick links ─────────────────────────────────────── */

  .quick-links {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
    width: 100%;
  }

  .quick-links-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-dim);
  }

  .quick-links-pills {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 8px;
  }

  .filter-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 14px;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 5px;
    font-size: 12px;
    font-weight: 500;
    text-decoration: none;
    transition: all 0.15s;
    letter-spacing: 0.02em;
  }

  .filter-pill:hover {
    background: var(--bg-hover);
    border-color: var(--border-strong);
  }

  .pill-critical {
    background: var(--red-bg, rgba(239,68,68,0.08));
    border-color: var(--red-border, rgba(239,68,68,0.2));
    color: var(--red, #ef4444);
  }

  .pill-high {
    background: var(--amber-bg, rgba(245,158,11,0.08));
    border-color: var(--amber-border, rgba(245,158,11,0.2));
    color: var(--amber, #f59e0b);
  }

  .pill-medium {
    background: var(--amber-bg, rgba(245,158,11,0.08));
    border-color: var(--amber-border, rgba(245,158,11,0.2));
    color: var(--amber, #f59e0b);
  }

  .pill-low {
    background: var(--green-bg, rgba(34,197,94,0.08));
    border-color: var(--green-border, rgba(34,197,94,0.2));
    color: var(--green, #22c55e);
  }

  .pill-count {
    font-size: 10px;
    opacity: 0.65;
    font-variant-numeric: tabular-nums;
  }

  /* ── Browse all ──────────────────────────────────────── */

  .browse-all {
    font-size: 13px;
    color: var(--text-dim);
    text-decoration: none;
    transition: color 0.15s;
    margin-top: 8px;
  }

  .browse-all:hover {
    color: var(--accent);
  }

  /* ── Responsive ──────────────────────────────────────── */

  @media (max-width: 720px) {
    .dashboard-grid {
      grid-template-columns: 1fr;
    }

    .stats-bar {
      gap: 12px;
      padding: 16px;
    }

    .stat-divider {
      display: none;
    }

    .stat-item {
      padding: 0 12px;
    }

    .pt-stats {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @media (max-width: 480px) {
    .search-form {
      flex-direction: column;
    }

    .search-btn {
      width: 100%;
    }

    .vuln-link {
      grid-template-columns: 1fr auto;
      grid-template-rows: auto auto;
    }

    .vuln-desc {
      grid-column: 1 / -1;
    }

    .vuln-date {
      display: none;
    }
  }
</style>
