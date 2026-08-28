<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { page } from "$app/stores";
import { getProductVulnerabilities, getProductVersions, getProductIntel, type ProductVulnsResponse, type ProductVersionsResponse, type ProductIntelResponse } from "$lib/api";
import { prettyName } from "$lib/utils";

const vendor = $derived($page.params.vendor ?? "");
const product = $derived($page.params.product ?? "");

let results = $state<ProductVulnsResponse | null>(null);
let versions = $state<ProductVersionsResponse | null>(null);
let intel = $state<ProductIntelResponse | null>(null);
let selectedVersion = $state("");
let loading = $state(true);
let currentOffset = $state(0);
const limit = 50;

onMount(() => {
  loadData();
});

async function loadData() {
  loading = true;
  const [vRes, rRes, iRes] = await Promise.all([
    getProductVersions(vendor, product),
    getProductVulnerabilities(vendor, product, { limit, offset: 0 }),
    getProductIntel(vendor, product)
  ]);
  if (vRes) {
    vRes.versions.sort((a, b) => compareVersions(b.version, a.version));
  }
  versions = vRes;
  results = rRes;
  intel = iRes;
  loading = false;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.\-]/).map((s) => (/^\d+$/.test(s) ? Number(s) : s));
  const pb = b.split(/[.\-]/).map((s) => (/^\d+$/.test(s) ? Number(s) : s));
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (typeof va === "number" && typeof vb === "number") {
      if (va !== vb) return va - vb;
    } else {
      const cmp = String(va).localeCompare(String(vb));
      if (cmp !== 0) return cmp;
    }
  }
  return 0;
}

async function loadVulns(offset = 0) {
  loading = true;
  currentOffset = offset;
  results = await getProductVulnerabilities(vendor, product, {
    version: selectedVersion || undefined,
    limit,
    offset
  });
  loading = false;
}

function handleVersionChange() {
  loadVulns(0);
}

function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

function formatVersion(vuln: { version: string | null; version_start_including: string | null; version_start_excluding: string | null; version_end_including: string | null; version_end_excluding: string | null }): string {
  if (vuln.version && vuln.version !== "*") return vuln.version;
  const parts: string[] = [];
  if (vuln.version_start_including) parts.push(`>= ${vuln.version_start_including}`);
  if (vuln.version_start_excluding) parts.push(`> ${vuln.version_start_excluding}`);
  if (vuln.version_end_including) parts.push(`<= ${vuln.version_end_including}`);
  if (vuln.version_end_excluding) parts.push(`< ${vuln.version_end_excluding}`);
  return parts.length > 0 ? parts.join(", ") : "all";
}

function truncate(text: string | null, len: number): string {
  if (!text) return "";
  return text.length > len ? text.slice(0, len) + "..." : text;
}

function fmtDate(d: string | null): string {
  if (!d) return "-";
  return new Date(d).toLocaleDateString("en-AU", { year: "numeric", month: "short", day: "numeric" });
}

const currentPage = $derived(Math.floor(currentOffset / limit) + 1);
const hasNextPage = $derived(results && results.results.length === limit);
</script>

<svelte:head>
  <title>{prettyName(product)} Vulnerabilities — patch8</title>
  <meta property="og:title" content="{prettyName(vendor)} {prettyName(product)} Vulnerabilities — patch8" />
  <meta property="og:description" content="CVEs affecting {prettyName(vendor)} {prettyName(product)} — severity breakdown, EPSS scores, KEV status, and affected versions" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/software/{vendor}/{product}" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="{prettyName(vendor)} {prettyName(product)} Vulnerabilities — patch8" />
  <meta name="twitter:description" content="CVEs affecting {prettyName(vendor)} {prettyName(product)} — severity breakdown, EPSS scores, KEV status, and affected versions" />
  <link rel="canonical" href="https://patch8.link42.app/software/{vendor}/{product}" />
</svelte:head>

<div class="page-header">
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <a href="{base}/software">Software</a> <span class="sep">/</span>
    <a href="{base}/software/{vendor}">{prettyName(vendor)}</a> <span class="sep">/</span>
    <span aria-current="page">{prettyName(product)}</span>
  </nav>
  <h1>{prettyName(product)} Vulnerabilities</h1>
</div>

{#if intel?.summary}
<div class="intel-summary">
  <div class="stat-card">
    <div class="stat-value">{intel.summary.total_cves.toLocaleString()}</div>
    <div class="stat-label">Total CVEs</div>
  </div>
  <div class="stat-card critical">
    <div class="stat-value">{intel.summary.critical}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card high">
    <div class="stat-value">{intel.summary.high}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card exploit">
    <div class="stat-value">{intel.summary.actively_exploited}</div>
    <div class="stat-label">Actively Exploited</div>
  </div>
  <div class="stat-card kev">
    <div class="stat-value">{intel.summary.in_kev}</div>
    <div class="stat-label">In KEV</div>
  </div>
  <div class="stat-card epss">
    <div class="stat-value">{intel.summary.max_epss ? (intel.summary.max_epss * 100).toFixed(1) + '%' : 'N/A'}</div>
    <div class="stat-label">Max EPSS</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{intel.summary.poc_available}</div>
    <div class="stat-label">PoC Available</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{intel.summary.automatable}</div>
    <div class="stat-label">Automatable</div>
  </div>
</div>
{/if}

{#if intel?.top_risk && intel.top_risk.length > 0}
<div class="top-risk">
  <h3>Highest Risk CVEs</h3>
  <div class="risk-list">
    {#each intel.top_risk as cve}
    <a href="{base}/vulnerabilities/{cve.cve_id}" class="risk-item">
      <span class="risk-cve">{cve.cve_id}</span>
      {#if cve.ssvc_exploitation === 'active'}
        <span class="ssvc-badge active">Exploited</span>
      {:else if cve.ssvc_exploitation === 'poc'}
        <span class="ssvc-badge poc">PoC</span>
      {/if}
      {#if cve.in_kev}
        <span class="ssvc-badge kev">KEV</span>
      {/if}
      {#if cve.epss_score}
        <span class="epss-pill">EPSS {(cve.epss_score * 100).toFixed(1)}%</span>
      {/if}
      {#if cve.severity}
        <span class="sev-badge {cve.severity.toLowerCase()}">{cve.severity}</span>
      {/if}
    </a>
    {/each}
  </div>
</div>
{/if}

<div class="filters">
  <select bind:value={selectedVersion} onchange={handleVersionChange}>
    <option value="">All versions</option>
    {#if versions}
      {#each versions.versions as v}
        <option value={v.version}>{v.version} ({v.vuln_count})</option>
      {/each}
    {/if}
  </select>
</div>

{#if loading && !results}
  <p class="loading">Loading...</p>
{:else if results}
  <div class="results-header">
    <span>{results.results.length} result{results.results.length === 1 ? "" : "s"} on this page</span>
    {#if currentOffset > 0 || hasNextPage}
      <span class="page-info">Page {currentPage}</span>
    {/if}
  </div>

  {#if results.results.length > 0}
  <div class="table-wrap">
    <table class={loading ? "loading-state" : ""}>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Version</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>EPSS</th>
          <th>KEV</th>
          <th>Published</th>
        </tr>
      </thead>
      <tbody>
        {#each results.results as vuln}
          <tr>
            <td>
              <a href="{base}/vulnerabilities/{vuln.cve_id}" class="cve-link">{vuln.cve_id}</a>
              {#if vuln.ssvc_exploitation === 'active'}
                <span class="ssvc-badge active" title="Actively Exploited">Exploited</span>
              {:else if vuln.ssvc_exploitation === 'poc'}
                <span class="ssvc-badge poc" title="Proof of Concept Available">PoC</span>
              {/if}
            </td>
            <td class="mono version-cell">{formatVersion(vuln)}</td>
            <td>
              {#if vuln.severity}
                <span class="sev-badge {sevClass(vuln.severity)}">{vuln.severity}</span>
              {:else}
                <span class="dim">-</span>
              {/if}
            </td>
            <td class="mono">{vuln.cvss_score?.toFixed(1) ?? "-"}</td>
            <td class="mono">{vuln.epss_score != null ? (vuln.epss_score * 100).toFixed(1) + "%" : "-"}</td>
            <td>{vuln.in_kev ? "Yes" : ""}</td>
            <td class="date">{fmtDate(vuln.published_at)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  {#if currentOffset > 0 || hasNextPage}
    <div class="pagination">
      <button disabled={currentOffset === 0 || loading} onclick={() => loadVulns(currentOffset - limit)}>Previous</button>
      <button disabled={!hasNextPage || loading} onclick={() => loadVulns(currentOffset + limit)}>Next</button>
    </div>
  {/if}
  {:else}
    <p class="empty">No vulnerabilities found for this product/version.</p>
  {/if}
{/if}

<style>
  .page-header { margin-bottom: 16px; }
  .breadcrumb {
    font-size: 13px;
    color: var(--text-dim);
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 0;
  }
  .breadcrumb a {
    color: var(--accent);
    text-decoration: none;
  }
  .breadcrumb a:hover { text-decoration: underline; }
  .sep { margin: 0 4px; }
  h1 { font-size: 20px; font-weight: 600; }

  .filters {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 20px;
  }
  select {
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-card);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
  }

  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: var(--text-mid);
    margin-bottom: 12px;
  }
  .page-info { font-family: "Geist Mono", monospace; }

  .table-wrap { overflow-x: auto; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    transition: opacity 0.2s;
  }
  table.loading-state {
    opacity: 0.5;
    pointer-events: none;
  }
  th {
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-dim);
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-strong);
    white-space: nowrap;
  }
  td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  tr:hover td { background: var(--bg-hover); }
  .cve-link {
    color: var(--accent);
    font-weight: 500;
    font-family: "Geist Mono", monospace;
    font-size: 13px;
    white-space: nowrap;
  }
  .cve-link:hover { text-decoration: underline; }
  .desc { color: var(--text-mid); max-width: 400px; }
  .mono { font-family: "Geist Mono", monospace; }
  .version-cell { font-size: 11px; white-space: nowrap; color: var(--text-mid); max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
  .date { white-space: nowrap; color: var(--text-mid); font-size: 12px; }
  .dim { color: var(--text-dim); }

  .sev-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .sev-badge.critical { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .sev-badge.high { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-badge.medium { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-badge.low { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }

  .pagination {
    display: flex;
    justify-content: center;
    gap: 8px;
    margin-top: 16px;
  }
  .pagination button {
    padding: 6px 14px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-card);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
  }
  .pagination button:hover:not(:disabled) { background: var(--bg-hover); }
  .pagination button:disabled { opacity: 0.4; cursor: default; }

  .loading { color: var(--text-dim); text-align: center; padding: 40px; }
  .empty { color: var(--text-dim); text-align: center; padding: 40px; }

  .intel-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-bottom: 24px; }
  .stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; text-align: center; }
  .stat-value { font-size: 22px; font-weight: 700; font-family: "Geist Mono", monospace; color: var(--text); }
  .stat-label { font-size: 11px; color: var(--text-dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.critical .stat-value { color: var(--red); }
  .stat-card.high .stat-value { color: var(--amber); }
  .stat-card.exploit .stat-value { color: var(--red); }
  .stat-card.kev .stat-value { color: var(--red); }
  .stat-card.epss .stat-value { color: var(--accent); }

  .top-risk { margin-bottom: 24px; }
  .top-risk h3 { font-size: 14px; font-weight: 600; color: var(--text-mid); margin-bottom: 10px; }
  .risk-list { display: flex; flex-direction: column; gap: 6px; }
  .risk-item { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; text-decoration: none; font-size: 13px; }
  .risk-item:hover { background: var(--bg-hover); }
  .risk-cve { font-family: "Geist Mono", monospace; color: var(--accent); font-weight: 500; min-width: 160px; }
  .ssvc-badge { font-size: 10px; font-weight: 600; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.3px; }
  .ssvc-badge.active { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .ssvc-badge.poc { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .ssvc-badge.kev { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .epss-pill { font-size: 11px; font-family: "Geist Mono", monospace; color: var(--text-mid); background: var(--bg); border: 1px solid var(--border); padding: 2px 6px; border-radius: 10px; }
</style>
