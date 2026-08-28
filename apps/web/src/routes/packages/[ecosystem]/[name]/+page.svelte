<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { page } from "$app/state";
import { getPackageVulnerabilities, type PackageVulnResponse } from "$lib/api";

let results = $state<PackageVulnResponse | null>(null);
let loading = $state(true);

const ecosystem = $derived((page.params as Record<string, string>).ecosystem);
const packageName = $derived((page.params as Record<string, string>).name);

onMount(async () => {
  if (ecosystem && packageName) {
    results = await getPackageVulnerabilities(ecosystem, packageName);
  }
  loading = false;
});

function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

function truncate(text: string | null, len: number): string {
  if (!text) return "";
  return text.length > len ? text.slice(0, len) + "..." : text;
}
</script>

<svelte:head>
  <title>{ecosystem}/{packageName} — patch8</title>
  <meta property="og:title" content="{ecosystem}/{packageName} — patch8" />
  <meta property="og:description" content="Vulnerabilities affecting {packageName} ({ecosystem}) — CVE details, EPSS scores, and fix versions" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/packages/{ecosystem}/{packageName}" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="{ecosystem}/{packageName} — patch8" />
  <meta name="twitter:description" content="Vulnerabilities affecting {packageName} ({ecosystem}) — CVE details, EPSS scores, and fix versions" />
  <link rel="canonical" href="https://patch8.link42.app/packages/{ecosystem}/{packageName}" />
</svelte:head>

<div class="page-header">
  <a href="{base}/packages" class="back-link">← Back to Packages</a>
  <h1><span class="eco-badge">{ecosystem}</span> {packageName}</h1>
</div>

{#if loading}
  <p class="loading">Loading vulnerabilities...</p>
{:else if results}
  <div class="results-header">
    <span>{results.results.length} vulnerabilit{results.results.length === 1 ? "y" : "ies"} found</span>
  </div>

  {#if results.results.length > 0}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Description</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>EPSS</th>
          <th>KEV</th>
          <th>Vulnerable Range</th>
          <th>Fixed Version</th>
        </tr>
      </thead>
      <tbody>
        {#each results.results as vuln}
          <tr>
            <td><a href="{base}/vulnerabilities/{vuln.cve_id}" class="cve-link">{vuln.cve_id}</a></td>
            <td class="desc">{truncate(vuln.description, 120)}</td>
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
            <td class="mono">{vuln.vulnerable_range || "-"}</td>
            <td class="mono">{vuln.fixed_version || "-"}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {:else}
    <p class="empty">No vulnerabilities found for this package.</p>
  {/if}
{:else}
  <p class="empty">Failed to load package details.</p>
{/if}

<style>
  .page-header { margin-bottom: 24px; }
  .back-link {
    display: inline-block;
    margin-bottom: 12px;
    color: var(--text-mid);
    font-size: 13px;
    text-decoration: none;
  }
  .back-link:hover { color: var(--text); }

  h1 {
    font-size: 24px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 12px;
    font-family: "Geist Mono", monospace;
  }

  .eco-badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 13px;
    font-family: "Geist Mono", monospace;
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-mid);
    font-weight: normal;
  }

  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: var(--text-mid);
    margin-bottom: 12px;
  }

  .table-wrap { overflow-x: auto; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
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
  .desc { color: var(--text-mid); max-width: 300px; }
  .mono { font-family: "Geist Mono", monospace; }
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

  .loading { color: var(--text-dim); text-align: center; padding: 40px; }
  .empty { color: var(--text-dim); text-align: center; padding: 40px; }
</style>
