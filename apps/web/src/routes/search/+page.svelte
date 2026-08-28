<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { page } from "$app/stores";
import { goto } from "$app/navigation";
import { searchVulnerabilities, autocompleteSoftware, type VulnSearchResponse, type AutocompleteResult } from "$lib/api";
import { sortVulnerabilities, type SortCol, type SortDir } from "$lib/sort";

let results = $state<VulnSearchResponse | null>(null);
let loading = $state(false);
let error = $state<string | null>(null);

let q = $state("");
let severity = $state("");
let inKev = $state(false);
let epssGt = $state("");
let vendor = $state("");
let product = $state("");
let softwareQuery = $state("");
let softwareSuggestions = $state<AutocompleteResult[]>([]);
let showSuggestions = $state(false);
let currentOffset = $state(0);
const limit = 25;

let sortCol = $state<SortCol | null>(null);
let sortDir = $state<SortDir>("desc");

onMount(() => {
  q = $page.url.searchParams.get("q") ?? "";
  severity = $page.url.searchParams.get("severity") ?? "";
  inKev = $page.url.searchParams.get("in_kev") === "1";
  epssGt = $page.url.searchParams.get("epss_gt") ?? "";
  vendor = $page.url.searchParams.get("vendor") ?? "";
  product = $page.url.searchParams.get("product") ?? "";
  if (vendor || product) {
    softwareQuery = [vendor, product].filter(Boolean).join(" ");
  }
  doSearch();
});

async function doSearch(offset = 0) {
  loading = true;
  currentOffset = offset;
  sortCol = null;
  try {
    error = null;
    results = await searchVulnerabilities({
      q: q || undefined,
      severity: severity || undefined,
      in_kev: inKev || undefined,
      epss_gt: epssGt ? Number(epssGt) : undefined,
      vendor: vendor || undefined,
      product: product || undefined,
      limit,
      offset,
    });
  } catch (e) {
    error = "Failed to search vulnerabilities. Please try again.";
    results = null;
  }
  loading = false;
}

function handleSubmit(e: SubmitEvent) {
  e.preventDefault();
  const sp = new URLSearchParams();
  if (q) sp.set("q", q);
  if (severity) sp.set("severity", severity);
  if (inKev) sp.set("in_kev", "1");
  if (epssGt) sp.set("epss_gt", epssGt);
  if (vendor) sp.set("vendor", vendor);
  if (product) sp.set("product", product);
  goto(`${base}/search?${sp.toString()}`, { replaceState: true });
  doSearch(0);
}

function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

function truncate(text: string | null, len: number): string {
  if (!text) return "";
  return text.length > len ? text.slice(0, len) + "..." : text;
}

function fmtDate(d: string | null): string {
  if (!d) return "-";
  return new Date(d).toLocaleDateString("en-AU", { year: "numeric", month: "short", day: "numeric" });
}

function toggleSort(col: SortCol) {
  if (sortCol === col) {
    if (sortDir === "desc") {
      sortDir = "asc";
    } else {
      sortCol = null;
    }
  } else {
    sortCol = col;
    sortDir = "desc";
  }
}

let debounceTimer: ReturnType<typeof setTimeout>;
async function handleSoftwareInput() {
  clearTimeout(debounceTimer);
  if (softwareQuery.length < 2) {
    softwareSuggestions = [];
    showSuggestions = false;
    return;
  }
  debounceTimer = setTimeout(async () => {
    const res = await autocompleteSoftware(softwareQuery);
    softwareSuggestions = res?.results ?? [];
    showSuggestions = softwareSuggestions.length > 0;
  }, 250);
}

function selectSoftware(item: AutocompleteResult) {
  vendor = item.vendor;
  product = item.product;
  softwareQuery = `${item.vendor} ${item.product}`;
  showSuggestions = false;
}

function clearSoftware() {
  vendor = "";
  product = "";
  softwareQuery = "";
  softwareSuggestions = [];
  showSuggestions = false;
  doSearch(0);
}

const currentPage = $derived(Math.floor(currentOffset / limit) + 1);
const totalPages = $derived(results ? Math.ceil(results.total / limit) : 0);

const sortedResults = $derived(
  sortVulnerabilities(results?.results ?? [], sortCol, sortDir)
);

function downloadCsv() {
  if (!results) return;
  const header = ["CVE ID", "Description", "Severity", "CVSS", "EPSS Score", "EPSS Percentile", "KEV", "KEV Due Date", "Published"];
  const rows = results.results.map((v) =>
    [
      v.cve_id,
      (v.description ?? "").replace(/[\r\n]+/g, " "),
      v.severity ?? "",
      v.cvss_score?.toString() ?? "",
      v.epss_score != null ? (v.epss_score * 100).toFixed(1) + "%" : "",
      v.epss_percentile != null ? (v.epss_percentile * 100).toFixed(1) + "%" : "",
      v.in_kev ? "Yes" : "No",
      v.kev_due_date ?? "",
      v.published_at ? new Date(v.published_at).toISOString().split("T")[0] : "",
    ]
      .map((val) => {
        const safe = String(val).replace(/[\r\n]+/g, " ");
        const noFormula = /^[=+@-]/.test(safe) ? "'" + safe : safe;
        return '"' + noFormula.replace(/"/g, '""') + '"';
      })
      .join(","),
  );

  const csv = "\uFEFF" + [header.join(","), ...rows].join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), {
    href: url,
    download: `patch8-vulnerabilities-${q || "all"}.csv`,
  });
  a.click();
  URL.revokeObjectURL(url);
}
</script>

<svelte:head>
  <title>Search — patch8</title>
  <meta property="og:title" content="Vulnerability Search — patch8" />
  <meta property="og:description" content="Search vulnerabilities by CVE ID, description, or software — filter by severity, EPSS score, and KEV status" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/search" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Vulnerability Search — patch8" />
  <meta name="twitter:description" content="Search vulnerabilities by CVE ID, description, or software — filter by severity, EPSS score, and KEV status" />
  <link rel="canonical" href="https://patch8.link42.app/search" />
</svelte:head>

<div class="page-header">
  <h1>Vulnerability Search</h1>
</div>

<form class="filters" onsubmit={handleSubmit}>
  <input type="text" placeholder="Search CVE IDs or descriptions..." bind:value={q} class="search-input" />

  <select bind:value={severity}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
  </select>

  <label class="toggle-label">
    <input type="checkbox" bind:checked={inKev} />
    KEV only
  </label>

  <select bind:value={epssGt}>
    <option value="">Any EPSS</option>
    <option value="0.9">EPSS &gt; 0.9</option>
    <option value="0.7">EPSS &gt; 0.7</option>
    <option value="0.5">EPSS &gt; 0.5</option>
    <option value="0.1">EPSS &gt; 0.1</option>
  </select>

  <div class="software-filter">
    <div class="autocomplete-wrap">
      <input
        type="text"
        placeholder="Filter by vendor/product..."
        bind:value={softwareQuery}
        oninput={handleSoftwareInput}
        onfocus={() => { if (softwareSuggestions.length > 0) showSuggestions = true; }}
        onblur={() => { setTimeout(() => showSuggestions = false, 200); }}
        class="search-input software-input"
      />
      {#if vendor}
        <button class="clear-btn" onclick={clearSoftware} type="button">&times;</button>
      {/if}
      {#if showSuggestions}
        <ul class="suggestions">
          {#each softwareSuggestions as item}
            <li>
              <button type="button" onmousedown={() => selectSoftware(item)}>
                <span class="vendor">{item.vendor}</span>
                <span class="product">{item.product}</span>
                <span class="count">{item.vuln_count} CVEs</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>

  <button type="submit" class="btn-primary" disabled={loading}>{loading ? "Searching..." : "Search"}</button>
</form>

{#if loading}
  <p class="loading">Loading...</p>
{:else if error}
  <p class="error">{error}</p>
{:else if results}
  <div class="results-header">
    <span>{results.total.toLocaleString()} result{results.total === 1 ? "" : "s"}</span>
    <div class="results-header-right">
      {#if totalPages > 1}
        <span class="page-info">Page {currentPage} of {totalPages}</span>
      {/if}
      {#if results.results.length > 0}
        <button class="export-btn" onclick={downloadCsv}>Export CSV</button>
      {/if}
    </div>
  </div>

  {#if results.results.length > 0}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Description</th>
          <th class="sortable" onclick={() => toggleSort("severity")} aria-sort={sortCol === "severity" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
            Severity {#if sortCol === "severity"}<span class="sort-arrow">{sortDir === "asc" ? "↑" : "↓"}</span>{/if}
          </th>
          <th class="sortable" onclick={() => toggleSort("cvss_score")} aria-sort={sortCol === "cvss_score" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
            CVSS {#if sortCol === "cvss_score"}<span class="sort-arrow">{sortDir === "asc" ? "↑" : "↓"}</span>{/if}
          </th>
          <th class="sortable" onclick={() => toggleSort("epss_score")} aria-sort={sortCol === "epss_score" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
            EPSS {#if sortCol === "epss_score"}<span class="sort-arrow">{sortDir === "asc" ? "↑" : "↓"}</span>{/if}
          </th>
          <th class="sortable" onclick={() => toggleSort("in_kev")} aria-sort={sortCol === "in_kev" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
            KEV {#if sortCol === "in_kev"}<span class="sort-arrow">{sortDir === "asc" ? "↑" : "↓"}</span>{/if}
          </th>
          <th class="sortable" onclick={() => toggleSort("published_at")} aria-sort={sortCol === "published_at" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
            Published {#if sortCol === "published_at"}<span class="sort-arrow">{sortDir === "asc" ? "↑" : "↓"}</span>{/if}
          </th>
        </tr>
      </thead>
      <tbody>
        {#each sortedResults as vuln}
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
            <td>{#if vuln.in_kev}<span class="kev-badge">KEV</span>{:else}<span class="dim">—</span>{/if}</td>
            <td class="date">{fmtDate(vuln.published_at)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  {#if totalPages > 1}
    <div class="pagination">
      <button disabled={currentOffset === 0} onclick={() => doSearch(currentOffset - limit)}>Previous</button>
      <button disabled={currentOffset + limit >= results.total} onclick={() => doSearch(currentOffset + limit)}>Next</button>
    </div>
  {/if}
  {:else}
    <p class="empty">No vulnerabilities found matching your criteria.</p>
  {/if}
{/if}

<style>
  .page-header { margin-bottom: 16px; }
  h1 { font-size: 20px; font-weight: 600; }

  .filters {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 20px;
  }
  .search-input {
    flex: 1;
    min-width: 200px;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-card);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    outline: none;
  }
  .search-input:focus { border-color: var(--accent); }
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
  .toggle-label {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 13px;
    color: var(--text-mid);
    cursor: pointer;
    white-space: nowrap;
  }
  .btn-primary {
    padding: 8px 16px;
    background: var(--accent);
    color: var(--text-inv);
    font-weight: 600;
    font-size: 13px;
    border-radius: 8px;
    transition: background 0.15s;
  }
  .btn-primary:hover { background: var(--accent-hover); }

  .results-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    color: var(--text-mid);
    margin-bottom: 12px;
  }
  .results-header-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .page-info { font-family: "Geist Mono", monospace; }
  .export-btn {
    padding: 4px 12px;
    font-size: 12px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-card);
    color: var(--text-dim);
    cursor: pointer;
    font-family: inherit;
  }
  .export-btn:hover {
    border-color: var(--accent);
    color: var(--text);
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
  th.sortable { cursor: pointer; user-select: none; }
  th.sortable:hover { color: var(--text); }
  .sort-arrow { font-size: 10px; margin-left: 2px; }
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

  .kev-badge { display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 3px; background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); letter-spacing: 0.03em; }

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
  .error { color: var(--red); text-align: center; padding: 40px; }

  .software-filter { position: relative; }
  .autocomplete-wrap { position: relative; display: inline-block; }
  .software-input { min-width: 180px; }
  .clear-btn {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--text-dim);
    font-size: 16px;
    cursor: pointer;
    padding: 0 4px;
  }
  .clear-btn:hover { color: var(--text); }
  .suggestions {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    z-index: 10;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-top: 4px;
    max-height: 240px;
    overflow-y: auto;
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    list-style: none;
    padding: 4px;
  }
  .suggestions li button {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 10px;
    text-align: left;
    background: none;
    border: none;
    border-radius: 6px;
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
  }
  .suggestions li button:hover { background: var(--bg-hover); }
  .suggestions .vendor { font-weight: 600; }
  .suggestions .product { color: var(--text-mid); }
  .suggestions .count { margin-left: auto; font-size: 11px; color: var(--text-dim); font-family: "Geist Mono", monospace; }
</style>
