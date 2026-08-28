<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { page } from "$app/stores";
import { goto } from "$app/navigation";
import { searchPackages, type PackageSearchResponse } from "$lib/api";

let results = $state<PackageSearchResponse | null>(null);
let loading = $state(false);
let error = $state<string | null>(null);

let q = $state("");
let ecosystem = $state("");
let currentOffset = $state(0);
const limit = 25;

onMount(() => {
  q = $page.url.searchParams.get("q") ?? "";
  ecosystem = $page.url.searchParams.get("ecosystem") ?? "";
  doSearch();
});

async function doSearch(offset = 0) {
  loading = true;
  currentOffset = offset;
  try {
    error = null;
    results = await searchPackages({
      q: q || undefined,
      ecosystem: ecosystem || undefined,
      limit,
      offset,
    });
  } catch (e) {
    error = "Failed to search packages. Please try again.";
    results = null;
  }
  loading = false;
}

function handleSubmit(e: SubmitEvent) {
  e.preventDefault();
  const sp = new URLSearchParams();
  if (q) sp.set("q", q);
  if (ecosystem) sp.set("ecosystem", ecosystem);
  goto(`${base}/packages?${sp.toString()}`, { replaceState: true });
  doSearch(0);
}

function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

const currentPage = $derived(Math.floor(currentOffset / limit) + 1);
// Note: PackageSearchResponse doesn't have a total field in the provided type,
// but we'll assume it might or we just handle next/prev based on results length
const hasNextPage = $derived(results && results.results.length === limit);
</script>

<svelte:head>
  <title>Packages — patch8</title>
  <meta property="og:title" content="Packages — patch8" />
  <meta property="og:description" content="Search vulnerable packages by ecosystem — npm, PyPI, Go, Maven, NuGet, and more" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/packages" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Packages — patch8" />
  <meta name="twitter:description" content="Search vulnerable packages by ecosystem — npm, PyPI, Go, Maven, NuGet, and more" />
  <link rel="canonical" href="https://patch8.link42.app/packages" />
</svelte:head>

<div class="packages-page">
  <h1>Packages</h1>

  <form class="filters" onsubmit={handleSubmit}>
  <input type="text" placeholder="Search package name..." bind:value={q} class="search-input" />

  <select bind:value={ecosystem}>
    <option value="">All ecosystems</option>
    <option value="npm">npm</option>
    <option value="pypi">PyPI</option>
    <option value="go">Go</option>
    <option value="maven">Maven</option>
    <option value="nuget">NuGet</option>
    <option value="crates.io">crates.io</option>
    <option value="rubygems">RubyGems</option>
    <option value="packagist">Packagist</option>
    <option value="cargo">Cargo</option>
    <option value="hex">Hex</option>
    <option value="pub">Pub</option>
  </select>

  <button type="submit" class="btn-primary" disabled={loading}>{loading ? "Searching..." : "Search"}</button>
</form>

{#if loading}
  <p class="loading">Loading...</p>
{:else if error}
  <p class="error">{error}</p>
{:else if results}
  <div class="results-header">
    <span>{results.results.length} result{results.results.length === 1 ? "" : "s"} on this page</span>
    {#if currentOffset > 0 || hasNextPage}
      <span class="page-info">Page {currentPage}</span>
    {/if}
  </div>

  {#if results.results.length > 0}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Ecosystem</th>
          <th>Package Name</th>
          <th>Vulnerabilities</th>
          <th>Max Severity</th>
          <th>Max EPSS</th>
        </tr>
      </thead>
      <tbody>
        {#each results.results as pkg}
          <tr>
            <td><span class="eco-badge">{pkg.ecosystem}</span></td>
            <td><a href="{base}/packages/{encodeURIComponent(pkg.ecosystem)}/{encodeURIComponent(pkg.package_name)}" class="pkg-link">{pkg.package_name}</a></td>
            <td>{pkg.vuln_count}</td>
            <td>
              {#if pkg.max_severity}
                <span class="sev-badge {sevClass(pkg.max_severity)}">{pkg.max_severity}</span>
              {:else}
                <span class="dim">-</span>
              {/if}
            </td>
            <td class="mono">{pkg.max_epss != null ? (pkg.max_epss * 100).toFixed(1) + "%" : "-"}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>

  {#if currentOffset > 0 || hasNextPage}
    <div class="pagination">
      <button disabled={currentOffset === 0} onclick={() => doSearch(currentOffset - limit)}>Previous</button>
      <button disabled={!hasNextPage} onclick={() => doSearch(currentOffset + limit)}>Next</button>
    </div>
  {/if}
   {:else}
     <p class="empty">No packages found matching your criteria.</p>
   {/if}
{/if}
</div>

<style>
  .packages-page {
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px 24px;
  }

  h1 {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 24px;
  }

  .filters {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 24px;
  }
  .search-input {
    flex: 1;
    min-width: 200px;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    outline: none;
  }
  .search-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-bg);
  }
  select {
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
  }
  .btn-primary {
    padding: 8px 16px;
    background: var(--accent);
    color: var(--text-inv);
    font-weight: 600;
    font-size: 13px;
    border-radius: 10px;
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
  .page-info { font-family: "Geist Mono", monospace; }

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

  .pkg-link {
    color: var(--accent);
    font-weight: 500;
    font-family: "Geist Mono", monospace;
    font-size: 13px;
    white-space: nowrap;
  }
  .pkg-link:hover { text-decoration: underline; }

  .eco-badge {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-family: "Geist Mono", monospace;
    background: var(--bg-card);
    border: 1px solid var(--border);
    color: var(--text-mid);
  }

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
</style>
