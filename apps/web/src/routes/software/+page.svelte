<script lang="ts">
import { base } from "$app/paths";
  import { onMount } from "svelte";
  import { page } from "$app/stores";
  import { goto } from "$app/navigation";
  import { searchSoftware, autocompleteSoftware, type SoftwareSearchResponse, type AutocompleteResult } from "$lib/api";
  import { highlightMatch, prettyName } from "$lib/utils";

  let results = $state<SoftwareSearchResponse | null>(null);
  let loading = $state(false);

  let q = $state("");
  let currentOffset = $state(0);
  const limit = 25;

  let suggestions = $state<AutocompleteResult[]>([]);
  let showSuggestions = $state(false);
  let highlightIndex = $state(-1);
  let autocompleteLoading = $state(false);
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  onMount(() => {
    q = $page.url.searchParams.get("q") ?? "";
    if (q) doSearch();
  });

  async function doSearch(offset = 0) {
    loading = true;
    currentOffset = offset;
    results = await searchSoftware({
      q: q || undefined,
      limit,
      offset,
    });
    loading = false;
  }

  function handleInput() {
    showSuggestions = true;
    if (q.length < 3) {
      suggestions = [];
      return;
    }

    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      autocompleteLoading = true;
      try {
        const res = await autocompleteSoftware(q, 10);
        suggestions = res?.results ?? [];
        highlightIndex = -1;
      } catch {
        suggestions = [];
      } finally {
        autocompleteLoading = false;
      }
    }, 300);
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (!showSuggestions || suggestions.length === 0) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      highlightIndex = (highlightIndex + 1) % suggestions.length;
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      highlightIndex = highlightIndex <= 0 ? suggestions.length - 1 : highlightIndex - 1;
    } else if (e.key === "Enter" && highlightIndex >= 0) {
      e.preventDefault();
      selectSuggestion(suggestions[highlightIndex]);
    } else if (e.key === "Escape") {
      showSuggestions = false;
    }
  }

  function selectSuggestion(item: AutocompleteResult) {
    showSuggestions = false;
    goto(`${base}/software/${encodeURIComponent(item.vendor)}/${encodeURIComponent(item.product)}`);
  }

  function handleBlur() {
    setTimeout(() => {
      showSuggestions = false;
    }, 200);
  }



  function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    const sp = new URLSearchParams();
    if (q) sp.set("q", q);
    goto(`${base}/software?${sp.toString()}`, { replaceState: true });
    doSearch(0);
  }

  function sevClass(sev: string | null): string {
    if (!sev) return "";
    return sev.toLowerCase();
  }

  const currentPage = $derived(Math.floor(currentOffset / limit) + 1);
  const hasNextPage = $derived(results && results.results.length === limit);
</script>

<svelte:head>
  <title>Software — patch8</title>
  <meta property="og:title" content="Software — patch8" />
  <meta property="og:description" content="Search affected software by vendor and product — track CVEs, EPSS scores, and exploitation status across the NVD database" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/software" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Software — patch8" />
  <meta name="twitter:description" content="Search affected software by vendor and product — track CVEs, EPSS scores, and exploitation status across the NVD database" />
  <link rel="canonical" href="https://patch8.link42.app/software" />
</svelte:head>

<div class="packages-page">
  <h1>Software</h1>

  <form class="filters" onsubmit={handleSubmit}>
    <div class="search-container">
      <input
        type="text"
        placeholder="Search vendor or product..."
        bind:value={q}
        oninput={handleInput}
        onkeydown={handleKeyDown}
        onblur={handleBlur}
        onfocus={() => { if (q.length >= 3) showSuggestions = true; }}
        class="search-input"
        autocomplete="off"
      />
      {#if showSuggestions && (suggestions.length > 0 || autocompleteLoading || q.length >= 3)}
        <div class="autocomplete-dropdown">
          {#if autocompleteLoading}
            <div class="autocomplete-item loading-item">Loading...</div>
          {:else if suggestions.length > 0}
            {#each suggestions as item, i}
              <div
                class="autocomplete-item {i === highlightIndex ? 'highlighted' : ''}"
                onmousedown={() => selectSuggestion(item)}
                role="button"
                tabindex="0"
              >
                <div class="item-text">
                  <span class="vendor">{@html highlightMatch(prettyName(item.vendor), q)}</span>
                  <span class="separator">/</span>
                  <span class="product">{@html highlightMatch(prettyName(item.product), q)}</span>
                </div>
                <span class="vuln-badge">{item.vuln_count}</span>
              </div>
            {/each}
          {:else if q.length >= 3}
            <div class="autocomplete-item empty-item">No suggestions found</div>
          {/if}
        </div>
      {/if}
    </div>
    <button type="submit" class="btn-primary" disabled={loading}>{loading ? "Searching..." : "Search"}</button>
  </form>

  {#if !results && !loading}
    <p class="empty">Search for a vendor or product above to see results.</p>
  {:else if loading}
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
        <table>
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Product</th>
              <th>Vulnerabilities</th>
              <th>Max Severity</th>
              <th>Max EPSS</th>
            </tr>
          </thead>
          <tbody>
            {#each results.results as item}
              <tr>
                <td><a href="{base}/software/{encodeURIComponent(item.vendor)}" class="pkg-link">{prettyName(item.vendor)}</a></td>
                <td><a href="{base}/software/{encodeURIComponent(item.vendor)}/{encodeURIComponent(item.product)}" class="pkg-link">{prettyName(item.product)}</a></td>
                <td>{item.vuln_count}</td>
                <td>
                  {#if item.max_severity}
                    <span class="sev-badge {sevClass(item.max_severity)}">{item.max_severity}</span>
                  {:else}
                    <span class="dim">-</span>
                  {/if}
                </td>
                <td class="mono">{item.max_epss != null ? (item.max_epss * 100).toFixed(1) + "%" : "-"}</td>
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
      <p class="empty">No software found matching your criteria.</p>
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
  .search-container {
    position: relative;
    flex: 1;
    min-width: 200px;
  }
  .search-input {
    width: 100%;
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
  .autocomplete-dropdown {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    width: 100%;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    z-index: 100;
    max-height: 300px;
    overflow-y: auto;
  }
  .autocomplete-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    cursor: pointer;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
  }
  .autocomplete-item:last-child {
    border-bottom: none;
  }
  .autocomplete-item:hover, .autocomplete-item.highlighted {
    background: var(--bg-hover);
  }
  .item-text {
    display: flex;
    gap: 6px;
    align-items: center;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }
  .vendor {
    color: var(--text-dim);
  }
  .product {
    color: var(--text);
  }
  .separator {
    color: var(--border-strong);
  }
  :global(.match) {
    font-weight: 600;
    color: var(--accent);
  }
  .vuln-badge {
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 2px 6px;
    border-radius: 10px;
    font-size: 11px;
    color: var(--text-mid);
    font-family: "Geist Mono", monospace;
  }
  .loading-item, .empty-item {
    color: var(--text-dim);
    padding: 12px;
    text-align: center;
    cursor: default;
  }
  .loading-item:hover, .empty-item:hover {
    background: transparent;
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
</style>
