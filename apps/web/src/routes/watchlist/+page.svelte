<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import {
  getMe,
  getWatchlist,
  addWatchlistItem,
  removeWatchlistItem,
  getWatchlistMatches,
  autocompleteSoftware,
  type AuthUser,
  type WatchlistItem,
  type WatchlistMatch,
  type AutocompleteResult
} from "$lib/api";
import { highlightMatch } from "$lib/utils";

let user = $state<AuthUser | null>(null);
let loadingAuth = $state(true);

let items = $state<WatchlistItem[]>([]);
let matches = $state<WatchlistMatch[]>([]);
let loadingData = $state(false);

// Form state
let softwareName = $state("");
let ecosystem = $state("");
let version = $state("");
let adding = $state(false);

// Autocomplete state
let suggestions = $state<AutocompleteResult[]>([]);
let showSuggestions = $state(false);
let highlightIndex = $state(-1);
let autocompleteLoading = $state(false);
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

const ecosystems = [
  "npm", "pypi", "go", "maven", "nuget", "crates.io", "rubygems", "packagist", "cargo", "hex", "pub"
];

onMount(async () => {
  user = await getMe();
  loadingAuth = false;
  if (user) {
    await loadData();
  }
});

async function loadData() {
  loadingData = true;
  const [wlRes, matchRes] = await Promise.all([
    getWatchlist(),
    getWatchlistMatches()
  ]);
  if (wlRes) items = wlRes.items;
  if (matchRes) matches = matchRes.matches;
  loadingData = false;
}

async function handleAdd(e: SubmitEvent) {
  e.preventDefault();
  if (!softwareName.trim()) return;

  adding = true;
  const newItem = await addWatchlistItem({
    software_name: softwareName.trim(),
    ecosystem: ecosystem || undefined,
    version: version.trim() || undefined,
  });

  if (newItem) {
    softwareName = "";
    ecosystem = "";
    version = "";
    await loadData();
  }
  adding = false;
}

async function handleRemove(id: string) {
  const success = await removeWatchlistItem(id);
  if (success) {
    await loadData();
  }
}

function handleSoftwareInput() {
  showSuggestions = true;
  if (softwareName.length < 3) {
    suggestions = [];
    return;
  }

  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(async () => {
    autocompleteLoading = true;
    try {
      const res = await autocompleteSoftware(softwareName, 10);
      suggestions = res?.results ?? [];
      highlightIndex = -1;
    } catch {
      suggestions = [];
    } finally {
      autocompleteLoading = false;
    }
  }, 300);
}

function handleSoftwareKeyDown(e: KeyboardEvent) {
  if (!showSuggestions || suggestions.length === 0) return;

  if (e.key === "ArrowDown") {
    e.preventDefault();
    highlightIndex = (highlightIndex + 1) % suggestions.length;
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    highlightIndex = highlightIndex <= 0 ? suggestions.length - 1 : highlightIndex - 1;
  } else if (e.key === "Enter" && highlightIndex >= 0) {
    e.preventDefault();
    selectSoftwareSuggestion(suggestions[highlightIndex]);
  } else if (e.key === "Escape") {
    showSuggestions = false;
  }
}

function selectSoftwareSuggestion(item: AutocompleteResult) {
  softwareName = item.product;
  showSuggestions = false;
}

function handleSoftwareBlur() {
  setTimeout(() => {
    showSuggestions = false;
  }, 200);
}



function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

function fmtDate(d: string | null): string {
  if (!d) return "-";
  return new Date(d).toLocaleDateString("en-AU", { year: "numeric", month: "short", day: "numeric" });
}
</script>

<svelte:head>
  <title>Watchlist — patch8</title>
  <meta property="og:title" content="Watchlist — patch8" />
  <meta property="og:description" content="Track software packages and get notified of new vulnerabilities — monitor CVEs affecting your dependencies" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/watchlist" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Watchlist — patch8" />
  <meta name="twitter:description" content="Track software packages and get notified of new vulnerabilities — monitor CVEs affecting your dependencies" />
  <link rel="canonical" href="https://patch8.link42.app/watchlist" />
</svelte:head>

<div class="page-header">
  <h1>Watchlist</h1>
</div>

{#if loadingAuth}
  <p class="loading">Loading...</p>
{:else if !user}
  <div class="auth-prompt">
    <p>Watchlists are unavailable in this static release.</p>
  </div>
{:else}
  <div class="add-form-container">
    <h2>Add Software</h2>
    <form class="filters" onsubmit={handleAdd}>
      <div class="search-container">
        <input
          type="text"
          placeholder="Software name (e.g. react, django)"
          bind:value={softwareName}
          oninput={handleSoftwareInput}
          onkeydown={handleSoftwareKeyDown}
          onblur={handleSoftwareBlur}
          onfocus={() => { if (softwareName.length >= 3) showSuggestions = true; }}
          class="search-input"
          autocomplete="off"
          required
        />
        {#if showSuggestions && (suggestions.length > 0 || autocompleteLoading || softwareName.length >= 3)}
          <div class="autocomplete-dropdown">
            {#if autocompleteLoading}
              <div class="autocomplete-item loading-item">Loading...</div>
            {:else if suggestions.length > 0}
              {#each suggestions as item, i}
                <div
                  class="autocomplete-item {i === highlightIndex ? 'highlighted' : ''}"
                  onmousedown={() => selectSoftwareSuggestion(item)}
                  role="button"
                  tabindex="0"
                >
                  <div class="item-text">
                    <span class="vendor-label">{@html highlightMatch(item.vendor, softwareName)}</span>
                    <span class="separator">/</span>
                    <span class="product-label">{@html highlightMatch(item.product, softwareName)}</span>
                  </div>
                  <span class="vuln-badge">{item.vuln_count}</span>
                </div>
              {/each}
            {:else if softwareName.length >= 3}
              <div class="autocomplete-item empty-item">No suggestions found</div>
            {/if}
          </div>
        {/if}
      </div>

      <select bind:value={ecosystem}>
        <option value="">Any ecosystem</option>
        {#each ecosystems as eco}
          <option value={eco}>{eco}</option>
        {/each}
      </select>

      <input
        type="text"
        placeholder="Version (optional)"
        bind:value={version}
        class="search-input version-input"
      />

      <button type="submit" class="btn-primary" disabled={adding || !softwareName.trim()}>
        {adding ? "Adding..." : "Add"}
      </button>
    </form>
  </div>

  {#if loadingData && items.length === 0}
    <p class="loading">Loading watchlist...</p>
  {:else}
    <div class="section">
      <h2>Tracked Packages</h2>
      {#if items.length > 0}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Software</th>
                <th>Ecosystem</th>
                <th>Version</th>
                <th>Added</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each items as item}
                <tr>
                  <td class="mono">{item.software_name}</td>
                  <td>
                    {#if item.ecosystem}
                      {item.ecosystem}
                    {:else}
                      <span class="dim">-</span>
                    {/if}
                  </td>
                  <td class="mono">
                    {#if item.version}
                      {item.version}
                    {:else}
                      <span class="dim">-</span>
                    {/if}
                  </td>
                  <td class="date">{fmtDate(item.created_at)}</td>
                  <td>
                    <button class="btn-remove" onclick={() => handleRemove(item.id)}>Remove</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="empty">Your watchlist is empty. Add some software above to start tracking.</p>
      {/if}
    </div>

    <div class="section">
      <h2>Matching Vulnerabilities</h2>
      {#if matches.length > 0}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Package</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>Fix Available</th>
              </tr>
            </thead>
            <tbody>
              {#each matches as match}
                <tr>
                  <td><a href="{base}/vulnerabilities/{match.cve_id}" class="cve-link">{match.cve_id}</a></td>
                  <td>
                    <div class="mono">{match.package_name}</div>
                    <div class="dim" style="font-size: 11px;">{match.ecosystem}</div>
                  </td>
                  <td>
                    {#if match.severity}
                      <span class="sev-badge {sevClass(match.severity)}">{match.severity}</span>
                    {:else}
                      <span class="dim">-</span>
                    {/if}
                  </td>
                  <td class="mono">{match.cvss_score?.toFixed(1) ?? "-"}</td>
                  <td class="mono">{match.epss_score != null ? (match.epss_score * 100).toFixed(1) + "%" : "-"}</td>
                  <td>{match.in_kev ? "Yes" : "—"}</td>
                  <td class="mono">
                    {#if match.fixed_version}
                      {match.fixed_version}
                    {:else}
                      <span class="dim">-</span>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="empty">No matching vulnerabilities found for your tracked packages.</p>
      {/if}
    </div>
  {/if}
{/if}

<style>
  .page-header { margin-bottom: 24px; }
  h1 { font-size: 20px; font-weight: 600; }
  h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: var(--text); }

  .section {
    margin-top: 40px;
  }

  .auth-prompt {
    text-align: center;
    padding: 60px 20px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-top: 20px;
  }
  .auth-prompt p {
    color: var(--text-mid);
    margin-bottom: 20px;
    font-size: 14px;
  }

  .add-form-container {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 32px;
  }

  .filters {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
  }
  .search-container { position: relative; flex: 2; min-width: 200px; }
  .search-input {
    width: 100%;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-card);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    outline: none;
  }
  .version-input {
    flex: 1;
    min-width: 120px;
  }
  .search-input:focus { border-color: var(--accent); }

  .autocomplete-dropdown { position: absolute; top: calc(100% + 4px); left: 0; width: 100%; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); z-index: 100; max-height: 300px; overflow-y: auto; }
  .autocomplete-item { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; cursor: pointer; font-size: 13px; border-bottom: 1px solid var(--border); }
  .autocomplete-item:last-child { border-bottom: none; }
  .autocomplete-item:hover, .autocomplete-item.highlighted { background: var(--bg-hover); }
  .item-text { display: flex; gap: 6px; align-items: center; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .vendor-label { color: var(--text-dim); }
  .product-label { color: var(--text); }
  .separator { color: var(--border-strong); }
  :global(.match) { font-weight: 600; color: var(--accent); }
  .vuln-badge { background: var(--bg); border: 1px solid var(--border); padding: 2px 6px; border-radius: 10px; font-size: 11px; color: var(--text-mid); font-family: "Geist Mono", monospace; }
  .loading-item, .empty-item { color: var(--text-dim); padding: 12px; text-align: center; cursor: default; }
  .loading-item:hover, .empty-item:hover { background: transparent; }

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

  .btn-primary {
    padding: 8px 16px;
    background: var(--accent);
    color: var(--text-inv);
    font-weight: 600;
    font-size: 13px;
    border-radius: 8px;
    transition: background 0.15s;
    border: none;
    cursor: pointer;
  }
  .btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

  .btn-remove {
    padding: 4px 8px;
    background: transparent;
    color: var(--red);
    border: 1px solid var(--red-border);
    border-radius: 4px;
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
  }
  .btn-remove:hover {
    background: var(--red-bg);
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

  .loading { color: var(--text-dim); text-align: center; padding: 40px; }
  .empty { color: var(--text-dim); text-align: center; padding: 40px; }
</style>
