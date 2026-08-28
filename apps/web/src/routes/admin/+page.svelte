<script lang="ts">
import { onMount } from "svelte";
import { getMe, getFeedStatus, triggerFeeds, triggerBackfill, type AuthUser, type FeedStatus } from "$lib/api";

let user = $state<AuthUser | null>(null);
let loadingAuth = $state(true);

let feeds = $state<FeedStatus[]>([]);
let loadingFeeds = $state(false);

// Trigger Feeds State
let triggerCadence = $state("high");
let triggerSource = $state("");
let triggerResult = $state<{ triggered: string[]; cadence: string } | null>(null);
let triggerError = $state<string | null>(null);
let triggering = $state(false);

// Backfill State
let backfillSource = $state("nvd");
let backfillStart = $state("");
let backfillEnd = $state("");
let backfillResult = $state<Record<string, unknown> | null>(null);
let backfillError = $state<string | null>(null);
let backfilling = $state(false);

onMount(async () => {
  user = await getMe();
  loadingAuth = false;

  if (user?.role === "admin") {
    await loadFeeds();
  }
});

async function loadFeeds() {
  loadingFeeds = true;
  const data = await getFeedStatus();
  feeds = data?.feeds ?? [];
  loadingFeeds = false;
}

async function handleTrigger(e: SubmitEvent) {
  e.preventDefault();
  triggering = true;
  triggerResult = null;
  triggerError = null;

  const res = await triggerFeeds({
    cadence: triggerCadence || undefined,
    source: triggerSource || undefined,
  });

  if (res) {
    triggerResult = res;
    await loadFeeds();
  } else {
    triggerError = "Failed to trigger feeds";
  }
  triggering = false;
}

async function handleBackfill(e: SubmitEvent) {
  e.preventDefault();
  backfilling = true;
  backfillResult = null;
  backfillError = null;

  const res = await triggerBackfill({
    source: backfillSource,
    start: backfillStart || undefined,
    end: backfillEnd || undefined,
  });

  if (res) {
    backfillResult = res;
    await loadFeeds();
  } else {
    backfillError = "Failed to trigger backfill";
  }
  backfilling = false;
}

function relativeTime(dateStr: string | null): string {
  if (!dateStr) return "never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}
</script>

<svelte:head>
  <title>Admin — patch8</title>
  <meta property="og:title" content="Admin — patch8" />
  <meta property="og:description" content="patch8 admin dashboard — manage feeds and vulnerability data ingestion" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/admin" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Admin — patch8" />
  <meta name="twitter:description" content="patch8 admin dashboard — manage feeds and vulnerability data ingestion" />
  <link rel="canonical" href="https://patch8.link42.app/admin" />
</svelte:head>

<div class="page-header">
  <h1>Admin Dashboard</h1>
</div>

{#if loadingAuth}
  <p class="loading">Checking access...</p>
{:else if !user || user.role !== "admin"}
  <div class="unauthorized">
    <p>Admin functions are unavailable in this static release.</p>
  </div>
{:else}
  <div class="admin-grid">
    <!-- Section 1: Feed Status -->
    <section class="admin-section">
      <div class="section-header">
        <h2>Feed Status</h2>
        <button class="btn-secondary" onclick={loadFeeds} disabled={loadingFeeds}>
          {loadingFeeds ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {#if loadingFeeds && feeds.length === 0}
        <p class="loading">Loading feed status...</p>
      {:else if feeds.length === 0}
        <p class="empty">No feed runs recorded yet.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Last Run</th>
                <th>Added</th>
                <th>Updated</th>
                <th>Errors</th>
              </tr>
            </thead>
            <tbody>
              {#each feeds as feed}
                <tr>
                  <td class="source-name">{feed.source}</td>
                  <td class="date">{relativeTime(feed.last_started)}</td>
                  <td class="mono">{feed.total_added.toLocaleString()}</td>
                  <td class="mono">{feed.total_updated.toLocaleString()}</td>
                  <td class="mono {feed.error_count > 0 ? 'error-text' : ''}">{feed.error_count}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- Section 2: Trigger Feeds -->
    <section class="admin-section">
      <div class="section-header">
        <h2>Trigger Feeds</h2>
      </div>

      <form class="admin-form" onsubmit={handleTrigger}>
        <div class="form-group">
          <label for="cadence">Cadence</label>
          <select id="cadence" bind:value={triggerCadence}>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="daily">Daily</option>
          </select>
        </div>

        <div class="form-group">
          <label for="source">Source (Optional)</label>
          <select id="source" bind:value={triggerSource}>
            <option value="">All in cadence</option>
            <option value="nvd">NVD</option>
            <option value="epss">EPSS</option>
            <option value="kev">KEV</option>
            <option value="osv">OSV</option>
            <option value="ghsa">GHSA</option>
          </select>
        </div>

        <button type="submit" class="btn-primary" disabled={triggering}>
          {triggering ? "Triggering..." : "Trigger"}
        </button>
      </form>

      {#if triggerResult}
        <div class="result-box success">
          <p><strong>Success:</strong> Triggered {triggerResult.cadence} cadence.</p>
          {#if triggerResult.triggered.length > 0}
            <p class="mono mt-2">Sources: {triggerResult.triggered.join(", ")}</p>
          {/if}
        </div>
      {/if}
      {#if triggerError}
        <div class="result-box error">
          <p>{triggerError}</p>
        </div>
      {/if}
    </section>

    <!-- Section 3: Backfill -->
    <section class="admin-section">
      <div class="section-header">
        <h2>Backfill</h2>
      </div>

      <form class="admin-form" onsubmit={handleBackfill}>
        <div class="form-group">
          <label for="bf-source">Source</label>
          <select id="bf-source" bind:value={backfillSource}>
            <option value="nvd">NVD</option>
            <option value="epss">EPSS</option>
            <option value="kev">KEV</option>
          </select>
        </div>

        {#if backfillSource === "nvd"}
          <div class="form-group">
            <label for="bf-start">Start Date (Optional)</label>
            <input type="date" id="bf-start" bind:value={backfillStart} />
          </div>

          <div class="form-group">
            <label for="bf-end">End Date (Optional)</label>
            <input type="date" id="bf-end" bind:value={backfillEnd} />
          </div>
        {/if}

        <button type="submit" class="btn-primary" disabled={backfilling}>
          {backfilling ? "Running..." : "Run Backfill"}
        </button>
      </form>

      {#if backfillResult}
        <div class="result-box success">
          <p><strong>Success:</strong> Backfill triggered.</p>
          <pre class="mono mt-2">{JSON.stringify(backfillResult, null, 2)}</pre>
        </div>
      {/if}
      {#if backfillError}
        <div class="result-box error">
          <p>{backfillError}</p>
        </div>
      {/if}
    </section>
  </div>
{/if}

<style>
  .page-header { margin-bottom: 24px; }
  h1 { font-size: 20px; font-weight: 600; }

  .loading, .empty { color: var(--text-dim); text-align: center; padding: 40px; }

  .unauthorized {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 32px;
    text-align: center;
    color: var(--text-mid);
  }

  .admin-grid {
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .admin-section {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }
  h2 { font-size: 16px; font-weight: 600; }

  .admin-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 400px;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  label {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-mid);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  select, input[type="date"] {
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-body);
    font-family: inherit;
    font-size: 13px;
    color: var(--text);
    outline: none;
  }
  select:focus, input[type="date"]:focus { border-color: var(--accent); }

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
    align-self: flex-start;
  }
  .btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
  .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

  .btn-secondary {
    padding: 6px 12px;
    background: var(--bg-body);
    color: var(--text);
    border: 1px solid var(--border);
    font-weight: 500;
    font-size: 12px;
    border-radius: 6px;
    transition: all 0.15s;
    cursor: pointer;
  }
  .btn-secondary:hover:not(:disabled) { background: var(--bg-hover); border-color: var(--border-strong); }
  .btn-secondary:disabled { opacity: 0.6; cursor: not-allowed; }

  .result-box {
    margin-top: 16px;
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 13px;
  }
  .result-box.success {
    background: var(--green-bg);
    border: 1px solid var(--green-border);
    color: var(--green);
  }
  .result-box.error {
    background: var(--red-bg);
    border: 1px solid var(--red-border);
    color: var(--red);
  }

  .mt-2 { margin-top: 8px; }

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

  .source-name {
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .mono { font-family: "Geist Mono", monospace; }
  .date { white-space: nowrap; color: var(--text-mid); font-size: 12px; }
  .error-text { color: var(--red); font-weight: 600; }

  pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 11px;
  }
</style>
