<script lang="ts">
import { onMount } from "svelte";
import { getFeedStatus, getMe, triggerFeeds, type FeedStatus, type AuthUser } from "$lib/api";

const CADENCE_MAP: Record<string, { label: string; schedule: string }> = {
  nvd: { label: "NVD", schedule: "Every 2 hours" },
  osv: { label: "OSV", schedule: "Every 6 hours" },
  epss: { label: "EPSS", schedule: "Daily" },
  kev: { label: "CISA KEV", schedule: "Every 6 hours" },
  ghsa: { label: "GitHub Advisories", schedule: "Every 6 hours" },
  msrc: { label: "Microsoft MSRC", schedule: "Daily" },
  euvd: { label: "ENISA EUVD", schedule: "Daily" },
  vulnrichment: { label: "CISA Vulnrichment", schedule: "Daily" },
};

let feeds = $state<FeedStatus[]>([]);
let loading = $state(true);
let error = $state<string | null>(null);
let user = $state<AuthUser | null>(null);
let isAdmin = $state(false);
let triggering = $state(false);
let triggerMessage = $state("");

// Merge API feeds with CADENCE_MAP so all configured feeds always show
let allFeeds = $derived.by(() => {
  const bySource = new Map<string, FeedStatus>(feeds.map((f) => [f.source, f]));
  return Object.keys(CADENCE_MAP).map((source) => {
    const existing = bySource.get(source);
    if (existing) return { ...existing, hasRun: existing.total_runs > 0 };
    return {
      source,
      hasRun: false,
      last_started: null,
      last_success: null,
      total_added: 0,
      total_updated: 0,
      total_runs: 0,
      error_count: 0,
    };
  });
});

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

function feedLabel(source: string): string {
  return CADENCE_MAP[source]?.label || source;
}

function feedSchedule(source: string): string {
  return CADENCE_MAP[source]?.schedule || "Unknown";
}

function statusClass(feed: {
  hasRun: boolean;
  last_started: string | null;
  last_success: string | null;
  error_count: number;
}): string {
  if (!feed.hasRun) return "pending";
  if (feed.error_count > 0 && !feed.last_success) return "error";
  if (feed.last_success && (Date.now() - new Date(feed.last_success).getTime()) / 3600000 > 48) return "stale";
  if (feed.last_started && (!feed.last_success || new Date(feed.last_started) > new Date(feed.last_success))) return "running";
  return "ok";
}

function statusText(feed: {
  hasRun: boolean;
  last_started: string | null;
  last_success: string | null;
  error_count: number;
}): string {
  if (!feed.hasRun) return "Pending";
  if (feed.error_count > 0 && !feed.last_success) return "Error";
  if (feed.last_success && (Date.now() - new Date(feed.last_success).getTime()) / 3600000 > 48) return "Stale";
  if (feed.last_started && (!feed.last_success || new Date(feed.last_started) > new Date(feed.last_success))) return "Running";
  return "OK";
}

async function handleTrigger() {
  triggering = true;
  triggerMessage = "";
  try {
    const res = await triggerFeeds({});
    if (res) {
      triggerMessage = `Triggered ${res.triggered.length} feeds`;
      setTimeout(async () => {
        const data = await getFeedStatus();
        feeds = data?.feeds ?? [];
        triggerMessage = "";
      }, 3000);
    } else {
      triggerMessage = "Failed to trigger feeds";
    }
  } catch {
    triggerMessage = "Error triggering feeds";
  } finally {
    triggering = false;
  }
}

onMount(async () => {
  try {
    user = await getMe();
    isAdmin = user?.role === "admin";
    const data = await getFeedStatus();
    feeds = data?.feeds ?? [];
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load feed status";
  } finally {
    loading = false;
  }
});
</script>

<svelte:head>
  <title>Feeds — patch8</title>
  <meta property="og:title" content="Feed Status — patch8" />
  <meta property="og:description" content="Live status of NVD, EPSS, KEV, OSV, and GHSA vulnerability feed ingestion" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/feeds" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Feed Status — patch8" />
  <meta name="twitter:description" content="Live status of NVD, EPSS, KEV, OSV, and GHSA vulnerability feed ingestion" />
  <link rel="canonical" href="https://patch8.link42.app/feeds" />
</svelte:head>

<div class="feeds-page">
  <h1>Feed Status</h1>

  {#if loading}
    <p class="status-msg">Loading feed status...</p>
  {:else if error}
    <div class="error-card">
      <p>{error}</p>
    </div>
  {:else}
    {#if isAdmin}
      <div class="admin-controls">
        <button
          class="trigger-btn"
          onclick={handleTrigger}
          disabled={triggering}
        >
          {triggering ? "Triggering..." : "Trigger Feeds"}
        </button>
        {#if triggerMessage}
          <span class="trigger-message">{triggerMessage}</span>
        {/if}
      </div>
    {/if}

    {@const merged = allFeeds}
    {@const activeFeeds = merged.filter((f) => statusClass(f) === "ok" || statusClass(f) === "running")}
    <div class="summary">
      <div class="summary-stat">
        <span class="summary-value">{activeFeeds.length}/{merged.length}</span>
        <span class="summary-label">Active Feeds</span>
      </div>
      <div class="summary-stat">
        <span class="summary-value">{merged.reduce((s, f) => s + f.total_added, 0).toLocaleString()}</span>
        <span class="summary-label">Total Added</span>
      </div>
      <div class="summary-stat">
        <span class="summary-value">{merged.filter((f) => f.error_count > 0).length}</span>
        <span class="summary-label">Errors</span>
      </div>
    </div>

    <section class="feed-list">
      {#each merged as feed}
        <div class="feed-card" class:feed-pending={!feed.hasRun}>
          <div class="feed-header">
            <div class="feed-name-row">
              <span class="feed-status status-{statusClass(feed)}">{statusText(feed)}</span>
              <span class="feed-name">{feedLabel(feed.source)}</span>
            </div>
            <span class="feed-schedule">{feedSchedule(feed.source)}</span>
          </div>

          {#if feed.hasRun}
            <div class="feed-stats">
              <div class="feed-stat">
                <span class="feed-stat-label">Last Run</span>
                <span class="feed-stat-value">{relativeTime(feed.last_started)}</span>
              </div>
              <div class="feed-stat">
                <span class="feed-stat-label">Added</span>
                <span class="feed-stat-value">{feed.total_added.toLocaleString()}</span>
              </div>
              <div class="feed-stat">
                <span class="feed-stat-label">Updated</span>
                <span class="feed-stat-value">{feed.total_updated.toLocaleString()}</span>
              </div>
              <div class="feed-stat">
                <span class="feed-stat-label">Runs</span>
                <span class="feed-stat-value">{feed.total_runs.toLocaleString()}</span>
              </div>
              <div class="feed-stat">
                <span class="feed-stat-label">Errors</span>
                <span class="feed-stat-value" class:has-errors={feed.error_count > 0}>{feed.error_count}</span>
              </div>
            </div>

            {#if feed.error_count > 0}
              <div class="feed-error">
                <span class="feed-error-label">Last error:</span>
                {feed.error_count} error{feed.error_count === 1 ? "" : "s"} recorded
              </div>
            {/if}
          {:else}
            <div class="feed-pending-msg">Awaiting first cron trigger</div>
          {/if}
        </div>
      {/each}
    </section>
  {/if}
</div>

<style>
  .feeds-page {
    max-width: 800px;
    margin: 0 auto;
    padding: 40px 24px;
  }

  h1 {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 24px;
  }

  .status-msg {
    color: var(--text-dim);
    font-size: 14px;
    text-align: center;
    padding: 60px 0;
  }

  .error-card {
    text-align: center;
    padding: 60px 0;
    color: var(--red);
    font-size: 14px;
  }

  /* ── Admin Controls ──────────────────────────────── */

  .admin-controls {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 24px;
  }

  .trigger-btn {
    padding: 8px 16px;
    background: var(--accent);
    color: var(--text-inv, #fff);
    border: none;
    border-radius: 8px;
    font-family: inherit;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.15s;
  }

  .trigger-btn:hover:not(:disabled) {
    opacity: 0.85;
  }

  .trigger-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .trigger-message {
    font-size: 13px;
    color: var(--text-mid);
  }

  /* ── Summary ─────────────────────────────────────── */

  .summary {
    display: flex;
    gap: 16px;
    margin-bottom: 32px;
    flex-wrap: wrap;
  }

  .summary-stat {
    flex: 1;
    min-width: 120px;
    padding: 16px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
    display: flex;
    flex-direction: column;
    gap: 4px;
    text-align: center;
  }

  .summary-value {
    font-size: 24px;
    font-weight: 700;
    color: var(--text);
    font-family: "Geist Mono", monospace;
  }

  .summary-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-dim);
  }

  /* ── Feed Cards ──────────────────────────────────── */

  .feed-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .feed-card {
    padding: 16px 20px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--bg-card);
  }

  .feed-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 14px;
  }

  .feed-name-row {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .feed-name {
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
  }

  .feed-status {
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding: 2px 8px;
    border-radius: 4px;
  }

  .status-ok {
    background: var(--green-bg);
    color: var(--green);
    border: 1px solid var(--green-border);
  }

  .status-error {
    background: var(--red-bg);
    color: var(--red);
    border: 1px solid var(--red-border);
  }

  .status-running {
    background: var(--amber-bg);
    color: var(--amber);
    border: 1px solid var(--amber-border);
  }

  .status-pending {
    background: var(--bg-subtle);
    color: var(--text-dim);
    border: 1px solid var(--border);
  }

  .status-stale {
    background: var(--bg-subtle);
    color: var(--text-dim);
    border: 1px solid var(--border);
  }

  .feed-pending {
    opacity: 0.7;
  }

  .feed-pending-msg {
    padding-top: 12px;
    border-top: 1px solid var(--border);
    font-size: 13px;
    color: var(--text-dim);
  }

  .feed-schedule {
    font-size: 12px;
    color: var(--text-dim);
    padding: 2px 8px;
    background: var(--bg-subtle);
    border-radius: 4px;
    border: 1px solid var(--border);
  }

  .feed-stats {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    padding-top: 12px;
    border-top: 1px solid var(--border);
  }

  .feed-stat {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .feed-stat-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-dim);
  }

  .feed-stat-value {
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
    font-family: "Geist Mono", monospace;
  }

  .has-errors {
    color: var(--red);
  }

  .feed-error {
    margin-top: 10px;
    padding: 10px 12px;
    background: var(--red-bg);
    border: 1px solid var(--red-border);
    border-radius: 6px;
    font-size: 12px;
    color: var(--red);
    word-break: break-all;
  }

  .feed-error-label {
    font-weight: 600;
    margin-right: 4px;
  }

  @media (max-width: 640px) {
    .summary {
      gap: 8px;
    }
    .summary-stat {
      min-width: 80px;
      padding: 12px 8px;
    }
    .summary-value {
      font-size: 18px;
    }
    .feed-header {
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
    }
    .feed-stats {
      gap: 12px;
    }
  }
</style>
