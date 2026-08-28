<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { getPatchTuesdayMonths, type PatchTuesdayMonth } from "$lib/api";

let months = $state<PatchTuesdayMonth[]>([]);
let loading = $state(true);
let error = $state<string | null>(null);

function formatMonth(m: string): string {
  const [year, mon] = m.split("-");
  const date = new Date(Number(year), Number(mon) - 1);
  return date.toLocaleDateString("en-AU", { year: "numeric", month: "long" });
}

function severityBarWidths(m: PatchTuesdayMonth): { critical: number; high: number; medium: number; low: number } {
  const total = m.total || 1;
  return {
    critical: (m.critical / total) * 100,
    high: (m.high / total) * 100,
    medium: (m.medium / total) * 100,
    low: ((m.low + (m.total - m.critical - m.high - m.medium - m.low)) / total) * 100,
  };
}

onMount(async () => {
  try {
    const data = await getPatchTuesdayMonths();
    months = data?.months ?? [];
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load reports";
  } finally {
    loading = false;
  }
});
</script>

<svelte:head>
  <title>Patch Tuesday Reports — patch8</title>
  <meta property="og:title" content="Patch Tuesday Reports — patch8" />
  <meta property="og:description" content="Patch Tuesday and vulnerability trend reports — monthly Microsoft security update analysis with EPSS and KEV data" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/reports/patch-tuesday" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="Patch Tuesday Reports — patch8" />
  <meta name="twitter:description" content="Patch Tuesday and vulnerability trend reports — monthly Microsoft security update analysis with EPSS and KEV data" />
  <link rel="canonical" href="https://patch8.link42.app/reports/patch-tuesday" />
</svelte:head>

<div class="rpt-page">
  <h1>Patch Tuesday Reports</h1>
  <p class="subtitle">Monthly Microsoft security update analysis — 24 month history</p>

  {#if loading}
    <p class="loading">Loading reports...</p>
  {:else if error}
    <p class="error-msg">{error}</p>
  {:else}
    <div class="rpt-month-grid">
      {#each months as m}
        {@const bars = severityBarWidths(m)}
        <div class="rpt-month-card">
          <a href="{base}/reports/patch-tuesday/{m.month}">
            <div class="card-title">{formatMonth(m.month)}</div>
            <div class="card-stats">
              <div class="card-stat">
                <span class="card-stat-value">{m.total}</span>
                <span class="card-stat-label">Total CVEs</span>
              </div>
              <div class="card-stat">
                <span class="card-stat-value" class:critical-highlight={m.critical > 0}>{m.critical}</span>
                <span class="card-stat-label">Critical</span>
              </div>
              <div class="card-stat">
                <span class="card-stat-value" class:critical-highlight={m.actively_exploited > 0}>{m.actively_exploited}</span>
                <span class="card-stat-label">Exploited</span>
              </div>
            </div>
            <div class="rpt-severity-bar">
              <span class="bar-critical" style="width: {bars.critical}%"></span>
              <span class="bar-high" style="width: {bars.high}%"></span>
              <span class="bar-medium" style="width: {bars.medium}%"></span>
              <span class="bar-low" style="width: {bars.low}%"></span>
            </div>
            <div class="card-footer">
              <span>KEV: {m.in_kev}</span>
              <span>Max EPSS: {m.max_epss !== null ? (m.max_epss * 100).toFixed(1) : "—"}%</span>
            </div>
          </a>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .rpt-page { max-width: 1000px; margin: 0 auto; padding: 40px 24px; }
  h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
  .subtitle { font-size: 14px; color: var(--text-dim); margin-bottom: 32px; }
  .rpt-month-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
  .rpt-month-card { padding: 20px; border: 1px solid var(--border); border-radius: 10px; background: var(--bg-card); transition: border-color 0.15s; }
  .rpt-month-card:hover { border-color: var(--accent); }
  .rpt-month-card a { text-decoration: none; color: inherit; display: block; }
  .card-title { font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 12px; }
  .card-stats { display: flex; gap: 16px; margin-bottom: 12px; }
  .card-stat { display: flex; flex-direction: column; gap: 2px; }
  .card-stat-value { font-size: 18px; font-weight: 700; font-family: "Geist Mono", monospace; color: var(--text); }
  .card-stat-value.critical-highlight { color: var(--red); }
  .card-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-dim); }
  .rpt-severity-bar { display: flex; height: 6px; border-radius: 3px; overflow: hidden; margin-bottom: 12px; background: var(--bg-subtle); }
  .rpt-severity-bar span { display: block; height: 100%; }
  .bar-critical { background: var(--red); }
  .bar-high { background: var(--amber); }
  .bar-medium { background: var(--amber); opacity: 0.5; }
  .bar-low { background: var(--green); }
  .card-footer { display: flex; gap: 16px; font-size: 12px; color: var(--text-dim); font-family: "Geist Mono", monospace; }
  .loading, .error-msg { text-align: center; padding: 60px 0; color: var(--text-dim); font-size: 14px; }
  .error-msg { color: var(--red); }
  @media (max-width: 640px) { .rpt-month-grid { grid-template-columns: 1fr; } .card-stats { gap: 12px; } }
</style>
