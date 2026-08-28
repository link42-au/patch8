<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { page } from "$app/state";
import { getPatchTuesdayDetail, type PatchTuesdayCve } from "$lib/api";
import { prettyName } from "$lib/utils";

// ── State ─────────────────────────────────────────────────

let detail = $state<Awaited<ReturnType<typeof getPatchTuesdayDetail>>>(null);
let loading = $state(true);
let error = $state<string | null>(null);

// ── Derived ───────────────────────────────────────────────

let month = $derived((page.params as Record<string, string>).month);
let exploited = $derived(detail?.vulnerabilities.filter((v) => v.ssvc_exploitation === "active") ?? []);
let formattedMonth = $derived.by(() => {
  if (!month) return "";
  const [y, m] = month.split("-");
  return new Date(Number(y), Number(m) - 1).toLocaleDateString("en-AU", { year: "numeric", month: "long" });
});

// ── Helpers ───────────────────────────────────────────────

function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

function fmtEpss(score: number | null): string {
  if (score == null) return "-";
  return (score * 100).toFixed(1) + "%";
}

function fmtProducts(products: string | null): string {
  if (!products) return "-";
  const parts = products.split(",").map((p) => {
    const trimmed = p.trim();
    const slash = trimmed.indexOf("/");
    if (slash > 0) return prettyName(trimmed.slice(0, slash)) + " " + prettyName(trimmed.slice(slash + 1));
    return prettyName(trimmed);
  });
  return parts.slice(0, 3).join(", ") + (parts.length > 3 ? " ..." : "");
}

function truncate(text: string | null, len: number): string {
  if (!text) return "";
  return text.length > len ? text.slice(0, len) + "..." : text;
}

onMount(async () => {
  try {
    if (!/^\d{4}-\d{2}$/.test(month)) {
      error = "Invalid month format";
      return;
    }
    detail = await getPatchTuesdayDetail(month);
    if (!detail) error = "Report not found";
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to load report";
  } finally {
    loading = false;
  }
});
</script>

<svelte:head>
  <title>{formattedMonth} Patch Tuesday — patch8</title>
  <meta property="og:title" content="{formattedMonth} Patch Tuesday — patch8" />
  <meta property="og:description" content="{formattedMonth} Patch Tuesday analysis — Microsoft security updates with EPSS scores, KEV data, and exploitation status" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/reports/patch-tuesday/{month}" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="{formattedMonth} Patch Tuesday — patch8" />
  <meta name="twitter:description" content="{formattedMonth} Patch Tuesday analysis — Microsoft security updates with EPSS scores, KEV data, and exploitation status" />
  <link rel="canonical" href="https://patch8.link42.app/reports/patch-tuesday/{month}" />
</svelte:head>

<div class="rpt-detail">
  <nav class="breadcrumb">
    <a href="{base}/reports/patch-tuesday">Patch Tuesday Reports</a>
    <span>/</span>
    <span>{formattedMonth}</span>
  </nav>

  <h1>{formattedMonth} Patch Tuesday</h1>
  <p class="subtitle">Microsoft monthly security update analysis</p>

  {#if loading}
    <p class="loading">Loading report...</p>
  {:else if error}
    <p class="error-msg">{error}</p>
  {:else if detail}
    <!-- AI Narrative -->
    {#if detail.narrative}
      <section class="rpt-narrative">
        <div class="rpt-narrative-header">
          <h2>Executive Briefing</h2>
          <span class="ai-indicator">AI-generated analysis</span>
        </div>
        {#each detail.narrative.split("\n\n") as para}
          <p>{para}</p>
        {/each}
      </section>
    {/if}

    <!-- Summary Stats -->
    <div class="rpt-stats-grid">
      <div class="stat-pill">
        <span class="stat-value">{detail.summary.total}</span>
        <span class="stat-label">Total CVEs</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value {detail.summary.critical > 0 ? 'danger' : ''}">{detail.summary.critical}</span>
        <span class="stat-label">Critical</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value">{detail.summary.high}</span>
        <span class="stat-label">High</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value">{detail.summary.in_kev}</span>
        <span class="stat-label">In KEV</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value {detail.summary.actively_exploited > 0 ? 'danger' : ''}">{detail.summary.actively_exploited}</span>
        <span class="stat-label">Actively Exploited</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value">{detail.summary.poc_available}</span>
        <span class="stat-label">PoC Available</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value">{detail.summary.automatable}</span>
        <span class="stat-label">Automatable</span>
      </div>
      <div class="stat-pill">
        <span class="stat-value">{fmtEpss(detail.summary.max_epss)}</span>
        <span class="stat-label">Max EPSS</span>
      </div>
    </div>

    <!-- Actively Exploited -->
    {#if exploited.length > 0}
      <section class="rpt-exploited-section">
        <h2>Actively Exploited Vulnerabilities</h2>
        <p class="exploited-warning">These vulnerabilities have confirmed active exploitation and should be prioritised for immediate patching.</p>
        <div class="exploited-cards">
          {#each exploited as cve}
            <div class="exploited-card">
              <div class="exploited-header">
                <a href="{base}/vulnerabilities/{cve.cve_id}" class="cve-link">{cve.cve_id}</a>
                {#if cve.severity}<span class="sev-badge {sevClass(cve.severity)}">{cve.severity}</span>{/if}
                {#if cve.cvss_score != null}<span class="mono">CVSS {cve.cvss_score.toFixed(1)}</span>{/if}
                {#if cve.epss_score != null}<span class="mono">EPSS {fmtEpss(cve.epss_score)}</span>{/if}
              </div>
              <p class="exploited-desc">{truncate(cve.description, 200)}</p>
              <div class="exploited-products">{fmtProducts(cve.products)}</div>
              {#if cve.kev_due_date}<div class="kev-due">KEV remediation due: {cve.kev_due_date}</div>{/if}
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <!-- Full CVE Table -->
    <section class="rpt-table-section">
      <h2>All Vulnerabilities ({detail.vulnerabilities.length})</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>EPSS</th>
              <th>Exploitation</th>
              <th>Products</th>
            </tr>
          </thead>
          <tbody>
            {#each detail.vulnerabilities as cve}
              <tr>
                <td><a href="{base}/vulnerabilities/{cve.cve_id}" class="cve-link">{cve.cve_id}</a></td>
                <td>
                  {#if cve.severity}
                    <span class="sev-badge {sevClass(cve.severity)}">{cve.severity}</span>
                  {:else}
                    <span class="dim">-</span>
                  {/if}
                </td>
                <td class="mono">{cve.cvss_score?.toFixed(1) ?? "-"}</td>
                <td class="mono">{fmtEpss(cve.epss_score)}</td>
                <td>
                  {#if cve.ssvc_exploitation === "active"}
                    <span class="exploit-active">Active</span>
                  {:else if cve.ssvc_exploitation === "poc"}
                    <span class="exploit-poc">PoC</span>
                  {:else}
                    <span class="dim">-</span>
                  {/if}
                </td>
                <td class="products-cell">{fmtProducts(cve.products)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>

    <div class="rpt-footer">
      <a href="{base}/search">Explore all vulnerabilities</a>
    </div>
  {/if}
</div>

<style>
  .rpt-detail { max-width: 1100px; margin: 0 auto; }
  .breadcrumb { font-size: 13px; color: var(--text-dim); margin-bottom: 16px; display: flex; gap: 8px; align-items: center; }
  .breadcrumb a { color: var(--accent); text-decoration: none; }
  .breadcrumb a:hover { text-decoration: underline; }
  h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
  .subtitle { font-size: 14px; color: var(--text-dim); margin-bottom: 32px; }
  h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; }

  /* ── Narrative ────────────────────────────────────── */

  .rpt-narrative { padding: 24px; border: 1px solid var(--border); border-radius: 10px; background: var(--bg-card); margin-bottom: 32px; }
  .rpt-narrative-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
  .rpt-narrative-header h2 { margin-bottom: 0; }
  .ai-indicator { font-size: 11px; color: var(--text-dim); padding: 2px 8px; background: var(--bg-subtle); border: 1px solid var(--border); border-radius: 4px; }
  .rpt-narrative p { font-size: 14px; line-height: 1.7; color: var(--text-mid); margin-bottom: 12px; }
  .rpt-narrative p:last-child { margin-bottom: 0; }

  /* ── Stats Grid ───────────────────────────────────── */

  .rpt-stats-grid { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 32px; }
  .stat-pill { flex: 1; min-width: 110px; padding: 14px 16px; border: 1px solid var(--border); border-radius: 10px; background: var(--bg-card); text-align: center; display: flex; flex-direction: column; gap: 4px; }
  .stat-value { font-size: 22px; font-weight: 700; font-family: "Geist Mono", monospace; color: var(--text); }
  .stat-value.danger { color: var(--red); }
  .stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-dim); }

  /* ── Exploited Section ────────────────────────────── */

  .rpt-exploited-section { margin-bottom: 32px; padding: 24px; border: 1px solid var(--red-border); border-radius: 10px; background: var(--red-bg); }
  .rpt-exploited-section h2 { color: var(--red); }
  .exploited-warning { font-size: 13px; color: var(--red); margin-bottom: 16px; opacity: 0.85; }
  .exploited-cards { display: flex; flex-direction: column; gap: 12px; }
  .exploited-card { padding: 16px; border: 1px solid var(--red-border); border-radius: 8px; background: var(--bg-card); }
  .exploited-header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
  .exploited-desc { font-size: 13px; color: var(--text-mid); line-height: 1.5; margin-bottom: 8px; }
  .exploited-products { font-size: 12px; color: var(--text-dim); }
  .kev-due { font-size: 12px; color: var(--red); margin-top: 6px; font-weight: 500; }

  /* ── Table ────────────────────────────────────────── */

  .rpt-table-section { margin-bottom: 32px; }
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-dim); padding: 8px 12px; border-bottom: 1px solid var(--border-strong); white-space: nowrap; }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: var(--bg-hover); }
  .cve-link { color: var(--accent); font-weight: 500; font-family: "Geist Mono", monospace; font-size: 13px; white-space: nowrap; text-decoration: none; }
  .cve-link:hover { text-decoration: underline; }
  .mono { font-family: "Geist Mono", monospace; }
  .dim { color: var(--text-dim); }
  .products-cell { color: var(--text-mid); max-width: 200px; font-size: 12px; }

  .sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; }
  .sev-badge.critical { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .sev-badge.high { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-badge.medium { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-badge.low { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }

  .exploit-active { font-size: 11px; font-weight: 600; color: var(--red); background: var(--red-bg); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--red-border); }
  .exploit-poc { font-size: 11px; font-weight: 600; color: var(--amber); background: var(--amber-bg); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--amber-border); }

  /* ── Footer ───────────────────────────────────────── */

  .rpt-footer { text-align: center; padding: 24px 0; }
  .rpt-footer a { color: var(--accent); text-decoration: none; font-size: 14px; }
  .rpt-footer a:hover { text-decoration: underline; }

  /* ── Loading / Error ──────────────────────────────── */

  .loading, .error-msg { text-align: center; padding: 60px 0; color: var(--text-dim); font-size: 14px; }
  .error-msg { color: var(--red); }

  /* ── Responsive ───────────────────────────────────── */

  @media (max-width: 640px) {
    .rpt-stats-grid { gap: 8px; }
    .stat-pill { min-width: 80px; padding: 10px 8px; }
    .stat-value { font-size: 18px; }
    .exploited-header { gap: 6px; }
    .rpt-narrative { padding: 16px; }
  }
</style>
