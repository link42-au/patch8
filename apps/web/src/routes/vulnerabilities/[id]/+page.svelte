<script lang="ts">
import { base } from "$app/paths";
import { onMount } from "svelte";
import { page } from "$app/stores";
import { getVulnerability, type VulnDetailResponse } from "$lib/api";
import type { AffectedPackage, AffectedSoftware, CweEntry, VulnReference } from "@patch8/shared";
import { prettyName } from "$lib/utils";

let data = $state<VulnDetailResponse | null>(null);
let loading = $state(true);

type ThreatContext = { actors: string[]; techniques: string[]; reports: { name: string; source: string; published: string | null }[]; first_seen: string | null; last_seen: string | null };

function unavailableThreatContext(): ThreatContext | null {
  return null;
}

// Threat intelligence remains unavailable without the removed gateway.
let threatContext = $state<ThreatContext | null>(unavailableThreatContext());
let threatLoading = $state(false);

onMount(async () => {
  const id = $page.params.id ?? "";
  data = await getVulnerability(id);
  loading = false;
});

function sevClass(sev: string | null): string {
  if (!sev) return "";
  return sev.toLowerCase();
}

function fmtDate(d: string | null): string {
  if (!d) return "-";
  return new Date(d).toLocaleDateString("en-AU", { year: "numeric", month: "short", day: "numeric" });
}

function parseJsonArray(val: unknown): string[] {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    try { return JSON.parse(val); } catch { return []; }
  }
  return [];
}

function parseRefs(val: unknown): VulnReference[] {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    try { return JSON.parse(val); } catch { return []; }
  }
  return [];
}

type CvssMetric = {
  abbr: string;
  name: string;
  valueAbbr: string;
  value: string;
  level: "high" | "medium" | "low";
};

const CVSS_V3_METRICS: Record<string, { name: string; values: Record<string, { value: string; level: "high" | "medium" | "low" }> }> = {
  AV: { name: "Attack Vector", values: { N: { value: "Network", level: "high" }, A: { value: "Adjacent", level: "medium" }, L: { value: "Local", level: "low" }, P: { value: "Physical", level: "low" } } },
  AC: { name: "Attack Complexity", values: { L: { value: "Low", level: "high" }, H: { value: "High", level: "low" } } },
  PR: { name: "Privileges Required", values: { N: { value: "None", level: "high" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "low" } } },
  UI: { name: "User Interaction", values: { N: { value: "None", level: "high" }, R: { value: "Required", level: "low" } } },
  S: { name: "Scope", values: { U: { value: "Unchanged", level: "low" }, C: { value: "Changed", level: "high" } } },
  C: { name: "Confidentiality", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  I: { name: "Integrity", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  A: { name: "Availability", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  E: { name: "Exploit Maturity", values: { X: { value: "Not Defined", level: "low" }, U: { value: "Unproven", level: "low" }, P: { value: "POC", level: "medium" }, F: { value: "Functional", level: "high" }, H: { value: "High", level: "high" }, A: { value: "Attacked", level: "high" } } },
  RL: { name: "Remediation Level", values: { X: { value: "Not Defined", level: "low" }, O: { value: "Official Fix", level: "low" }, T: { value: "Temporary Fix", level: "medium" }, W: { value: "Workaround", level: "medium" }, U: { value: "Unavailable", level: "high" } } },
  RC: { name: "Report Confidence", values: { X: { value: "Not Defined", level: "low" }, U: { value: "Unknown", level: "medium" }, R: { value: "Reasonable", level: "low" }, C: { value: "Confirmed", level: "high" } } },
};

const CVSS_V4_METRICS: Record<string, { name: string; values: Record<string, { value: string; level: "high" | "medium" | "low" }> }> = {
  AV: { name: "Attack Vector", values: { N: { value: "Network", level: "high" }, A: { value: "Adjacent", level: "medium" }, L: { value: "Local", level: "low" }, P: { value: "Physical", level: "low" } } },
  AC: { name: "Attack Complexity", values: { L: { value: "Low", level: "high" }, H: { value: "High", level: "low" } } },
  AT: { name: "Attack Requirements", values: { N: { value: "None", level: "high" }, P: { value: "Present", level: "low" } } },
  PR: { name: "Privileges Required", values: { N: { value: "None", level: "high" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "low" } } },
  UI: { name: "User Interaction", values: { N: { value: "None", level: "high" }, P: { value: "Passive", level: "medium" }, A: { value: "Active", level: "low" } } },
  VC: { name: "Vuln. Confidentiality", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  VI: { name: "Vuln. Integrity", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  VA: { name: "Vuln. Availability", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  SC: { name: "Sub. Confidentiality", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  SI: { name: "Sub. Integrity", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  SA: { name: "Sub. Availability", values: { N: { value: "None", level: "low" }, L: { value: "Low", level: "medium" }, H: { value: "High", level: "high" } } },
  E: { name: "Exploit Maturity", values: { X: { value: "Not Defined", level: "low" }, U: { value: "Unproven", level: "low" }, P: { value: "POC", level: "medium" }, F: { value: "Functional", level: "high" }, H: { value: "High", level: "high" }, A: { value: "Attacked", level: "high" } } },
  RL: { name: "Remediation Level", values: { X: { value: "Not Defined", level: "low" }, O: { value: "Official Fix", level: "low" }, T: { value: "Temporary Fix", level: "medium" }, W: { value: "Workaround", level: "medium" }, U: { value: "Unavailable", level: "high" } } },
  RC: { name: "Report Confidence", values: { X: { value: "Not Defined", level: "low" }, U: { value: "Unknown", level: "medium" }, R: { value: "Reasonable", level: "low" }, C: { value: "Confirmed", level: "high" } } },
};

function parseCvssVector(vector: string): CvssMetric[] {
  const parts = vector.split("/");
  if (parts.length < 2) return [];

  const prefix = parts[0];
  const isV4 = prefix.startsWith("CVSS:4");
  const metricDefs = isV4 ? CVSS_V4_METRICS : CVSS_V3_METRICS;

  const result: CvssMetric[] = [];
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const colonIdx = part.indexOf(":");
    if (colonIdx === -1) continue;
    const abbr = part.slice(0, colonIdx);
    const valueAbbr = part.slice(colonIdx + 1);
    const def = metricDefs[abbr];
    if (!def) continue;
    const valueDef = def.values[valueAbbr];
    if (!valueDef) continue;
    result.push({ abbr, name: def.name, valueAbbr, value: valueDef.value, level: valueDef.level });
  }
  return result;
}

function formatVersionRange(sw: AffectedSoftware): string {
  const parts: string[] = [];
  if (sw.version_start_including) parts.push(`>= ${sw.version_start_including}`);
  if (sw.version_start_excluding) parts.push(`> ${sw.version_start_excluding}`);
  if (sw.version_end_including) parts.push(`<= ${sw.version_end_including}`);
  if (sw.version_end_excluding) parts.push(`< ${sw.version_end_excluding}`);
  return parts.length > 0 ? parts.join(", ") : "*";
}

function truncateCpe(uri: string): string {
  const parts = uri.split(":");
  if (parts.length >= 6) {
    return parts.slice(2, 6).join(":");
  }
  return uri;
}

const vuln = $derived(data?.vulnerability);
const weaknesses = $derived(vuln ? parseJsonArray(vuln.weaknesses) : []);
const references = $derived.by(() => {
  const raw = vuln ? parseRefs(vuln.references) : [];
  const seen = new Set<string>();
  return raw.filter((r) => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });
});
const cvssMetrics = $derived(vuln?.cvss_vector ? parseCvssVector(vuln.cvss_vector) : []);
const cweDetails = $derived(data?.cwe_details ?? []);
const affectedSoftware = $derived.by(() => {
  const raw = data?.affected_software ?? [];
  const seen = new Set<string>();
  return raw.filter((s) => {
    const key = `${s.vendor}|${s.product}|${s.version ?? ""}|${s.version_start_including ?? ""}|${s.version_end_excluding ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
});
const aliases = $derived(data?.aliases ?? []);
</script>

<svelte:head>
  <title>{vuln?.cve_id ?? "Loading..."} — patch8</title>
  <meta property="og:title" content="{vuln?.cve_id ?? 'Vulnerability'} — patch8" />
  <meta property="og:description" content="{vuln?.cve_id ?? 'Vulnerability'}{vuln?.severity ? ` (${vuln.severity})` : ''}{vuln?.description ? ` — ${vuln.description.slice(0, 120)}` : ' — vulnerability details, EPSS score, and KEV status'}" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/vulnerabilities/{vuln?.cve_id ?? ''}" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="{vuln?.cve_id ?? 'Vulnerability'} — patch8" />
  <meta name="twitter:description" content="{vuln?.cve_id ?? 'Vulnerability'}{vuln?.severity ? ` (${vuln.severity})` : ''}{vuln?.description ? ` — ${vuln.description.slice(0, 120)}` : ' — vulnerability details, EPSS score, and KEV status'}" />
  <link rel="canonical" href="https://patch8.link42.app/vulnerabilities/{vuln?.cve_id ?? ''}" />
</svelte:head>

{#if loading}
  <p class="loading">Loading...</p>
{:else if !vuln}
  <p class="error">Vulnerability data is unavailable in this static release.</p>
{:else}
  <nav class="breadcrumb">
    <a href="{base}/">patch8</a> <span class="sep">/</span> <span>Vulnerabilities</span> <span class="sep">/</span> <span>{vuln.cve_id}</span>
  </nav>

  <div class="detail-header">
    <div class="cve-row">
      <h1>{vuln.cve_id}</h1>
      {#if vuln.severity}
        <span class="sev-badge {sevClass(vuln.severity)}">{vuln.severity}</span>
      {/if}
      {#if vuln.in_kev}
        <span class="kev-badge">KEV</span>
      {/if}
    </div>
    <div class="score-row">
      {#if vuln.cvss_score != null}
        <span class="score-pill cvss">CVSS {vuln.cvss_score.toFixed(1)}</span>
      {/if}
      {#if vuln.epss_score != null}
        <span class="score-pill epss">EPSS {(vuln.epss_score * 100).toFixed(1)}%</span>
      {/if}
      {#if vuln.epss_percentile != null}
        <span class="percentile">{(vuln.epss_percentile * 100).toFixed(0)}th percentile</span>
      {/if}
    </div>
    <div class="meta-row">
      <span>Published: {fmtDate(vuln.published_at)}</span>
      <span>Modified: {fmtDate(vuln.modified_at)}</span>
      <a href="https://threat10.link42.app/search?q={encodeURIComponent(vuln.cve_id)}&type=cve" class="cross-link" target="_blank" rel="noopener">View in threat10</a>
    </div>
  </div>

  {#if vuln.in_kev}
    <div class="kev-banner">
      <span class="kev-banner-label">CISA KEV</span>
      <span>Remediation due: <strong>{fmtDate(vuln.kev_due_date)}</strong></span>
      {#if vuln.kev_date_added}
        <span class="kev-added">Added {fmtDate(vuln.kev_date_added)}</span>
      {/if}
    </div>
  {/if}

  {#if vuln.description}
    <section class="section">
      <h2>Description</h2>
      <p class="description">{vuln.description}</p>
    </section>
  {/if}

  {#if vuln.cvss_vector}
    <section class="section">
      <h2>CVSS</h2>
      <div class="cvss-detail">
        <div class="cvss-bar-wrap">
          <div class="cvss-bar" style="width: {((vuln.cvss_score ?? 0) / 10) * 100}%"></div>
        </div>
        <code class="vector">{vuln.cvss_vector}</code>
        <span class="version-tag">{vuln.cvss_version ?? "v3.1"}</span>
      </div>
      {#if cvssMetrics.length > 0}
        <div class="cvss-breakdown">
          {#each cvssMetrics as metric}
            <div class="cvss-metric {metric.level}">
              <span class="metric-name">{metric.name}</span>
              <span class="metric-value">{metric.value}</span>
            </div>
          {/each}
        </div>
      {/if}
    </section>
  {/if}

  {#if vuln.in_kev}
    <section class="section kev-section">
      <h2>Known Exploited Vulnerability</h2>
      <div class="kev-grid">
        <div><span class="kev-label">Date Added</span><span>{fmtDate(vuln.kev_date_added)}</span></div>
        <div><span class="kev-label">Due Date</span><span>{fmtDate(vuln.kev_due_date)}</span></div>
        <div><span class="kev-label">Ransomware</span><span>{vuln.kev_ransomware ?? "Unknown"}</span></div>
      </div>
    </section>
  {/if}

  {#if threatLoading}
    <section class="section threat-section">
      <h2>Threat Intelligence</h2>
      <p class="loading-text">Loading threat context...</p>
    </section>
  {:else if threatContext && (threatContext.actors.length > 0 || threatContext.techniques.length > 0 || threatContext.reports.length > 0)}
    <section class="section threat-section">
      <h2>Threat Intelligence</h2>

      {#if threatContext.actors.length > 0}
        <div class="threat-subsection">
          <h3>Threat Actors</h3>
          <div class="threat-tags">
            {#each threatContext.actors as actor}
              <a href="https://threat10.link42.app/threat-actors/{encodeURIComponent(actor)}" class="threat-tag actor-tag">{actor}</a>
            {/each}
          </div>
        </div>
      {/if}

      {#if threatContext.techniques.length > 0}
        <div class="threat-subsection">
          <h3>ATT&CK Techniques</h3>
          <div class="threat-tags">
            {#each threatContext.techniques as technique}
              <a href="https://threat10.link42.app/techniques/{technique}" class="threat-tag technique-tag">{technique}</a>
            {/each}
          </div>
        </div>
      {/if}

      {#if threatContext.reports.length > 0}
        <div class="threat-subsection">
          <h3>Reports ({threatContext.reports.length})</h3>
          <div class="threat-reports">
            {#each threatContext.reports as report}
              <div class="threat-report">
                <span class="report-name">{report.name}</span>
                <span class="report-meta">{report.source}{report.published ? ` · ${report.published.slice(0, 10)}` : ""}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </section>
  {/if}

  {#if cweDetails.length > 0}
    <section class="section">
      <h2>Weaknesses ({cweDetails.length})</h2>
      <div class="cwe-list">
        {#each cweDetails as cwe}
          <div class="cwe-card">
            <div class="cwe-header">
              <span class="cwe-badge">{cwe.id}</span>
              <span class="cwe-name">{cwe.name}</span>
            </div>
            <p class="cwe-desc">{cwe.description}</p>
          </div>
        {/each}
      </div>
    </section>
  {:else if weaknesses.length > 0}
    <section class="section">
      <h2>Weaknesses</h2>
      <div class="badge-row">
        {#each weaknesses as cwe}
          <span class="cwe-badge">{cwe}</span>
        {/each}
      </div>
    </section>
  {/if}

  {#if affectedSoftware.length > 0}
    <section class="section">
      <h2>Affected Software ({affectedSoftware.length})</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Product</th>
              <th>Version Range</th>
              <th>CPE</th>
            </tr>
          </thead>
          <tbody>
            {#each affectedSoftware as sw}
              <tr>
                <td><a href="{base}/software/{encodeURIComponent(sw.vendor)}" class="vendor-link">{prettyName(sw.vendor)}</a></td>
                <td><a href="{base}/software/{encodeURIComponent(sw.vendor)}/{encodeURIComponent(sw.product)}" class="vendor-link">{prettyName(sw.product)}</a></td>
                <td class="mono">{#if sw.version}{sw.version}{:else}{formatVersionRange(sw)}{/if}</td>
                <td class="dim mono cpe-cell" title={sw.cpe_uri ?? ""}>{sw.cpe_uri ? truncateCpe(sw.cpe_uri) : "-"}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if data && data.affected_packages.length > 0}
    <section class="section">
      <h2>Affected Packages ({data.affected_packages.length})</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Ecosystem</th>
              <th>Package</th>
              <th>Vulnerable Range</th>
              <th>Fixed Version</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {#each data.affected_packages as pkg}
              <tr>
                <td><span class="eco-badge">{pkg.ecosystem}</span></td>
                <td class="mono">{pkg.package_name}</td>
                <td class="mono">{pkg.vulnerable_range ?? "-"}</td>
                <td class="mono fixed">{pkg.fixed_version ?? "-"}</td>
                <td class="dim">{pkg.source}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  {#if references.length > 0}
    <section class="section">
      <h2>References ({references.length})</h2>
      <ul class="ref-list">
        {#each references as ref}
          <li>
            <a href={ref.url} target="_blank" rel="noopener noreferrer" class="ref-link">{ref.url}</a>
            {#if ref.tags && ref.tags.length > 0}
              {#each ref.tags as tag}
                <span class="ref-tag">{tag}</span>
              {/each}
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if data && data.sources.length > 0}
    <section class="section">
      <h2>Sources</h2>
      <div class="badge-row">
        {#each data.sources as src}
          <span class="source-badge">{src.source}</span>
        {/each}
      </div>
    </section>
  {/if}

  {#if aliases.length > 0}
    <section class="section">
      <h2>Aliases</h2>
      <div class="badge-row">
        {#each aliases as alias}
          <span class="alias-badge">{alias.alias_type}: {alias.alias_value}</span>
        {/each}
      </div>
    </section>
  {/if}
{/if}

<style>
  .breadcrumb { font-size: 13px; color: var(--text-dim); margin-bottom: 16px; }
  .breadcrumb a { color: var(--text-mid); text-decoration: none; }
  .breadcrumb a:hover { color: var(--text); text-decoration: underline; }
  .breadcrumb .sep { margin: 0 6px; color: var(--border-strong); }

  .loading, .error { text-align: center; padding: 40px; color: var(--text-dim); }

  .detail-header { margin-bottom: 24px; }
  .cve-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  h1 { font-size: 24px; font-weight: 700; font-family: "Geist Mono", monospace; }

  .sev-badge {
    padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.03em;
  }
  .sev-badge.critical { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .sev-badge.high { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-badge.medium { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }
  .sev-badge.low { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .kev-badge {
    padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
    background: var(--accent-bg); color: var(--accent); border: 1px solid var(--accent-border);
  }

  .score-row { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
  .score-pill {
    padding: 4px 10px; border-radius: 6px; font-size: 13px; font-weight: 600;
    font-family: "Geist Mono", monospace;
  }
  .score-pill.cvss { background: var(--bg-hover); color: var(--text); }
  .score-pill.epss { background: var(--purple-bg); color: var(--purple); border: 1px solid var(--purple-border); }
  .percentile { font-size: 12px; color: var(--text-dim); }

  .meta-row { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: var(--text-dim); }

  .section { margin-bottom: 24px; }
  .section h2 { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
  .description { color: var(--text-mid); font-size: 14px; line-height: 1.7; }

  .cvss-detail { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .cvss-bar-wrap {
    width: 120px; height: 8px; background: var(--bg-hover); border-radius: 4px; overflow: hidden;
  }
  .cvss-bar { height: 100%; background: var(--accent); border-radius: 4px; }
  .vector { font-size: 12px; color: var(--text-mid); background: var(--bg-subtle); padding: 4px 8px; border-radius: 4px; }
  .version-tag { font-size: 11px; color: var(--text-dim); }

  .cvss-breakdown {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    margin-top: 12px;
  }
  @media (min-width: 600px) {
    .cvss-breakdown { grid-template-columns: 1fr 1fr 1fr 1fr; }
  }
  .cvss-metric {
    padding: 6px 10px;
    border-left: 3px solid;
    background: var(--bg-subtle);
    border-radius: 4px;
  }
  .cvss-metric.high { border-left-color: var(--red); }
  .cvss-metric.medium { border-left-color: var(--amber); }
  .cvss-metric.low { border-left-color: var(--green); }
  .metric-name { font-size: 11px; color: var(--text-dim); display: block; }
  .metric-value { font-size: 13px; font-weight: 600; color: var(--text); font-family: "Geist Mono", monospace; }

  .kev-section { background: var(--accent-bg); border: 1px solid var(--accent-border); border-radius: 10px; padding: 16px; }
  .kev-grid { display: flex; gap: 32px; flex-wrap: wrap; }
  .kev-label { display: block; font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px; }

  .badge-row { display: flex; flex-wrap: wrap; gap: 6px; }
  .cwe-badge {
    padding: 3px 10px; border-radius: 6px; font-size: 12px; font-family: "Geist Mono", monospace;
    background: var(--bg-subtle); border: 1px solid var(--border); color: var(--text-mid);
  }
  .cwe-list { display: flex; flex-direction: column; gap: 8px; }
  .cwe-card {
    padding: 10px 14px;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .cwe-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .cwe-name { font-size: 13px; font-weight: 600; color: var(--text); }
  .cwe-desc { font-size: 12px; color: var(--text-mid); line-height: 1.5; margin: 0; }

  .vendor-link { color: var(--accent); font-weight: 500; }
  .vendor-link:hover { text-decoration: underline; }
  .cpe-cell { font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .alias-badge {
    padding: 3px 10px; border-radius: 6px; font-size: 12px; font-family: "Geist Mono", monospace;
    background: var(--bg-card); border: 1px solid var(--border); color: var(--text-mid);
  }
  .source-badge {
    padding: 4px 12px; border-radius: 6px; font-size: 12px; font-weight: 500;
    background: var(--bg-card); border: 1px solid var(--border);
  }
  .eco-badge {
    padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 500;
    background: var(--purple-bg); color: var(--purple); border: 1px solid var(--purple-border);
  }

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--text-dim); padding: 8px 12px;
    border-bottom: 1px solid var(--border-strong); white-space: nowrap;
  }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .mono { font-family: "Geist Mono", monospace; font-size: 12px; }
  .fixed { color: var(--green); }
  .dim { color: var(--text-dim); font-size: 12px; }

  .ref-list { list-style: none; padding: 0; }
  .ref-list li { padding: 6px 0; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .ref-link {
    color: var(--accent); font-size: 13px; word-break: break-all;
  }
  .ref-link:hover { text-decoration: underline; }
  .ref-tag {
    font-size: 10px; padding: 1px 6px; border-radius: 3px;
    background: var(--bg-subtle); color: var(--text-dim); border: 1px solid var(--border);
  }
  .cross-link {
    color: var(--accent);
    text-decoration: none;
    font-size: 0.85rem;
  }
  .cross-link:hover {
    text-decoration: underline;
  }

  .threat-section {
    border-left: 3px solid var(--accent);
  }

  .threat-subsection {
    margin-bottom: 1rem;
  }

  .threat-subsection h3 {
    font-size: 0.85rem;
    color: var(--text-dim);
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .threat-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }

  .threat-tag {
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
    text-decoration: none;
    transition: opacity 0.15s;
  }

  .threat-tag:hover {
    opacity: 0.8;
  }

  .actor-tag {
    background: var(--red-bg, rgba(220, 38, 38, 0.1));
    color: var(--red, #dc2626);
    border: 1px solid var(--red-border, rgba(220, 38, 38, 0.2));
  }

  .technique-tag {
    background: var(--purple-bg, rgba(139, 92, 246, 0.1));
    color: var(--purple, #8b5cf6);
    border: 1px solid var(--purple-border, rgba(139, 92, 246, 0.2));
    font-family: var(--font-mono, monospace);
  }

  .threat-reports {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .threat-report {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .report-name {
    font-size: 0.9rem;
    color: var(--text);
  }

  .report-meta {
    font-size: 0.8rem;
    color: var(--text-dim);
  }

  .loading-text {
    color: var(--text-dim);
    font-size: 0.9rem;
  }

  .kev-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: var(--red-bg);
    border: 1px solid var(--red-border);
    border-radius: 8px;
    font-size: 13px;
    color: var(--red);
    margin-bottom: 16px;
  }
  .kev-banner-label {
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 2px 8px;
    background: var(--red);
    color: white;
    border-radius: 4px;
  }
  .kev-added {
    color: var(--text-dim);
    margin-left: auto;
    font-size: 12px;
  }
</style>
