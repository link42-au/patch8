<script lang="ts">
import { base } from "$app/paths";
  import { onMount } from "svelte";
  import { page } from "$app/stores";
  import { getVendorProducts, type VendorProductsResponse } from "$lib/api";
  import { prettyName } from "$lib/utils";

  let data = $state<VendorProductsResponse | null>(null);
  let loading = $state(true);

  const vendor = $derived($page.params.vendor ?? "");

  onMount(async () => {
    data = await getVendorProducts(vendor);
    loading = false;
  });

  function sevClass(sev: string | null): string {
    if (!sev) return "";
    return sev.toLowerCase();
  }

</script>

<svelte:head>
  <title>{decodeURIComponent(vendor)} — Software — patch8</title>
  <meta property="og:title" content="{prettyName(decodeURIComponent(vendor))} — Software — patch8" />
  <meta property="og:description" content="Vulnerabilities affecting {prettyName(decodeURIComponent(vendor))} products — CVE details, EPSS scores, and severity breakdown" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://patch8.link42.app/software/{vendor}" />
  <meta property="og:site_name" content="Patch8" />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="{prettyName(decodeURIComponent(vendor))} — Software — patch8" />
  <meta name="twitter:description" content="Vulnerabilities affecting {prettyName(decodeURIComponent(vendor))} products — CVE details, EPSS scores, and severity breakdown" />
  <link rel="canonical" href="https://patch8.link42.app/software/{vendor}" />
</svelte:head>

<div class="vendor-page">
  <nav class="breadcrumb">
    <a href="{base}/software">Software</a> <span class="sep">/</span> <span>{prettyName(decodeURIComponent(vendor))}</span>
  </nav>

  <h1>{prettyName(decodeURIComponent(vendor))}</h1>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if data && data.results.length > 0}
    <div class="results-header">
      <span>{data.results.length} product{data.results.length === 1 ? "" : "s"}</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Product</th>
            <th>Vulnerabilities</th>
            <th>Max Severity</th>
            <th>Max EPSS</th>
          </tr>
        </thead>
        <tbody>
          {#each data.results as item}
            <tr>
              <td><a href="{base}/software/{encodeURIComponent(vendor)}/{encodeURIComponent(item.product)}" class="pkg-link">{prettyName(item.product)}</a></td>
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
  {:else}
    <p class="empty">No products found for this vendor.</p>
  {/if}
</div>

<style>
  .vendor-page {
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px 24px;
  }

  .breadcrumb {
    font-size: 13px;
    color: var(--text-dim);
    margin-bottom: 8px;
  }
  .breadcrumb a {
    color: var(--accent);
  }
  .breadcrumb a:hover { text-decoration: underline; }
  .sep { margin: 0 4px; }

  h1 {
    font-size: 24px;
    font-weight: 700;
    margin-bottom: 24px;
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

  .pkg-link {
    color: var(--accent);
    font-weight: 500;
    font-size: 13px;
    white-space: nowrap;
  }
  .pkg-link:hover { text-decoration: underline; }
</style>
