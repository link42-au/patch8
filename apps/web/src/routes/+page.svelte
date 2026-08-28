<main id="main">
  <section class="hero" aria-labelledby="hero-title">
    <p class="eyebrow">Public vulnerability intelligence</p>
    <h1 id="hero-title">Know what needs patching.</h1>
    <p class="lede">
      Patch8's static shell is live-verified on GitHub Pages. Exact CVE lookup and CISA Known Exploited Vulnerabilities
      context remain planned and are not implemented.
    </p>

    <form class="lookup" aria-label="Planned CVE lookup">
      <label for="cve">CVE identifier</label>
      <div class="lookup-row">
        <input id="cve" value="CVE-2026-0001" disabled aria-describedby="lookup-status" />
        <button type="button" disabled>Lookup planned</button>
      </div>
      <p id="lookup-status" class="status">
        The live shell makes no data queries; exact CVE and KEV adapters remain planned.
      </p>
    </form>
  </section>

  <section id="capabilities" class="section" aria-labelledby="capabilities-title">
    <div class="section-heading">
      <p class="eyebrow">First-release boundary</p>
      <h2 id="capabilities-title">Small, direct, and transparent</h2>
    </div>
    <div class="cards">
      <article>
        <span class="state planned">Planned</span>
        <h3>Exact CVE detail</h3>
        <p>A bounded anonymous browser request to NVD CVE API 2.0, with no API key shipped by Patch8.</p>
      </article>
      <article>
        <span class="state planned">Planned</span>
        <h3>Known exploitation</h3>
        <p>Context from the official CISA KEV catalogue at an immutable, reviewed repository revision.</p>
      </article>
      <article>
        <span class="state disabled">Disabled</span>
        <h3>EPSS and OSV</h3>
        <p>EPSS awaits a direct-display policy update. OSV remains outside the first release.</p>
      </article>
    </div>
  </section>

  <section id="sources" class="section source-panel" aria-labelledby="sources-title">
    <div>
      <p class="eyebrow">Data responsibility</p>
      <h2 id="sources-title">Upstreams stay upstream</h2>
    </div>
    <p>
      Patch8 will read approved public sources in the browser. This repository will not ingest, mirror, rebuild, or sell
      vulnerability data. Every enabled field must pass the repository's source and field policy.
    </p>
  </section>
</main>
