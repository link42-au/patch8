# Patch8

Patch8 is the public, read-only vulnerability intelligence application in the Link42 family. This repository replaces
the historical Worker/D1 service with a static SvelteKit application intended for GitHub Pages.

## Status

| Area | State | Evidence |
|---|---|---|
| Legacy interface restoration | **live-verified** | The historical Patch8 layout, dashboard, routes, components, brand assets, tokens, responsive behaviour, and visible copy are locked by tests and deployed in [commit `1b932e3`](https://github.com/link42-au/patch8/commit/1b932e34). |
| Static Pages shell | **live-verified** | [Hosted run 33160759689](https://github.com/link42-au/patch8/actions/runs/33160759689) verified the restored legacy interface at [`link42-au.github.io/patch8/`](https://link42-au.github.io/patch8/). This status does not claim data-backed capability. |
| DuckDB-Wasm data client | **in progress** | Synthetic query-routed Parquet, deterministic fixtures, prepared SQL, corrupt-current fallback, and local Chromium, Firefox, and Playwright WebKit proofs are implemented without changing the legacy UI. Actual desktop/mobile Safari and live HF evidence remain incomplete; see [`docs/p2-duckdb-proof.md`](docs/p2-duckdb-proof.md). |
| Patch8 dataset builder | **planned; not implemented** | An app-owned Python pipeline will normalize approved NVD, CVE Program, CISA KEV, and CISA Vulnrichment fields. |
| Public dataset | **blocked** | The best-effort public Hugging Face dataset `link42-au/patch8-data` does not exist yet. Local build work can proceed. |
| FIRST EPSS | **disabled** | Direct display awaits a version-2 source-policy decision; dataset republication remains prohibited. |
| OSV | **disabled for first release** | It awaits an enforceable home-database licence registry. |
| AppThreat | **rejected for first release** | Record-level provenance and a supportable browser range-reader did not clear the release gates. |

`live-verified` applies only to the static P1 shell and its deployment canary. It does not mean the complete Patch8
product is live: no upstream data adapter or vulnerability lookup has been implemented or live-verified.

The restored routes deliberately show unavailable or empty states where the historical interface depended on the
removed Worker/D1 API. Login, account, watchlist persistence, feed administration, backfills, and live vulnerability,
package, software, report, and feed data cannot operate without that backend and are not simulated.

## Approved architecture

- Static SvelteKit and TypeScript, built with `@sveltejs/adapter-static`.
- Public GitHub Pages and public GitHub Actions.
- An app-owned Python ingestion/build pipeline generates bounded, query-routed Parquet from rights-approved official
  NVD, CISA KEV, and CISA Vulnrichment fields. CVE Program `cvelistV5` remains fail-closed until P3 adds its explicit
  machine-readable source rule.
- The first full build runs locally. Public Actions later run bounded source-change updates without accumulating one
  permanent Parquet file per day.
- Public best-effort dataset storage at `link42-au/patch8-data`, activated through an immutable revision manifest with
  a previous-good release. Publication remains blocked until the Hugging Face organization and dataset exist.
- DuckDB-Wasm queries the pinned Parquet revision directly in the browser. Clients remain read-only.
- No application server, Worker, D1, hosted query database, auth, account, paid/private feature, runtime AI, API gateway,
  NVD key, Hugging Face write token in the browser, or other runtime secret.
- No Link42-owned EPSS dataset, history, durable shared cache, or bulk export.
- Every output must pass the source-rights two-key gate: an enabled public-dataset source rule and an allowed field rule.
- Small copied schemas, synthetic fixtures, rights decisions, file locks, and attribution remain reviewable in Git.

See [`PLAN.md`](PLAN.md) for the feature sequence, release protocol, publication blocker, acceptance tests, and rollback
design.

## Commands

Requires Node.js 22.23.1 and pnpm 10.15.1.

```text
pnpm install --frozen-lockfile
pnpm check
pnpm typecheck
pnpm test
pnpm build
pnpm verify:architecture
pnpm verify:static
pnpm test:e2e
```

`pnpm verify` runs the non-browser release checks in their required order. Browser smoke testing is separate because it
needs an installed Chromium runtime; the Pages workflow installs it and runs both gates.

## Evidence carried into this repository

- [`contracts/`](contracts/) retains the synthetic F3 manifest schema/fixtures and validator as historical integrity and
  rollback evidence. P3 will replace it with the app-owned immutable Parquet release contract after the P2 browser
  spike establishes practical query and partition budgets.
- [`docs/licensing/patch8.md`](docs/licensing/patch8.md) and
  [`docs/licensing/source-policy.json`](docs/licensing/source-policy.json) are the copied F2 rights evidence. The JSON is
  the full Link42 v1 registry; Patch8 consumes only entries whose `product` is `patch8`.
- [`docs/upstreams/patch8-direct-apis.md`](docs/upstreams/patch8-direct-apis.md) records the F5 source-selection evidence.
- [`docs/attribution.md`](docs/attribution.md) records notices that apply to the P1 shell and planned first-release data.

## Licence

Patch8 software is licensed under [AGPL-3.0-or-later](LICENSE). Upstream data is not relicensed under the software
licence and remains governed by its source-specific terms. Third-party font and tool licences are described in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
