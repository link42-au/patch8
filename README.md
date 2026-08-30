# Patch8

Patch8 is the public, read-only vulnerability intelligence application in the Link42 family. This repository replaces
the historical Worker/D1 service with a static SvelteKit application intended for GitHub Pages.

## Status

| Area | State | Evidence |
|---|---|---|
| Legacy interface restoration | **live-verified** | The historical Patch8 layout, dashboard, routes, components, brand assets, tokens, responsive behaviour, and current visible copy are locked by tests and deployed in [commit `1b932e3`](https://github.com/link42-au/patch8/commit/1b932e34). Future data work may make only minimal semantic copy/meta/disabled-control changes required for honest unavailable/partial/stale states, without route, layout, or visual redesign. |
| Static Pages shell | **live-verified** | [Hosted run 33160759689](https://github.com/link42-au/patch8/actions/runs/33160759689) verified the restored legacy interface at [`link42-au.github.io/patch8/`](https://link42-au.github.io/patch8/). This status does not claim data-backed capability. |
| DuckDB-Wasm data client | **in progress** | Synthetic query-routed Parquet, deterministic fixtures, prepared SQL, corrupt-current fallback, local Chromium/Firefox/Playwright WebKit, and immutable public-HF Chromium range proofs pass without changing the legacy UI. Actual desktop/mobile Safari, cache, and memory evidence remain incomplete; see [`docs/p2-duckdb-proof.md`](docs/p2-duckdb-proof.md). |
| v1 data and release contracts | **P3c source-complete** | Contract 3 / policy 3.0.0 retains source-specific CVE metadata, the exact CVSS-v2 severity path, and stable KEV identity while representing only actual NVD nodes. It pins live NVD timestamp/delta/reconciliation semantics. Exact schemas, 24 source-policy fixtures, 59 manifest fixtures, and immutable historical/current baselines pass. |
| Patch8 dataset builder | **P4 source-complete** | The standard-library NVD/KEV core has pre-allocation streamed limits, exact final-source identity, total deadlines, sealed crash-idempotent staging, exact observations/provenance, canonical lists/order, stable KEV reconciliation, a durable seven-day complete-NVD clock, atomic activation, and 40 deterministic tests. Live in-memory source-shape/identity canaries passed without retaining payloads; no production dataset is claimed. |
| Public dataset | **P2 canary live-verified; release blocked** | The public, ungated Hugging Face dataset [`link42-au/patch`](https://huggingface.co/datasets/link42-au/patch) serves the synthetic P2 canary anonymously at manifest revision `aa4e13c4564924c12a16720d8bebe57208dfccdd`. It does not yet contain a verified Patch8 vulnerability release; the local full build and scoped publisher write/readback remain pending. |
| FIRST EPSS | **disabled** | No Link42 fetch, cache, dataset, history, or republication is authorized by v1. |
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
  CVE Program, NVD, CISA KEV, CVE-linked GitHub Advisory Database, CISA Vulnrichment, and MITRE CWE fields. P3 registers
  the exact `cvelistV5` public-dataset rule; descriptions still stay unavailable until P4a implements and verifies the
  commit-pinned adapter.
- The first full build runs locally. Public Actions later run bounded source-change updates without accumulating one
  permanent Parquet file per day.
- Public best-effort dataset storage at `link42-au/patch`, activated through an immutable revision manifest with
  a previous-good release. The public identity and anonymous read path exist; publication remains blocked pending the
  local full build, least-privilege publisher credential, and scoped immutable write/readback canary.
- DuckDB-Wasm queries the pinned Parquet revision directly in the browser. Clients remain read-only.
- No application server, Worker, D1, hosted query database, auth, account, paid/private feature, runtime AI, API gateway,
  NVD key, Hugging Face write token in the browser, or other runtime secret.
- No Link42-owned EPSS dataset, history, durable shared cache, or bulk export.
- Every output must pass the source-rights two-key gate: an enabled public-dataset source rule and an allowed field rule.
- App-owned schemas, synthetic fixtures, rights decisions, file locks, and attribution remain reviewable in Git.

See [`docs/data-scope-v1.md`](docs/data-scope-v1.md) for the authoritative v1 data contract and [`PLAN.md`](PLAN.md) for
the feature sequence, release protocol, publication blocker, acceptance tests, and rollback design.

## Commands

Requires Node.js 22.23.1 and pnpm 10.15.1.

```text
pnpm install --frozen-lockfile
pnpm check
pnpm typecheck
pnpm test
pnpm test:ingestion
pnpm build
pnpm verify:architecture
pnpm verify:static
pnpm test:e2e
```

`pnpm verify` runs the non-browser release checks in their required order. Browser smoke testing is separate because it
needs an installed Chromium runtime; the Pages workflow installs it and runs both gates.

## Evidence carried into this repository

- [`contracts/`](contracts/) contains the P3 app-owned source-policy, content, and immutable Parquet manifest contracts
  plus 82 synthetic positive/fail-closed fixtures. These are source evidence, not a built or published v1 dataset.
- [`docs/licensing/patch8.md`](docs/licensing/patch8.md) and
  [`docs/licensing/source-policy.json`](docs/licensing/source-policy.json) are the Patch8 rights evidence and closed
  public-dataset registry.
- [`docs/upstreams/patch8-direct-apis.md`](docs/upstreams/patch8-direct-apis.md) records the F5 source-selection evidence.
- [`docs/attribution.md`](docs/attribution.md) records notices that apply to the P1 shell and planned first-release data.

## Licence

Patch8 software is licensed under [AGPL-3.0-or-later](LICENSE). Upstream data is not relicensed under the software
licence and remains governed by its source-specific terms. Third-party font and tool licences are described in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
