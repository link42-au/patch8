# Patch8 DuckDB Dataset Plan

Status: approved architecture; implementation not started

Approved: 2026-08-28

## Purpose

Patch8 is a public, read-only vulnerability intelligence application with no continuously running application server,
hosted database, login, account, paid feature, or runtime secret. The existing legacy interface is the product and
visual authority. Its routes, layout, components, brand assets, visible copy, design tokens, interaction patterns, and
responsive behaviour must be preserved while its removed Worker/D1 data path is replaced.

Patch8 will build an application-owned, query-routed Parquet dataset from approved official sources. A static browser
client will query those files with DuckDB-Wasm. Source code, tests, policy, and workflows live in
[`link42-au/patch8`](https://github.com/link42-au/patch8); the bounded public dataset will live in the best-effort public
Hugging Face dataset repository `link42-au/patch8-data` once that organization and repository exist.

## Project information

| Area | Decision |
|---|---|
| Audience | Public, anonymous users of the legacy Patch8 vulnerability intelligence interface |
| Application | Existing static SvelteKit/TypeScript app on GitHub Pages |
| Browser query engine | DuckDB-Wasm over query-routed Parquet |
| Dataset builder | App-owned Python pipeline, with deterministic transforms and tests |
| Dataset storage | Public best-effort Hugging Face dataset repository `link42-au/patch8-data` |
| Initial build | Run locally to avoid hosted Actions time and establish the first verified release |
| Updates | Bounded source-change builds on public GitHub Actions; no permanent file-per-day layout |
| Runtime services | None: no API, Worker, D1, server, auth, account, billing, or paid/private feature |
| Client writes | None to shared storage; browser-local state remains local and exportable |
| EPSS | No Link42-owned EPSS dataset, history, cache, or republication |

## Status definitions

| Status | Meaning |
|---|---|
| **planned** | Approved work has not begun. |
| **in progress** | Work has begun but all acceptance evidence is not complete. |
| **source-complete** | Source and required local tests pass; nothing new is claimed about hosted state. |
| **published** | An artifact is hosted, but its production canary is incomplete or unrecorded. |
| **live-verified** | The exact hosted revision and required production canary passed and were recorded. |
| **blocked** | The named external dependency prevents further work. |
| **superseded** | Retained only as historical evidence; it is not the approved implementation. |

`done` is not used. A missing hosted run, browser canary, immutable dataset revision, or readback is not a pass.

## Non-negotiable boundaries

- The restored legacy monorepo UI is authoritative. Do not redesign, simplify, replace, or reinterpret it.
- Data work must populate the existing routes and states. It must not introduce a replacement landing page.
- The application remains static and read-only. It must work without credentials or a Link42 runtime service.
- Hugging Face is public best-effort storage, not an availability guarantee. Patch8 must expose honest stale,
  unavailable, and previous-good states.
- Patch8 publishes normalized, query-oriented data rather than raw upstream mirrors.
- The existing source-rights **two-key gate** is mandatory: a source must be enabled for public dataset publication,
  and every emitted field must match that source's allow-list. A missing source rule, unknown field, blocked use mode, or
  unproven lineage fails closed.
- [`docs/licensing/source-policy.json`](docs/licensing/source-policy.json) and
  [`docs/licensing/patch8.md`](docs/licensing/patch8.md) govern ingestion. The builder records the policy version and
  authorizing source/field rule in row provenance.
- FIRST EPSS is never ingested or published by Link42. Its existing direct-display possibility remains disabled until
  an independently approved policy-v2 feature; it is not part of this plan.
- OSV, AppThreat, ENISA EUVD, MSRC, Cisco PSIRT, and any other disabled, blocked, conditional, or excluded source stay
  absent unless a separately approved policy feature clears their exact use.
- Raw API envelopes, upstream archives, linked document bodies, credentials, and blocked fields never enter public
  Parquet, Git history, or Actions artifacts.

## Approved data sources

The first implementation covers only redistribution-approved fields from these official sources. Three sources are
already enabled in the policy. The CVE Program input remains fail-closed until P3 adds and tests its own explicit
public-dataset source rule; the existing general CVE terms analysis is not treated as a machine-readable source key.

| Source | Role | Publication boundary |
|---|---|---|
| NVD CVE API 2.0 and change history | NIST analysis, CVSS, CWE, CPE applicability, references, and update watermarks | NIST-authored and structured factual fields only; third-party or CVE-derived content requires proven lineage. |
| CVE Program `cvelistV5` | Canonical CVE Record lineage and permitted CVE fields | **P3 policy registration required before fetch or output.** Preserve the CVE/MITRE notice and record provenance; do not publish unidentified third-party material. |
| CISA Known Exploited Vulnerabilities | KEV catalogue context and history | Normalize the official CC0 catalogue; do not create a redundant raw mirror. |
| CISA Vulnrichment | CISA ADP SSVC/CVSS/CWE enrichment | Publish only CISA-authored enrichment and provenance, not a second full CVE mirror. |

Adding a source is an architectural and rights-policy change. It requires an explicit plan feature, primary-source
terms evidence, an enabled source policy, field allow-lists, fixtures, attribution, and fail-closed tests.

## Storage and release architecture

```text
Official NVD / CVE / KEV / Vulnrichment sources
                         |
                         v
          Patch8 Python ingestion and normalization
                         |
                         v
       rights gate -> schemas -> query-routed Parquet
                         |
                         v
        local candidate release + deterministic checks
                         |
                         v
    public HF dataset link42-au/patch8-data (best effort)
                         |
             immutable data revision
                         |
                         v
        small current manifest + previous-good pointer
                         |
                         v
        static Patch8 + DuckDB-Wasm in the browser
```

### Dataset layout

The exact partition boundaries are accepted only after P2 measures the legacy query corpus, but the contract is fixed:

- Files are routed by bounded, deterministic keys such as CVE year/identifier bucket, update window, KEV membership,
  and product/vendor bucket.
- The browser resolves a logical query to a small explicit file set before DuckDB executes SQL.
- No interactive path depends on scanning one monolithic vulnerability file.
- Target and maximum file sizes, transferred bytes, requests, query latency, and browser memory become release gates
  from the P2 benchmark rather than undocumented assumptions.
- Current paths are replaced on rebuild. The repository tree does not accumulate one file per day. Hugging Face commit
  history provides immutable revisions and deduplicated history outside the logical current dataset layout.

### Manifest-last publication

Publication uses two immutable commits so a manifest never claims the identity of the commit that contains itself:

1. Upload the complete candidate Parquet tree at bounded stable paths and obtain its immutable Hugging Face data
   revision.
2. Read back every file from that revision and verify path, size, SHA-256, Parquet schema, row counts, partition bounds,
   provenance, rights-policy version, and representative DuckDB queries.
3. Create a small release manifest that pins the immutable data revision and records reader/schema compatibility,
   build/source watermarks, file routing, checksums, freshness thresholds, and the previous verified release.
4. Commit `manifest.json` only after the candidate passes. The browser may discover this small file from the repository
   tip, but it fetches all Parquet from the manifest's immutable data revision.
5. A failed candidate never advances the manifest. The client retains and can activate the previous-good manifest and
   cached files without mixing revisions.

The first full dataset is built and verified on the maintainer's machine. Scheduled public Actions subsequently poll
source watermarks and perform a bounded delta build only when sources changed. Periodic reconciliation proves the
delta result matches a clean rebuild. Actions must stop safely on throttling, schema drift, policy drift, time budget,
or size budget and leave the current manifest untouched.

## Feature plan

Each feature is one focused implementation, test, commit, and push. Dependencies discovered during implementation are
recorded before blocked work continues.

| # | Feature | Depends on | Acceptance and required tests | Target | Current |
|---|---|---|---|---|---|
| P0 | **Adopt DuckDB dataset architecture** | User approval | This plan and README consistently define the legacy UI authority, app-owned Parquet build, DuckDB-Wasm client, public best-effort `link42-au/patch8-data` storage, two-key rights gate, bounded updates, manifest-last activation, previous-good rollback, and publication blocker. Local links and Markdown diff validate. | source-complete | **source-complete** |
| P1 | **Lock the restored legacy interface as authority** | P0 | Existing route, DOM, copy, asset, token, responsive, and visual tests remain the authority. Add missing screenshot baselines only where needed. No data feature may change layout or replace an existing route/state; Auth/Admin remain absent. | live-verified | **live-verified** |
| P2 | **Prove synthetic Parquet and DuckDB-Wasm browser access** | P0, P1 | Add a small representative, rights-safe synthetic dataset and manifest. The static browser resolves routes, loads only declared Parquet, and runs exact-CVE, filtered list, detail join, KEV, product, pagination, empty, stale, corrupt, and previous-good queries with DuckDB-Wasm. Chrome, Firefox, desktop Safari, and representative mobile Safari evidence records requests, bytes, latency, memory, cache behaviour, CORS/range behaviour, and explicit file-size/query budgets. No backend or token is contacted. Evidence: [`docs/p2-duckdb-proof.md`](docs/p2-duckdb-proof.md). Deterministic fixtures plus local Chromium, Firefox, and Playwright WebKit same-origin/query/corrupt/fallback/byte-budget checks pass; actual desktop/mobile Safari and live HF evidence remain unexecuted. | source-complete | **in progress** |
| P3 | **Implement the source, field, and manifest contracts** | P2 | Replace the historical manifest evidence with a tested Patch8 contract for `link42-au/patch8-data`. Add a primary-source-evidence-backed CVE Program `cvelistV5` public-dataset rule before any CVE fetch or output. Validate immutable data revision, safe paths, unique files, SHA-256, schema fingerprints, row counts, partition bounds, source watermarks, compatibility, freshness, policy version, and previous-good. The two-key gate rejects disabled or unregistered sources, unknown fields, blocked artifacts, unproven lineage, raw payloads, mixed revisions, and unsafe URLs. | source-complete | planned |
| P4 | **Build official CVE and NVD normalization** | P3 | A deterministic Python pipeline performs the initial bounded full import and modified-window deltas from official CVE Program and NVD sources. It emits only policy-approved normalized observations and provenance. Fixtures cover pagination, overlap watermarks, deduplication, removals, change history, CVE lineage, NVD/CVE conflicts, malformed data, throttling, restart, and clean-build/delta equivalence. | source-complete | planned |
| P5 | **Build official KEV and Vulnrichment normalization** | P3, P4 | Add commit-pinned official CISA KEV and Vulnrichment inputs. Normalize only approved fields, keep observations source-specific, and join by CVE without overwriting provenance. Fixtures cover additions, edits, removals, SSVC/CVSS/CWE lineage, conflicting values, source revision changes, and deterministic history. No raw mirror or EPSS-derived column is emitted. | source-complete | planned |
| P6 | **Generate query-routed Parquet releases locally** | P4, P5 | Compile the canonical observations into the P2-budgeted partition layout with deterministic ordering and byte-stable output where the selected writer permits it. Validate schemas, routing coverage, uniqueness, bounds, rights provenance, representative legacy queries, no orphan rows, no blocked fields, and no file-per-day accumulation. Produce a local candidate manifest and previous-good rollback fixture without needing HF credentials. | source-complete | planned |
| P7 | **Publish the first verified HF dataset release** | P6, HF1 | Run the initial full build locally, upload candidate files to public `link42-au/patch8-data`, read them back by immutable revision, run the release suite, and advance `manifest.json` in a second commit. Record exact data/manifest revisions, hashes, source watermarks, bytes, build time, query canary, and previous-good state. A failed check leaves no active release claim. | live-verified | blocked |
| P8 | **Automate bounded daily source-change builds** | P7 | A public scheduled Action checks official source watermarks, exits without artifact churn when unchanged, and performs restartable deltas when changed. It enforces pacing, overlap, time/size/request budgets, deterministic tests, rights gates, candidate readback, manifest-last activation, and previous-good rollback. It overwrites bounded logical paths rather than adding dated daily files. A self-hosted run may be used when a full reconciliation exceeds public-runner budgets. | live-verified | planned |
| P9 | **Populate legacy CVE search, list, and detail views** | P7 | Existing legacy routes query the immutable release through the P2 client. Exact lookup, search/filter, pagination, CVSS/CWE/CPE, KEV, Vulnrichment, provenance, source timestamps, freshness, disabled EPSS, empty/error/stale, and previous-good states pass fixture and browser tests without UI redesign. | live-verified | planned |
| P10 | **Populate legacy product, package, report, and export views** | P9 | Existing views expose only coverage supported by the approved data and label limitations honestly. Product/vendor intelligence, recent activity, prioritisation, and CSV/JSON exports use pinned queried rows, preserve field provenance/freshness, escape untrusted data, and make no server or AI call. Unsupported package capability stays visibly unavailable rather than fabricated. | live-verified | planned |
| P11 | **Add browser-local saved state** | P9 | Watchlists and saved searches are local, versioned, exportable/importable, recover from corrupt data, and never imply alerts, accounts, shared persistence, or cross-device synchronization. | live-verified | planned |
| P12 | **Cut over and operate the static product** | P8, P10, P11 | Production Pages canaries cover clean/warm cache, current and previous-good revisions, failed update, stale source, offline fallback, representative queries, desktop/mobile Safari, absence of backend/auth/secret calls, and legacy visual regressions. Releases record cost, Actions use, data age, transferred bytes, and rollback evidence. | live-verified | planned |

## External dependency

| ID | Dependency | Blocks | State |
|---|---|---|---|
| HF1 | Create the public Hugging Face organization/account ownership and dataset repository `link42-au/patch8-data`; configure the least-privilege write credential only for the publication workflow. | P7 and later live dataset features | **blocked: organization and dataset do not yet exist** |

P2-P6 are intentionally not blocked by HF1. Synthetic browser work and the complete local pipeline must proceed without
remote write access. No developer token, placeholder secret, private repository, paid Hugging Face organization, or
storage bucket is created implicitly.

## P2 implementation dependencies

| Dependency | Scope | Decision |
|---|---|---|
| `@duckdb/duckdb-wasm@1.32.0` | Browser runtime | Exact pin selected for the synthetic SQL/Parquet proof. It embeds DuckDB v1.4.3. |
| `hyparquet-writer@0.16.8` | Development only | Small deterministic fixture writer; it is not shipped as a Patch8 runtime or used for third-party data. |
| DuckDB v1.4.3 `wasm_mvp` Parquet extension | Same-origin static runtime asset | Exact official binary is size/SHA/licence locked in [`docs/duckdb-parquet-extension.md`](docs/duckdb-parquet-extension.md); external auto-install/autoload is disabled. |

## Required verification

| Layer | Evidence |
|---|---|
| Policy | Enabled source plus allowed field for every output; blocked-source/field, missing lineage, raw-payload, and EPSS absence tests. |
| Ingestion | Pinned fixtures, pagination/delta overlap, restart, throttling, schema drift, conflict, removal, deterministic rebuild, and reconciliation tests. |
| Dataset | Safe bounded paths, schemas, row counts, partition bounds, checksums, provenance, freshness, routing coverage, and no daily-file accumulation. |
| DuckDB client | Exact query corpus, selected-file proof, SQL parameterization, malformed/corrupt file handling, revision isolation, cache, and previous-good rollback. |
| Browser | Current Chrome, Firefox, Safari, and representative mobile Safari; clean/warm cache, constrained network, stale/offline/update-failure states, accessibility, and legacy visual regression. |
| Security | No runtime credentials/backend/auth; allow-listed HTTPS origins; safe URLs/paths; size/time/memory bounds; untrusted values rendered as text; dependency and secret scans. |
| Publication | Candidate immutable revision, readback, manifest-last switch, previous-good pointer, representative live queries, source watermarks, and recorded production canary. |

## Risks and defaults

| Risk | Default mitigation |
|---|---|
| Public best-effort HF dataset is unavailable or slow | Show freshness and unavailability honestly; retain verified browser cache and previous-good; do not silently switch revisions. |
| DuckDB-Wasm downloads too much data | P2 sets hard file/query budgets from measurements; reshape partitions before ingesting official history. |
| Daily rebuilds grow storage or Actions use | Stable bounded paths, delta builds only on change, Xet/Git history rather than dated tree files, and periodic cost/use evidence. |
| Upstream APIs throttle or change | Conservative pacing, overlap watermarks, restartable checkpoints, schema gates, last-known-good release, and no manifest advance on failure. |
| Conflicting upstream observations become a false canonical claim | Preserve source-specific observations and provenance; deterministic precedence is presentation metadata, never erased lineage. |
| Rights policy is bypassed during transformation | Enforce source and field keys at normalization and release validation; unknowns fail closed and cannot appear in Parquet. |
| Legacy route lacks supporting approved data | Keep the legacy unavailable/limited state and describe coverage; never invent data or redesign the route. |

## Implementation order

Proceed strictly in feature order. The first code feature is P2, the synthetic representative Parquet and DuckDB-Wasm
browser spike. Official NVD/CVE/KEV/Vulnrichment ingestion begins only after that spike establishes practical query,
partition, transfer, browser, and rollback budgets. HF publication begins only after the local build is complete and
HF1 is resolved.
