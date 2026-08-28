# P2 DuckDB-Wasm browser proof

Status: **in progress**

Date: 2026-08-28

P2 proves the browser-side query shape without connecting the synthetic data to the legacy interface. No route,
Svelte component, DOM contract, CSS, visible copy, or production data source changed.

## Implemented evidence

- `@duckdb/duckdb-wasm@1.32.0`, using its DuckDB v1.4.3 `wasm_mvp` runtime.
- Exact same-origin Parquet extension is pinned by size and SHA-256; external extension auto-install/autoload is
  disabled. See [`duckdb-parquet-extension.md`](duckdb-parquet-extension.md).
- Deterministic, rights-safe fixtures use invented CVE/product text and `synthetic_patch8_p2` provenance. The fixture
  builder emits eight valid Parquet files, one deliberately corrupt file, and current/previous manifests. Rebuilding
  byte-for-byte is part of `pnpm test`.
- Current valid Parquet totals 7,705 bytes. Previous-good Parquet totals 4,208 bytes. The corrupt input is 47 bytes.
- Each manifest caps a logical query at 32,768 declared bytes. Exact CVE routing selects one 2,393-byte shard; the
  synthetic product-filter query selects only the two product shards and the CVE shards containing returned IDs.
- SQL values are passed through DuckDB prepared statements. Only validated manifest paths form internal Parquet table
  expressions.
- Local Chromium, Firefox, and Playwright WebKit execute exact-ID, severity/KEV filtered list, detail join, product aggregation, pagination, empty,
  corrupt-current, and previous-good queries against generated Parquet. The test records exact Parquet response bytes
  in each local/hosted run and fails above 131,072 aggregate bytes.
- The Chromium request audit rejects `/api/`, authorization headers, and every non-site runtime request. DuckDB Wasm,
  its worker, the Parquet extension, and Parquet files are all served from the proof origin.
- A deterministic, ignored-output, synthetic-only Hugging Face bundle and manifest-last handoff are source-ready. The
  optional real-browser proof pins immutable data/manifest revisions and checks anonymous CORS, HTTP 206 ranges,
  partial DuckDB reads, route/byte budgets, and previous-good fallback. See
  [`p2-hf-publication.md`](p2-hf-publication.md).
- The public P2 canary passed in Chromium against manifest revision
  `aa4e13c4564924c12a16720d8bebe57208dfccdd` and data revision
  `dba086354122790626c7f2b1bf9746f407b9bac5`. The exact query transferred 176,465 of 3,617,105 bytes; the full proof
  transferred 287,285 Parquet bytes. Every payload GET was HTTP 206, with no remote HTTP 200 fallback.
- Remote files are resolved anonymously from validated immutable `link42-au/patch` URLs to approved HTTPS
  `*.cdn.hf.co` targets by HEAD, then registered with full-read fallback disabled. CDN URLs are not persisted.

## Incomplete acceptance

The hosted workflow currently provides Chromium only. A local Playwright 1.62.1 engine matrix passed all six tests on
Chromium, Firefox, and WebKit on 2026-08-28. Playwright WebKit is compatibility evidence, not a claim that desktop or
mobile Safari itself passed. P2 therefore remains **in progress**, not `source-complete`, until actual desktop and
representative mobile Safari run the same query, request-origin, transfer-budget, corrupt-update, and previous-good
assertions.

The public, ungated Hugging Face dataset `link42-au/patch` now contains the live-verified synthetic P2 feasibility
canary. That invented data is not a verified Patch8 vulnerability release. P7 retains the official-source local-build
and scoped publisher write/readback gates. Explicit stale-manifest activation, persistent-cache behaviour, and browser
memory profiling also remain unmeasured.
