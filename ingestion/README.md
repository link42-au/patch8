# Patch8 ingestion

This directory contains the source-complete P4/P4a NVD, KEV, and CVE Program core. It is Python-standard-library-only and is exercised by
`pnpm test:ingestion` as part of `pnpm test` and `pnpm verify`.

## Implemented boundary

- `PolicyGate` seals reviewed contract 3 / policy 3.0.0 before an adapter can use
  them. A disabled source, unregistered field, changed same-version policy, or blocked description fails closed.
- `BoundedJsonClient` permits only the reviewed HTTPS endpoint and enforces explicit request, streamed-byte, interval,
  throttle, retry-after, socket-timeout, total-deadline, and page ceilings. Acquisition validates declared length before
  reading, caps streaming at remaining bytes plus one, resets each blocking read to the smaller of its socket timeout and
  remaining operation time, rejects redirects/final-identity drift, and records the final URL.
- `NvdPager` implements deterministic full pagination and current `lastModStartDate` / `lastModEndDate` requests. Delta windows use an exact
  two-hour overlap, advance one contiguous watermark, validate NVD's documented
  publish-date order, reject page/total/schema drift, and persist an atomic restart cursor containing hashes and allowed
  ordering keys but no raw response page. Strict version/invariant/state seals reject forged or conflicting restart
  state. Two-phase page prepare/checkpoint/promote journaling replays exactly across either atomic-write crash boundary.
- NVD normalization emits exact source-specific CVE metadata, NIST-authored CVSS v4.0/v3.1/v3.0/v2.0 observations,
  deterministic selected pointers, CWE identifiers, HTTP(S) references, CPE matches, version bounds, and provenance.
  Official extensible but unapproved fields are ignored and cannot enter output. Reference tags are trimmed,
  deduplicated, and sorted. Source timestamps without offsets are normalized as UTC, matching the API convention.
- KEV normalization validates the complete official JSON object, declared/actual counts, exact reviewed entry shape,
  unique CVE IDs, canonical dates/numerically sorted CWE sets, newest-first rows, exact source bytes, and builder revision. It emits only the contracted
  `kev_observations`, per-entry provenance, and source snapshot structures.
- KEV reconciliation records deterministic adds, edits, and removals. Only a complete successful snapshot may yield
  `not_listed`; a missing, failed, or incomplete reconciliation remains `unknown`.
- Full NVD reconciliation has a durable success clock and source-snapshot link. A delta cannot reset it or run after the
  seven-day maximum; an overdue or failed full reconciliation remains honestly stale and blocks further deltas.
- CVE Program ingestion accepts only the exact official codeload archive at an immutable commit. It bounds compressed
  and expanded bytes, records, members, and total time; rejects path/type/commit/origin/redirect drift; verifies CVE,
  schema, assigner/CNA provider, record SHA, and notice lineage; and emits only PUBLISHED metadata plus English CNA
  descriptions. Every English observation is retained and the first valid source-order observation is pointed to
  deterministically. Rejected records, NVD descriptions, ADP, affected, reference, supporting-media, and unknown fields
  cannot enter output. A refetched immutable archive must exactly match any sealed restart state before activation.
- The fixture corpus is synthetic and rights-safe. Fifty tests cover pagination/overshoot, zero-result responses,
  cross-page duplication, sealed checkpoint forgery, both page-commit crash boundaries, acquisition/deadline budgets,
  remaining-time socket/wait caps, redirects, throttle handling, canonical lists/order, schema drift, watermark gaps/overlap, full-reconciliation age,
  KEV changes/removals/unknown state, immutable official repository URLs, CVE Program lineage/rejected/unregistered
  content/commit drift/forged staging, complete-archive member/type/path/expanded-byte boundaries, safe ignored metadata,
  repeat-build determinism, and clean/delta equivalence.

`CveProgramPipeline`, `KevPipeline`, and `NvdPipeline` are active under contract 3. NVD provides normalized staging, restart,
full/delta equivalence, and manifest-independent atomic state activation.
No source is fetched merely by running the test suite. Separate in-memory canaries validated official NVD shapes and
representative CVE Program records at commit `10c6b415a7a12a0c0fab006359939fcd34e2c78f`; no source payload was retained. No raw response, linked page,
Parquet file, public dataset, manifest, or browser-visible data is produced.

## Resolved P3c dependency

Live validation against the official NVD 2.0 API after P3b found that its configuration container has only `nodes`.
`operator` and `negate` belong to the actual nodes. Contract 2 instead required a synthetic configuration-root row with
non-null direct-source values mapped to nonexistent `cve.configurations[].operator` and `.negate` paths.

P3c implemented contract 3 / policy 3.0.0: it removes the synthetic root observation, makes each top-level actual NVD
node's `parent_node_id` null, and retains every actual/empty node, node order, operator, negate, CPE match, and bound. It
also removes the nonexistent raw paths, records timezone-less NVD timestamps as UTC, pins the live `lastMod*` parameters,
and replaces the rejected `includeMatchStringChange` parameter with conservative overlap plus periodic complete
reconciliation. This source core still does not claim a production dataset.

## Source protocol notes

The NVD path is the official [CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities). Full results are consumed
in the API's documented publish-date order; modified updates use `lastModStartDate` and `lastModEndDate`.
The live API rejects `includeMatchStringChange`; overlapping deltas therefore require periodic clean reconciliation to
detect match-string-only changes.
The default production pacing remains the reviewed six seconds between requests, with a maximum 2,000 records per page
and 120 days per modified window.

The KEV path is the canonical [CISA feed](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) or the exact
`known_exploited_vulnerabilities.json` file in CISA's official
[`cisagov/kev-data`](https://github.com/cisagov/kev-data) repository at a 40-character immutable commit. CISA documents
that repository as synchronized with the canonical catalogue and distributes it under CC0. A mutable branch, fork,
partial object, count mismatch, or silent fallback is rejected.

## Run

```text
pnpm test:ingestion
```

The tests require Python 3.11 or newer and install no packages.
