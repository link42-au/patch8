# Patch8 v1 machine contracts

Status: **P3 source-complete; no ingestion or production dataset implemented**.

- [`data-content-v1.json`](data-content-v1.json) closes the v1 source, table/read-model, capability, freshness, notice,
  and blocked-token sets defined by [`docs/data-scope-v1.md`](../docs/data-scope-v1.md).
- [`source-policy.schema.json`](source-policy.schema.json) validates the app-owned public-dataset rights registry at
  [`docs/licensing/source-policy.json`](../docs/licensing/source-policy.json). Unknown source, field, use mode,
  authorship, and lineage default to block.
- [`dataset-manifest.schema.json`](dataset-manifest.schema.json) defines an immutable `link42-au/patch` release with
  compatibility, policy identity, previous-good, five clocks, hard growth bounds, routed Parquet artifacts, source
  snapshots, field lineage, derivations, and explicit source/capability coverage.
- [`fixtures/source-policy.cases.json`](fixtures/source-policy.cases.json) and
  [`fixtures/dataset-manifest.cases.json`](fixtures/dataset-manifest.cases.json) exercise valid contracts and their
  fail-closed boundaries.

Validate the policy, schemas, and fixtures with:

```text
pnpm validate:contract
```

A pass proves that the local machine contracts and synthetic fixture corpus agree. It does not prove an upstream fetch,
Parquet writer, published Hugging Face release, browser integration, or production state; those remain later plan
features.
