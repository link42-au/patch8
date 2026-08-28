# Copied F3 dataset-manifest evidence

Status: **historical contract evidence copied for P1; locally validated, not a Patch8 runtime contract**.

This directory deliberately carries the Link42 F3 manifest schema and synthetic fixtures into the independent Patch8
repository. They preserve tested integrity, bounded routing, provenance, compatibility, and rollback invariants without
creating a shared runtime dependency.

The version-1 schema is historical evidence for an earlier shared Hugging Face publication model; it is not the active
Patch8 runtime contract. The approved [`PLAN.md`](../PLAN.md) returns to an app-owned Hugging Face Parquet dataset, but
only after P2 measures a synthetic DuckDB-Wasm browser path and P3 replaces this evidence with a Patch8-specific
source/field/manifest contract. Do not publish or consume a release under this historical schema.

Validate the copied schema and fixtures with:

```text
pnpm validate:contract
```

Passing proves only that this copied schema, validator, and synthetic fixture corpus agree locally. It does not prove a
remote artifact, browser query, cache, update, rollback, or production deployment.
