# Patch8 v1 machine contracts

Status: **P3b source-complete; no production dataset implemented**.

- [`data-content-v1.json`](data-content-v1.json) closes the v1 source, exact ordered field/type/nullability and table-key,
  output-lineage/derivation, capability dependency, freshness, notice, and blocked-token sets defined by
  [`docs/data-scope-v1.md`](../docs/data-scope-v1.md). Contract version 2 adds reusable source-specific CVE metadata,
  complete ordered NVD configuration-node observations, the exact CVSS-v2 severity path, and stable KEV entry identity.
- [`source-policy.schema.json`](source-policy.schema.json) validates the app-owned public-dataset rights registry at
  [`docs/licensing/source-policy.json`](../docs/licensing/source-policy.json). Unknown source, field, use mode,
  authorship, and lineage default to block.
- [`dataset-manifest.schema.json`](dataset-manifest.schema.json) defines an immutable `link42-au/patch` release with
  compatibility, policy identity, previous-good, five clocks, hard growth bounds, routed Parquet artifacts, source
  snapshots, field lineage, derivations, and explicit source/capability coverage.
- [`fixtures/source-policy.cases.json`](fixtures/source-policy.cases.json) and
  [`fixtures/dataset-manifest.cases.json`](fixtures/dataset-manifest.cases.json) exercise valid contracts and their
  fail-closed boundaries (23 source-policy cases and 59 manifest cases).

The validator independently seals the complete semantic content-contract and source-policy digests to their declared
`contract_version:policy_version` pair. An approved material change must increment both versions, refresh affected
per-source fingerprints, and add a new reviewed baseline entry; an existing baseline entry is immutable and must never
be replaced in place. Repository, field, schema, key, lineage, and policy changes therefore cannot reuse version
`2:2.0.0` by merely updating hashes or regenerating manifest schemas. The original `1:1.0.0` baseline remains historical
evidence and was not rewritten.

Validate the policy, schemas, and fixtures with:

```text
pnpm validate:contract
```

A pass proves that the local machine contracts and synthetic fixture corpus agree. It does not prove an upstream fetch,
Parquet writer, published Hugging Face release, browser integration, or production state; those remain later plan
features.
