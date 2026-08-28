# Copied F3 dataset-manifest evidence

Status: **historical contract evidence copied for P1; locally validated, not a Patch8 runtime contract**.

This directory deliberately carries the Link42 F3 manifest schema and synthetic fixtures into the independent Patch8
repository. They preserve tested integrity, bounded routing, provenance, compatibility, and rollback invariants without
creating a shared runtime dependency.

The version-1 schema describes the superseded Link42-owned Hugging Face publication model. Patch8 must not use that
model for exact-CVE point lookup. The selected first-release design instead requires a dynamic anonymous NVD API
contract and an immutable official CISA KEV file lock. Those successor contracts belong to P2 after F6; they are not
silently invented by this repository shell.

Validate the copied schema and fixtures with:

```text
pnpm validate:contract
```

Passing proves only that this copied schema, validator, and synthetic fixture corpus agree locally. It does not prove a
remote artifact, browser query, cache, update, rollback, or production deployment.
