# Patch8 source-policy evidence

Status: P3c source-complete app-owned policy and research evidence; not legal advice or runtime capability.

- [`patch8.md`](patch8.md) is the human-readable rights and redistribution register.
- [`source-policy.json`](source-policy.json) is the closed Patch8 public-dataset registry validated by
  [`../../contracts/source-policy.schema.json`](../../contracts/source-policy.schema.json). It contains only Patch8
  sources and uses exact `patch8_*` identifiers.

The only recognized use mode is `public_dataset_republication`. FIRST EPSS is blocked; OSV, EUVD, and Cisco are excluded;
MSRC is blocked. Unknown modes, sources, fields, authorship, or lineage fail closed. Approved policy `3.0.0` retains
P3b's exact CVSS-v2 severity and record-state fields, removes the two nonexistent NVD configuration-container paths,
and pins the live bounded-delta/complete-reconciliation method. Every non-NVD source rule is byte-for-byte unchanged.
These contract changes retain no upstream payload and publish no upstream data.
