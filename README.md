# Patch8

Patch8 is the public, read-only vulnerability intelligence application in the Link42 family. This repository replaces
the historical Worker/D1 service with a static SvelteKit application intended for GitHub Pages.

## Status

| Area | State | Evidence |
|---|---|---|
| Repository shell | **source-complete** | Static build, tests, copied policy/contracts, architecture assertions, and Pages workflow are present locally. |
| Published site | **not published** | No Pages deployment or production canary has been recorded from this repository. |
| Exact CVE lookup | **planned; not implemented** | The approved source is anonymous browser-direct NVD CVE API 2.0. P1 makes no runtime data request. |
| CISA KEV context | **planned; not implemented** | The approved source is official KEV JSON at an immutable `cisagov/kev-data` revision. No lock or adapter exists yet. |
| FIRST EPSS | **disabled** | Direct display awaits a version-2 source-policy decision; dataset republication remains prohibited. |
| OSV | **disabled for first release** | It awaits an enforceable home-database licence registry. |
| AppThreat | **rejected for first release** | Record-level provenance and a supportable browser range-reader did not clear the release gates. |

`source-complete` means the P1 repository slice and its local checks are complete. It does not mean the application has
been published, queried live upstreams, passed a production canary, or implemented vulnerability lookup.

## Architecture boundary

- Static SvelteKit and TypeScript, built with `@sveltejs/adapter-static`.
- Public GitHub Pages and public GitHub Actions.
- No application server, Worker, D1, hosted database, ingestion, auth, account, paid/private feature, runtime AI, API
  gateway, NVD key, Hugging Face write token, or other runtime secret.
- Future clients remain read-only. Patch8 will not build, mirror, or republish a Link42-owned vulnerability dataset.
- Small copied schemas, synthetic fixtures, rights decisions, file locks, and attribution remain reviewable in Git.

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
  rollback evidence. Its Hugging Face publication model is superseded for Patch8 point lookup; P2 will adopt the F6
  split between dynamic API contracts and immutable file locks.
- [`docs/licensing/patch8.md`](docs/licensing/patch8.md) and
  [`docs/licensing/source-policy.json`](docs/licensing/source-policy.json) are the copied F2 rights evidence. The JSON is
  the full Link42 v1 registry; Patch8 consumes only entries whose `product` is `patch8`.
- [`docs/upstreams/patch8-direct-apis.md`](docs/upstreams/patch8-direct-apis.md) records the F5 source-selection evidence.
- [`docs/attribution.md`](docs/attribution.md) records notices that apply to the P1 shell and planned first-release data.

## Licence

Patch8 software is licensed under [AGPL-3.0-or-later](LICENSE). Upstream data is not relicensed under the software
licence and remains governed by its source-specific terms. Third-party font and tool licences are described in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
