# Third-party notices

Patch8 is licensed under AGPL-3.0-or-later. Third-party dependencies and assets retain their own licences.

## Code and assets shipped to browsers

- **Geist and Geist Mono v1.7.1** — SIL Open Font License 1.1. Copyright 2024 The Geist Project Authors. The unmodified
  variable WOFF2 files came from the official Vercel Geist v1.7.1 release through Rule1's verified local copies. The OFL
  text is retained in [`LICENSES/OFL-1.1-Geist.txt`](LICENSES/OFL-1.1-Geist.txt) and in the published `fonts/` directory.
- **Svelte 5.56.10** — MIT. Copyright Svelte contributors.
- **SvelteKit 2.70.3** and **adapter-static 3.0.10** — MIT. Copyright their contributors.
- **DuckDB-Wasm 1.32.0 and DuckDB v1.4.3 Parquet extension** — MIT. Copyright DuckDB contributors. Patch8 serves the
  pinned `wasm_mvp` extension from the application origin; its immutable source, size, digest, and update rule are in
  [`docs/duckdb-parquet-extension.md`](docs/duckdb-parquet-extension.md).

## Development-only tooling

Playwright Test, axe-core integration, Vitest, Testing Library, jsdom, TypeScript, Vite, Svelte Check, and Biome are
development/build dependencies and are not application data sources. Exact versions are pinned in `pnpm-lock.yaml`.

Upstream vulnerability records are not bundled in P1 and are not relicensed under Patch8's software licence. Their
planned notices and source-specific rights are recorded in [`docs/attribution.md`](docs/attribution.md) and
[`docs/licensing/patch8.md`](docs/licensing/patch8.md).
