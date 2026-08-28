# Vendored DuckDB-Wasm Parquet extension

Status: P2 synthetic browser-proof runtime dependency

Patch8 serves the Parquet extension from the same static origin as the application. DuckDB-Wasm's default extension
autoload would otherwise make an external request during the first Parquet query, contradicting the zero-runtime
architecture and making the proof depend on an unpinned CDN response.

## Immutable identity

| Property | Value |
|---|---|
| DuckDB-Wasm npm package | `@duckdb/duckdb-wasm@1.32.0` |
| DuckDB engine reported by that package | `v1.4.3` |
| Platform | `wasm_mvp` |
| Official source | `https://extensions.duckdb.org/v1.4.3/wasm_mvp/parquet.duckdb_extension.wasm` |
| Repository path | `apps/web/static/duckdb-extensions/v1.4.3/wasm_mvp/parquet.duckdb_extension.wasm` |
| Bytes | `2,867,304` |
| SHA-256 | `0785c6c95d003eff4faa7b3b4b660f02c9c92f6d68d135ddf330d42e3a650600` |
| Licence | DuckDB MIT licence |

The P2 browser runtime sets `custom_extension_repository` to the same-origin `duckdb-extensions` directory, explicitly
installs and loads `parquet`, then disables known-extension auto-install and autoload before running dataset queries.
Tests fail if the vendored file's size/hash changes, if it is absent from the static build, or if Chromium makes a
non-site runtime request.

This binary is application code, not vulnerability data. It must be updated only with the pinned DuckDB-Wasm runtime,
its engine/platform identity, recorded official URL, reviewed licence, new digest, build readback, and browser tests.
