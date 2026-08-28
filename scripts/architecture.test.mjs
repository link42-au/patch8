import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";
import assert from "node:assert/strict";

test("root scripts enforce the static-only release gate", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.match(packageJson.scripts.verify, /verify:architecture/);
  assert.match(packageJson.scripts.verify, /verify:static/);
  assert.equal(packageJson.license, "AGPL-3.0-or-later");
});

test("Pages workflow has least privilege and no secret dependency", async () => {
  const workflow = await readFile(new URL("../.github/workflows/pages.yml", import.meta.url), "utf8");
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /pages: write/);
  assert.doesNotMatch(workflow, /secrets\./);
  assert.doesNotMatch(workflow, /wrangler|cloudflare|digitalocean/i);
});

test("DuckDB Parquet extension is pinned and same-origin", async () => {
  const extension = new URL(
    "../apps/web/static/duckdb-extensions/v1.4.3/wasm_mvp/parquet.duckdb_extension.wasm",
    import.meta.url,
  );
  const bytes = await readFile(extension);
  const metadata = await stat(extension);
  assert.equal(metadata.size, 2_867_304);
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    "0785c6c95d003eff4faa7b3b4b660f02c9c92f6d68d135ddf330d42e3a650600",
  );

  const runtime = await readFile(new URL("../apps/web/src/lib/dataset/browser.ts", import.meta.url), "utf8");
  assert.match(runtime, /custom_extension_repository/);
  assert.match(runtime, /autoinstall_known_extensions = false/);
  assert.match(runtime, /autoload_known_extensions = false/);
  assert.match(runtime, /allowFullHTTPReads: false/);
  assert.match(runtime, /forceFullHTTPReads: false/);
  assert.match(runtime, /method: "HEAD"/);
  assert.match(runtime, /credentials: "omit"/);
  assert.ok(runtime.includes("cdn\\.hf\\.co"));
  assert.match(runtime, /registerFileURL\(name, resolvedUrl, duckdb\.DuckDBDataProtocol\.HTTP, false\)/);
  assert.doesNotMatch(runtime, /builtin_httpfs|INSTALL httpfs|LOAD httpfs/);
  assert.doesNotMatch(runtime, /extensions\.duckdb\.org/);
});
