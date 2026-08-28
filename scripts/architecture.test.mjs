import { readFile } from "node:fs/promises";
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
