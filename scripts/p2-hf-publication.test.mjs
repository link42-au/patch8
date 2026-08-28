import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import {
  CURRENT_TARGET,
  DATASET_REPOSITORY,
  MANIFEST_PATH,
  RANGE_ROW_COUNT,
  RANGE_ROW_GROUP_SIZE,
  finalize,
  prepare,
} from "../apps/web/scripts/build-p2-hf-release.mjs";

const tree = async (root, directory = root) => {
  const entries = await readdir(directory, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) result.push(...(await tree(root, path)));
    else {
      const bytes = await readFile(path);
      result.push({
        path: relative(root, path),
        bytes: bytes.byteLength,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      });
    }
  }
  return result.sort((left, right) => left.path.localeCompare(right.path));
};

const temporaryOutput = async () => join(await mkdtemp(join(tmpdir(), "patch8-p2-hf-test-")), ".p2-hf-release");

test("P2 HF publication is deterministic, synthetic-only, and manifest-last", async () => {
  const first = await temporaryOutput();
  const second = await temporaryOutput();
  try {
    const firstPrepare = await prepare(first);
    const secondPrepare = await prepare(second);
    assert.deepEqual(await tree(firstPrepare.output), await tree(secondPrepare.output));
    assert.equal(firstPrepare.files.length, 10);

    const largeShard = resolve(firstPrepare.output, "synthetic/p2/current/vulnerabilities-2026-10.parquet");
    assert.ok((await stat(largeShard)).size > 3_000_000, "range shard must be representative, not a tiny fixture");
    assert.equal((await readFile(largeShard)).subarray(0, 4).toString(), "PAR1");

    const card = await readFile(resolve(firstPrepare.output, "synthetic/p2/DATASET_CARD_FRAGMENT.md"), "utf8");
    assert.match(card, /deterministic, invented test data/);
    assert.match(card, /does not blanket-relicense/);
    assert.match(card, /source-rights two-key gate/);

    const dataRevision = "1".repeat(40);
    const firstFinalize = await finalize(dataRevision, first);
    const secondFinalize = await finalize(dataRevision, second);
    assert.deepEqual(await tree(firstFinalize.output), await tree(secondFinalize.output));
    assert.equal(firstFinalize.manifest.dataset_repository, DATASET_REPOSITORY);
    assert.equal(firstFinalize.manifest.manifest_path, MANIFEST_PATH);
    assert.equal(firstFinalize.manifest.data_revision, dataRevision);
    assert.deepEqual(firstFinalize.manifest.range_proof, {
      artifact_path: "synthetic/p2/current/vulnerabilities-2026-10.parquet",
      row_count: RANGE_ROW_COUNT,
      row_group_size: RANGE_ROW_GROUP_SIZE,
      row_groups: 64,
      minimum_bytes: 3_000_000,
    });
    assert.equal(firstFinalize.manifest.current.previous_release, firstFinalize.manifest.previous.release_id);
    assert.equal(firstFinalize.manifest.fixture_only, true);
    assert.equal(firstFinalize.manifest.current.fixture_only, true);
    assert.equal(CURRENT_TARGET, "CVE-2026-102112");
    assert.ok(firstFinalize.manifest.current.artifacts.every(({ path }) => path.startsWith("synthetic/p2/")));
    assert.deepEqual(
      await readdir(firstFinalize.output),
      ["synthetic"],
      "manifest revision must not copy data-revision payloads",
    );
  } finally {
    await rm(dirname(first), { recursive: true, force: true });
    await rm(dirname(second), { recursive: true, force: true });
  }
});

test("P2 HF finalization rejects mutable or malformed revisions", async () => {
  const output = await temporaryOutput();
  try {
    await prepare(output);
    await assert.rejects(finalize("main", output), /lowercase 40-hex/);
    await assert.rejects(finalize("A".repeat(40), output), /lowercase 40-hex/);
  } finally {
    await rm(dirname(output), { recursive: true, force: true });
  }
});

test("P2 HF browser proof is opt-in, immutable, anonymous, and bounded", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.match(packageJson.scripts["test:e2e:hf"], /p2-hf\.spec\.ts/);

  const browserProof = await readFile(new URL("../e2e/fixtures/p2-hf-browser-proof.ts", import.meta.url), "utf8");
  const browserTest = await readFile(new URL("../e2e/p2-hf.spec.ts", import.meta.url), "utf8");
  const gitignore = await readFile(new URL("../.gitignore", import.meta.url), "utf8");
  assert.match(browserProof, /resolve\/\$\{revision\}/);
  assert.match(browserProof, /credentials: "omit"/);
  assert.match(browserProof, /Range: "bytes=0-1023"/);
  assert.doesNotMatch(browserProof, /HF_TOKEN|HUGGINGFACE_TOKEN|authorization/i);
  assert.match(browserTest, /status: 206/);
  assert.match(browserTest, /toBeLessThan\(loaded\.exactArtifact\.bytes\)/);
  assert.match(browserTest, /PATCH8_HF_P2_REVISION/);
  assert.match(gitignore, /^\.p2-hf-release\/$/m);
});
