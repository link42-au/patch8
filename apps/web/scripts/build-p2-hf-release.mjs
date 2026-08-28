#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parquetWriteBuffer } from "hyparquet-writer";

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
export const DEFAULT_OUTPUT = resolve(REPOSITORY_ROOT, ".p2-hf-release");
export const DATASET_REPOSITORY = "link42-au/patch";
export const CURRENT_TARGET = "CVE-2026-102112";
export const MANIFEST_PATH = "synthetic/p2/manifest.json";
export const RANGE_ROW_COUNT = 4_096;
export const RANGE_ROW_GROUP_SIZE = 64;
const DATA_PREFIX = "synthetic/p2";
const POLICY = "p2-synthetic-1";
const SOURCE = "synthetic_patch8_p2_hf";
const GENERATED_AT = "2026-08-28T00:00:00Z";
const REVISION = /^[0-9a-f]{40}$/;

const vulnerabilitySchema = [
  ["id", "STRING"],
  ["cve_id", "STRING"],
  ["description", "STRING"],
  ["published_at", "STRING"],
  ["modified_at", "STRING"],
  ["severity", "STRING"],
  ["cvss_score", "DOUBLE"],
  ["cvss_vector", "STRING"],
  ["cvss_version", "STRING"],
  ["in_kev", "INT32"],
  ["kev_due_date", "STRING"],
  ["package_count", "INT32"],
  ["source_count", "INT32"],
  ["source_id", "STRING"],
  ["rights_policy_version", "STRING"],
];

const softwareSchema = [
  ["cve_id", "STRING"],
  ["vendor", "STRING"],
  ["product", "STRING"],
  ["version", "STRING"],
  ["cpe_uri", "STRING"],
  ["source_id", "STRING"],
  ["rights_policy_version", "STRING"],
];

const kevSchema = [
  ["cve_id", "STRING"],
  ["date_added", "STRING"],
  ["due_date", "STRING"],
  ["ransomware", "STRING"],
  ["required_action", "STRING"],
  ["source_id", "STRING"],
  ["rights_policy_version", "STRING"],
];

const columns = (rows, schema) =>
  schema.map(([name, type]) => ({
    name,
    type,
    data: rows.map((row) => row[name]),
    nullable: false,
  }));

const parquet = (rows, schema, rowGroupSize) =>
  new Uint8Array(
    parquetWriteBuffer({
      columnData: columns(rows, schema),
      codec: "UNCOMPRESSED",
      rowGroupSize,
      statistics: true,
      kvMetadata: [
        { key: "fixture", value: "patch8-p2-hf-range-proof" },
        { key: "rights_policy_version", value: POLICY },
        { key: "synthetic_only", value: "true" },
      ],
    }),
  );

const deterministicText = (seed, length) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let state = (seed + 1) * 2_654_435_761;
  let value = "";
  for (let index = 0; index < length; index += 1) {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    value += alphabet[state % alphabet.length];
  }
  return value;
};

const vulnerability = (id, index, options = {}) => {
  const severity = options.severity ?? ["LOW", "MEDIUM", "HIGH"][index % 3];
  const inKev = options.inKev === true;
  return {
    id: id.toLowerCase(),
    cve_id: id,
    description:
      options.description ??
      `Synthetic P2 range row ${id}. ${deterministicText(index + (options.seedOffset ?? 0), 768)}`,
    published_at: "2026-08-20T00:00:00Z",
    modified_at: GENERATED_AT,
    severity,
    cvss_score: options.score ?? (severity === "HIGH" ? 8.1 : severity === "MEDIUM" ? 5.4 : 2.6),
    cvss_vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:${severity === "CRITICAL" ? "H" : "L"}/I:L/A:L`,
    cvss_version: "3.1",
    in_kev: inKev ? 1 : 0,
    kev_due_date: inKev ? "2026-09-10" : "",
    package_count: 0,
    source_count: inKev ? 2 : 1,
    source_id: SOURCE,
    rights_policy_version: POLICY,
  };
};

const vulnerabilityRows = (bucket, count, options = {}) =>
  Array.from({ length: count }, (_, index) => {
    const id =
      options.forceTargetIndex === index ? CURRENT_TARGET : `CVE-2026-${bucket}${String(index).padStart(4, "0")}`;
    if (id === CURRENT_TARGET) {
      return vulnerability(id, index, {
        description: options.previous
          ? "Synthetic previous-good immutable Hugging Face range-proof vulnerability."
          : "Synthetic current immutable Hugging Face range-proof vulnerability.",
        inKev: true,
        score: options.previous ? 8.8 : 9.8,
        severity: options.previous ? "HIGH" : "CRITICAL",
        seedOffset: options.seedOffset,
      });
    }
    return vulnerability(id, index, { seedOffset: options.seedOffset });
  });

const software = (cveId, vendor, product, version) => ({
  cve_id: cveId,
  vendor,
  product,
  version,
  cpe_uri: `cpe:2.3:a:${vendor.toLowerCase()}:${product.toLowerCase()}:${version}:*:*:*:*:*:*:*`,
  source_id: SOURCE,
  rights_policy_version: POLICY,
});

const kev = (cveId, dueDate) => ({
  cve_id: cveId,
  date_added: "2026-08-20",
  due_date: dueDate,
  ransomware: "Unknown",
  required_action: "Synthetic remediation action for immutable range testing only.",
  source_id: SOURCE,
  rights_policy_version: POLICY,
});

const DATASET_CARD = `# Patch8 P2 synthetic feasibility data

Everything under \`synthetic/p2/\` is deterministic, invented test data for browser-side Parquet, DuckDB-Wasm,
HTTP range, CORS, routing, and previous-good feasibility checks. It is not vulnerability intelligence and must not be
used for security decisions.

The synthetic rows are repository-authored and released as CC0-1.0 test fixtures. That statement applies only to these
explicit P2 synthetic rows. It does not blanket-relicense, override, or make any representation about future NVD, CVE
Program, CISA KEV, Vulnrichment, EPSS, or other upstream-derived rows. Every future source and field remains subject to
Patch8's source-rights two-key gate, provenance, attribution, and source-specific licence terms.

The active manifest is published only after the data files, and pins them by an immutable Hugging Face revision, byte
size, and SHA-256 digest. No credentials belong in this dataset or in browser requests.
`;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const dataFiles = () => ({
  [`${DATA_PREFIX}/current/vulnerabilities-2026-10.parquet`]: parquet(
    vulnerabilityRows("10", RANGE_ROW_COUNT),
    vulnerabilitySchema,
    RANGE_ROW_GROUP_SIZE,
  ),
  [`${DATA_PREFIX}/current/vulnerabilities-2026-20.parquet`]: parquet(
    vulnerabilityRows("20", 512, { seedOffset: 10_000 }),
    vulnerabilitySchema,
    64,
  ),
  [`${DATA_PREFIX}/current/affected-software-2026-10.parquet`]: parquet(
    [
      software(CURRENT_TARGET, "Acme", "Widget", "1.0"),
      software("CVE-2026-102113", "Acme", "Widget", "2.0"),
      software("CVE-2026-100001", "Beta", "Tool", "3.0"),
    ],
    softwareSchema,
    2,
  ),
  [`${DATA_PREFIX}/current/affected-software-2026-20.parquet`]: parquet(
    [software("CVE-2026-200001", "Gamma", "Service", "1.0")],
    softwareSchema,
    1,
  ),
  [`${DATA_PREFIX}/current/kev.parquet`]: parquet([kev(CURRENT_TARGET, "2026-09-10")], kevSchema, 1),
  [`${DATA_PREFIX}/previous/vulnerabilities-2026-10.parquet`]: parquet(
    vulnerabilityRows("10", 512, { previous: true, seedOffset: 20_000, forceTargetIndex: 256 }),
    vulnerabilitySchema,
    64,
  ),
  [`${DATA_PREFIX}/previous/affected-software-2026-10.parquet`]: parquet(
    [software(CURRENT_TARGET, "Acme", "Widget", "1.0")],
    softwareSchema,
    1,
  ),
  [`${DATA_PREFIX}/previous/kev.parquet`]: parquet([kev(CURRENT_TARGET, "2026-09-12")], kevSchema, 1),
  [`${DATA_PREFIX}/corrupt.parquet`]: new TextEncoder().encode("deliberately corrupt synthetic parquet fixture\n"),
  [`${DATA_PREFIX}/DATASET_CARD_FRAGMENT.md`]: new TextEncoder().encode(DATASET_CARD),
});

const artifactDefinitions = {
  current: [
    [
      "cves-2026-10",
      `${DATA_PREFIX}/current/vulnerabilities-2026-10.parquet`,
      "vulnerabilities",
      { cve_year: 2026, cve_bucket: "10" },
    ],
    [
      "cves-2026-20",
      `${DATA_PREFIX}/current/vulnerabilities-2026-20.parquet`,
      "vulnerabilities",
      { cve_year: 2026, cve_bucket: "20" },
    ],
    [
      "software-2026-10",
      `${DATA_PREFIX}/current/affected-software-2026-10.parquet`,
      "affected_software",
      { cve_year: 2026, cve_bucket: "10", vendor_buckets: ["ac", "be"] },
    ],
    [
      "software-2026-20",
      `${DATA_PREFIX}/current/affected-software-2026-20.parquet`,
      "affected_software",
      { cve_year: 2026, cve_bucket: "20", vendor_buckets: ["ga"] },
    ],
    ["kev-current", `${DATA_PREFIX}/current/kev.parquet`, "kev", { global: true }],
  ],
  previous: [
    [
      "cves-2026-10",
      `${DATA_PREFIX}/previous/vulnerabilities-2026-10.parquet`,
      "vulnerabilities",
      { cve_year: 2026, cve_bucket: "10" },
    ],
    [
      "software-2026-10",
      `${DATA_PREFIX}/previous/affected-software-2026-10.parquet`,
      "affected_software",
      { cve_year: 2026, cve_bucket: "10", vendor_buckets: ["ac"] },
    ],
    ["kev-current", `${DATA_PREFIX}/previous/kev.parquet`, "kev", { global: true }],
  ],
};

const safeOutput = (output) => {
  const resolved = resolve(output);
  if (!resolved.endsWith("/.p2-hf-release")) {
    throw new Error(`Refusing unsafe P2 HF output path: ${resolved}`);
  }
  return resolved;
};

const write = async (root, relativePath, bytes) => {
  const path = resolve(root, relativePath);
  if (!path.startsWith(`${root}/`)) throw new Error(`Unsafe output path: ${relativePath}`);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, bytes);
};

export async function prepare(output = DEFAULT_OUTPUT) {
  const root = safeOutput(output);
  const dataRoot = resolve(root, "data-revision");
  await rm(dataRoot, { recursive: true, force: true });
  await rm(resolve(root, "manifest-revision"), { recursive: true, force: true });
  const files = dataFiles();
  for (const [path, bytes] of Object.entries(files)) await write(dataRoot, path, bytes);
  const totalBytes = Object.values(files).reduce((total, bytes) => total + bytes.byteLength, 0);
  return { output: dataRoot, files: Object.keys(files).sort(), totalBytes };
}

const artifact = async (dataRoot, [id, path, table, route]) => {
  const bytes = await readFile(resolve(dataRoot, path));
  return { id, path, table, bytes: bytes.byteLength, sha256: sha256(bytes), route };
};

const p2Manifest = (releaseId, previousRelease, artifacts) => ({
  manifest_version: 0,
  fixture_only: true,
  release_id: releaseId,
  generated_at: GENERATED_AT,
  rights_policy_version: POLICY,
  max_query_bytes: 8_388_608,
  previous_release: previousRelease,
  artifacts,
});

export async function finalize(dataRevision, output = DEFAULT_OUTPUT) {
  if (!REVISION.test(dataRevision)) throw new Error("PATCH8_HF_P2_DATA_REVISION must be a lowercase 40-hex revision");
  const root = safeOutput(output);
  const dataRoot = resolve(root, "data-revision");
  const manifestRoot = resolve(root, "manifest-revision");
  await stat(resolve(dataRoot, `${DATA_PREFIX}/DATASET_CARD_FRAGMENT.md`));
  const current = await Promise.all(artifactDefinitions.current.map((definition) => artifact(dataRoot, definition)));
  const previous = await Promise.all(artifactDefinitions.previous.map((definition) => artifact(dataRoot, definition)));
  const corruptBytes = await readFile(resolve(dataRoot, `${DATA_PREFIX}/corrupt.parquet`));
  const manifest = {
    publication_manifest_version: 1,
    fixture_only: true,
    dataset_repository: DATASET_REPOSITORY,
    manifest_path: MANIFEST_PATH,
    data_revision: dataRevision,
    generated_at: GENERATED_AT,
    rights_policy_version: POLICY,
    range_proof: {
      artifact_path: `${DATA_PREFIX}/current/vulnerabilities-2026-10.parquet`,
      row_count: RANGE_ROW_COUNT,
      row_group_size: RANGE_ROW_GROUP_SIZE,
      row_groups: RANGE_ROW_COUNT / RANGE_ROW_GROUP_SIZE,
      minimum_bytes: 3_000_000,
    },
    current: p2Manifest("p2-hf-current", "p2-hf-previous", current),
    previous: p2Manifest("p2-hf-previous", null, previous),
    corrupt_artifact: {
      path: `${DATA_PREFIX}/corrupt.parquet`,
      bytes: corruptBytes.byteLength,
      sha256: sha256(corruptBytes),
    },
  };
  await rm(manifestRoot, { recursive: true, force: true });
  await write(manifestRoot, MANIFEST_PATH, new TextEncoder().encode(`${JSON.stringify(manifest, null, 2)}\n`));
  return { output: manifestRoot, manifest };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  const command = process.argv[2];
  const outputIndex = process.argv.indexOf("--output");
  const output = outputIndex >= 0 ? process.argv[outputIndex + 1] : DEFAULT_OUTPUT;
  if (command === "prepare") {
    const result = await prepare(output);
    console.log(`Prepared ${result.files.length} synthetic P2 files (${result.totalBytes} bytes) in ${result.output}`);
  } else if (command === "finalize") {
    const result = await finalize(process.env.PATCH8_HF_P2_DATA_REVISION ?? "", output);
    console.log(`Finalized manifest-last bundle in ${result.output}`);
  } else {
    throw new Error("Usage: build-p2-hf-release.mjs <prepare|finalize> [--output PATH]");
  }
}
