import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parquetWriteBuffer } from "hyparquet-writer";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../src/lib/dataset/fixtures");
const CHECK = process.argv.includes("--check");
const POLICY = "p2-synthetic-1";
const SOURCE = "synthetic_patch8_p2";

const columns = (rows, schema) =>
  schema.map(([name, type]) => ({
    name,
    type,
    data: rows.map((row) => row[name]),
    nullable: false,
  }));

const parquet = (rows, schema) =>
  new Uint8Array(
    parquetWriteBuffer({
      columnData: columns(rows, schema),
      codec: "UNCOMPRESSED",
      rowGroupSize: 2,
      statistics: true,
      kvMetadata: [
        { key: "fixture", value: "patch8-p2" },
        { key: "rights_policy_version", value: POLICY },
      ],
    }),
  );

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

const vulnerability = (id, description, severity, score, inKev, published, dueDate = "") => ({
  id: id.toLowerCase(),
  cve_id: id,
  description,
  published_at: published,
  modified_at: "2026-08-28T00:00:00Z",
  severity,
  cvss_score: score,
  cvss_vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:${severity === "CRITICAL" ? "H" : "L"}/I:L/A:L`,
  cvss_version: "3.1",
  in_kev: inKev ? 1 : 0,
  kev_due_date: dueDate,
  package_count: 0,
  source_count: inKev ? 2 : 1,
  source_id: SOURCE,
  rights_policy_version: POLICY,
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
  required_action: "Synthetic remediation action for browser testing only.",
  source_id: SOURCE,
  rights_policy_version: POLICY,
});

const datasets = {
  "current-vulnerabilities-2026-10.parquet": parquet(
    [
      vulnerability(
        "CVE-2026-1001",
        "Synthetic critical widget vulnerability.",
        "CRITICAL",
        9.8,
        true,
        "2026-08-20T00:00:00Z",
        "2026-09-10",
      ),
      vulnerability(
        "CVE-2026-1099",
        "Synthetic medium tool vulnerability.",
        "MEDIUM",
        5.4,
        false,
        "2026-08-21T00:00:00Z",
      ),
    ],
    vulnerabilitySchema,
  ),
  "current-vulnerabilities-2026-20.parquet": parquet(
    [
      vulnerability(
        "CVE-2026-2001",
        "Synthetic high widget vulnerability.",
        "HIGH",
        8.1,
        false,
        "2026-08-22T00:00:00Z",
      ),
    ],
    vulnerabilitySchema,
  ),
  "current-software-2026-10.parquet": parquet(
    [software("CVE-2026-1001", "Acme", "Widget", "1.0"), software("CVE-2026-1099", "Beta", "Tool", "3.2")],
    softwareSchema,
  ),
  "current-software-2026-20.parquet": parquet([software("CVE-2026-2001", "Acme", "Widget", "2.0")], softwareSchema),
  "current-kev.parquet": parquet([kev("CVE-2026-1001", "2026-09-10")], kevSchema),
  "previous-vulnerabilities-2026-10.parquet": parquet(
    [
      vulnerability(
        "CVE-2026-1001",
        "Synthetic previous-good widget vulnerability.",
        "HIGH",
        8.8,
        true,
        "2026-08-20T00:00:00Z",
        "2026-09-12",
      ),
    ],
    vulnerabilitySchema,
  ),
  "previous-software-2026-10.parquet": parquet([software("CVE-2026-1001", "Acme", "Widget", "1.0")], softwareSchema),
  "previous-kev.parquet": parquet([kev("CVE-2026-1001", "2026-09-12")], kevSchema),
  "corrupt.parquet": new TextEncoder().encode("deliberately corrupt synthetic parquet fixture\n"),
};

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const artifact = (id, path, table, route) => ({
  id,
  path,
  table,
  bytes: datasets[path].byteLength,
  sha256: sha256(datasets[path]),
  route,
});

const manifest = (releaseId, previousRelease, prefix) => ({
  manifest_version: 0,
  fixture_only: true,
  release_id: releaseId,
  generated_at: "2026-08-28T00:00:00Z",
  rights_policy_version: POLICY,
  max_query_bytes: 32768,
  previous_release: previousRelease,
  artifacts:
    prefix === "current"
      ? [
          artifact("cves-2026-10", "current-vulnerabilities-2026-10.parquet", "vulnerabilities", {
            cve_year: 2026,
            cve_bucket: "10",
          }),
          artifact("cves-2026-20", "current-vulnerabilities-2026-20.parquet", "vulnerabilities", {
            cve_year: 2026,
            cve_bucket: "20",
          }),
          artifact("software-2026-10", "current-software-2026-10.parquet", "affected_software", {
            cve_year: 2026,
            cve_bucket: "10",
            vendor_buckets: ["ac", "be"],
          }),
          artifact("software-2026-20", "current-software-2026-20.parquet", "affected_software", {
            cve_year: 2026,
            cve_bucket: "20",
            vendor_buckets: ["ac"],
          }),
          artifact("kev-current", "current-kev.parquet", "kev", { global: true }),
        ]
      : [
          artifact("cves-2026-10", "previous-vulnerabilities-2026-10.parquet", "vulnerabilities", {
            cve_year: 2026,
            cve_bucket: "10",
          }),
          artifact("software-2026-10", "previous-software-2026-10.parquet", "affected_software", {
            cve_year: 2026,
            cve_bucket: "10",
            vendor_buckets: ["ac"],
          }),
          artifact("kev-current", "previous-kev.parquet", "kev", { global: true }),
        ],
});

const manifests = {
  "current-manifest.json": new TextEncoder().encode(
    `${JSON.stringify(manifest("p2-current", "p2-previous", "current"), null, 2)}\n`,
  ),
  "previous-manifest.json": new TextEncoder().encode(
    `${JSON.stringify(manifest("p2-previous", null, "previous"), null, 2)}\n`,
  ),
};

await mkdir(ROOT, { recursive: true });
for (const [name, bytes] of Object.entries({ ...datasets, ...manifests })) {
  const path = resolve(ROOT, name);
  if (CHECK) {
    const existing = await readFile(path);
    if (!existing.equals(Buffer.from(bytes))) throw new Error(`P2 fixture drift: ${name}`);
  } else {
    await writeFile(path, bytes);
  }
}

console.log(
  `${CHECK ? "Verified" : "Generated"} ${Object.keys(datasets).length} binary fixtures and ${Object.keys(manifests).length} manifests.`,
);
