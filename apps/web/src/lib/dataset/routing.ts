import type { P2Artifact, P2Manifest, P2Table } from "./types";

const CVE_PATTERN = /^CVE-(\d{4})-(\d{4,})$/i;
const SAFE_PATH = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;

export function cveRoute(id: string): { year: number; bucket: string } | null {
  const match = CVE_PATTERN.exec(id.trim());
  if (!match) return null;
  return { year: Number(match[1]), bucket: match[2].slice(0, 2).padEnd(2, "0") };
}

export function vendorBucket(vendor: string): string {
  return vendor
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "")
    .slice(0, 2)
    .padEnd(2, "_");
}

export function validateManifest(manifest: P2Manifest): void {
  if (manifest.manifest_version !== 0 || manifest.fixture_only !== true) throw new Error("Unsupported P2 manifest");
  if (manifest.rights_policy_version !== "p2-synthetic-1") throw new Error("Unexpected P2 rights policy");
  if (!Number.isInteger(manifest.max_query_bytes) || manifest.max_query_bytes <= 0) {
    throw new Error("Invalid P2 query budget");
  }

  const ids = new Set<string>();
  const paths = new Set<string>();
  for (const artifact of manifest.artifacts) {
    if (ids.has(artifact.id) || paths.has(artifact.path)) throw new Error("Duplicate P2 artifact");
    if (!SAFE_PATH.test(artifact.path) || artifact.path.includes("..")) throw new Error("Unsafe P2 artifact path");
    if (!Number.isInteger(artifact.bytes) || artifact.bytes <= 0) throw new Error("Invalid P2 artifact size");
    if (!/^[0-9a-f]{64}$/.test(artifact.sha256)) throw new Error("Invalid P2 artifact hash");
    ids.add(artifact.id);
    paths.add(artifact.path);
  }
}

export function artifactsForCve(manifest: P2Manifest, table: P2Table, id: string): P2Artifact[] {
  const route = cveRoute(id);
  if (!route) return [];
  return manifest.artifacts.filter(
    (artifact) =>
      artifact.table === table && artifact.route.cve_year === route.year && artifact.route.cve_bucket === route.bucket,
  );
}

export function artifactsForVendor(manifest: P2Manifest, vendor?: string): P2Artifact[] {
  const candidates = manifest.artifacts.filter((artifact) => artifact.table === "affected_software");
  if (!vendor) return candidates;
  const bucket = vendorBucket(vendor);
  return candidates.filter((artifact) => artifact.route.vendor_buckets?.includes(bucket));
}

export function globalArtifacts(manifest: P2Manifest, table: P2Table): P2Artifact[] {
  return manifest.artifacts.filter((artifact) => artifact.table === table && artifact.route.global === true);
}

export function allArtifacts(manifest: P2Manifest, table: P2Table): P2Artifact[] {
  return manifest.artifacts.filter((artifact) => artifact.table === table);
}
