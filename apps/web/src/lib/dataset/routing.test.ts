import { describe, expect, it } from "vitest";
import currentManifestJson from "./fixtures/current-manifest.json";
import { allArtifacts, artifactsForCve, artifactsForVendor, cveRoute, validateManifest, vendorBucket } from "./routing";
import type { P2Manifest } from "./types";

const manifest = currentManifestJson as P2Manifest;

describe("P2 query routing", () => {
  it("validates the synthetic manifest and prunes exact CVE files", () => {
    expect(() => validateManifest(manifest)).not.toThrow();
    expect(cveRoute("CVE-2026-1001")).toEqual({ year: 2026, bucket: "10" });
    expect(artifactsForCve(manifest, "vulnerabilities", "CVE-2026-1001").map(({ path }) => path)).toEqual([
      "current-vulnerabilities-2026-10.parquet",
    ]);
    expect(artifactsForCve(manifest, "vulnerabilities", "not-a-cve")).toEqual([]);
  });

  it("selects product shards without widening to unrelated tables", () => {
    expect(vendorBucket("Acme Corporation")).toBe("ac");
    expect(artifactsForVendor(manifest, "Acme").map(({ table }) => table)).toEqual([
      "affected_software",
      "affected_software",
    ]);
    expect(allArtifacts(manifest, "kev")).toHaveLength(1);
  });

  it("rejects unsafe or over-budget manifest values", () => {
    const unsafe = structuredClone(manifest);
    unsafe.artifacts[0].path = "../outside.parquet";
    expect(() => validateManifest(unsafe)).toThrow("Unsafe");

    const invalidBudget = structuredClone(manifest);
    invalidBudget.max_query_bytes = 0;
    expect(() => validateManifest(invalidBudget)).toThrow("budget");
  });
});
