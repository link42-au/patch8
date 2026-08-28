import { describe, expect, it } from "vitest";
import { type SortableVuln, sortVulnerabilities } from "../sort";

const vulns: SortableVuln[] = [
  { severity: "LOW", cvss_score: 3.1, epss_score: 0.01, in_kev: 0, published_at: "2025-01-15" },
  { severity: "CRITICAL", cvss_score: 9.8, epss_score: 0.95, in_kev: 1, published_at: "2025-03-01" },
  { severity: "HIGH", cvss_score: 7.5, epss_score: 0.42, in_kev: 0, published_at: "2025-02-10" },
  { severity: "MEDIUM", cvss_score: 5.0, epss_score: 0.15, in_kev: 1, published_at: "2024-12-20" },
  { severity: null, cvss_score: null, epss_score: null, in_kev: 0, published_at: null },
];

describe("sortVulnerabilities", () => {
  it("returns original order when col is null", () => {
    const result = sortVulnerabilities(vulns, null, "desc");
    expect(result).toEqual(vulns);
  });

  it("does not mutate the original array", () => {
    const copy = [...vulns];
    sortVulnerabilities(vulns, "cvss_score", "desc");
    expect(vulns).toEqual(copy);
  });

  describe("severity sorting", () => {
    it("sorts descending by severity order", () => {
      const result = sortVulnerabilities(vulns, "severity", "desc");
      expect(result.map((v) => v.severity)).toEqual(["CRITICAL", "HIGH", "MEDIUM", "LOW", null]);
    });

    it("sorts ascending by severity order", () => {
      const result = sortVulnerabilities(vulns, "severity", "asc");
      expect(result.map((v) => v.severity)).toEqual([null, "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
    });
  });

  describe("CVSS sorting", () => {
    it("sorts descending by CVSS score", () => {
      const result = sortVulnerabilities(vulns, "cvss_score", "desc");
      expect(result.map((v) => v.cvss_score)).toEqual([9.8, 7.5, 5.0, 3.1, null]);
    });

    it("sorts ascending by CVSS score with nulls last", () => {
      const result = sortVulnerabilities(vulns, "cvss_score", "asc");
      expect(result.map((v) => v.cvss_score)).toEqual([3.1, 5.0, 7.5, 9.8, null]);
    });
  });

  describe("EPSS sorting", () => {
    it("sorts descending by EPSS score", () => {
      const result = sortVulnerabilities(vulns, "epss_score", "desc");
      expect(result.map((v) => v.epss_score)).toEqual([0.95, 0.42, 0.15, 0.01, null]);
    });

    it("sorts ascending by EPSS score with nulls last", () => {
      const result = sortVulnerabilities(vulns, "epss_score", "asc");
      expect(result.map((v) => v.epss_score)).toEqual([0.01, 0.15, 0.42, 0.95, null]);
    });
  });

  describe("KEV sorting", () => {
    it("sorts descending (KEV entries first)", () => {
      const result = sortVulnerabilities(vulns, "in_kev", "desc");
      const kevVals = result.map((v) => v.in_kev);
      expect(kevVals.slice(0, 2)).toEqual([1, 1]);
      expect(kevVals.slice(2)).toEqual([0, 0, 0]);
    });

    it("sorts ascending (non-KEV first)", () => {
      const result = sortVulnerabilities(vulns, "in_kev", "asc");
      const kevVals = result.map((v) => v.in_kev);
      expect(kevVals.slice(0, 3)).toEqual([0, 0, 0]);
      expect(kevVals.slice(3)).toEqual([1, 1]);
    });
  });

  describe("published_at sorting", () => {
    it("sorts descending by date (newest first)", () => {
      const result = sortVulnerabilities(vulns, "published_at", "desc");
      expect(result.map((v) => v.published_at)).toEqual(["2025-03-01", "2025-02-10", "2025-01-15", "2024-12-20", null]);
    });

    it("sorts ascending by date with nulls last", () => {
      const result = sortVulnerabilities(vulns, "published_at", "asc");
      expect(result.map((v) => v.published_at)).toEqual(["2024-12-20", "2025-01-15", "2025-02-10", "2025-03-01", null]);
    });
  });

  it("handles empty array", () => {
    expect(sortVulnerabilities([], "cvss_score", "desc")).toEqual([]);
  });

  it("handles single item", () => {
    const single = [vulns[0]];
    expect(sortVulnerabilities(single, "cvss_score", "desc")).toEqual(single);
  });

  it("handles all-null values", () => {
    const nulls: SortableVuln[] = [
      { severity: null, cvss_score: null, epss_score: null, in_kev: 0, published_at: null },
      { severity: null, cvss_score: null, epss_score: null, in_kev: 0, published_at: null },
    ];
    const result = sortVulnerabilities(nulls, "cvss_score", "desc");
    expect(result).toHaveLength(2);
  });
});
