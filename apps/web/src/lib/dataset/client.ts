import {
  allArtifacts,
  artifactsForCve,
  artifactsForVendor,
  cveRoute,
  globalArtifacts,
  validateManifest,
} from "./routing";
import type {
  P2Artifact,
  P2Detail,
  P2Manifest,
  P2Product,
  P2SearchPage,
  P2SearchParams,
  P2SqlRuntime,
  P2Vulnerability,
  QueryResult,
} from "./types";

export interface P2DatasetOptions {
  current: P2Manifest;
  previous: P2Manifest;
  artifactUrls: Record<string, string>;
  runtimeFactory: () => P2SqlRuntime;
}

const SAFE_NAME = /^[A-Za-z0-9._-]+$/;

const normalizeRow = <T extends object>(row: T): T =>
  Object.fromEntries(
    Object.entries(row as Record<string, unknown>).map(([key, value]) => [
      key,
      typeof value === "bigint" ? Number(value) : value,
    ]),
  ) as T;

export class P2DatasetClient {
  private readonly current: P2Manifest;
  private readonly previous: P2Manifest;
  private readonly artifactUrls: Record<string, string>;
  private readonly runtimeFactory: () => P2SqlRuntime;
  private runtime: P2SqlRuntime;
  private readonly registered = new Set<string>();

  constructor(options: P2DatasetOptions) {
    validateManifest(options.current);
    validateManifest(options.previous);
    if (options.current.previous_release !== options.previous.release_id) {
      throw new Error("P2 previous-good release mismatch");
    }
    this.current = options.current;
    this.previous = options.previous;
    this.artifactUrls = options.artifactUrls;
    this.runtimeFactory = options.runtimeFactory;
    this.runtime = this.runtimeFactory();
  }

  private fileName(manifest: P2Manifest, artifact: P2Artifact): string {
    const name = `${manifest.release_id}-${artifact.id}.parquet`;
    if (!SAFE_NAME.test(name)) throw new Error("Unsafe P2 registered file name");
    return name;
  }

  private async register(manifest: P2Manifest, artifacts: P2Artifact[]): Promise<string[]> {
    const selected = [...new Map(artifacts.map((artifact) => [artifact.id, artifact])).values()];
    const bytes = selected.reduce((total, artifact) => total + artifact.bytes, 0);
    if (bytes > manifest.max_query_bytes) throw new Error("P2 query exceeds declared byte budget");

    const names: string[] = [];
    for (const artifact of selected) {
      const name = this.fileName(manifest, artifact);
      const url = this.artifactUrls[artifact.path];
      if (!url) throw new Error(`Missing P2 artifact URL: ${artifact.path}`);
      if (!this.registered.has(name)) {
        await this.runtime.registerFile(name, url);
        this.registered.add(name);
      }
      names.push(name);
    }
    return names;
  }

  private from(names: string[]): string {
    if (names.length === 0) throw new Error("No routed P2 artifacts");
    return `read_parquet([${names.map((name) => `'${name}'`).join(",")}])`;
  }

  private evidence<T>(manifest: P2Manifest, artifacts: P2Artifact[], value: T, usedFallback: boolean): QueryResult<T> {
    return {
      value,
      releaseId: manifest.release_id,
      usedFallback,
      selectedFiles: artifacts.map((artifact) => artifact.path),
      declaredBytes: artifacts.reduce((total, artifact) => total + artifact.bytes, 0),
    };
  }

  private async withFallback<T>(
    query: (manifest: P2Manifest, usedFallback: boolean) => Promise<QueryResult<T>>,
  ): Promise<QueryResult<T>> {
    try {
      return await query(this.current, false);
    } catch (currentError) {
      await this.runtime.close();
      this.runtime = this.runtimeFactory();
      this.registered.clear();
      try {
        return await query(this.previous, true);
      } catch (previousError) {
        const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
        throw new AggregateError(
          [currentError, previousError],
          `Current and previous-good P2 queries failed: current=${message(currentError)}; previous=${message(previousError)}`,
        );
      }
    }
  }

  async exact(id: string): Promise<QueryResult<P2Vulnerability | null>> {
    const normalizedId = id.toUpperCase();
    return this.withFallback(async (manifest, usedFallback) => {
      const artifacts = artifactsForCve(manifest, "vulnerabilities", normalizedId);
      if (artifacts.length === 0) return this.evidence(manifest, [], null, usedFallback);
      const names = await this.register(manifest, artifacts);
      const rows = await this.runtime.query<P2Vulnerability>(
        `SELECT * FROM ${this.from(names)} WHERE cve_id = ? LIMIT 1`,
        [normalizedId],
      );
      return this.evidence(manifest, artifacts, rows[0] ? normalizeRow(rows[0]) : null, usedFallback);
    });
  }

  async search(params: P2SearchParams = {}): Promise<QueryResult<P2SearchPage>> {
    return this.withFallback(async (manifest, usedFallback) => {
      const limit = Math.min(Math.max(params.limit ?? 25, 1), 100);
      const offset = Math.max(params.offset ?? 0, 0);
      let cveIds: string[] | null = null;
      let softwareArtifacts: P2Artifact[] = [];

      if (params.vendor || params.product) {
        softwareArtifacts = artifactsForVendor(manifest, params.vendor);
        if (softwareArtifacts.length === 0) {
          return this.evidence(manifest, [], { total: 0, limit, offset, results: [] }, usedFallback);
        }
        const softwareNames = await this.register(manifest, softwareArtifacts);
        const clauses: string[] = [];
        const values: unknown[] = [];
        if (params.vendor) {
          clauses.push("lower(vendor) = lower(?)");
          values.push(params.vendor);
        }
        if (params.product) {
          clauses.push("lower(product) = lower(?)");
          values.push(params.product);
        }
        const matches = await this.runtime.query<{ cve_id: string }>(
          `SELECT DISTINCT cve_id FROM ${this.from(softwareNames)} WHERE ${clauses.join(" AND ")}`,
          values,
        );
        cveIds = matches.map(({ cve_id }) => cve_id);
        if (cveIds.length === 0) {
          return this.evidence(manifest, softwareArtifacts, { total: 0, limit, offset, results: [] }, usedFallback);
        }
      }

      const exactRoute = params.q ? cveRoute(params.q) : null;
      const cveArtifacts = cveIds
        ? [
            ...new Map(
              cveIds.flatMap((id) => artifactsForCve(manifest, "vulnerabilities", id)).map((a) => [a.id, a]),
            ).values(),
          ]
        : exactRoute
          ? artifactsForCve(manifest, "vulnerabilities", params.q ?? "")
          : allArtifacts(manifest, "vulnerabilities");
      if (cveArtifacts.length === 0) {
        return this.evidence(manifest, softwareArtifacts, { total: 0, limit, offset, results: [] }, usedFallback);
      }

      const names = await this.register(manifest, [...softwareArtifacts, ...cveArtifacts]);
      const cveNames = names.filter((name) => name.includes("-cves-"));
      const clauses: string[] = [];
      const values: unknown[] = [];
      if (params.q) {
        if (exactRoute) {
          clauses.push("cve_id = ?");
          values.push(params.q.toUpperCase());
        } else {
          clauses.push("lower(description) LIKE lower(?)");
          values.push(`%${params.q}%`);
        }
      }
      if (params.severity) {
        clauses.push("severity = ?");
        values.push(params.severity.toUpperCase());
      }
      if (params.inKev) clauses.push("in_kev = 1");
      if (cveIds) {
        clauses.push(`cve_id IN (${cveIds.map(() => "?").join(",")})`);
        values.push(...cveIds);
      }
      const where = clauses.length > 0 ? ` WHERE ${clauses.join(" AND ")}` : "";
      const countRows = await this.runtime.query<{ total: number }>(
        `SELECT count(*) AS total FROM ${this.from(cveNames)}${where}`,
        values,
      );
      const rows = await this.runtime.query<P2Vulnerability>(
        `SELECT * FROM ${this.from(cveNames)}${where} ORDER BY cve_id LIMIT ? OFFSET ?`,
        [...values, limit, offset],
      );
      const total = Number(countRows[0]?.total ?? 0);
      return this.evidence(
        manifest,
        [...softwareArtifacts, ...cveArtifacts],
        { total, limit, offset, results: rows.map(normalizeRow) },
        usedFallback,
      );
    });
  }

  async detail(id: string): Promise<QueryResult<P2Detail | null>> {
    const normalizedId = id.toUpperCase();
    return this.withFallback(async (manifest, usedFallback) => {
      const artifacts = [
        ...artifactsForCve(manifest, "vulnerabilities", normalizedId),
        ...artifactsForCve(manifest, "affected_software", normalizedId),
        ...globalArtifacts(manifest, "kev"),
      ];
      if (!artifacts.some((artifact) => artifact.table === "vulnerabilities")) {
        return this.evidence(manifest, [], null, usedFallback);
      }
      const names = await this.register(manifest, artifacts);
      const cves = names.filter((name) => name.includes("-cves-"));
      const software = names.filter((name) => name.includes("-software-"));
      const kev = names.filter((name) => name.includes("-kev-"));
      const softwareFrom =
        software.length > 0
          ? this.from(software)
          : "(SELECT NULL::VARCHAR AS cve_id, NULL::VARCHAR AS vendor, NULL::VARCHAR AS product, NULL::VARCHAR AS version, NULL::VARCHAR AS cpe_uri)";
      const kevFrom =
        kev.length > 0
          ? this.from(kev)
          : "(SELECT NULL::VARCHAR AS cve_id, NULL::VARCHAR AS date_added, NULL::VARCHAR AS required_action)";
      const rows = await this.runtime.query<P2Detail>(
        `SELECT v.*, s.vendor, s.product, s.version, s.cpe_uri, k.date_added AS kev_date_added, k.required_action AS kev_required_action
         FROM ${this.from(cves)} v
         LEFT JOIN ${softwareFrom} s USING (cve_id)
         LEFT JOIN ${kevFrom} k USING (cve_id)
         WHERE v.cve_id = ? LIMIT 1`,
        [normalizedId],
      );
      return this.evidence(manifest, artifacts, rows[0] ? normalizeRow(rows[0]) : null, usedFallback);
    });
  }

  async products(vendor?: string, limit = 25, offset = 0): Promise<QueryResult<P2Product[]>> {
    return this.withFallback(async (manifest, usedFallback) => {
      const artifacts = artifactsForVendor(manifest, vendor);
      if (artifacts.length === 0) return this.evidence(manifest, [], [], usedFallback);
      const names = await this.register(manifest, artifacts);
      const where = vendor ? " WHERE lower(vendor) = lower(?)" : "";
      const values: unknown[] = vendor ? [vendor] : [];
      const rows = await this.runtime.query<P2Product>(
        `SELECT vendor, product, count(DISTINCT cve_id) AS vuln_count FROM ${this.from(names)}${where}
         GROUP BY vendor, product ORDER BY vendor, product LIMIT ? OFFSET ?`,
        [...values, Math.min(Math.max(limit, 1), 100), Math.max(offset, 0)],
      );
      return this.evidence(manifest, artifacts, rows.map(normalizeRow), usedFallback);
    });
  }

  async close(): Promise<void> {
    await this.runtime.close();
  }
}
