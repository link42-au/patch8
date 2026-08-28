import * as duckdb from "@duckdb/duckdb-wasm";
import mvpWasm from "@duckdb/duckdb-wasm/dist/duckdb-mvp.wasm?url";
import mvpWorker from "@duckdb/duckdb-wasm/dist/duckdb-browser-mvp.worker.js?url";
import corruptUrl from "./fixtures/corrupt.parquet?url";
import currentKevUrl from "./fixtures/current-kev.parquet?url";
import currentSoftware10Url from "./fixtures/current-software-2026-10.parquet?url";
import currentSoftware20Url from "./fixtures/current-software-2026-20.parquet?url";
import currentVulnerabilities10Url from "./fixtures/current-vulnerabilities-2026-10.parquet?url";
import currentVulnerabilities20Url from "./fixtures/current-vulnerabilities-2026-20.parquet?url";
import currentManifestJson from "./fixtures/current-manifest.json";
import previousKevUrl from "./fixtures/previous-kev.parquet?url";
import previousSoftware10Url from "./fixtures/previous-software-2026-10.parquet?url";
import previousVulnerabilities10Url from "./fixtures/previous-vulnerabilities-2026-10.parquet?url";
import previousManifestJson from "./fixtures/previous-manifest.json";
import { P2DatasetClient } from "./client";
import type { P2Manifest, P2SqlRuntime } from "./types";

const resolveFileUrl = async (value: string): Promise<string> => {
  const url = new URL(value, window.location.href);
  if (url.origin === window.location.origin) return url.href;
  if (
    url.protocol !== "https:" ||
    url.hostname !== "huggingface.co" ||
    !/^\/datasets\/link42-au\/patch\/resolve\/[0-9a-f]{40}\/synthetic\/p2\/.+\.parquet$/.test(url.pathname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("Remote Parquet URL is not an anonymous immutable Patch8 artifact");
  }
  const response = await fetch(url, {
    method: "HEAD",
    credentials: "omit",
    redirect: "follow",
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Remote Parquet resolution failed (${response.status})`);
  const target = new URL(response.url);
  if (
    target.protocol !== "https:" ||
    !/(?:^|\.)cdn\.hf\.co$/.test(target.hostname) ||
    target.username ||
    target.password ||
    target.hash
  ) {
    throw new Error("Remote Parquet redirect did not resolve to an approved HF CDN URL");
  }
  return target.href;
};

const artifactUrls: Record<string, string> = {
  "corrupt.parquet": corruptUrl,
  "current-kev.parquet": currentKevUrl,
  "current-software-2026-10.parquet": currentSoftware10Url,
  "current-software-2026-20.parquet": currentSoftware20Url,
  "current-vulnerabilities-2026-10.parquet": currentVulnerabilities10Url,
  "current-vulnerabilities-2026-20.parquet": currentVulnerabilities20Url,
  "previous-kev.parquet": previousKevUrl,
  "previous-software-2026-10.parquet": previousSoftware10Url,
  "previous-vulnerabilities-2026-10.parquet": previousVulnerabilities10Url,
};

export class BrowserDuckDbRuntime implements P2SqlRuntime {
  private readonly worker = new Worker(mvpWorker);
  private readonly db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), this.worker);
  private connection: duckdb.AsyncDuckDBConnection | null = null;
  private ready: Promise<void> | null = null;

  private async initialize(): Promise<void> {
    await this.db.instantiate(mvpWasm);
    await this.db.open({
      accessMode: duckdb.DuckDBAccessMode.READ_WRITE,
      filesystem: { allowFullHTTPReads: false, forceFullHTTPReads: false, reliableHeadRequests: true },
      query: { castBigIntToDouble: true },
    });
    const extensionConnection = await this.db.connect();
    try {
      const repository = new URL("duckdb-extensions", window.location.href);
      if (repository.origin !== window.location.origin)
        throw new Error("DuckDB extension repository must be same-origin");
      const repositoryUrl = repository.href.replace(/\/$/, "").replaceAll("'", "''");
      await extensionConnection.query(`SET custom_extension_repository = '${repositoryUrl}'`);
      await extensionConnection.query("INSTALL parquet");
      await extensionConnection.query("LOAD parquet");
      await extensionConnection.query("SET autoinstall_known_extensions = false");
      await extensionConnection.query("SET autoload_known_extensions = false");
    } finally {
      await extensionConnection.close();
    }
    this.connection = await this.db.connect();
  }

  private async getConnection(): Promise<duckdb.AsyncDuckDBConnection> {
    if (!this.ready) this.ready = this.initialize();
    await this.ready;
    if (!this.connection) throw new Error("DuckDB-Wasm connection is unavailable");
    return this.connection;
  }

  async registerFile(name: string, url: string): Promise<void> {
    await this.getConnection();
    const resolvedUrl = await resolveFileUrl(url);
    await this.db.registerFileURL(name, resolvedUrl, duckdb.DuckDBDataProtocol.HTTP, false);
  }

  async query<T>(sql: string, params: unknown[] = []): Promise<T[]> {
    const connection = await this.getConnection();
    const statement = await connection.prepare(sql);
    try {
      const result = await statement.query(...params);
      return result.toArray().map((row) => row.toJSON() as T);
    } finally {
      await statement.close();
    }
  }

  async close(): Promise<void> {
    if (this.connection) await this.connection.close();
    await this.db.terminate();
  }
}

const currentManifest = currentManifestJson as P2Manifest;
const previousManifest = previousManifestJson as P2Manifest;

export function createP2BrowserClient(options?: { corruptCurrent?: boolean }): P2DatasetClient {
  const current = structuredClone(currentManifest);
  const urls = { ...artifactUrls };
  if (options?.corruptCurrent) {
    const artifact = current.artifacts.find((candidate) => candidate.id === "cves-2026-10");
    if (!artifact) throw new Error("P2 corrupt-current target is missing");
    urls[artifact.path] = corruptUrl;
  }
  return new P2DatasetClient({
    current,
    previous: previousManifest,
    artifactUrls: urls,
    runtimeFactory: () => new BrowserDuckDbRuntime(),
  });
}
