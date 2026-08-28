import { createServer, type Server } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type Request } from "@playwright/test";
import type {
  P2Detail,
  P2Product,
  P2SearchPage,
  P2Vulnerability,
  QueryResult,
} from "../apps/web/src/lib/dataset/types";

interface LoadedEvidence {
  dataRevision: string;
  exactArtifact: { path: string; bytes: number };
  range: {
    status: number;
    bytes: number;
    contentRange: string | null;
    acceptRanges: string | null;
    responseType: string;
  };
}

interface QueryEvidence {
  exact: QueryResult<P2Vulnerability | null>;
  filtered: QueryResult<P2SearchPage>;
  detail: QueryResult<P2Detail | null>;
  products: QueryResult<P2Product[]>;
  fallback: QueryResult<P2Vulnerability | null>;
}

const REVISION = process.env.PATCH8_HF_P2_REVISION ?? "";
const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const ROOT = fileURLToPath(new URL("../apps/web/.p2-hf-proof", import.meta.url));

const allowedRemoteHost = (hostname: string): boolean =>
  hostname === "huggingface.co" || hostname.endsWith(".huggingface.co") || hostname.endsWith(".hf.co");

const parquetSourceUrl = (request: Request): string | null => {
  let candidate: Request | null = request;
  while (candidate) {
    const url = candidate.url();
    if (new URL(url).pathname.endsWith(".parquet")) return url;
    candidate = candidate.redirectedFrom();
  }
  return null;
};

const contentType = (path: string): string => {
  if (extname(path) === ".js") return "text/javascript; charset=utf-8";
  if (extname(path) === ".wasm") return "application/wasm";
  return "application/octet-stream";
};

const startProofServer = async (): Promise<{ server: Server; origin: string }> => {
  const server = createServer(async (request, response) => {
    try {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end('<!doctype html><meta charset="utf-8"><script type="module" src="/proof.js"></script>');
        return;
      }
      const relative = decodeURIComponent(new URL(request.url ?? "/", "http://p2.invalid").pathname).replace(
        /^\/+/,
        "",
      );
      const path = resolve(ROOT, relative);
      if (path !== ROOT && !path.startsWith(`${ROOT}${sep}`)) throw new Error("Unsafe proof path");
      const file = await readFile(path);
      response.writeHead(200, {
        "content-length": (await stat(path)).size,
        "content-type": contentType(path),
      });
      if (request.method === "HEAD") response.end();
      else response.end(file);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolveReady) => server.listen(0, "127.0.0.1", resolveReady));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("P2 HF proof server did not bind");
  return { server, origin: `http://127.0.0.1:${address.port}` };
};

test("immutable HF files support anonymous CORS, partial ranges, DuckDB, and fallback", async ({ page }) => {
  test.skip(!REVISION_PATTERN.test(REVISION), "Set PATCH8_HF_P2_REVISION to an immutable 40-hex manifest revision");
  const { server, origin } = await startProofServer();
  const requests: { url: string; method: string; authorization?: string; cookie?: string }[] = [];
  const responses: {
    url: string;
    method: string;
    status: number;
    length: number;
    cors?: string;
    range?: string;
    parquetSource?: string;
  }[] = [];
  const resolvedParquetSources = new Map<string, string>();
  let phase: "load" | "range-query" | "full-query" = "load";
  const phaseResponses: Record<string, typeof responses> = { load: [], "range-query": [], "full-query": [] };

  page.on("request", (request) => {
    const headers = request.headers();
    requests.push({
      url: request.url(),
      method: request.method(),
      authorization: headers.authorization,
      cookie: headers.cookie,
    });
  });
  page.on("response", (response) => {
    const request = response.request();
    let source = parquetSourceUrl(request);
    if (source && request.method() === "HEAD") resolvedParquetSources.set(response.url(), source);
    source ??= resolvedParquetSources.get(request.url()) ?? null;
    const item = {
      url: response.url(),
      method: request.method(),
      status: response.status(),
      length: Number(response.headers()["content-length"] ?? 0),
      cors: response.headers()["access-control-allow-origin"],
      range: request.headers().range,
      parquetSource: source ?? undefined,
    };
    responses.push(item);
    phaseResponses[phase].push(item);
  });

  try {
    await page.goto(origin);
    await page.waitForFunction(() => typeof window.loadPatch8P2HfProof === "function");
    const manifestUrl = `https://huggingface.co/datasets/link42-au/patch/resolve/${REVISION}/synthetic/p2/manifest.json`;
    const loaded = (await page.evaluate((url) => window.loadPatch8P2HfProof(url), manifestUrl)) as LoadedEvidence;

    expect(loaded.dataRevision).toMatch(REVISION_PATTERN);
    expect(loaded.exactArtifact.path).toBe("synthetic/p2/current/vulnerabilities-2026-10.parquet");
    expect(loaded.exactArtifact.bytes).toBeGreaterThan(3_000_000);
    expect(loaded.range).toMatchObject({ status: 206, bytes: 1024, responseType: "cors" });
    expect(loaded.range.contentRange).toBe(`bytes 0-1023/${loaded.exactArtifact.bytes}`);
    expect(loaded.range.acceptRanges).toBe("bytes");

    phase = "range-query";
    const exact = (await page.evaluate(() => window.runPatch8P2HfRangeQuery())) as QueryResult<P2Vulnerability | null>;
    expect(exact.value).toMatchObject({ cve_id: "CVE-2026-102112", severity: "CRITICAL", in_kev: 1 });
    expect(exact.selectedFiles).toEqual([loaded.exactArtifact.path]);
    expect(exact.declaredBytes).toBe(loaded.exactArtifact.bytes);

    const exactGets = phaseResponses["range-query"].filter(
      ({ method, parquetSource }) => method === "GET" && parquetSource,
    );
    const exactBytes = exactGets.reduce((total, { length }) => total + length, 0);
    expect(exactGets.some(({ status }) => status === 206)).toBe(true);
    expect(exactGets.some(({ status }) => status === 200)).toBe(false);
    expect(exactBytes).toBeGreaterThan(0);
    expect(exactBytes).toBeLessThan(loaded.exactArtifact.bytes);

    phase = "full-query";
    const result = (await page.evaluate(() => window.runPatch8P2HfQueryProof())) as QueryEvidence;
    expect(result.exact.value.cve_id).toBe("CVE-2026-102112");
    expect(result.filtered.value.total).toBe(1);
    expect(result.detail.value).toMatchObject({ vendor: "Acme", product: "Widget", kev_date_added: "2026-08-20" });
    expect(result.products.value).toEqual([{ vendor: "Acme", product: "Widget", vuln_count: 2 }]);
    expect(result.fallback.usedFallback).toBe(true);
    expect(result.fallback.releaseId).toBe("p2-hf-previous");
    expect(result.fallback.value.description).toContain("previous-good");

    const fullGets = phaseResponses["full-query"].filter(
      ({ method, parquetSource }) => method === "GET" && parquetSource,
    );
    const fullBytes = fullGets.reduce((total, { length }) => total + length, 0);
    expect(fullGets.some(({ status }) => status === 206)).toBe(true);
    expect(fullGets.some(({ status }) => status === 200)).toBe(false);
    expect(fullBytes).toBeLessThanOrEqual(16_777_216);
    expect(requests.every(({ authorization, cookie }) => !authorization && !cookie)).toBe(true);
    expect(
      requests.some(({ url }) => {
        const parsed = new URL(url);
        return parsed.origin === origin && parsed.pathname.startsWith("/api/");
      }),
    ).toBe(false);
    expect(
      requests.every(({ url }) => {
        const parsed = new URL(url);
        return parsed.origin === origin || allowedRemoteHost(parsed.hostname);
      }),
    ).toBe(true);

    expect(requests.some(({ url }) => url === manifestUrl)).toBe(true);
    const manifestResponse = phaseResponses.load.find(
      ({ url, status }) => status === 200 && allowedRemoteHost(new URL(url).hostname),
    );
    expect(manifestResponse).toBeDefined();
    expect(["*", origin]).toContain(manifestResponse?.cors);
    const immutableParquetRequests = requests.filter(
      ({ url }) =>
        url.startsWith("https://huggingface.co/datasets/link42-au/patch/resolve/") && url.endsWith(".parquet"),
    );
    expect(immutableParquetRequests.length).toBeGreaterThan(0);
    expect(
      immutableParquetRequests.every(({ url }) => url.includes(`/resolve/${loaded.dataRevision}/synthetic/p2/`)),
    ).toBe(true);
    console.log(
      `P2 HF evidence: revision ${REVISION}, data ${loaded.dataRevision}, exact ${exactBytes}/${loaded.exactArtifact.bytes} bytes ` +
        `[${exactGets.map(({ status, length, range, url }) => `${new URL(url).hostname} ${status} ${range ?? "redirect"} ${length}`).join("; ")}], ` +
        `full ${fullBytes} bytes [${fullGets.map(({ status }) => status).join(",")}].`,
    );
  } finally {
    await new Promise<void>((resolveClosed, reject) => {
      server.close((error) => (error ? reject(error) : resolveClosed()));
    });
  }
});
