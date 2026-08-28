import { createServer, type Server } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";
import type {
  P2Detail,
  P2Product,
  P2SearchPage,
  P2Vulnerability,
  QueryResult,
} from "../apps/web/src/lib/dataset/types";

interface P2ProofResult {
  exact: QueryResult<P2Vulnerability | null>;
  filtered: QueryResult<P2SearchPage>;
  secondPage: QueryResult<P2SearchPage>;
  detail: QueryResult<P2Detail | null>;
  products: QueryResult<P2Product[]>;
  empty: QueryResult<P2Vulnerability | null>;
  fallback: QueryResult<P2Vulnerability | null>;
}

const ROOT = fileURLToPath(new URL("../apps/web/.p2-proof", import.meta.url));
let server: Server;
let origin: string;

const contentType = (path: string): string => {
  switch (extname(path)) {
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".wasm":
      return "application/wasm";
    case ".parquet":
      return "application/octet-stream";
    default:
      return "application/octet-stream";
  }
};

test.beforeAll(async () => {
  server = createServer(async (request, response) => {
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
      const fileStat = await stat(path);
      const headers: Record<string, string | number> = {
        "accept-ranges": "bytes",
        "access-control-allow-origin": "*",
        "cache-control": "no-store",
        "content-type": contentType(path),
      };

      const range = request.headers.range?.match(/^bytes=(\d+)-(\d*)$/);
      if (range) {
        const start = Number(range[1]);
        const end = range[2] ? Math.min(Number(range[2]), fileStat.size - 1) : fileStat.size - 1;
        headers["content-length"] = end - start + 1;
        headers["content-range"] = `bytes ${start}-${end}/${fileStat.size}`;
        response.writeHead(206, headers);
        if (request.method !== "HEAD") response.end(file.subarray(start, end + 1));
        else response.end();
        return;
      }

      headers["content-length"] = fileStat.size;
      response.writeHead(200, headers);
      if (request.method !== "HEAD") response.end(file);
      else response.end();
    } catch {
      response.writeHead(404).end();
    }
  });

  await new Promise<void>((resolveReady) => {
    server.listen(0, "127.0.0.1", () => resolveReady());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("P2 proof server did not bind");
  origin = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolveClosed, reject) => {
    server.close((error) => (error ? reject(error) : resolveClosed()));
  });
});

test("real Chromium queries routed synthetic Parquet with DuckDB-Wasm", async ({ page }) => {
  const requests: { url: string; authorization?: string }[] = [];
  let parquetBytes = 0;

  page.on("request", (request) => {
    requests.push({ url: request.url(), authorization: request.headers().authorization });
  });
  page.on("response", (response) => {
    if (new URL(response.url()).pathname.endsWith(".parquet")) {
      parquetBytes += Number(response.headers()["content-length"] ?? 0);
    }
  });

  await page.goto(origin);
  await page.waitForFunction(() => typeof window.runPatch8P2Proof === "function");
  const result = (await page.evaluate(() => window.runPatch8P2Proof())) as P2ProofResult;

  expect(result.exact.value.cve_id).toBe("CVE-2026-1001");
  expect(result.exact.selectedFiles).toEqual(["current-vulnerabilities-2026-10.parquet"]);
  expect(result.exact.declaredBytes).toBeLessThanOrEqual(32768);

  expect(result.filtered.value).toMatchObject({ total: 1, limit: 1, offset: 0 });
  expect(result.filtered.value.results.map((row) => row.cve_id)).toEqual(["CVE-2026-1001"]);
  expect(result.filtered.value.results[0].in_kev).toBe(1);

  expect(result.secondPage.value).toMatchObject({ total: 2, limit: 1, offset: 1 });
  expect(result.secondPage.value.results.map((row) => row.cve_id)).toEqual(["CVE-2026-2001"]);
  expect(result.secondPage.selectedFiles).toContain("current-software-2026-10.parquet");
  expect(result.secondPage.selectedFiles).toContain("current-vulnerabilities-2026-20.parquet");

  expect(result.detail.value).toMatchObject({
    cve_id: "CVE-2026-1001",
    vendor: "Acme",
    product: "Widget",
    kev_date_added: "2026-08-20",
  });
  expect(result.detail.selectedFiles).toContain("current-kev.parquet");

  expect(result.products.value).toEqual([{ vendor: "Acme", product: "Widget", vuln_count: 2 }]);
  expect(result.empty.value).toBeNull();
  expect(result.empty.usedFallback).toBe(false);

  expect(result.fallback.usedFallback).toBe(true);
  expect(result.fallback.releaseId).toBe("p2-previous");
  expect(result.fallback.value.description).toContain("previous-good");

  expect(parquetBytes).toBeGreaterThan(0);
  expect(parquetBytes).toBeLessThanOrEqual(131072);
  expect(requests.some(({ url }) => new URL(url).pathname.startsWith("/api/"))).toBe(false);
  expect(requests.every(({ authorization }) => authorization === undefined)).toBe(true);
  expect(requests.every(({ url }) => new URL(url).origin === origin)).toBe(true);
  const parquetRequests = requests.filter(({ url }) => new URL(url).pathname.endsWith(".parquet")).length;
  console.log(`P2 Chromium evidence: ${parquetBytes} Parquet bytes across ${parquetRequests} same-origin requests.`);
});
