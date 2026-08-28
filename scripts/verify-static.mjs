#!/usr/bin/env node

import { createHash } from "node:crypto";
import { access, readFile, readdir, stat } from "node:fs/promises";

const BUILD = new URL("../apps/web/build/", import.meta.url);

await access(new URL("index.html", BUILD));
await access(new URL("404.html", BUILD));
await access(new URL("favicon.svg", BUILD));
await access(new URL("fonts/Geist-wght-v1.7.1.woff2", BUILD));
const parquetExtension = new URL("duckdb-extensions/v1.4.3/wasm_mvp/parquet.duckdb_extension.wasm", BUILD);
await access(parquetExtension);
const parquetExtensionBytes = await readFile(parquetExtension);
const parquetExtensionStat = await stat(parquetExtension);
if (parquetExtensionStat.size !== 2_867_304) throw new Error("Static DuckDB Parquet extension size changed");
if (
  createHash("sha256").update(parquetExtensionBytes).digest("hex") !==
  "0785c6c95d003eff4faa7b3b4b660f02c9c92f6d68d135ddf330d42e3a650600"
) {
  throw new Error("Static DuckDB Parquet extension checksum changed");
}

const html = await readFile(new URL("index.html", BUILD), "utf8");
for (const text of [
  "Vulnerability intelligence, prioritised",
  "Search CVE IDs, descriptions, or packages",
  "Recent KEV Vulnerabilities",
  "Critical CVEs",
  "High EPSS Risk",
  "Patch Tuesday",
]) {
  if (!html.includes(text)) throw new Error(`Static output is missing required status copy: ${text}`);
}

const rootEntries = await readdir(BUILD);
for (const forbidden of ["server", "worker.js", "functions", "api"]) {
  if (rootEntries.includes(forbidden)) throw new Error(`Static output contains forbidden runtime entry: ${forbidden}`);
}

console.log(`Static output verified: ${rootEntries.length} top-level entries and the legacy Patch8 dashboard shell.`);
