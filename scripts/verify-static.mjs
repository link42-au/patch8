#!/usr/bin/env node

import { access, readFile, readdir } from "node:fs/promises";

const BUILD = new URL("../apps/web/build/", import.meta.url);

await access(new URL("index.html", BUILD));
await access(new URL("404.html", BUILD));
await access(new URL("favicon.svg", BUILD));
await access(new URL("fonts/Geist-wght-v1.7.1.woff2", BUILD));

const html = await readFile(new URL("index.html", BUILD), "utf8");
for (const text of [
  "Know what needs patching.",
  "static shell is live-verified on GitHub Pages",
  "Lookup planned",
  "The live shell makes no data queries",
]) {
  if (!html.includes(text)) throw new Error(`Static output is missing required status copy: ${text}`);
}

const rootEntries = await readdir(BUILD);
for (const forbidden of ["server", "worker.js", "functions", "api"]) {
  if (rootEntries.includes(forbidden)) throw new Error(`Static output contains forbidden runtime entry: ${forbidden}`);
}

console.log(`Static output verified: ${rootEntries.length} top-level entries and honest planned-capability copy.`);
