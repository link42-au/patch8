#!/usr/bin/env node

import { readFile, readdir } from "node:fs/promises";
import { extname, relative } from "node:path";

const ROOT = new URL("../", import.meta.url);
const FORBIDDEN_NAMES = [
  ".dev.vars",
  "drizzle.config.ts",
  "schema.sql",
  "wrangler.json",
  "wrangler.jsonc",
  "wrangler.toml",
];
const FORBIDDEN_DEPENDENCIES = [
  "@cloudflare/workers-types",
  "@huggingface/hub",
  "better-auth",
  "drizzle-orm",
  "hono",
  "openai",
  "wrangler",
];
const SECRET_REFERENCE = /\b(?:NVD_API_KEY|HF_TOKEN|HUGGINGFACE_TOKEN|OPENAI_API_KEY|DATABASE_URL)\b/;
const DATASET_FETCH_RUNTIME = "apps/web/src/lib/dataset/browser.ts";

const walk = async (directory) => {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    if (
      [
        ".git",
        ".p2-hf-proof",
        ".p2-hf-release",
        ".p2-proof",
        ".svelte-kit",
        "build",
        "node_modules",
        "playwright-report",
        "test-results",
      ].includes(entry.name)
    ) {
      continue;
    }
    const url = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directory);
    if (entry.isDirectory()) paths.push(...(await walk(url)));
    else paths.push(url);
  }
  return paths;
};

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const webPackageJson = JSON.parse(await readFile(new URL("../apps/web/package.json", import.meta.url), "utf8"));
const dependencyNames = [packageJson, webPackageJson].flatMap((value) => [
  ...Object.keys(value.dependencies ?? {}),
  ...Object.keys(value.devDependencies ?? {}),
]);

for (const dependency of FORBIDDEN_DEPENDENCIES) {
  if (dependencyNames.includes(dependency)) throw new Error(`Forbidden runtime dependency: ${dependency}`);
}

const files = await walk(ROOT);
for (const file of files) {
  const path = relative(new URL("../", import.meta.url).pathname, file.pathname);
  const name = file.pathname.split("/").at(-1) ?? "";
  if (FORBIDDEN_NAMES.includes(name) || name.startsWith(".env")) {
    throw new Error(`Forbidden backend or secret configuration file: ${path}`);
  }

  if ([".js", ".mjs", ".svelte", ".ts", ".yaml", ".yml"].includes(extname(name))) {
    const source = await readFile(file, "utf8");
    if (!path.startsWith("scripts/") && SECRET_REFERENCE.test(source)) {
      throw new Error(`Secret-like runtime configuration reference: ${path}`);
    }
    if (path.startsWith("apps/web/src/") && path !== DATASET_FETCH_RUNTIME && /\bfetch\s*\(/.test(source)) {
      throw new Error(`Static browser code must not bypass the dataset runtime with fetch: ${path}`);
    }
    if (path.startsWith(".github/") && /\bsecrets\./.test(source)) {
      throw new Error(`Public Pages workflow must not depend on repository secrets: ${path}`);
    }
  }
}

console.log(
  `Architecture verified: ${files.length} source files, static client only, approved dataset resolution only, no backend fetch or runtime secret.`,
);
