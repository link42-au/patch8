import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const ROUTES = [
  "/",
  "/admin",
  "/feeds",
  "/packages",
  "/packages/[ecosystem]/[name]",
  "/reports/patch-tuesday",
  "/reports/patch-tuesday/[month]",
  "/search",
  "/software",
  "/software/[vendor]",
  "/software/[vendor]/[product]",
  "/vulnerabilities/[id]",
  "/watchlist",
];

test("legacy route structure is retained", async () => {
  for (const route of ROUTES) {
    const path = route === "/" ? "+page.svelte" : `${route.slice(1)}/+page.svelte`;
    await access(new URL(`../apps/web/src/routes/${path}`, import.meta.url));
  }
});

test("legacy shell remains static and unavailable features are honest", async () => {
  const layout = await readFile(new URL("../apps/web/src/routes/+layout.svelte", import.meta.url), "utf8");
  const api = await readFile(new URL("../apps/web/src/lib/api.ts", import.meta.url), "utf8");
  const dashboard = await readFile(new URL("../apps/web/src/routes/+page.svelte", import.meta.url), "utf8");
  const watchlist = await readFile(new URL("../apps/web/src/routes/watchlist/+page.svelte", import.meta.url), "utf8");

  for (const label of ["Search", "Software", "Packages", "Reports", "Feeds"])
    assert.match(layout, new RegExp(`label: "${label}"`));
  assert.doesNotMatch(layout, /Sign in|signOut|signInHref/);
  assert.match(api, /Data adapters are not implemented in this static release/);
  assert.doesNotMatch(api, /fetch\s*\(|VITE_|API_KEY|TOKEN/);
  assert.match(dashboard, /Vulnerability intelligence, prioritised/);
  assert.match(dashboard, /KEV data unavailable in this static release/);
  assert.match(watchlist, /Watchlists are unavailable in this static release/);
});
