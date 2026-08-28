import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("static shell is honest, responsive, and accessible", async ({ page }) => {
  const runtimeRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== "http://127.0.0.1:4173") runtimeRequests.push(request.url());
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Know what needs patching." })).toBeVisible();
  await expect(page.getByText(/static shell is live-verified on GitHub Pages/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Lookup planned" })).toBeDisabled();
  await expect(page.getByText(/The live shell makes no data queries/)).toBeVisible();

  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const serious = results.violations.filter(({ impact }) => impact === "serious" || impact === "critical");
  expect(serious).toEqual([]);
  expect(runtimeRequests).toEqual([]);

  await page.setViewportSize({ width: 320, height: 800 });
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth + 1);
});
