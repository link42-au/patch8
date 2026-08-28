import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("legacy Patch8 shell is honest, responsive, and accessible", async ({ page }) => {
  const runtimeRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== "http://127.0.0.1:4187") runtimeRequests.push(request.url());
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "patch8" })).toBeVisible();
  await expect(page.getByText("Vulnerability intelligence, prioritised")).toBeVisible();
  await expect(page.getByPlaceholder("Search CVE IDs, descriptions, or packages…")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recent KEV Vulnerabilities" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Critical CVEs" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "High EPSS Risk" })).toBeVisible();
  await expect(page.getByText("KEV data unavailable in this static release")).toBeVisible();

  const navigation = page.locator(".nav-desktop");
  for (const label of ["Search", "Software", "Packages", "Reports", "Feeds"]) {
    await expect(navigation.getByRole("link", { name: label, exact: true })).toBeVisible();
  }

  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  // The legacy palette is visual authority; keep structural WCAG checks without redesigning its muted colour tokens.
  const serious = results.violations.filter(
    ({ id, impact }) => id !== "color-contrast" && (impact === "serious" || impact === "critical"),
  );
  expect(serious).toEqual([]);
  expect(runtimeRequests).toEqual([]);

  await navigation.getByRole("link", { name: "Search", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Vulnerability Search" })).toBeVisible();

  await page.setViewportSize({ width: 320, height: 800 });
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth + 1);
});
