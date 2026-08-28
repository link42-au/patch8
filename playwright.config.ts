import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  outputDir: "test-results",
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:4187",
    browserName: "chromium",
    viewport: { width: 1280, height: 900 },
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium" }],
  webServer: {
    command: "pnpm --filter @patch8/web preview --host 127.0.0.1 --port 4187",
    url: "http://127.0.0.1:4187/",
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
