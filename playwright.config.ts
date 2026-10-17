import { defineConfig, devices } from "@playwright/test";

// Chromium comes preinstalled under PLAYWRIGHT_BROWSERS_PATH (build 1194,
// the one @playwright/test 1.56.1 expects). Never run `playwright install`
// locally; CI installs it with `npx playwright install --with-deps chromium`.
// Specs live in e2e/ (the gate's directory); until that directory enters
// scope the hello spec lives in tests/e2e/, so both are matched here.
export default defineConfig({
  testDir: ".",
  testMatch: ["e2e/**/*.spec.ts", "tests/e2e/**/*.spec.ts"],
  testIgnore: ["**/node_modules/**", "**/dist/**"],
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "line",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "off",
    video: "off",
    screenshot: "off",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "npx vite preview --port 4173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
