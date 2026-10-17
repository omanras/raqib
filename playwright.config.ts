import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// The browser is the preinstalled Chromium found through
// PLAYWRIGHT_BROWSERS_PATH; `playwright install` is never run locally (CI
// installs it). The server under test is the built app (`npm start`) on a test
// port with its data directory in a fresh temporary folder. Workers inherit
// DAWR_E2E_DATA_DIR from the main process, so tests can find the database.
const port = Number(process.env.E2E_PORT ?? 3210);
process.env.DAWR_E2E_DATA_DIR ??= mkdtempSync(join(tmpdir(), 'dawr-e2e-'));
process.env.DAWR_E2E_BASE_URL ??= `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  reporter: 'line',
  timeout: 60_000,
  use: {
    baseURL: process.env.DAWR_E2E_BASE_URL,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm start',
    url: `${process.env.DAWR_E2E_BASE_URL}/api/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'ignore',
    stderr: 'pipe',
    env: {
      PORT: String(port),
      HOST: '127.0.0.1',
      DATA_DIR: process.env.DAWR_E2E_DATA_DIR,
      BASE_URL: process.env.DAWR_E2E_BASE_URL,
      NODE_ENV: 'test',
      LOG_LEVEL: 'warn',
    },
  },
});
