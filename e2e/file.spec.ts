// The single-file build opened from disk: dist/index.html via file://,
// the same sample tour as offline.spec.ts, no http(s) request at all.
// IndexedDB may be unavailable for a file:// page: then the banner must
// say so and the app must still work; where it is available the household
// must survive a reload.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "@playwright/test";
import { tour } from "./helpers";

const DIST = join(process.cwd(), "dist", "index.html");
const URL_ = pathToFileURL(DIST).href;

test("dist/index.html from file:// runs the sample tour with no network", async ({ page, context }) => {
  expect(existsSync(DIST), "build first: npx vite build").toBe(true);
  const network: string[] = [];
  await context.route(/^(https?|wss?):/, (route) => {
    network.push(route.request().url());
    return route.abort();
  });
  page.on("request", (r) => {
    if (/^(https?|wss?):/.test(r.url()) && !network.includes(r.url())) network.push(r.url());
  });

  await tour(page, URL_);
  expect(network).toEqual([]);
  expect(page.url().startsWith(URL_)).toBe(true);

  const memory = (await page.getByTestId("memory-banner").count()) > 0;
  test.info().annotations.push({ type: "IndexedDB from file://", description: memory ? "unavailable: in memory, banner shown" : "available: the household persists" });
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Qayd");
  if (memory) {
    // nothing persisted, as the banner said
    await expect(page.getByTestId("memory-banner")).toContainText("nothing will persist in this browser");
    await expect(page.getByTestId("count-ledger.csv")).toHaveText("absent");
  } else {
    await expect(page.getByTestId("memory-banner")).toHaveCount(0);
    await expect(page.getByTestId("count-ledger.csv")).toHaveText("273 rows");
    await expect(page.getByTestId("count-decisions.yml")).toHaveText("5 decisions");
  }
});

test("file:// without IndexedDB: the banner, and the tour still works", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "indexedDB", { value: undefined, configurable: true });
  });
  await page.goto(URL_);
  await expect(page.getByTestId("memory-banner")).toContainText("nothing will persist in this browser");
  await tour(page, null);
  await expect(page.getByTestId("memory-banner")).toBeVisible();
});
