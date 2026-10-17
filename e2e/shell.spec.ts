// The shell: first run and the sample household kept across a reload, two
// tabs where the last write wins, and the header's language and theme.
// (The narrow window is mobile.spec.ts; no IndexedDB is private-mode.spec.ts.)
import { expect, test } from "@playwright/test";
import { COUNTS, expectCounts } from "./helpers";

test("empty state, then the sample: the shell shows the five files' row counts and keeps them on reload", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Qayd");
  await expect(page.getByTestId("empty-state")).toBeVisible();
  for (const [file] of COUNTS) await expect(page.getByTestId(`count-${file}`)).toHaveText("absent");
  await expect(page.getByTestId("memory-banner")).toHaveCount(0);
  await page.getByTestId("load-sample").click();
  await expectCounts(page);
  await expect(page.getByTestId("empty-state")).toHaveCount(0);
  await page.reload();
  await expectCounts(page);
});

test("two tabs: the last write wins and the other tab reloads", async ({ context }) => {
  const a = await context.newPage();
  const b = await context.newPage();
  await a.goto("/");
  await b.goto("/");
  await expect(b.getByTestId("empty-state")).toBeVisible();
  await a.getByTestId("load-sample").click();
  await expect(b.getByTestId("count-ledger.csv")).toHaveText("271 rows");
  await expect(b.getByTestId("reloaded-banner")).toBeVisible();
  await b.goto("/#/files");
  await b.getByTestId("paste-file").selectOption("rates.csv");
  await b.getByTestId("paste-text").fill("date,currency,rate\n2026-01-01,USD,0.385\n2026-02-01,USD,0.386\n");
  await b.getByTestId("paste-use").click();
  await expect(a.getByTestId("count-rates.csv")).toHaveText("2 rows");
});

test("language and theme: Arabic sets dir=rtl; the choice persists", async ({ page }) => {
  await page.goto("/");
  await page.getByTestId("language").selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("lang", "ar");
  await page.getByTestId("theme").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
});
