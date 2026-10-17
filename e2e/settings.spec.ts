// Settings on the sample household: Arabic right to left with Latin digits
// and ISO dates, the choice kept; export all, erase all in two steps,
// import all, byte for byte.
import { expect, test } from "@playwright/test";
import { COUNTS, go, loadSample } from "./helpers";

test("Arabic: dir=rtl, translated headings, Latin digits and ISO dates; the choice persists", async ({ page }) => {
  await loadSample(page);
  await go(page, "Settings");
  await page.getByTestId("settings-language").selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("html")).toHaveAttribute("lang", "ar");
  await expect(page.locator("main h2").first()).toHaveText("الإعدادات");
  await page.getByRole("link", { name: "اللوحة" }).click();
  await expect(page.locator("main h2").first()).toHaveText("اللوحة");
  await expect(page.getByTestId("as-of")).toHaveValue("2026-09-30");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("الأسطر: 271");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await expect(page.locator("main h2").first()).toHaveText("اللوحة");
});

test("export all, erase all (two steps), import all: the counts come back", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await loadSample(page);
  await go(page, "Settings");
  await expect(page.getByTestId("base-currency")).toHaveText("OMR");
  await page.getByTestId("export-all").click();
  const bundle = await page.evaluate(() => navigator.clipboard.readText());
  expect(bundle.startsWith("=== policies.yml ===\n")).toBe(true);
  expect(bundle).toContain("\n=== rates.csv ===\ndate,currency,rate\n");

  await page.getByTestId("erase-ask").click();
  await page.getByTestId("erase-yes").click();
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("absent");
  await go(page, "Dashboard");
  await expect(page.getByTestId("empty-state")).toBeVisible();

  await go(page, "Settings");
  await page.getByTestId("bundle-text").fill(bundle);
  await page.getByTestId("bundle-import").click();
  for (const [file, text] of COUNTS) {
    await expect(page.getByTestId(`count-${file}`)).toHaveText(text);
  }
  await page.getByRole("link", { name: "Files" }).click();
  await page.getByTestId("copy-ledger.csv").click();
  const ledger = await page.evaluate(() => navigator.clipboard.readText());
  expect(bundle).toContain("=== ledger.csv ===\n" + ledger + "\n=== holdings.csv ===");
});
