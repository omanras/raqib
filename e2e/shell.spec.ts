// M1.1: the store and the shell in a real browser (Chromium): first run,
// the sample household, persistence across a reload, export equal to the
// bundled bytes, a refused import, two tabs, language and theme.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";

const EXAMPLES = join(process.cwd(), "reference", "examples");
const example = (name: string) => readFileSync(join(EXAMPLES, name), "utf8");

const COUNTS: [string, string][] = [
  ["policies.yml", "8 policies"],
  ["ledger.csv", "271 rows"],
  ["holdings.csv", "72 rows"],
  ["decisions.yml", "4 decisions"],
  ["rates.csv", "24 rows"],
];

async function expectCounts(page: Page) {
  for (const [file, text] of COUNTS) await expect(page.getByTestId(`count-${file}`)).toHaveText(text);
}

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

test("export copies text equal to the bundled file, and download offers it", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/");
  await page.getByTestId("load-sample").click();
  await page.getByRole("link", { name: "Files" }).click();
  for (const name of ["ledger.csv", "policies.yml"]) {
    await page.getByTestId(`copy-${name}`).click();
    await expect(page.getByTestId(`file-${name}`).getByRole("status")).toHaveText("Copied");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(example(name));
  }
  const download = page.waitForEvent("download");
  await page.getByTestId("download-holdings.csv").click();
  const d = await download;
  expect(d.suggestedFilename()).toBe("holdings.csv");
  expect(readFileSync(await d.path(), "utf8")).toBe(example("holdings.csv"));
});

test("import: a wrong header is refused with the expected header shown; a good file replaces the stored one", async ({ page }) => {
  await page.goto("/#/files");
  await page.getByTestId("import-ledger.csv").setInputFiles({ name: "ledger.csv", mimeType: "text/csv", buffer: Buffer.from("date,amount,note\n2026-01-01,1,x\n") });
  const refused = page.getByTestId("file-ledger.csv").getByRole("alert");
  await expect(refused).toContainText("Refused ledger.csv");
  await expect(refused).toContainText("Expected header: date,amount,currency,account,category,tags,note");
  await expect(refused).toContainText("First line: date,amount,note");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("absent");
  await page.getByTestId("import-many").setInputFiles(
    ["policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv"].map((name) => ({ name, mimeType: "text/plain", buffer: Buffer.from(example(name)) })),
  );
  await expectCounts(page);
  await page.getByTestId("import-rates.csv").setInputFiles({ name: "r.csv", mimeType: "text/csv", buffer: Buffer.from([0x64, 0xff, 0x0a]) });
  await expect(page.getByTestId("file-rates.csv").getByRole("alert")).toContainText("not UTF-8");
  await page.getByTestId("paste-file").selectOption("rates.csv");
  await page.getByTestId("paste-text").fill("date,currency,rate\n2026-01-01,USD,0.385\n");
  await page.getByTestId("paste-use").click();
  await expect(page.getByTestId("count-rates.csv")).toHaveText("1 row");
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

test("at 400 px wide the navigation is reachable and nothing scrolls sideways", async ({ page }) => {
  await page.setViewportSize({ width: 400, height: 800 });
  await page.goto("/");
  await page.getByTestId("load-sample").click();
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Settings" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("without IndexedDB the app runs in memory and says nothing will persist", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "indexedDB", {
      get() {
        throw new Error("blocked by the browser");
      },
    });
  });
  await page.goto("/");
  await expect(page.getByTestId("memory-banner")).toContainText("nothing will persist in this browser");
  await page.getByTestId("load-sample").click();
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("271 rows");
});
