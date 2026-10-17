// M1.4: the Review screen on the sample household. The 2026-Q3 review
// shows the WLT-01 breach of 2026-07 among the findings and the planted
// decision as due; the eight sections come in the CLI's order; the charts
// are inline SVG; "Copy as HTML" and "Download" give one page with no script.
import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

async function openReview(page: Page) {
  await page.goto("/");
  await page.getByTestId("load-sample").click();
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("271 rows");
  await page.getByTestId("as-of").fill("2026-09-30");
  await expect(page.getByTestId("summary")).toContainText("as of 2026-09-30");
  await page.getByRole("link", { name: "Review", exact: true }).click();
  await expect(page.locator("main h2")).toHaveText("Review");
}

test("the 2026-Q3 review: the WLT-01 breach of 2026-07 and the decision due", async ({ page }) => {
  await openReview(page);
  // default: the quarter of the as-of date
  await expect(page.getByTestId("review-period")).toHaveValue("2026-Q3");
  await expect(page.getByTestId("review-kind")).toHaveValue("quarter");

  await expect(page.locator(".review h3")).toHaveText([
    "Period",
    "Policy board",
    "Income vs expense per month",
    "Spending by category",
    "Allocation by class",
    "Findings of the period",
    "Decisions open and due",
    "Details: every row a verdict cites",
  ]);

  const breach = page.getByTestId("review-findings").locator('tr[data-code="BREACH"]');
  await expect(breach).toHaveCount(1);
  await expect(breach).toContainText("WLT-01");
  await expect(breach).toContainText("2026-07");
  await expect(page.getByTestId("review-findings").locator('tr[data-code="DECISION-DUE"]')).toContainText("2026-09-15");

  const due = page.getByTestId("review-decisions").locator('tr[data-id="D-2026-06-01"]');
  await expect(due).toHaveAttribute("data-status", "due");

  const board = page.getByTestId("review-board");
  await expect(board.locator("thead th")).toHaveCount(5);
  await expect(board.locator("tbody tr").first()).toContainText("WLT-01");
  await expect(board.locator("tbody tr").first().locator("td").nth(1)).toContainText("breach");

  for (const id of ["chart-income-expense", "chart-spending", "chart-allocation"]) {
    await expect(page.getByTestId(id).locator("svg")).toHaveAttribute("viewBox", /^0 0 \d+ \d+$/);
  }
  await expect(page.getByTestId("chart-spending").locator("svg text").filter({ hasText: /^housing$/ })).toHaveCount(1);
  await expect(page.getByTestId("chart-spending").locator("svg text").filter({ hasText: /^900 OMR$/ })).toHaveCount(1);
  await expect(page.getByTestId("chart-allocation").locator('line[stroke="var(--band)"]').first()).toBeAttached();
});

test("the period picker: month, quarter, year, and a bad period refused", async ({ page }) => {
  await openReview(page);
  await page.getByTestId("review-kind").selectOption("month");
  await expect(page.getByTestId("review-period")).toHaveValue("2026-09");
  await expect(page.getByTestId("review-board").locator("thead th")).toHaveCount(3);
  await page.getByTestId("review-kind").selectOption("year");
  await expect(page.getByTestId("review-period")).toHaveValue("2026");
  await expect(page.getByTestId("review-board").locator("thead th")).toHaveCount(11);
  await page.getByTestId("review-period").fill("2026-07");
  await expect(page.getByTestId("review-kind")).toHaveValue("month");
  await expect(page.getByTestId("review-findings").locator('tr[data-code="BREACH"]')).toContainText("WLT-01");
  await page.getByTestId("review-period").fill("2026-13");
  await expect(page.getByTestId("review-bad-period")).toBeVisible();
  await expect(page.getByTestId("review-board")).toHaveCount(0);
});

test("copy as HTML and download give the same self-contained page with no script", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await openReview(page);
  await page.getByTestId("review-copy").click();
  await expect(page.getByTestId("review-copied")).toHaveText("Copied: one page, no script.");
  const html = await page.evaluate(() => navigator.clipboard.readText());
  expect(html.startsWith("<!DOCTYPE html>\n")).toBe(true);
  expect(html).toContain("<title>Qayd review 2026-Q3</title>");
  expect(html).toContain(":root {");
  expect(html.toLowerCase()).not.toContain("<script");
  expect(html).not.toMatch(/\son[a-z]+=/i);
  expect(html).not.toMatch(/(src|href)="https?:/);
  for (const id of ["period", "board", "income-expense", "spending", "allocation", "findings", "decisions", "details"]) {
    expect(html).toContain(`<section id="${id}">`);
  }

  const download = page.waitForEvent("download");
  await page.getByTestId("review-download").click();
  const d = await download;
  expect(d.suggestedFilename()).toBe("qayd-review-2026-Q3.html");
  expect(readFileSync((await d.path()) as string, "utf8")).toBe(html);
});

test("the charts follow the theme tokens in dark mode", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await openReview(page);
  const token = (name: string) => page.evaluate((n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim(), name);
  expect(await token("--grid")).toBe("#2d343f");
  expect(await token("--income")).toBe("#6ea2e4");
  const color = await page.getByTestId("chart-spending").evaluate((el) => getComputedStyle(el).color);
  expect(color).toBe("rgb(232, 234, 238)");
});
