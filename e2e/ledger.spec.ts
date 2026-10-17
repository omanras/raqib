// Ledger on the sample household: a row that breaches WLT-01 and its
// reversal, a malformed row refused by the engine before it is appended,
// and the raw panel that saves only once no line is invalid.
import { expect, test } from "@playwright/test";
import { loadSample, setAsOf } from "./helpers";

test("a discretionary row of 200 OMR breaches WLT-01; its reversal holds again", async ({ page }) => {
  await loadSample(page);
  await setAsOf(page, "2026-09-30");
  await page.getByRole("link", { name: "Ledger" }).click();
  await page.getByTestId("add-date").fill("2026-09-28");
  await page.getByTestId("add-amount").fill("-200");
  await expect(page.getByTestId("add-currency")).toHaveValue("OMR");
  await page.getByTestId("add-account").selectOption("cash");
  await page.getByTestId("add-category").selectOption("discretionary");
  await page.getByTestId("add-note").fill("new tablet");
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("ledger-outcome")).toContainText("Appended at line 273");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("272 rows");
  // newest first: the new row (2026-09-28) leads the table
  await expect(page.getByTestId("ledger-table").locator("tbody tr").first()).toHaveAttribute("data-line", "273");

  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByTestId("policy-WLT-01")).toHaveAttribute("data-verdict", "breach");
  await expect(page.getByTestId("mvl-WLT-01")).toHaveText("217.507 OMR vs 120 OMR (10% of income)");
  await expect(page.getByTestId("summary")).toHaveText("RED as of 2026-09-30: 7 of 8 policies hold, 2 red findings, 0 warnings");

  await page.getByRole("link", { name: "Ledger" }).click();
  await page.getByTestId("filter-category").selectOption("discretionary");
  await page.getByTestId("reverse-273").click();
  await expect(page.getByTestId("ledger-outcome")).toContainText("Appended the reversing row at line 274");
  await page.getByTestId("filter-text").fill("reverses ledger.csv:273");
  await expect(page.getByTestId("ledger-table").locator("tbody tr")).toHaveCount(1);
  await expect(page.getByTestId("ledger-table").locator("tbody tr")).toContainText("reversal");

  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByTestId("policy-WLT-01")).toHaveAttribute("data-verdict", "hold");
  await expect(page.getByTestId("summary")).toHaveText("RED as of 2026-09-30: 8 of 8 policies hold, 1 red finding, 0 warnings");
});

test("the engine refuses a malformed row before it is appended", async ({ page }) => {
  await loadSample(page);
  await page.getByRole("link", { name: "Ledger" }).click();
  await page.getByTestId("add-date").fill("2026-09-28");
  await page.getByTestId("add-amount").fill("1,200.00");
  await page.getByTestId("add-tags").fill("a;;b");
  await page.getByTestId("add-submit").click();
  const out = page.getByTestId("ledger-outcome");
  await expect(out).toContainText("Not appended");
  await expect(out).toContainText("BAD-AMOUNT");
  await expect(out).toContainText("BAD-TAGS");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("271 rows");
});

test("raw panel: problems by line, Save only once no line is invalid", async ({ page }) => {
  await loadSample(page);
  await page.getByRole("link", { name: "Ledger" }).click();
  const raw = page.getByTestId("raw-ledger.csv");
  await raw.locator("summary").click();
  const area = page.getByTestId("raw-text-ledger.csv");
  const text = await area.inputValue();
  await area.fill(text + "2026-09-29,-5,OMR,cash,coffee,,espresso\n");
  await expect(page.getByTestId("raw-problems-ledger.csv")).toContainText("ledger.csv:273 UNKNOWN-CATEGORY: category 'coffee' is not declared");
  await expect(page.getByTestId("raw-save-ledger.csv")).toBeDisabled();
  await area.fill(text + "2026-09-29,-5,OMR,cash,food,,espresso\n");
  await expect(page.getByTestId("raw-save-ledger.csv")).toBeEnabled();
  await page.getByTestId("raw-save-ledger.csv").click();
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("272 rows");
});
