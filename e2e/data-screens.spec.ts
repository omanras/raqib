// M1.2: Dashboard, Ledger and Holdings on the sample household: the planted
// verdicts, a breaching row and its reversal, the raw panel, a new
// snapshot, and a stale snapshot when as-of moves past its allowed age.
import { expect, test, type Page } from "@playwright/test";

async function loadSample(page: Page) {
  await page.goto("/");
  await page.getByTestId("load-sample").click();
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("271 rows");
}

async function setAsOf(page: Page, date: string) {
  await page.getByRole("link", { name: "Dashboard" }).click();
  await page.getByTestId("as-of").fill(date);
  await expect(page.getByTestId("summary")).toContainText(`as of ${date}`);
}

test("dashboard at 2026-09-30: 8 hold and 1 red finding, in the CLI's words", async ({ page }) => {
  await loadSample(page);
  await setAsOf(page, "2026-09-30");
  await expect(page.getByTestId("summary")).toHaveText("RED as of 2026-09-30: 8 of 8 policies hold, 1 red finding, 0 warnings");
  await expect(page.locator('[data-testid="board"] .chip[data-verdict="hold"]')).toHaveCount(8);
  await expect(page.getByTestId("findings").locator("li")).toHaveCount(1);
  await expect(page.getByTestId("findings")).toContainText("DECISION-DUE decisions.yml:26 decision D-2026-06-01 is open and its review date 2026-09-15 is 15 days past");
  await expect(page.getByTestId("mvl-WLT-01")).toHaveText("17.507 OMR vs 120 OMR (10% of income)");
  await expect(page.getByTestId("mvl-WLT-06")).toHaveText("4.75% vs 2%..30%");
  // the why expander lists every cited row with its file:line and the line itself
  const why = page.getByTestId("policy-WLT-01").locator("details");
  await why.locator("summary").click();
  await expect(why.locator("tr")).toHaveCount(2);
  await expect(why.locator("tr").first()).toContainText("ledger.csv:270");
  await expect(why.locator("tr").first()).toContainText("2026-09-15,-17.507,OMR,cash,discretionary,,gift");
  // the as-of date persists
  await page.reload();
  await expect(page.getByTestId("summary")).toHaveText("RED as of 2026-09-30: 8 of 8 policies hold, 1 red finding, 0 warnings");
});

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

test("holdings: a new snapshot from the latest; stale once as-of is past the allowed age", async ({ page }) => {
  await loadSample(page);
  await setAsOf(page, "2026-09-30");
  await page.getByRole("link", { name: "Holdings" }).click();
  await expect(page.getByTestId("freshness")).toHaveAttribute("data-state", "fresh");
  await expect(page.getByTestId("snapshot-2026-09-30")).toBeVisible();
  await setAsOf(page, "2026-12-31");
  await expect(page.getByTestId("policy-WLT-02")).toHaveAttribute("data-verdict", "stale");
  await expect(page.getByTestId("mvl-WLT-02")).toHaveText("stale 10900 OMR as of 2026-09-30 (92 days) vs 3706.778066666666666666666666 OMR (6 months of expense)");
  await page.getByRole("link", { name: "Holdings" }).click();
  await expect(page.getByTestId("freshness")).toHaveAttribute("data-state", "stale");
  await expect(page.getByTestId("freshness")).toHaveText("Stale: the current snapshot 2026-09-30 is 92 days old; 45 allowed.");
  await page.getByTestId("snap-new").click();
  await expect(page.getByTestId("snap-valueText-0")).toHaveValue("10900.000");
  await page.getByTestId("snap-date").fill("2026-12-31");
  await page.getByTestId("snap-valueText-0").fill("11800.000");
  await page.getByTestId("snap-submit").click();
  await expect(page.getByTestId("count-holdings.csv")).toHaveText("75 rows");
  await expect(page.getByTestId("freshness")).toHaveAttribute("data-state", "fresh");
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByTestId("policy-WLT-02")).not.toHaveAttribute("data-verdict", "stale");
});
