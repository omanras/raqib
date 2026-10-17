// Dashboard on the sample household: the planted verdicts at 2026-09-30 in
// the CLI's words, the why expander with every cited row, the as-of date
// kept across a reload, and the verdicts moving with the as-of date.
import { expect, test } from "@playwright/test";
import { loadSample, setAsOf } from "./helpers";

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

test("the verdicts move with the as-of date: before the planted decision is due it is green", async ({ page }) => {
  await loadSample(page);
  await setAsOf(page, "2026-09-14");
  await expect(page.getByTestId("summary")).toHaveText("GREEN as of 2026-09-14: 8 of 8 policies hold, 0 red findings, 0 warnings");
  await setAsOf(page, "2026-07-31");
  await expect(page.getByTestId("policy-WLT-01")).toHaveAttribute("data-verdict", "breach");
  await expect(page.getByTestId("summary")).toContainText("RED as of 2026-07-31");
});
