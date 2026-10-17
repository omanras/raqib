// Policies on the sample household: a cap added through the form reaches
// the dashboard; a refused combination with the engine's reason; an edit
// and a removal with its confirmation.
import { expect, test } from "@playwright/test";
import { go, loadSample } from "./helpers";

test("a cap added through the form is judged on the dashboard", async ({ page }) => {
  await loadSample(page);
  await go(page, "Policies");
  await page.getByTestId("pol-add").click();
  await page.getByTestId("pf-type").selectOption("cap");
  await page.getByTestId("pf-id").fill("WLT-09");
  await page.getByTestId("pf-title").fill("food per month");
  await page.getByTestId("pf-measure").selectOption("sum");
  await page.getByTestId("pf-group").selectOption("expense");
  await page.getByTestId("pf-category").selectOption("food");
  await page.getByTestId("pf-sum-period").selectOption("month");
  await page.getByTestId("pf-limit").selectOption("value");
  await page.getByTestId("pf-limit-value").fill("150");
  await page.getByTestId("pf-save").click();
  await expect(page.getByTestId("pol-outcome")).toHaveText("Saved WLT-09.");
  await expect(page.getByTestId("count-policies.yml")).toHaveText("9 policies");
  await go(page, "Dashboard");
  await expect(page.getByTestId("policy-WLT-09")).toHaveAttribute("data-verdict", "hold");
  await expect(page.getByTestId("mvl-WLT-09")).toHaveText("112.416 OMR vs 150 OMR");
  await expect(page.getByTestId("summary")).toHaveText("RED as of 2026-09-30: 9 of 9 policies hold, 1 red finding, 0 warnings");
});

test("an unknown combination is refused with the engine's reason; an edit and a removal", async ({ page }) => {
  await loadSample(page);
  await go(page, "Policies");
  await page.getByTestId("pol-add").click();
  await page.getByTestId("pf-type").selectOption("allocation");
  await page.getByTestId("pf-id").fill("X-1");
  await page.getByTestId("pf-title").fill("cash band");
  await page.getByTestId("pf-min-pct").fill("40");
  await page.getByTestId("pf-max-pct").fill("30");
  await page.getByTestId("pf-save").click();
  await expect(page.getByTestId("pol-outcome")).toContainText("band must satisfy 0 <= min_pct <= max_pct <= 100");
  await expect(page.getByTestId("count-policies.yml")).toHaveText("8 policies");

  await page.getByTestId("pol-edit-WLT-07").click();
  await page.getByTestId("pf-limit-value").fill("1900");
  await page.getByTestId("pf-save").click();
  await expect(page.getByTestId("pol-outcome")).toHaveText("Saved WLT-07.");
  await go(page, "Dashboard");
  await expect(page.getByTestId("policy-WLT-07")).toHaveAttribute("data-verdict", "breach");
  await expect(page.getByTestId("mvl-WLT-07")).toHaveText("1947.2064 OMR vs 1900 OMR");

  await go(page, "Policies");
  await page.getByTestId("pol-remove-WLT-04").click();
  const confirm = page.getByTestId("pol-remove-confirm");
  await expect(confirm).toContainText("Remove WLT-04? As of 2026-09-30 this disappears from the dashboard:");
  await expect(confirm).toContainText("hold     WLT-04     no margin, no options  no row vs none (any tag of margin,options) [ever]");
  await page.getByTestId("pol-remove-yes").click();
  await expect(page.getByTestId("pol-outcome")).toHaveText("Removed WLT-04.");
  await expect(page.getByTestId("pol-WLT-04")).toHaveCount(0);
  await expect(page.getByTestId("count-policies.yml")).toHaveText("7 policies");
});
