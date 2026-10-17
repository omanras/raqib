// Holdings on the sample household: the current snapshot fresh at
// 2026-09-30, stale at 2026-12-31, and a new snapshot from the latest.
import { expect, test } from "@playwright/test";
import { loadSample, setAsOf } from "./helpers";

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
