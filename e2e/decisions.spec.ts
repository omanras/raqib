// Decisions on the sample household: due first, a new decision, and
// closing the due one turns the dashboard green.
import { expect, test } from "@playwright/test";
import { go, loadSample } from "./helpers";

test("decisions: due first; a new decision; closing the due one turns the dashboard green", async ({ page }) => {
  await loadSample(page);
  await go(page, "Decisions");
  const list = page.getByTestId("decision-list").locator("li");
  await expect(list.first()).toHaveAttribute("data-testid", "decision-D-2026-06-01");
  await expect(list.first()).toHaveAttribute("data-status", "due");
  await expect(list.first()).toContainText("review by 2026-09-15 (15 days overdue)");
  await expect(page.getByTestId("decision-D-2026-01-10")).toContainText("(92 days left)");
  await expect(page.getByTestId("decision-D-2025-12-05")).toContainText("decided 2025-12-05 · closes WLT-05");

  await page.getByTestId("dec-new").click();
  await expect(page.getByTestId("dec-id")).toHaveText("D-2026-09-30-1");
  await page.getByTestId("dec-title").fill("keep the pilot closed");
  await page.getByTestId("dec-policy").selectOption("WLT-05");
  await page.getByTestId("dec-review-by").fill("2027-03-31");
  await page.getByTestId("dec-criteria").fill("no new money before the review");
  await page.getByTestId("dec-submit").click();
  await expect(page.getByTestId("dec-outcome")).toHaveText("Recorded D-2026-09-30-1 at line 34.");
  await expect(page.getByTestId("count-decisions.yml")).toHaveText("5 decisions");

  await page.getByTestId("close-D-2026-06-01").click();
  await expect(page.getByTestId("dec-outcome")).toHaveText("Closed D-2026-06-01.");
  await expect(page.getByTestId("decision-D-2026-06-01")).toHaveAttribute("data-status", "closed");
  await go(page, "Dashboard");
  await expect(page.getByTestId("summary")).toHaveText("GREEN as of 2026-09-30: 8 of 8 policies hold, 0 red findings, 0 warnings");
});
