// M1.3: Policies, Decisions, Settings and the Arabic interface on the
// sample household: a cap added through the form reaches the dashboard,
// a refused combination, an edit and a removal; a new decision and a
// closed one; Arabic right to left; export all, erase all, import all.
import { expect, test, type Page } from "@playwright/test";

async function loadSample(page: Page) {
  await page.goto("/");
  await page.getByTestId("load-sample").click();
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("271 rows");
  await page.getByTestId("as-of").fill("2026-09-30");
  await expect(page.getByTestId("summary")).toContainText("as of 2026-09-30");
}

const go = (page: Page, name: string) => page.getByRole("link", { name, exact: true }).click();

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
  const counts: [string, string][] = [
    ["policies.yml", "8 policies"],
    ["ledger.csv", "271 rows"],
    ["holdings.csv", "72 rows"],
    ["decisions.yml", "4 decisions"],
    ["rates.csv", "24 rows"],
  ];
  for (const [file, text] of counts) {
    await expect(page.getByTestId(`count-${file}`)).toHaveText(text);
  }
  await page.getByRole("link", { name: "Files" }).click();
  await page.getByTestId("copy-ledger.csv").click();
  const ledger = await page.evaluate(() => navigator.clipboard.readText());
  expect(bundle).toContain("=== ledger.csv ===\n" + ledger + "\n=== holdings.csv ===");
});
