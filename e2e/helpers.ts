// Shared steps of the end-to-end suite: the sample household, navigation,
// and the tour of every screen that offline.spec.ts, file.spec.ts,
// private-mode.spec.ts and mobile.spec.ts repeat under their conditions.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, type Page } from "@playwright/test";

export const EXAMPLES = join(process.cwd(), "reference", "examples");
export const example = (name: string) => readFileSync(join(EXAMPLES, name), "utf8");

export const FILES = ["policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv"] as const;

export const COUNTS: [string, string][] = [
  ["policies.yml", "8 policies"],
  ["ledger.csv", "271 rows"],
  ["holdings.csv", "72 rows"],
  ["decisions.yml", "4 decisions"],
  ["rates.csv", "24 rows"],
];

/** The navigation, in its order, with each screen's heading. */
export const SCREENS: [string, string][] = [
  ["Dashboard", "Dashboard"],
  ["Ledger", "Ledger"],
  ["Holdings", "Holdings"],
  ["Decisions", "Decisions"],
  ["Policies", "Policies"],
  ["Review", "Review"],
  ["Settings", "Settings"],
  ["Files", "Files"],
];

export const RED_0930 = "RED as of 2026-09-30: 8 of 8 policies hold, 1 red finding, 0 warnings";

export async function expectCounts(page: Page) {
  for (const [file, text] of COUNTS) await expect(page.getByTestId(`count-${file}`)).toHaveText(text);
}

export const go = (page: Page, name: string) => page.getByRole("link", { name, exact: true }).click();

/** Follow the navigation link to `#/slug` (any language) and wait until that screen has replaced the last one. */
export async function showScreen(page: Page, slug: string) {
  const link = page.locator(`nav a[href="#/${slug}"]`);
  const h2 = page.locator("main h2").first();
  const was = await page.locator('nav a[aria-current="page"]').getAttribute("href");
  const before = (await h2.textContent()) ?? "";
  await link.click();
  await expect(link).toHaveAttribute("aria-current", "page");
  if (was !== `#/${slug}`) await expect(h2).not.toHaveText(before);
}

/** Open the app at `url` ("/" by default; null: already open), load the sample, set the as-of date. */
export async function loadSample(page: Page, url: string | null = "/", asOf = "2026-09-30") {
  if (url !== null) await page.goto(url);
  await page.getByTestId("load-sample").click();
  await expectCounts(page);
  await go(page, "Dashboard");
  await page.getByTestId("as-of").fill(asOf);
  await expect(page.getByTestId("summary")).toContainText(`as of ${asOf}`);
}

/** Set the as-of date on the dashboard and wait for the verdicts to follow. */
export async function setAsOf(page: Page, date: string) {
  await go(page, "Dashboard");
  await page.getByTestId("as-of").fill(date);
  await expect(page.getByTestId("summary")).toContainText(`as of ${date}`);
}

/** True when the page itself does not scroll sideways. */
export const noSideScroll = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);

/**
 * The sample tour, from an opened app with nothing stored: every screen in
 * the navigation's order, with the change each one exists for, checked
 * against the planned verdicts. `each` runs on every screen once it shows.
 */
export async function tour(page: Page, url: string | null = "/", each: (screen: string) => Promise<void> = async () => {}) {
  await loadSample(page, url);

  // Dashboard: the planted verdicts
  await expect(page.getByTestId("summary")).toHaveText(RED_0930);
  await expect(page.locator('[data-testid="board"] .chip[data-verdict="hold"]')).toHaveCount(8);
  await each("Dashboard");

  // Ledger: a row that breaches WLT-01, seen red, reversed, seen green
  await go(page, "Ledger");
  await expect(page.locator("main h2").first()).toHaveText("Ledger");
  await page.getByTestId("add-date").fill("2026-09-28");
  await page.getByTestId("add-amount").fill("-200");
  await page.getByTestId("add-account").selectOption("cash");
  await page.getByTestId("add-category").selectOption("discretionary");
  await page.getByTestId("add-note").fill("new tablet");
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("ledger-outcome")).toContainText("Appended at line 273");
  await each("Ledger");
  await go(page, "Dashboard");
  await expect(page.getByTestId("policy-WLT-01")).toHaveAttribute("data-verdict", "breach");
  await go(page, "Ledger");
  await page.getByTestId("reverse-273").click();
  await expect(page.getByTestId("ledger-outcome")).toContainText("Appended the reversing row at line 274");
  await go(page, "Dashboard");
  await expect(page.getByTestId("policy-WLT-01")).toHaveAttribute("data-verdict", "hold");
  await expect(page.getByTestId("summary")).toHaveText(RED_0930);

  // Holdings: the current snapshot is fresh
  await go(page, "Holdings");
  await expect(page.getByTestId("freshness")).toHaveAttribute("data-state", "fresh");
  await each("Holdings");

  // Decisions: the planted one is due; a new one is recorded
  await go(page, "Decisions");
  await expect(page.getByTestId("decision-D-2026-06-01")).toHaveAttribute("data-status", "due");
  await page.getByTestId("dec-new").click();
  await page.getByTestId("dec-title").fill("keep the pilot closed");
  await page.getByTestId("dec-policy").selectOption("WLT-05");
  await page.getByTestId("dec-review-by").fill("2027-03-31");
  await page.getByTestId("dec-criteria").fill("no new money before the review");
  await each("Decisions");
  await page.getByTestId("dec-submit").click();
  await expect(page.getByTestId("dec-outcome")).toHaveText("Recorded D-2026-09-30-1 at line 34.");

  // Policies: today's verdicts beside the declared texts; the form opens
  await go(page, "Policies");
  await expect(page.getByTestId("pol-WLT-01")).toBeVisible();
  await page.getByTestId("pol-add").click();
  await expect(page.getByTestId("pf-type")).toBeVisible();
  await each("Policies");

  // Review: the 2026-Q3 findings; the page as a download
  await go(page, "Review");
  await expect(page.getByTestId("review-period")).toHaveValue("2026-Q3");
  await expect(page.getByTestId("review-findings").locator('tr[data-code="BREACH"]')).toContainText("WLT-01");
  await expect(page.getByTestId("review-decisions").locator('tr[data-id="D-2026-06-01"]')).toHaveAttribute("data-status", "due");
  await each("Review");
  const review = page.waitForEvent("download");
  await page.getByTestId("review-download").click();
  const page1 = readFileSync((await (await review).path()) as string, "utf8");
  expect(page1.startsWith("<!DOCTYPE html>\n")).toBe(true);
  expect(page1).not.toContain("<script");

  // Settings: Arabic right to left and back; dark and back
  await go(page, "Settings");
  await page.getByTestId("settings-language").selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  await each("Settings (ar)");
  await page.getByTestId("settings-language").selectOption("en");
  await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
  await page.getByTestId("settings-theme").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByTestId("settings-theme").selectOption("system");
  await each("Settings");

  // Files: the ledger downloads with the two rows the tour appended
  await go(page, "Files");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("273 rows");
  const ledger = page.waitForEvent("download");
  await page.getByTestId("download-ledger.csv").click();
  const text = readFileSync((await (await ledger).path()) as string, "utf8");
  expect(text.startsWith(example("ledger.csv"))).toBe(true);
  expect(text.slice(example("ledger.csv").length).split("\n")).toHaveLength(3);
  await each("Files");
}
