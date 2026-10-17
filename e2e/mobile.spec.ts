// A phone-sized window (400 x 800): the sample tour with its forms filled
// and submitted, and on every screen the page does not scroll sideways,
// the navigation is reachable, and every control outside a scrolling table
// lies inside the window. The same in Arabic (right to left).
import { expect, test, type Page } from "@playwright/test";
import { loadSample, noSideScroll, showScreen, tour } from "./helpers";

test.use({ viewport: { width: 400, height: 800 }, hasTouch: true });

const SLUGS = ["dashboard", "ledger", "holdings", "decisions", "policies", "review", "settings", "files"];

/** Controls whose box leaves the window, unless they sit in a scrolling table. */
function outside(page: Page) {
  return page.evaluate(() => {
    const w = window.innerWidth;
    const bad: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("input, select, textarea, button, a[href], summary"))) {
      if (el.closest(".table-wrap")) continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) continue; // not rendered (closed details, hidden file input)
      if (r.left < -0.5 || r.right > w + 0.5) bad.push(`${el.tagName.toLowerCase()}[${el.getAttribute("data-testid") ?? el.textContent?.trim().slice(0, 30) ?? ""}] ${Math.round(r.left)}..${Math.round(r.right)}`);
    }
    return bad;
  });
}

async function check(page: Page, where: string) {
  expect(await noSideScroll(page), `${where}: the page scrolls sideways`).toBe(true);
  expect(await outside(page), `${where}: controls outside the window`).toEqual([]);
  const nav = page.locator("nav.nav a");
  await expect(nav).toHaveCount(8);
  for (const a of await nav.all()) await expect(a).toBeVisible();
}

test("at 400 x 800 the sample tour works and nothing leaves the window", async ({ page }) => {
  const seen: string[] = [];
  await tour(page, "/", async (screen) => {
    seen.push(screen);
    await check(page, screen);
  });
  expect(seen).toEqual(["Dashboard", "Ledger", "Holdings", "Decisions", "Policies", "Review", "Settings (ar)", "Settings", "Files"]);
});

test("at 400 x 800 in Arabic every screen fits, with its forms open", async ({ page }) => {
  await loadSample(page);
  await page.getByTestId("language").selectOption("ar");
  await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
  for (const slug of SLUGS) {
    await showScreen(page, slug);
    if (slug === "holdings") await page.getByTestId("snap-new").click();
    if (slug === "decisions") await page.getByTestId("dec-new").click();
    if (slug === "policies") await page.getByTestId("pol-add").click();
    for (const raw of await page.locator("details.raw > summary").all()) await raw.click();
    await check(page, `ar ${slug}`);
  }
});

test("at 400 x 800 a row can be added by touch alone", async ({ page }) => {
  await loadSample(page);
  await page.locator('a[href="#/ledger"]').first().tap();
  await page.getByTestId("add-date").tap();
  await page.getByTestId("add-date").fill("2026-09-29");
  await page.getByTestId("add-amount").tap();
  await page.getByTestId("add-amount").fill("-4.500");
  await page.getByTestId("add-category").selectOption("food");
  await page.getByTestId("add-submit").tap();
  await expect(page.getByTestId("ledger-outcome")).toContainText("Appended at line 273");
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("272 rows");
});
