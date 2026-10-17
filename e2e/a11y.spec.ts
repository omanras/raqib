// Accessibility smoke on every screen, in English and in Arabic, with the
// forms and raw panels open: every form control has a label, every button
// and chip has text (state is never colour only), every chart has a title,
// no positive tabindex, and Tab moves through the page in DOM order.
import { expect, test, type Page } from "@playwright/test";
import { loadSample, showScreen } from "./helpers";

const SLUGS = ["dashboard", "ledger", "holdings", "decisions", "policies", "review", "settings", "files"];

async function open(page: Page, slug: string) {
  await showScreen(page, slug);
  if (slug === "holdings") await page.getByTestId("snap-new").click();
  if (slug === "decisions") await page.getByTestId("dec-new").click();
  if (slug === "policies") await page.getByTestId("pol-add").click();
  if (slug === "dashboard") await page.locator('[data-testid="board"] details > summary').first().click();
  for (const raw of await page.locator("details.raw > summary").all()) await raw.click();
}

/** Every problem the page has with labels, texts and tabindex. */
function problems(page: Page) {
  return page.evaluate(() => {
    const out: string[] = [];
    const name = (el: Element) => el.getAttribute("data-testid") ?? el.id ?? el.tagName.toLowerCase();
    const text = (el: Element | null) => (el?.textContent ?? "").replace(/\s+/g, " ").trim();
    const labelText = (label: HTMLLabelElement) => {
      const copy = label.cloneNode(true) as HTMLElement;
      copy.querySelectorAll("input, select, textarea, button").forEach((c) => c.remove());
      return text(copy);
    };
    const labelled = (el: HTMLElement) => {
      if ((el.getAttribute("aria-label") ?? "").trim() !== "") return true;
      const ids = (el.getAttribute("aria-labelledby") ?? "").split(/\s+/).filter(Boolean);
      if (ids.some((id) => text(document.getElementById(id)) !== "")) return true;
      const labels = (el as HTMLInputElement).labels;
      return labels !== null && Array.from(labels).some((l) => labelText(l) !== "");
    };
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("input, select, textarea"))) {
      if (el.getAttribute("type") === "hidden") continue;
      if (!labelled(el)) out.push(`control without a label: ${el.tagName.toLowerCase()} ${name(el)}`);
    }
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("button, a[href], summary"))) {
      if (text(el) === "" && (el.getAttribute("aria-label") ?? "").trim() === "") out.push(`${el.tagName.toLowerCase()} without text: ${name(el)}`);
    }
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(".chip"))) {
      if (text(el) === "") out.push(`chip without text: ${name(el)}`);
    }
    for (const svg of Array.from(document.querySelectorAll("svg"))) {
      const title = svg.querySelector(":scope > title");
      if (svg.getAttribute("role") !== "img" || text(title) === "") out.push(`chart without a title: ${name(svg.parentElement ?? svg)}`);
    }
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("[tabindex]"))) {
      if (el.tabIndex > 0) out.push(`positive tabindex: ${name(el)}`);
    }
    return out;
  });
}

/**
 * From the skip link (the first element of the page), press Tab until focus
 * comes back to an element it already visited; the elements visited must
 * follow one another in the DOM.
 */
async function tabOrder(page: Page): Promise<{ visited: number; backwards: string[] }> {
  await page.evaluate(() => {
    document.querySelectorAll("[data-tab-seen]").forEach((e) => e.removeAttribute("data-tab-seen"));
    const first = document.querySelector<HTMLElement>("a.skip");
    if (first === null) throw new Error("no skip link");
    first.focus();
    first.setAttribute("data-tab-seen", "");
    (window as unknown as { __tabPrev: Element | null }).__tabPrev = first;
  });
  const backwards: string[] = [];
  let visited = 0;
  for (let i = 0; i < 600; i++) {
    await page.keyboard.press("Tab");
    const step = await page.evaluate(() => {
      const w = window as unknown as { __tabPrev: Element | null };
      const el = document.activeElement;
      if (!el || el === document.body) return "body";
      if (el.hasAttribute("data-tab-seen")) return "again";
      el.setAttribute("data-tab-seen", "");
      const prev = w.__tabPrev;
      w.__tabPrev = el;
      const label = `${el.tagName.toLowerCase()} ${el.getAttribute("data-testid") ?? (el.textContent ?? "").trim().slice(0, 30)}`;
      if (prev && !(prev.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING)) return `back:${label}`;
      return "ok";
    });
    if (step === "again") break;
    if (step === "body") continue;
    visited++;
    if (step.startsWith("back:")) backwards.push(step.slice(5));
  }
  return { visited, backwards };
}

for (const language of ["en", "ar"] as const) {
  test(`labels, texts and tab order on every screen (${language})`, async ({ page }) => {
    test.setTimeout(120_000);
    await loadSample(page);
    if (language === "ar") {
      await page.getByTestId("language").selectOption("ar");
      await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
    }
    for (const slug of SLUGS) {
      await open(page, slug);
      expect(await problems(page), `${language} ${slug}`).toEqual([]);
      const order = await tabOrder(page);
      expect(order.backwards, `${language} ${slug}: focus moved backwards`).toEqual([]);
      expect(order.visited, `${language} ${slug}: focus visited too few elements`).toBeGreaterThan(12);
    }
  });
}

test("the checks are not blind: planted faults are reported", async ({ page }) => {
  await loadSample(page);
  await page.evaluate(() => {
    const main = document.getElementById("main") as HTMLElement;
    main.insertAdjacentHTML("afterbegin", '<input data-testid="planted-input"><button data-testid="planted-button"></button><span class="chip" data-testid="planted-chip"></span><a href="#/ledger" tabindex="3" data-testid="planted-tab">x</a>');
  });
  expect(await problems(page)).toEqual([
    "control without a label: input planted-input",
    "button without text: planted-button",
    "chip without text: planted-chip",
    "positive tabindex: planted-tab",
  ]);
  expect((await tabOrder(page)).backwards).toEqual(["a planted-tab"]);
});

test("the skip link is the first stop and moves focus to the main content", async ({ page }) => {
  await loadSample(page);
  await page.reload();
  await expect(page.getByTestId("summary")).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.locator(":focus")).toHaveClass(/skip/);
  await page.keyboard.press("Enter");
  await expect(page.locator(":focus")).toHaveId("main");
});

test("verdicts are words: every chip on the dashboard says its verdict", async ({ page }) => {
  await loadSample(page);
  const chips = page.locator('[data-testid="board"] .chip[data-verdict]');
  await expect(chips).toHaveCount(8);
  for (const chip of await chips.all()) {
    expect(await chip.textContent()).toBe(await chip.getAttribute("data-verdict"));
  }
});
