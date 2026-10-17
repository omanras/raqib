// Private mode and its relatives, simulated by stubbing IndexedDB before the
// app starts: the open request fails (Firefox private windows), open throws
// (a sandboxed frame), reading the API throws, the API is missing, open
// never answers, or the database opens and later refuses a write (quota).
// Each time the in-memory banner shows and the whole sample tour still works.
import { expect, test, type Page } from "@playwright/test";
import { tour } from "./helpers";

const BANNER = "IndexedDB is not available: nothing will persist in this browser. Export your files before you close this tab.";

const STUBS: [string, () => void][] = [
  [
    "the open request fails",
    () => {
      IDBFactory.prototype.open = function () {
        const req = { result: undefined, error: new DOMException("A mutation operation was attempted on a database that did not allow mutations.", "InvalidStateError"), onsuccess: null, onerror: null as null | ((e: unknown) => void), onupgradeneeded: null };
        setTimeout(() => req.onerror?.({ target: req }), 0);
        return req as unknown as IDBOpenDBRequest;
      };
    },
  ],
  [
    "open throws",
    () => {
      IDBFactory.prototype.open = () => {
        throw new DOMException("The operation is insecure.", "SecurityError");
      };
    },
  ],
  [
    "reading the API throws",
    () => {
      Object.defineProperty(window, "indexedDB", {
        get() {
          throw new Error("blocked by the browser");
        },
      });
    },
  ],
  [
    "the API is missing",
    () => {
      Object.defineProperty(window, "indexedDB", { value: undefined, configurable: true });
    },
  ],
  [
    "open never answers",
    () => {
      IDBFactory.prototype.open = () => ({ onsuccess: null, onerror: null, onupgradeneeded: null }) as unknown as IDBOpenDBRequest;
    },
  ],
];

for (const [name, stub] of STUBS) {
  test(`private mode, ${name}: the in-memory banner, and the tour works`, async ({ page }) => {
    await page.addInitScript(stub);
    await page.goto("/");
    await expect(page.getByTestId("memory-banner")).toHaveText(BANNER, { timeout: 10_000 });
    await tour(page, null);
    await expect(page.getByTestId("memory-banner")).toHaveText(BANNER);
    await page.getByRole("link", { name: "Settings", exact: true }).click();
    await expect(page.locator("main")).toContainText("Memory only: nothing persists in this browser.");
    // and it is true: a reload starts empty
    await page.reload();
    await expect(page.getByTestId("memory-banner")).toHaveText(BANNER, { timeout: 10_000 });
    await expect(page.getByTestId("count-ledger.csv")).toHaveText("absent");
    await page.getByRole("link", { name: "Dashboard", exact: true }).click();
    await expect(page.getByTestId("empty-state")).toBeVisible();
  });
}

async function refuseWrites(page: Page) {
  await page.addInitScript(() => {
    IDBObjectStore.prototype.put = () => {
      throw new DOMException("The quota has been exceeded.", "QuotaExceededError");
    };
  });
}

test("a write refused after a good open: the banner appears and the household stays in memory", async ({ page }) => {
  await refuseWrites(page);
  await page.goto("/");
  await expect(page.getByTestId("memory-banner")).toHaveCount(0);
  await tour(page, null);
  await expect(page.getByTestId("memory-banner")).toHaveText(BANNER);
  await expect(page.getByTestId("count-ledger.csv")).toHaveText("273 rows");
});
