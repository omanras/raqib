// The household store over injected backends: IndexedDB itself is driven in
// e2e/ (a real browser); here the fallbacks, the writes, two tabs.
import { describe, expect, it } from "vitest";
import { MemoryBackend, type Backend, type FileChanges, type Stored } from "../../src/store/backend";
import { cleanMeta, DEFAULT_META, hasAnyFile, HouseholdStore, noFiles, type Notifier, type StoreEnv } from "../../src/store/household";
import { sampleHousehold } from "../../src/store/sample";

/** A backend that persists (like IndexedDB), shared by the tabs of a test. */
class SharedBackend implements Backend {
  readonly persistent = true;
  failWrites = false;
  private mem = new MemoryBackend();
  read(): Promise<Stored> {
    return this.mem.read();
  }
  async writeFiles(c: FileChanges): Promise<void> {
    if (this.failWrites) throw new Error("QuotaExceededError");
    return this.mem.writeFiles(c);
  }
  async writeMeta(m: unknown): Promise<void> {
    if (this.failWrites) throw new Error("QuotaExceededError");
    return this.mem.writeMeta(m);
  }
  clear(): Promise<void> {
    return this.mem.clear();
  }
}

/** The tabs of one browser: a post reaches every other tab's listener. */
function bus() {
  const listeners = new Map<string, () => void>();
  return (tab: string): Notifier => ({
    post: () => {
      for (const [t, on] of listeners) if (t !== tab) on();
    },
    listen: (on) => void listeners.set(tab, on),
    close: () => void listeners.delete(tab),
  });
}

const settle = () => new Promise((r) => setTimeout(r, 0));

function env(backend: Backend | Error, notifier = bus()): StoreEnv {
  return { openBackend: () => (backend instanceof Error ? Promise.reject(backend) : Promise.resolve(backend)), notifier };
}

describe("store/household", () => {
  it("falls back to memory when IndexedDB is unavailable, and says why", async () => {
    const s = await HouseholdStore.open(env(new Error("IndexedDB is not available")));
    expect([s.snapshot.persistent, s.snapshot.memoryReason]).toEqual([false, "IndexedDB is not available"]);
    expect(s.snapshot.files).toEqual(noFiles());
    expect(s.snapshot.meta).toEqual(DEFAULT_META);
    await s.setFiles(sampleHousehold());
    expect(hasAnyFile(s.snapshot.files)).toBe(true);
  });

  it("the browser env treats a missing IndexedDB as memory only", async () => {
    const { browserEnv } = await import("../../src/store/household");
    const s = await HouseholdStore.open(browserEnv());
    expect(s.snapshot.persistent).toBe(false); // node has no indexedDB
    expect(s.snapshot.memoryReason).toContain("not available");
    s.close();
  });

  it("writes files and meta through, and a second open reads them back", async () => {
    const backend = new SharedBackend();
    const s = await HouseholdStore.open(env(backend));
    const seen: number[] = [];
    s.subscribe((snap) => seen.push(Object.values(snap.files).filter((x) => x !== null).length));
    await s.setFiles({ "ledger.csv": "date,amount,currency,account,category,tags,note\n" });
    await s.setMeta({ asOf: "2026-09-30", language: "ar", theme: "dark" });
    expect(seen).toEqual([1, 1]);
    const again = await HouseholdStore.open(env(backend));
    expect(again.snapshot.files["ledger.csv"]).toBe("date,amount,currency,account,category,tags,note\n");
    expect(again.snapshot.meta).toEqual({ asOf: "2026-09-30", language: "ar", theme: "dark" });
    expect(again.snapshot.persistent).toBe(true);
    await again.setFiles({ "ledger.csv": null });
    expect((await HouseholdStore.open(env(backend))).snapshot.files["ledger.csv"]).toBeNull();
    await again.erase();
    expect((await HouseholdStore.open(env(backend))).snapshot).toMatchObject({ files: noFiles(), meta: DEFAULT_META });
  });

  it("when IndexedDB refuses a write, keeps the state in memory and shows the banner", async () => {
    const backend = new SharedBackend();
    const s = await HouseholdStore.open(env(backend));
    backend.failWrites = true;
    await s.setFiles({ "rates.csv": "date,currency,rate\n" });
    expect([s.snapshot.persistent, s.snapshot.memoryReason, s.snapshot.files["rates.csv"]]).toEqual([false, "QuotaExceededError", "date,currency,rate\n"]);
    await s.setMeta({ theme: "light" });
    expect(s.snapshot.meta.theme).toBe("light");
  });

  it("two tabs: the last write wins and the other tab reloads", async () => {
    const backend = new SharedBackend();
    const tabs = bus();
    const a = await HouseholdStore.open(env(backend, tabs));
    const b = await HouseholdStore.open(env(backend, tabs));
    await a.setFiles({ "rates.csv": "date,currency,rate\n2026-01-01,USD,0.385\n" });
    await settle();
    expect([b.snapshot.files["rates.csv"], b.snapshot.external]).toEqual(["date,currency,rate\n2026-01-01,USD,0.385\n", true]);
    await b.setFiles({ "rates.csv": "date,currency,rate\n" });
    await settle();
    expect([a.snapshot.files["rates.csv"], a.snapshot.external, b.snapshot.external]).toEqual(["date,currency,rate\n", true, false]);
    a.close();
    b.close();
  });

  it("meta read from storage is validated", () => {
    expect(cleanMeta({ asOf: "2026-02-30", language: "fr", theme: "blue" })).toEqual(DEFAULT_META);
    expect(cleanMeta(null)).toEqual(DEFAULT_META);
    expect(cleanMeta({ asOf: "2026-02-28", language: "ar", theme: "dark" })).toEqual({ asOf: "2026-02-28", language: "ar", theme: "dark" });
  });
});
