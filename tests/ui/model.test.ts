// The data screens' model (src/ui/model.ts) over the sample household: the
// text behind a citation, the ledger filters and order, the reversing row,
// appending through the engine, snapshots and their age.
import { describe, expect, it } from "vitest";
import { check } from "../../src/engine/commands";
import { loadHousehold } from "../../src/engine/household";
import type { Config, LedgerRow } from "../../src/engine/types";
import { appendLedger, appendSnapshot, blocking, citedLine, filterLedger, freshness, ledgerFacets, newestFirst, NO_FILTER, prefillSnapshot, reversalOf, snapshotsNewestFirst, todayIso } from "../../src/ui/model";
import { sampleHousehold } from "../../src/store/sample";

const files = sampleHousehold();
const h = loadHousehold(files);
const config = h.config as Config;
const ledger = h.ctx?.ledger ?? [];
const holdings = h.ctx?.holdings ?? [];

describe("ui/model", () => {
  it("today is the device's local date as ISO text", () => {
    expect(todayIso(new Date(2026, 9, 17, 23, 59))).toBe("2026-10-17");
    expect(todayIso(new Date(2024, 1, 29, 0, 0))).toBe("2024-02-29");
  });

  it("finds the line a citation names", () => {
    expect(citedLine(files, "ledger.csv:270")).toEqual({ file: "ledger.csv", line: 270, text: "2026-09-15,-17.507,OMR,cash,discretionary,,gift" });
    expect(citedLine(files, "holdings.csv:72").text).toBe("2026-09-30,broker,world equity ETF,equity,10,1430.00,USD");
    expect(citedLine(files, "decisions.yml:26").text).toBe("- id: D-2026-06-01");
    expect(citedLine(files, "rates.csv:999").text).toBeNull();
    expect(citedLine(files, "ledger.csv").line).toBeNull();
  });

  it("orders the ledger newest first and filters it", () => {
    const all = newestFirst(ledger);
    expect(all[0]?.line).toBe(269); // 2026-09-24, the latest date
    expect(all.at(-1)?.line).toBe(2);
    const sept = filterLedger(ledger, { ...NO_FILTER, month: "2026-09" });
    expect(sept.length).toBe(12);
    expect(filterLedger(ledger, { ...NO_FILTER, month: "2026-09", category: "discretionary" }).map((r) => r.line)).toEqual([270]);
    expect(filterLedger(ledger, { ...NO_FILTER, tag: "pilot", account: "broker" }).length).toBe(17);
    expect(filterLedger(ledger, { ...NO_FILTER, text: "NEW PHONE" }).map((r) => r.line)).toEqual([249]);
    const f = ledgerFacets(ledger);
    expect([f.months[0], f.months.at(-1), f.tags]).toEqual(["2026-09", "2024-10", ["pilot", "transfer"]]);
  });

  it("the reversal mirrors the row on its own date, tagged and citing it", () => {
    const phone = ledger.find((r) => r.line === 249) as LedgerRow;
    expect(reversalOf(phone)).toEqual({ date: "2026-07-20", amountText: "125.000", currency: "OMR", account: "cash", category: "discretionary", tagsText: "reversal", note: "reverses ledger.csv:249" });
    const dividend = ledger.find((r) => r.line === 271) as LedgerRow;
    expect(reversalOf(dividend)).toMatchObject({ amountText: "-3.50", currency: "USD", tagsText: "pilot;reversal" });
  });

  it("appends a row through the engine, refuses an invalid one, allows a duplicate", () => {
    const row = { date: "2026-09-28", amountText: "-200", currency: "OMR", account: "cash", category: "discretionary", tagsText: "", note: "new tablet" };
    const r = appendLedger(files["ledger.csv"], config, row);
    if (!r.ok) throw new Error("refused");
    expect(r.line).toBe(273);
    expect(r.text).toBe(files["ledger.csv"] + "2026-09-28,-200,OMR,cash,discretionary,,new tablet\n");
    const after = loadHousehold({ ...files, "ledger.csv": r.text });
    expect(check(after, "2026-09-30").policies[0]).toMatchObject({ id: "WLT-01", verdict: "breach" });
    const reversed = appendLedger(r.text, config, reversalOf(after.ctx!.ledger.find((x) => x.line === 273)!));
    if (!reversed.ok) throw new Error("refused");
    expect(check(loadHousehold({ ...files, "ledger.csv": reversed.text }), "2026-09-30").policies.find((p) => p.id === "WLT-01")?.verdict).toBe("hold");
    const bad = appendLedger(files["ledger.csv"], config, { ...row, amountText: "1,200", category: "coffee", note: "two\nlines" });
    expect(bad.ok).toBe(false);
    // a note across two lines breaks the record in two, as the CLI would read it
    if (!bad.ok) expect(bad.problems.map((p) => [p.line, p.code])).toEqual([
      [273, "BAD-CSV"],
      [274, "COLUMN-COUNT"],
    ]);
    const bad2 = appendLedger(files["ledger.csv"], config, { ...row, amountText: "1,200", category: "coffee" });
    if (!bad2.ok) expect(bad2.problems.map((p) => p.code)).toEqual(["BAD-AMOUNT", "UNKNOWN-CATEGORY"]);
    const dup = appendLedger(files["ledger.csv"], config, { date: "2026-09-15", amountText: "-17.507", currency: "OMR", account: "cash", category: "discretionary", tagsText: "", note: "gift" });
    expect(dup.ok && dup.warnings.map((p) => [p.code, p.dup_of])).toEqual([["DUP-ROW", 270]]);
    expect(appendLedger(null, config, row)).toMatchObject({ ok: true, line: 2 });
  });

  it("snapshots: newest first, prefilled from the latest, appended through the engine, aged against the limit", () => {
    const snaps = snapshotsNewestFirst(holdings);
    expect([snaps.length, snaps[0]?.date, snaps[0]?.rows.map((r) => r.line)]).toEqual([24, "2026-09-30", [71, 72, 73]]);
    const pre = prefillSnapshot(holdings);
    expect(pre.map((r) => [r.account, r.valueText, r.currency])).toEqual([
      ["savings", "10900.000", "OMR"],
      ["broker", "1430.00", "USD"],
      ["cash", "150.000", "OMR"],
    ]);
    const r = appendSnapshot(files["holdings.csv"], config, "2026-10-31", pre);
    expect(r.ok && [r.line, r.text.split("\n").at(-2)]).toEqual([74, "2026-10-31,cash,gold coin,gold,1,150.000,OMR"]);
    expect(appendSnapshot(files["holdings.csv"], config, "2026-10-31", [{ ...pre[0]!, cls: "crypto" }]).ok).toBe(false);
    expect(appendSnapshot(files["holdings.csv"], config, "2026-10-31", []).ok).toBe(false);
    expect(freshness(holdings, "2026-09-30", 45)).toEqual({ kind: "fresh", date: "2026-09-30", age: 0, max: 45 });
    expect(freshness(holdings, "2026-12-31", 45)).toEqual({ kind: "stale", date: "2026-09-30", age: 92, max: 45 });
    expect(freshness(holdings, "2026-11-14", 45).kind).toBe("fresh");
    expect(freshness(holdings, "2024-01-01", 45)).toEqual({ kind: "none" });
    expect(freshness(holdings, "2026-12-31", null)).toEqual({ kind: "unknown", date: "2026-09-30", age: 92 });
  });

  it("only invalid problems block a save", () => {
    const p = [
      { file: "ledger.csv", line: 3, code: "DUP-ROW", class: "warn" as const, reason: "x", dup_of: 2 },
      { file: "ledger.csv", line: 4, code: "BAD-DATE", class: "invalid" as const, reason: "y" },
    ];
    expect(blocking(p).map((x) => x.code)).toEqual(["BAD-DATE"]);
  });
});
