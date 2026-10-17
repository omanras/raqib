// Holdings (app ADR section 3): snapshots newest first, the current
// snapshot's age against snapshot_max_age_days (stale is red, A3), "New
// snapshot" pre-filled from the latest one and appended through the
// engine's writer after the engine has judged its lines, and the raw panel.
import { useMemo, useState } from "preact/hooks";
import { parseHoldings } from "../engine/holdings";
import type { Problem } from "../engine/types";
import { useT } from "../i18n";
import { fill, IsoDateInput, ProblemList, RawPanel, useAsOf } from "./common";
import { useApp } from "./context";
import { appendSnapshot, freshness, prefillSnapshot, snapshotsNewestFirst, type HoldingInput } from "./model";

function Freshness() {
  const t = useT();
  const { household } = useApp();
  const asOf = useAsOf();
  const f = freshness(household.ctx?.holdings ?? [], asOf, household.config?.snapshotMaxAgeDays ?? null);
  if (f.kind === "none") return <p class="msg-red" data-testid="freshness" data-state="none">{t("hold.none")}</p>;
  if (f.kind === "unknown") {
    return (
      <p class="msg-red" data-testid="freshness" data-state="unknown">
        {fill(t("hold.noAge"), { date: f.date, age: f.age })}
      </p>
    );
  }
  return (
    <p class={f.kind === "stale" ? "msg-red" : "msg-ok"} data-testid="freshness" data-state={f.kind}>
      {fill(t(f.kind === "stale" ? "hold.stale" : "hold.fresh"), { date: f.date, age: f.age, max: f.max })}
    </p>
  );
}

function NewSnapshot({ onDone }: { onDone: (line: number) => void }) {
  const t = useT();
  const { store, snap, household } = useApp();
  const asOf = useAsOf();
  const [date, setDate] = useState(asOf);
  const [rows, setRows] = useState<HoldingInput[]>(() => prefillSnapshot(household.ctx?.holdings ?? []));
  const [problems, setProblems] = useState<Problem[]>([]);
  const edit = (i: number, key: keyof HoldingInput, v: string) => setRows(rows.map((r, j) => (j === i ? { ...r, [key]: v } : r)));
  const cols: [keyof HoldingInput, string][] = [
    ["account", t("hold.account")],
    ["asset", t("hold.asset")],
    ["cls", t("hold.class")],
    ["quantityText", t("hold.quantity")],
    ["valueText", t("hold.value")],
    ["currency", t("hold.currency")],
  ];
  return (
    <form
      class="card"
      aria-labelledby="new-snap-title"
      onSubmit={async (e) => {
        e.preventDefault();
        const r = appendSnapshot(snap.files["holdings.csv"], household.config, date, rows);
        if (!r.ok) {
          setProblems(r.problems);
          return;
        }
        setProblems([]);
        await store.setFiles({ "holdings.csv": r.text });
        onDone(r.line);
      }}
      data-testid="new-snapshot"
    >
      <h3 id="new-snap-title">{t("hold.newTitle")}</h3>
      <label>
        {t("hold.date")} <IsoDateInput value={date} onDate={setDate} testid="snap-date" />
      </label>
      <div class="table-wrap">
        <table class="rows">
          <thead>
            <tr>
              {cols.map(([k, label]) => (
                <th key={k} scope="col">
                  {label}
                </th>
              ))}
              <th scope="col">
                <span class="visually-hidden">{t("hold.removeRow")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                {cols.map(([k, label]) => (
                  <td key={k}>
                    <input type="text" dir="ltr" aria-label={`${label} ${i + 1}`} value={r[k]} onInput={(e) => edit(i, k, (e.currentTarget as HTMLInputElement).value)} size={k === "asset" ? 18 : 9} data-testid={`snap-${k}-${i}`} />
                  </td>
                ))}
                <td>
                  <button type="button" onClick={() => setRows(rows.filter((_, j) => j !== i))}>
                    {t("hold.removeRow")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div class="actions">
        <button type="button" onClick={() => setRows([...rows, { account: "", asset: "", cls: "", quantityText: "", valueText: "", currency: household.config?.baseCurrency ?? "" }])}>
          {t("hold.addRow")}
        </button>
        <button type="submit" class="primary" data-testid="snap-submit">
          {t("hold.saveSnapshot")}
        </button>
      </div>
      {problems.length > 0 && (
        <div class="msg-red" role="alert">
          {t("ledger.refused")}
          <ProblemList problems={problems} />
        </div>
      )}
    </form>
  );
}

export function Holdings() {
  const t = useT();
  const { household } = useApp();
  const rows = household.ctx?.holdings ?? [];
  const snapshots = useMemo(() => snapshotsNewestFirst(rows), [rows]);
  const [adding, setAdding] = useState(false);
  const [appended, setAppended] = useState<number | null>(null);
  const problems = household.problemsByFile["holdings.csv"] ?? [];
  return (
    <section aria-labelledby="holdings-title">
      <h2 id="holdings-title" tabIndex={-1} data-screen-title>
        {t("nav.holdings")}
      </h2>
      <Freshness />
      {problems.length > 0 && <ProblemList problems={problems} testid="holdings-problems" />}
      <div class="actions">
        <button type="button" class="primary" onClick={() => setAdding(!adding)} aria-expanded={adding} data-testid="snap-new">
          {t("hold.new")}
        </button>
        {appended !== null && (
          <span role="status" class="msg-ok">
            {t("hold.appended")} {appended}
          </span>
        )}
      </div>
      {adding && (
        <NewSnapshot
          onDone={(line) => {
            setAdding(false);
            setAppended(line);
          }}
        />
      )}
      <h3>{t("hold.snapshots")}</h3>
      {snapshots.length === 0 && <p class="muted">{t("hold.empty")}</p>}
      {snapshots.map((s) => (
        <details key={s.date} class="card snapshot" open={s === snapshots[0]} data-testid={`snapshot-${s.date}`}>
          <summary class="mono">{s.date}</summary>
          <div class="table-wrap">
            <table class="rows">
              <thead>
                <tr>
                  <th scope="col">{t("ledger.line")}</th>
                  <th scope="col">{t("hold.account")}</th>
                  <th scope="col">{t("hold.asset")}</th>
                  <th scope="col">{t("hold.class")}</th>
                  <th scope="col" class="num">
                    {t("hold.quantity")}
                  </th>
                  <th scope="col" class="num">
                    {t("hold.value")}
                  </th>
                  <th scope="col">{t("hold.currency")}</th>
                </tr>
              </thead>
              <tbody>
                {s.rows.map((r) => (
                  <tr key={r.line}>
                    <td class="mono">{r.line}</td>
                    <td>{r.account}</td>
                    <td>{r.asset}</td>
                    <td>{r.cls}</td>
                    <td class="mono num" dir="ltr">
                      {r.quantityText}
                    </td>
                    <td class="mono num" dir="ltr">
                      {r.valueText}
                    </td>
                    <td class="mono">{r.currency}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      ))}
      <RawPanel file="holdings.csv" check={(x) => parseHoldings(x, household.config).problems} />
    </section>
  );
}
