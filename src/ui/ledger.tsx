// Ledger (app ADR section 3): the rows newest first, filters, "Add row"
// validated by the engine before it is appended, "Reverse" that appends the
// mirror row (A6: rows are never edited in place), and the raw CSV panel.
import { useMemo, useState } from "preact/hooks";
import { parseLedger } from "../engine/ledger";
import type { Config, LedgerRow, Problem } from "../engine/types";
import { useT } from "../i18n";
import { IsoDateInput, ProblemList, RawPanel, useAsOf } from "./common";
import { useApp } from "./context";
import { appendLedger, filterLedger, ledgerFacets, newestFirst, NO_FILTER, reversalOf, type LedgerFilter, type LedgerInput } from "./model";

type Outcome = { ok: true; line: number; duplicate: boolean; reversal: boolean } | { ok: false; problems: Problem[] } | null;

function allCategories(config: Config | null): string[] {
  return config ? Object.values(config.categories).flat() : [];
}

function Filters({ f, set, rows }: { f: LedgerFilter; set: (f: LedgerFilter) => void; rows: readonly LedgerRow[] }) {
  const t = useT();
  const facets = useMemo(() => ledgerFacets(rows), [rows]);
  const select = (key: "month" | "account" | "category" | "tag", label: string, values: string[]) => (
    <label>
      {label}{" "}
      <select value={f[key]} onChange={(e) => set({ ...f, [key]: (e.currentTarget as HTMLSelectElement).value })} data-testid={`filter-${key}`}>
        <option value="">{t("ledger.any")}</option>
        {values.map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </select>
    </label>
  );
  return (
    <fieldset class="filters">
      <legend>{t("ledger.filters")}</legend>
      {select("month", t("ledger.month"), facets.months)}
      {select("account", t("ledger.account"), facets.accounts)}
      {select("category", t("ledger.category"), facets.categories)}
      {select("tag", t("ledger.tag"), facets.tags)}
      <label>
        {t("ledger.text")}{" "}
        <input type="text" value={f.text} onInput={(e) => set({ ...f, text: (e.currentTarget as HTMLInputElement).value })} data-testid="filter-text" />
      </label>
    </fieldset>
  );
}

function AddRow({ onAppend }: { onAppend: (input: LedgerInput) => void }) {
  const t = useT();
  const { household } = useApp();
  const config = household.config;
  const asOf = useAsOf();
  const blank = (): LedgerInput => ({
    date: asOf,
    amountText: "",
    currency: config?.baseCurrency ?? "",
    account: config?.accounts[0] ?? "",
    category: allCategories(config)[0] ?? "",
    tagsText: "",
    note: "",
  });
  const [input, setInput] = useState<LedgerInput>(blank);
  const field = (key: keyof LedgerInput) => (e: Event) => setInput({ ...input, [key]: (e.currentTarget as HTMLInputElement).value });
  return (
    <form
      class="card add-row"
      aria-labelledby="add-row-title"
      onSubmit={(e) => {
        e.preventDefault();
        onAppend(input);
      }}
    >
      <h3 id="add-row-title">{t("ledger.addTitle")}</h3>
      <div class="grid">
        <label>
          {t("ledger.date")} <IsoDateInput value={input.date} onDate={(date) => setInput({ ...input, date })} testid="add-date" />
        </label>
        <label>
          {t("ledger.amount")} <input type="text" inputMode="decimal" dir="ltr" value={input.amountText} onInput={field("amountText")} placeholder="-12.500" required data-testid="add-amount" />
        </label>
        <label>
          {t("ledger.currency")} <input type="text" dir="ltr" value={input.currency} onInput={field("currency")} maxLength={3} size={4} data-testid="add-currency" />
        </label>
        <label>
          {t("ledger.account")}{" "}
          <select value={input.account} onChange={field("account")} data-testid="add-account">
            {(config?.accounts ?? []).map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("ledger.category")}{" "}
          <select value={input.category} onChange={field("category")} data-testid="add-category">
            {allCategories(config).map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("ledger.tags")} <input type="text" dir="ltr" value={input.tagsText} onInput={field("tagsText")} placeholder={t("ledger.tagsHint")} data-testid="add-tags" />
        </label>
        <label class="wide">
          {t("ledger.note")} <input type="text" value={input.note} onInput={field("note")} data-testid="add-note" />
        </label>
      </div>
      <div class="actions">
        <button type="submit" class="primary" data-testid="add-submit">
          {t("ledger.add")}
        </button>
      </div>
    </form>
  );
}

export function Ledger() {
  const t = useT();
  const { store, snap, household } = useApp();
  const config = household.config;
  const text = snap.files["ledger.csv"];
  const rows = household.ctx?.ledger ?? [];
  const [filter, setFilter] = useState<LedgerFilter>(NO_FILTER);
  const [outcome, setOutcome] = useState<Outcome>(null);
  const shown = useMemo(() => newestFirst(filterLedger(rows, filter)), [rows, filter]);
  const problems = household.problemsByFile["ledger.csv"] ?? [];

  const append = async (input: LedgerInput, reversal: boolean) => {
    const r = appendLedger(text, config, input);
    if (!r.ok) {
      setOutcome({ ok: false, problems: r.problems });
      return;
    }
    await store.setFiles({ "ledger.csv": r.text });
    setOutcome({ ok: true, line: r.line, duplicate: r.warnings.some((p) => p.code === "DUP-ROW"), reversal });
  };

  return (
    <section aria-labelledby="ledger-title">
      <h2 id="ledger-title" tabIndex={-1} data-screen-title>
        {t("nav.ledger")}
      </h2>
      {config === null && <p class="msg-red">{t("ledger.needPolicies")}</p>}
      {problems.length > 0 && <ProblemList problems={problems} testid="ledger-problems" />}
      <AddRow onAppend={(input) => void append(input, false)} />
      {outcome && outcome.ok && (
        <p class="msg-ok" role="status" data-testid="ledger-outcome">
          {outcome.reversal ? t("ledger.reversed") : t("ledger.added")} {outcome.line}
          {outcome.duplicate && ` · ${t("ledger.duplicate")}`}
        </p>
      )}
      {outcome && !outcome.ok && (
        <div class="msg-red" role="alert" data-testid="ledger-outcome">
          {t("ledger.refused")}
          <ProblemList problems={outcome.problems} />
        </div>
      )}
      <Filters f={filter} set={setFilter} rows={rows} />
      <p class="muted">
        {shown.length} / {rows.length} {t("ledger.shown")}
      </p>
      <div class="table-wrap">
        <table class="rows" data-testid="ledger-table">
          <caption class="visually-hidden">{t("ledger.rows")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("ledger.line")}</th>
              <th scope="col">{t("ledger.date")}</th>
              <th scope="col" class="num">
                {t("ledger.amount")}
              </th>
              <th scope="col">{t("ledger.currency")}</th>
              <th scope="col">{t("ledger.account")}</th>
              <th scope="col">{t("ledger.category")}</th>
              <th scope="col">{t("ledger.tags")}</th>
              <th scope="col">{t("ledger.note")}</th>
              <th scope="col">
                <span class="visually-hidden">{t("ledger.reverse")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 && (
              <tr>
                <td colSpan={9} class="muted">
                  {t("ledger.empty")}
                </td>
              </tr>
            )}
            {shown.map((r) => (
              <tr key={r.line} data-line={r.line}>
                <td class="mono">{r.line}</td>
                <td class="mono">{r.date}</td>
                <td class="mono num" dir="ltr">
                  {r.amountText}
                </td>
                <td class="mono">{r.currency}</td>
                <td>{r.account}</td>
                <td>{r.category}</td>
                <td class="mono">{r.tags.join(";")}</td>
                <td>{r.note}</td>
                <td>
                  <button type="button" aria-label={`${t("ledger.reverseOf")} ${r.line}`} onClick={() => void append(reversalOf(r), true)} data-testid={`reverse-${r.line}`}>
                    {t("ledger.reverse")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <RawPanel file="ledger.csv" check={(x) => parseLedger(x, config).problems} />
    </section>
  );
}
