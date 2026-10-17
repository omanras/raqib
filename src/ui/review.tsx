// Review (app ADR section 3): a period (month, quarter or year, ISO;
// default the quarter of the as-of date) and the eight sections of the
// CLI's review page in its order, the charts being the engine's own inline
// SVG. "Copy as HTML" and "Download" give the very page the CLI writes.
import { useMemo, useState } from "preact/hooks";
import { daysUntilReview, isDue } from "../engine/decisions";
import { money } from "../engine/decimal";
import { periodOf, parsePeriod, type PeriodKind } from "../engine/periods";
import { limitDisplay, measureDisplay, orderDecisions } from "../engine/report";
import { allocationBands, allocationItems, amountCell, buildReview, columnHead, declaredText, renderReviewPage, reviewAsOf, svgHbars, svgIncomeExpense, type Review } from "../engine/review";
import { useT, type StringKey } from "../i18n";
import { copyText, downloadText } from "./clipboard";
import { fill, useAsOf, VerdictChip } from "./common";
import { useApp } from "./context";

const KINDS: readonly PeriodKind[] = ["month", "quarter", "year"];

/** The engine's SVG (escaped text, no script) placed as is. */
function Svg({ markup, testid }: { markup: string; testid: string }) {
  return <div class="chart" dir="ltr" data-testid={testid} dangerouslySetInnerHTML={{ __html: markup }} />;
}

function Sections({ r }: { r: Review }) {
  const t = useT();
  const cfg = r.household.config;
  const base = cfg?.baseCurrency ?? "";
  const files = Object.entries(r.household.files)
    .map(([name, count]) => `${name} (${count === null || count === undefined ? "absent" : `${count} rows`})`)
    .join(", ");
  return (
    <>
      <section id="period" aria-labelledby="rv-period">
        <h3 id="rv-period">{t("rev.s.period")}</h3>
        <dl class="facts">
          <dt>{t("rev.periodLabel")}</dt>
          <dd class="mono" dir="ltr">
            {r.period.text} ({fill(t("rev.from"), { start: r.period.start, end: r.period.end })})
          </dd>
          <dt>{t("rev.asOf")}</dt>
          <dd class="mono">{r.asOf}</dd>
          <dt>{t("rev.base")}</dt>
          <dd class="mono">{base}</dd>
          <dt>{t("rev.files")}</dt>
          <dd class="mono" dir="ltr">
            {files}
          </dd>
          <dt>{t("rev.policies")}</dt>
          <dd>{fill(t("rev.declaredCount"), { n: cfg?.policies.length ?? 0 })}</dd>
        </dl>
      </section>

      <section id="board" aria-labelledby="rv-board">
        <h3 id="rv-board">{t("rev.s.board")}</h3>
        <div class="table-wrap">
          <table class="rows" data-testid="review-board">
            <thead>
              <tr>
                <th scope="col">{t("rev.policy")}</th>
                <th scope="col">{t("rev.declared")}</th>
                {r.columns.map((c) => (
                  <th scope="col" key={c.month.text} class="mono">
                    {columnHead(c)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(cfg?.policies ?? []).map((p) => (
                <tr key={p.id}>
                  <th scope="row">
                    <span class="mono">{p.id}</span>
                    <br />
                    {p.title}
                  </th>
                  <td class="muted" dir="ltr">
                    {declaredText(p, base)}
                  </td>
                  {r.columns.map((c) => {
                    const v = c.verdicts.find((x) => x.policy.id === p.id);
                    return (
                      <td key={c.month.text} dir="ltr">
                        {v && (
                          <>
                            <VerdictChip verdict={v.verdict} />
                            <div class="muted">
                              {measureDisplay(v, base)} vs {limitDisplay(v, base)}
                            </div>
                            {v.reason && (
                              <div class="muted">
                                <em>{v.reason}</em>
                              </div>
                            )}
                          </>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section id="income-expense" aria-labelledby="rv-ie">
        <h3 id="rv-ie">{t("rev.s.incomeExpense")}</h3>
        <p class="muted">{fill(t("rev.ieNote"), { asOf: r.asOf, base, period: r.period.text })}</p>
        <Svg markup={svgIncomeExpense(r.months12, r.period, base)} testid="chart-income-expense" />
        <div class="table-wrap">
          <table class="rows">
            <thead>
              <tr>
                <th scope="col">{t("rev.month")}</th>
                <th scope="col" class="num">
                  {t("rev.income")}
                </th>
                <th scope="col" class="num">
                  {t("rev.expense")}
                </th>
              </tr>
            </thead>
            <tbody>
              {r.months12.map(([m, inc, exp]) => (
                <tr key={m.text}>
                  <td class="mono">{m.text}</td>
                  <td class="mono num" dir="ltr">
                    {amountCell(inc, base)}
                  </td>
                  <td class="mono num" dir="ltr">
                    {amountCell(exp, base)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section id="spending" aria-labelledby="rv-sp">
        <h3 id="rv-sp">{t("rev.s.spending")}</h3>
        <p class="muted">{fill(t("rev.spNote"), { period: r.period.text, base })}</p>
        <Svg markup={svgHbars(r.spending.map(([c, v]) => [c, v, ""]), base, "t-sp", `Spending by category, ${r.period.text}`)} testid="chart-spending" />
      </section>

      <section id="allocation" aria-labelledby="rv-al">
        <h3 id="rv-al">{t("rev.s.allocation")}</h3>
        <p class="muted">{fill(t("rev.alNote"), { asOf: r.asOf })}</p>
        <Svg markup={svgHbars(allocationItems(r, base), base, "t-al", `Allocation by class as of ${r.asOf}`, allocationBands(r), "pct")} testid="chart-allocation" />
      </section>

      <section id="findings" aria-labelledby="rv-f">
        <h3 id="rv-f">{t("rev.s.findings")}</h3>
        {r.findings.length === 0 ? (
          <p>{t("rev.noFinding")}</p>
        ) : (
          <div class="table-wrap">
            <table class="rows" data-testid="review-findings">
              <thead>
                <tr>
                  <th scope="col">{t("rev.class")}</th>
                  <th scope="col">{t("rev.finding")}</th>
                  <th scope="col">{t("rev.policy")}</th>
                  <th scope="col">{t("rev.when")}</th>
                  <th scope="col">{t("rev.reason")}</th>
                  <th scope="col">{t("rev.cites")}</th>
                </tr>
              </thead>
              <tbody>
                {r.findings.map((f, i) => (
                  <tr key={i} data-code={f.code}>
                    <td>
                      <span class={`chip ${f.cls === "red" ? "chip-red" : "chip-warn"}`}>{f.cls}</span>
                    </td>
                    <td class="mono">{f.code}</td>
                    <td class="mono">{f.policy ?? ""}</td>
                    <td class="mono">{f.period || f.date || ""}</td>
                    <td dir="ltr">{f.reason}</td>
                    <td class="mono" dir="ltr">
                      {f.cites.join(" ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section id="decisions" aria-labelledby="rv-d">
        <h3 id="rv-d">{t("rev.s.decisions")}</h3>
        {r.household.decisions.length === 0 ? (
          <p>{t("rev.noDecision")}</p>
        ) : (
          <div class="table-wrap">
            <table class="rows" data-testid="review-decisions">
              <thead>
                <tr>
                  <th scope="col">{t("rev.status")}</th>
                  <th scope="col">{t("rev.id")}</th>
                  <th scope="col">{t("rev.title")}</th>
                  <th scope="col">{t("rev.policy")}</th>
                  <th scope="col">{t("rev.reviewBy")}</th>
                  <th scope="col" class="num">
                    {t("rev.days")}
                  </th>
                  <th scope="col">{t("rev.cite")}</th>
                </tr>
              </thead>
              <tbody>
                {orderDecisions(r.household.decisions, r.asOf).map((d) => {
                  const status = d.status === "open" ? (isDue(d, r.asOf) ? "due" : "open") : "closed";
                  return (
                    <tr key={d.id} data-status={status} data-id={d.id}>
                      <td>
                        <span class={`chip ${status === "due" ? "chip-red" : "chip-neutral"}`}>{t(`dec.status.${status}` as StringKey)}</span>
                      </td>
                      <td class="mono">{d.id}</td>
                      <td>{d.title}</td>
                      <td class="mono">{(d.closes && "closes " + d.closes) || d.policy || ""}</td>
                      <td class="mono">{d.reviewBy}</td>
                      <td class="mono num" dir="ltr">
                        {d.status === "open" ? daysUntilReview(d, r.asOf) : ""}
                      </td>
                      <td class="mono">{d.cite}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section id="details" aria-labelledby="rv-x">
        <h3 id="rv-x">{t("rev.s.details")}</h3>
        <details>
          <summary>{fill(t("rev.ledgerRows"), { n: r.rows.ledger.length })}</summary>
          <div class="table-wrap">
            <table class="rows">
              <thead>
                <tr>
                  {(["rev.cite", "rev.date", "rev.amount", "rev.currency", "rev.account", "rev.category", "rev.tags", "rev.note"] as const).map((k) => (
                    <th scope="col" key={k}>
                      {t(k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {r.rows.ledger.map((x) => (
                  <tr key={x.cite}>
                    <td class="mono">{x.cite}</td>
                    <td class="mono">{x.date}</td>
                    <td class="mono num" dir="ltr">
                      {money(x.amount)}
                    </td>
                    <td class="mono">{x.currency}</td>
                    <td>{x.account}</td>
                    <td>{x.category}</td>
                    <td class="mono">{x.tags.join(";")}</td>
                    <td>{x.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
        <details>
          <summary>{fill(t("rev.holdingsRows"), { n: r.rows.holdings.length })}</summary>
          <div class="table-wrap">
            <table class="rows">
              <thead>
                <tr>
                  {(["rev.cite", "rev.date", "rev.account", "rev.asset", "rev.class", "rev.quantity", "rev.value", "rev.currency"] as const).map((k) => (
                    <th scope="col" key={k}>
                      {t(k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {r.rows.holdings.map((x) => (
                  <tr key={x.cite}>
                    <td class="mono">{x.cite}</td>
                    <td class="mono">{x.date}</td>
                    <td>{x.account}</td>
                    <td>{x.asset}</td>
                    <td>{x.cls}</td>
                    <td class="mono num" dir="ltr">
                      {money(x.quantity)}
                    </td>
                    <td class="mono num" dir="ltr">
                      {money(x.value)}
                    </td>
                    <td class="mono">{x.currency}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
        <details>
          <summary>{fill(t("rev.rateRows"), { n: r.rows.rates.length })}</summary>
          <div class="table-wrap">
            <table class="rows">
              <thead>
                <tr>
                  {(["rev.cite", "rev.date", "rev.currency", "rev.rate"] as const).map((k) => (
                    <th scope="col" key={k}>
                      {t(k)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {r.rows.rates.map((x) => (
                  <tr key={x.cite}>
                    <td class="mono">{x.cite}</td>
                    <td class="mono">{x.date}</td>
                    <td class="mono">{x.currency}</td>
                    <td class="mono num" dir="ltr">
                      {money(x.rate)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      </section>
    </>
  );
}

export function ReviewScreen() {
  const t = useT();
  const { household } = useApp();
  const asOf = useAsOf();
  const [text, setText] = useState(() => periodOf(asOf, "quarter"));
  const [copied, setCopied] = useState<boolean | null>(null);
  const period = parsePeriod(text);
  const fatal = household.fatal.length > 0;
  const review = useMemo(() => (period && !fatal ? buildReview(household, period, reviewAsOf(period, asOf)) : null), [household, text, asOf, fatal]);
  const kind = period?.kind ?? "quarter";
  const page = () => (review ? renderReviewPage(review) : "");
  return (
    <section aria-labelledby="review-title" class="review">
      <h2 id="review-title" tabIndex={-1} data-screen-title>
        {t("nav.review")}
      </h2>
      <div class="actions">
        <label>
          {t("rev.kind")}{" "}
          <select value={kind} onChange={(e) => setText(periodOf(period?.end ?? asOf, (e.currentTarget as HTMLSelectElement).value as PeriodKind))} data-testid="review-kind">
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`rev.kind.${k}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("rev.periodText")}{" "}
          <input type="text" dir="ltr" size={9} value={text} onInput={(e) => setText((e.currentTarget as HTMLInputElement).value.trim())} aria-invalid={period === null} data-testid="review-period" />
        </label>
      </div>
      {period === null && (
        <p class="msg-red" role="alert" data-testid="review-bad-period">
          {t("rev.badPeriod")}
        </p>
      )}
      {fatal && <p class="msg-red">{t("dash.fatal")}</p>}
      {review && (
        <>
          <div class="actions">
            <button type="button" class="primary" onClick={async () => setCopied(await copyText(page()))} data-testid="review-copy">
              {t("rev.copy")}
            </button>
            <button type="button" onClick={() => downloadText(`qayd-review-${review.period.text}.html`, page(), "text/html")} data-testid="review-download">
              {t("rev.download")}
            </button>
            <span class="muted">{t("rev.copyNote")}</span>
            {copied === true && (
              <span role="status" data-testid="review-copied">
                {t("rev.copied")}
              </span>
            )}
          </div>
          {copied === false && (
            <label>
              {t("files.copyManual")}
              <textarea readOnly rows={6} value={page()} dir="ltr" onFocus={(e) => (e.currentTarget as HTMLTextAreaElement).select()} />
            </label>
          )}
          <Sections r={review} />
        </>
      )}
    </section>
  );
}
