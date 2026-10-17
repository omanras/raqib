// Dashboard (app ADR section 3): the check as of a date. One row per
// policy in the CLI's order (reds first), its verdict, title, "measure vs
// limit" exactly as the CLI prints it, and its scope; a "why" expander with
// the reason and every cited row (file:line and the line itself); the
// findings; and the CLI's summary line, verbatim.
import { useMemo } from "preact/hooks";
import { buildCheck, fatalText } from "../engine/commands";
import { limitDisplay, measureDisplay, scopeDisplay, summaryLine } from "../engine/report";
import { order, verdictCites, type Verdict } from "../engine/rules";
import { useT } from "../i18n";
import { AsOfInput, problemText, useAsOf, VerdictChip } from "./common";
import { useApp } from "./context";
import { citedLine } from "./model";

function CitedRows({ cites }: { cites: string[] }) {
  const t = useT();
  const { snap } = useApp();
  if (cites.length === 0) return <p class="muted">{t("dash.noCites")}</p>;
  return (
    <table class="cited">
      <caption class="visually-hidden">{t("dash.cited")}</caption>
      <tbody>
        {cites.map((c) => {
          const l = citedLine(snap.files, c);
          return (
            <tr key={c}>
              <th scope="row" class="mono">
                {c}
              </th>
              <td class="mono" dir="ltr">
                {l.text ?? t("dash.unreadable")}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function PolicyRow({ v, base, asOf }: { v: Verdict; base: string; asOf: string }) {
  const t = useT();
  // as in the CLI's text: a verdict without cited rows shows its findings' cites
  const own = verdictCites(v);
  const cites = own.length > 0 ? own : v.findings.flatMap((f) => f.cites);
  return (
    <li class="policy" data-testid={`policy-${v.policy.id}`} data-verdict={v.verdict}>
      <div class="policy-line">
        <VerdictChip verdict={v.verdict} />
        <span class="mono pid">{v.policy.id}</span>
        <span class="ptitle">{v.policy.title}</span>
        <span class="mvl mono" dir="ltr" data-testid={`mvl-${v.policy.id}`}>
          {measureDisplay(v, base)} vs {limitDisplay(v, base)}
        </span>
        <span class="scope mono" dir="ltr">
          {scopeDisplay(v, asOf)}
        </span>
      </div>
      <details class="why">
        <summary>{t("dash.why")}</summary>
        {v.reason && (
          <p>
            <strong>{t("dash.reason")}:</strong> <span dir="ltr">{v.reason}</span>
          </p>
        )}
        <CitedRows cites={cites} />
      </details>
    </li>
  );
}

export function Dashboard() {
  const t = useT();
  const { household } = useApp();
  const asOf = useAsOf();
  const report = useMemo(() => buildCheck(household, asOf), [household, asOf]);
  const base = report.baseCurrency ?? "";
  const fatal = household.fatal.length > 0;
  return (
    <section aria-labelledby="dash-title">
      <h2 id="dash-title" tabIndex={-1} data-screen-title>
        {t("nav.dashboard")}
      </h2>
      <AsOfInput />
      <p class={`summary mono ${report.green ? "green" : "red"}`} dir="ltr" role="status" data-testid="summary">
        {fatal ? fatalText(household).split("\n")[0] : summaryLine(report)}
      </p>
      {fatal && <p>{t("dash.fatal")}</p>}
      {!fatal && (
        <>
          <h3>{t("dash.board")}</h3>
          <ol class="board" data-testid="board">
            {order(report.verdicts).map((v) => (
              <PolicyRow key={v.policy.id} v={v} base={base} asOf={asOf} />
            ))}
          </ol>
        </>
      )}
      <h3>{t("dash.findings")}</h3>
      {report.findings.length === 0 ? (
        <p class="muted">{t("dash.noFindings")}</p>
      ) : (
        <ul class="findings" data-testid="findings">
          {report.findings.map((f, i) => (
            <li key={i} class={f.cls} data-code={f.code}>
              <span class={`chip ${f.cls === "red" ? "chip-red" : "chip-warn"}`}>{f.cls}</span>{" "}
              <span dir="ltr">
                <span class="mono">{f.code}</span> <span class="mono">{f.cites.join(" ")}</span> {f.reason}
              </span>
            </li>
          ))}
        </ul>
      )}
      {fatal && (
        <ul class="problems">
          {household.fatal.map((p, i) => (
            <li key={i} class="mono red">
              {problemText(p)}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
