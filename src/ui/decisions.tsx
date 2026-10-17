// Decisions (app ADR section 3): due first, then open, then closed (the
// CLI's order), days to review with overdue in red (A3), closed ones with
// the policy they close; "New decision" (id D-<date>-<n>) and "Close",
// both checked by the engine before decisions.yml is written; raw panel.
import { useState } from "preact/hooks";
import { appendDecision, daysUntilReview, isDue, parseDecisions, type DecisionFields } from "../engine/decisions";
import { orderDecisions } from "../engine/report";
import type { Config, Decision, Problem } from "../engine/types";
import { useT, type T } from "../i18n";
import { fill, IsoDateInput, ProblemList, RawPanel, useAsOf } from "./common";
import { useApp } from "./context";
import { closeDecision, nextDecisionId } from "./textEdit";

type Outcome = { ok: true; text: string } | { ok: false; text: string; problems: Problem[] } | null;

function daysText(days: number, t: T): string {
  const key = days < 0 ? (days === -1 ? "dec.overdue.one" : "dec.overdue.many") : days === 1 ? "dec.daysLeft.one" : "dec.daysLeft.many";
  return fill(t(key), { n: Math.abs(days) });
}

function problemsAfter(before: string | null, after: string, config: Config | null): Problem[] {
  const key = (p: Problem) => `${p.code}|${p.field ?? ""}|${p.reason}`;
  const old = new Set(parseDecisions(before, config).problems.map(key));
  return parseDecisions(after, config).problems.filter((p) => !old.has(key(p)));
}

function DecisionItem({ d, asOf, onClose }: { d: Decision; asOf: string; onClose: (d: Decision) => void }) {
  const t = useT();
  const due = isDue(d, asOf);
  const status = d.status === "closed" ? "closed" : due ? "due" : "open";
  const days = d.status === "open" ? daysUntilReview(d, asOf) : null;
  return (
    <li class="decision" data-testid={`decision-${d.id}`} data-status={status}>
      <div class="policy-line">
        <span class={`chip ${status === "due" ? "chip-red" : "chip-neutral"}`}>{t(`dec.status.${status}`)}</span>
        <span class="mono pid">{d.id}</span>
        <span class="ptitle">{d.title}</span>
        {d.status === "open" ? (
          <span class={days !== null && days < 0 ? "overdue" : "muted"} dir="ltr">
            {t("dec.reviewBy")} <span class="mono">{d.reviewBy}</span> ({daysText(days as number, t)})
          </span>
        ) : (
          <span class="muted">
            {t("dec.decided")} <span class="mono">{d.date}</span>
            {d.closes ? ` · ${t("dec.closes")} ${d.closes}` : d.policy ? ` · ${t("dec.policy")} ${d.policy}` : ""}
          </span>
        )}
        {d.status === "open" && d.policy && (
          <span class="muted">
            {t("dec.policy")} <span class="mono">{d.policy}</span>
          </span>
        )}
      </div>
      {d.criteria && (
        <p class="muted criteria">
          {t("dec.criteria")}: {d.criteria}
        </p>
      )}
      <div class="actions">
        <span class="mono muted">{d.cite}</span>
        {d.status === "open" && (
          <button type="button" onClick={() => onClose(d)} aria-label={`${t("dec.closeOf")} ${d.id}`} data-testid={`close-${d.id}`}>
            {t("dec.close")}
          </button>
        )}
      </div>
    </li>
  );
}

function NewDecision({ onSave }: { onSave: (fields: DecisionFields) => void }) {
  const t = useT();
  const { snap, household } = useApp();
  const asOf = useAsOf();
  const policies = household.config?.policies ?? [];
  const kills = policies.filter((p) => p.type === "kill");
  const [date, setDate] = useState(asOf);
  const [title, setTitle] = useState("");
  const [policy, setPolicy] = useState("");
  const [criteria, setCriteria] = useState("");
  const [reviewBy, setReviewBy] = useState("");
  const [closes, setCloses] = useState("");
  const id = nextDecisionId(snap.files["decisions.yml"], date);
  return (
    <form
      class="card"
      aria-labelledby="new-dec-title"
      onSubmit={(e) => {
        e.preventDefault();
        onSave({ id, date, title, policy: policy || null, criteria, reviewBy, status: "open", closes: closes || null });
      }}
      data-testid="new-decision"
    >
      <h3 id="new-dec-title">{t("dec.newTitle")}</h3>
      <div class="grid">
        <label>
          {t("dec.dateLabel")} <IsoDateInput value={date} onDate={setDate} testid="dec-date" />
        </label>
        <label>
          {t("dec.idLabel")}{" "}
          <output class="mono" data-testid="dec-id">
            {id}
          </output>
        </label>
        <label class="wide">
          {t("dec.titleLabel")} <input type="text" value={title} onInput={(e) => setTitle((e.currentTarget as HTMLInputElement).value)} required data-testid="dec-title" />
        </label>
        <label>
          {t("dec.policyLabel")}{" "}
          <select value={policy} onChange={(e) => setPolicy((e.currentTarget as HTMLSelectElement).value)} data-testid="dec-policy">
            <option value="">{t("dec.noPolicy")}</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("dec.reviewByLabel")} <IsoDateInput value={reviewBy} onDate={setReviewBy} testid="dec-review-by" />
        </label>
        <label>
          {t("dec.closesLabel")}{" "}
          <select value={closes} onChange={(e) => setCloses((e.currentTarget as HTMLSelectElement).value)} data-testid="dec-closes">
            <option value="">{t("dec.noPolicy")}</option>
            {kills.map((p) => (
              <option key={p.id} value={p.id}>
                {p.id}
              </option>
            ))}
          </select>
        </label>
        <label class="wide">
          {t("dec.criteriaLabel")} <input type="text" value={criteria} onInput={(e) => setCriteria((e.currentTarget as HTMLInputElement).value)} data-testid="dec-criteria" />
        </label>
      </div>
      <div class="actions">
        <button type="submit" class="primary" data-testid="dec-submit">
          {t("dec.add")}
        </button>
      </div>
    </form>
  );
}

export function Decisions() {
  const t = useT();
  const { store, snap, household } = useApp();
  const asOf = useAsOf();
  const config = household.config;
  const text = snap.files["decisions.yml"];
  const [adding, setAdding] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>(null);
  const problems = household.problemsByFile["decisions.yml"] ?? [];

  const write = async (next: string, okText: string, failText: string) => {
    const fresh = problemsAfter(text, next, config);
    if (fresh.length > 0) {
      setOutcome({ ok: false, text: failText, problems: fresh });
      return false;
    }
    await store.setFiles({ "decisions.yml": next });
    setOutcome({ ok: true, text: okText });
    return true;
  };

  const onSave = async (f: DecisionFields) => {
    const next = appendDecision(text, f);
    const line = (text === null || text.trim() === "" || text.trim() === "[]" ? "" : text.endsWith("\n") ? text : text + "\n").split("\n").length;
    if (await write(next, fill(t("dec.added"), { id: f.id, line }), t("dec.refused"))) setAdding(false);
  };

  const onClose = async (d: Decision) => {
    const e = closeDecision(text ?? "", d.line);
    if (!e.ok) {
      setOutcome({ ok: false, text: fill(t("dec.cantClose"), { id: d.id }), problems: [] });
      return;
    }
    await write(e.text, fill(t("dec.closedAt"), { id: d.id }), t("dec.refused"));
  };

  const list = orderDecisions(household.decisions, asOf);
  return (
    <section aria-labelledby="dec-title">
      <h2 id="dec-title" tabIndex={-1} data-screen-title>
        {t("nav.decisions")}
      </h2>
      {problems.length > 0 && <ProblemList problems={problems} testid="decisions-problems" />}
      <div class="actions">
        <button type="button" class="primary" onClick={() => setAdding(!adding)} aria-expanded={adding} data-testid="dec-new">
          {t("dec.new")}
        </button>
      </div>
      {adding && <NewDecision onSave={(f) => void onSave(f)} />}
      {outcome && outcome.ok && (
        <p class="msg-ok" role="status" data-testid="dec-outcome">
          {outcome.text}
        </p>
      )}
      {outcome && !outcome.ok && (
        <div class="msg-red" role="alert" data-testid="dec-outcome">
          {outcome.text}
          {outcome.problems.length > 0 && <ProblemList problems={outcome.problems} />}
        </div>
      )}
      <h3>{t("dec.list")}</h3>
      {list.length === 0 ? (
        <p class="muted">{t("dec.none")}</p>
      ) : (
        <ul class="board" data-testid="decision-list">
          {list.map((d) => (
            <DecisionItem key={d.id} d={d} asOf={asOf} onClose={(x) => void onClose(x)} />
          ))}
        </ul>
      )}
      <RawPanel file="decisions.yml" check={(x) => parseDecisions(x, config).problems} />
    </section>
  );
}
