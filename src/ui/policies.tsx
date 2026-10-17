// Policies (app ADR section 3): the declarations grouped by type, each with
// its declared texts and today's verdict; a form per type covering every
// measure, limit, match and band field of the engine (A2: the app edits
// what the owner declares, it never proposes a policy); edit, add, remove
// (after a confirmation that shows what leaves the dashboard); raw panel.
import { useMemo, useState } from "preact/hooks";
import { buildCheck } from "../engine/commands";
import { PERIOD_KINDS } from "../engine/periods";
import { bandText, limitText, matchText, measureText, parsePolicies } from "../engine/policies";
import { verdictLine } from "../engine/report";
import { POLICY_TYPES, type Config, type Policy, type Problem } from "../engine/types";
import { useT, type StringKey } from "../i18n";
import { fill, ProblemList, RawPanel, useAsOf, VerdictChip } from "./common";
import { useApp } from "./context";
import { addFromDraft, blankDraft, draftOf, editFromDraft, LIMITS_OF, MEASURES_OF, removeAt, type Change, type PolicyDraft } from "./policyModel";

type Outcome = { ok: true; text: string } | { ok: false; change: Extract<Change, { ok: false }> } | null;

function Select<T extends string>({ label, value, options, onChange, testid, labelOf }: { label: string; value: T; options: readonly T[]; onChange: (v: T) => void; testid: string; labelOf?: (v: T) => string }) {
  return (
    <label>
      {label}{" "}
      <select value={value} onChange={(e) => onChange((e.currentTarget as HTMLSelectElement).value as T)} data-testid={testid}>
        {options.map((o) => (
          <option key={o} value={o}>
            {labelOf ? labelOf(o) : o === "" ? "-" : o}
          </option>
        ))}
      </select>
    </label>
  );
}

function Text({ label, value, onChange, testid, mono = true }: { label: string; value: string; onChange: (v: string) => void; testid: string; mono?: boolean }) {
  return (
    <label>
      {label}{" "}
      <input type="text" dir={mono ? "ltr" : "auto"} value={value} onInput={(e) => onChange((e.currentTarget as HTMLInputElement).value)} data-testid={testid} />
    </label>
  );
}

function PolicyForm({ initial, isNew, onSubmit, onCancel }: { initial: PolicyDraft; isNew: boolean; onSubmit: (d: PolicyDraft) => void; onCancel: () => void }) {
  const t = useT();
  const { household } = useApp();
  const config = household.config as Config;
  const [d, setD] = useState<PolicyDraft>(initial);
  const set = <K extends keyof PolicyDraft>(k: K) => (v: PolicyDraft[K]) => setD({ ...d, [k]: v });
  const groups = Object.keys(config.categories);
  const allCategories = Object.values(config.categories).flat();
  const periods = PERIOD_KINDS;
  const measures = MEASURES_OF[d.type] ?? [];
  const limits = LIMITS_OF[d.type] ?? [];
  const showMeasure = measures.length > 0;
  const showMatch = d.type === "routine" || d.type === "red_line";
  const periodLabel = (p: string) => t(`pol.period.${p}` as StringKey);
  return (
    <form
      class="card policy-form"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(d);
      }}
      data-testid="policy-form"
    >
      <h4>{isNew ? t("pol.addTitle") : fill(t("pol.editTitle"), { id: initial.id })}</h4>
      <div class="grid">
        {isNew && (
          <Select
            label={t("pol.type")}
            value={d.type}
            options={POLICY_TYPES}
            onChange={(type) => setD({ ...blankDraft(config, type), id: d.id, title: d.title })}
            testid="pf-type"
            labelOf={(x) => t(`ptype.${x}` as StringKey)}
          />
        )}
        <Text label={t("pol.id")} value={d.id} onChange={set("id")} testid="pf-id" />
        <label class="wide">
          {t("pol.title")} <input type="text" value={d.title} onInput={(e) => set("title")((e.currentTarget as HTMLInputElement).value)} data-testid="pf-title" />
        </label>
      </div>
      {showMeasure && (
        <fieldset>
          <legend>{t("pol.measure")}</legend>
          {measures.length > 1 && (
            <Select label={t("pol.measureKind")} value={d.measureKind} options={measures} onChange={set("measureKind")} testid="pf-measure" labelOf={(x) => t(`pol.kind.${x}` as StringKey)} />
          )}
          {d.measureKind === "sum" && (
            <>
              <Select label={t("pol.group")} value={d.sumGroup} options={groups} onChange={(g) => setD({ ...d, sumGroup: g, sumCategory: "" })} testid="pf-group" />
              <Select
                label={t("pol.category")}
                value={d.sumCategory}
                options={["", ...(config.categories[d.sumGroup] ?? [])]}
                onChange={set("sumCategory")}
                testid="pf-category"
                labelOf={(x) => (x === "" ? t("pol.wholeGroup") : x)}
              />
              <Select label={t("pol.period")} value={d.sumPeriod} options={periods} onChange={set("sumPeriod")} testid="pf-sum-period" labelOf={periodLabel} />
            </>
          )}
          {d.measureKind === "holdings" && (
            <>
              <Select label={t("pol.by")} value={d.holdingsBy} options={["class", "account"] as const} onChange={(by) => setD({ ...d, holdingsBy: by, holdingsName: (by === "class" ? config.classes : config.accounts)[0] ?? "" })} testid="pf-holdings-by" labelOf={(x) => t(`pol.by.${x}` as StringKey)} />
              <Select label={d.holdingsBy === "class" ? t("pol.class") : t("pol.account")} value={d.holdingsName} options={d.holdingsBy === "class" ? config.classes : config.accounts} onChange={set("holdingsName")} testid="pf-holdings-name" />
            </>
          )}
          {d.measureKind === "share" && <Select label={t("pol.class")} value={d.shareClass} options={config.classes} onChange={set("shareClass")} testid="pf-share-class" />}
          {d.measureKind === "drawdown" && (
            <>
              <Select label={t("pol.account")} value={d.drawdownAccount} options={config.accounts} onChange={set("drawdownAccount")} testid="pf-dd-account" />
              <Text label={t("pol.window")} value={d.windowDays} onChange={set("windowDays")} testid="pf-window" />
            </>
          )}
        </fieldset>
      )}
      {limits.length > 0 && (
        <fieldset>
          <legend>{t("pol.limit")}</legend>
          {limits.length > 1 && <Select label={t("pol.limitKind")} value={d.limitKind} options={limits} onChange={set("limitKind")} testid="pf-limit" labelOf={(x) => t(`pol.limit.${x}` as StringKey)} />}
          <Text label={`${t("pol.value")}${d.limitKind === "pct" || d.limitKind === "pct_of" ? " (%)" : ""}`} value={d.limitValue} onChange={set("limitValue")} testid="pf-limit-value" />
        </fieldset>
      )}
      {d.type === "allocation" && (
        <fieldset>
          <legend>{t("pol.band")}</legend>
          <Text label={t("pol.minPct")} value={d.minPct} onChange={set("minPct")} testid="pf-min-pct" />
          <Text label={t("pol.maxPct")} value={d.maxPct} onChange={set("maxPct")} testid="pf-max-pct" />
        </fieldset>
      )}
      {showMatch && (
        <fieldset>
          <legend>{t("pol.match")}</legend>
          <Text label={t("pol.tags")} value={d.tags} onChange={set("tags")} testid="pf-tags" />
          <Text label={t("pol.tagsAny")} value={d.tagsAny} onChange={set("tagsAny")} testid="pf-tags-any" />
          <Select label={t("pol.matchAccount")} value={d.matchAccount} options={["", ...config.accounts]} onChange={set("matchAccount")} testid="pf-match-account" labelOf={(x) => (x === "" ? t("pol.any") : x)} />
          <Select label={t("pol.matchCategory")} value={d.matchCategory} options={["", ...allCategories]} onChange={set("matchCategory")} testid="pf-match-category" labelOf={(x) => (x === "" ? t("pol.any") : x)} />
          <Text label={t("pol.minAmount")} value={d.minAmount} onChange={set("minAmount")} testid="pf-min-amount" />
          {d.type === "routine" && <Select label={t("pol.period")} value={d.period} options={periods} onChange={set("period")} testid="pf-period" labelOf={periodLabel} />}
        </fieldset>
      )}
      <div class="actions">
        <button type="submit" class="primary" data-testid="pf-save">
          {t("pol.save")}
        </button>
        <button type="button" onClick={onCancel}>
          {t("pol.cancel")}
        </button>
      </div>
    </form>
  );
}

function Declared({ p, base }: { p: Policy; base: string }) {
  const parts = [p.measure ? measureText(p.measure) : null, p.limit ? limitText(p.limit, base) : null, p.match ? matchText(p.match) : null, p.band ? bandText(p.band) : null, p.period ? `per ${p.period}` : null].filter((x): x is string => x !== null);
  return (
    <span class="mono muted" dir="ltr">
      {parts.join(" · ")}
    </span>
  );
}

export function Policies() {
  const t = useT();
  const { store, snap, household } = useApp();
  const asOf = useAsOf();
  const config = household.config;
  const text = snap.files["policies.yml"] ?? "";
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const [removing, setRemoving] = useState<number | null>(null);
  const [outcome, setOutcome] = useState<Outcome>(null);
  const report = useMemo(() => (household.fatal.length === 0 ? buildCheck(household, asOf) : null), [household, asOf]);
  const verdictOf = (id: string) => report?.verdicts.find((v) => v.policy.id === id) ?? null;
  const base = config?.baseCurrency ?? "";

  const apply = async (c: Change, okKey: StringKey) => {
    if (!c.ok) {
      setOutcome({ ok: false, change: c });
      return;
    }
    await store.setFiles({ "policies.yml": c.text });
    setOutcome({ ok: true, text: fill(t(okKey), { id: c.id }) });
    setEditing(null);
    setRemoving(null);
  };

  const policies = config?.policies ?? [];
  const groups: { key: StringKey; items: [Policy, number][] }[] = [
    ...POLICY_TYPES.map((type) => ({ key: `type.${type}` as StringKey, items: policies.map((p, i) => [p, i] as [Policy, number]).filter(([p]) => p.type === type) })),
    { key: "type.other" as StringKey, items: policies.map((p, i) => [p, i] as [Policy, number]).filter(([p]) => !(POLICY_TYPES as readonly string[]).includes(p.type)) },
  ];

  return (
    <section aria-labelledby="pol-title">
      <h2 id="pol-title" tabIndex={-1} data-screen-title>
        {t("nav.policies")}
      </h2>
      {config === null && <p class="msg-red">{t("pol.needConfig")}</p>}
      {(household.problemsByFile["policies.yml"]?.length ?? 0) > 0 && <ProblemList problems={household.problemsByFile["policies.yml"] ?? []} testid="policies-problems" />}
      {outcome && outcome.ok && (
        <p class="msg-ok" role="status" data-testid="pol-outcome">
          {outcome.text}
        </p>
      )}
      {outcome && !outcome.ok && (
        <div class="msg-red" role="alert" data-testid="pol-outcome">
          {outcome.change.layout ? t("pol.layout") : t("pol.refused")}
          {outcome.change.reason && <p dir="ltr">{outcome.change.reason}</p>}
          {outcome.change.problems.length > 0 && <ProblemList problems={outcome.change.problems as Problem[]} />}
        </div>
      )}
      {config !== null && (
        <>
          <div class="actions">
            <button type="button" class="primary" onClick={() => setEditing("new")} data-testid="pol-add">
              {t("pol.add")}
            </button>
          </div>
          {editing === "new" && (
            <PolicyForm initial={blankDraft(config, "cap")} isNew onCancel={() => setEditing(null)} onSubmit={(d) => void apply(addFromDraft(text, config, d), "pol.saved")} />
          )}
          {policies.length === 0 && <p class="muted">{t("pol.none")}</p>}
          {groups
            .filter((g) => g.items.length > 0)
            .map((g) => (
              <section key={g.key} class="policy-group" aria-label={t(g.key)}>
                <h3>{t(g.key)}</h3>
                <ul class="board">
                  {g.items.map(([p, i]) => {
                    const v = verdictOf(p.id);
                    const draft = draftOf(p, config);
                    return (
                      <li key={p.id} class="policy" data-testid={`pol-${p.id}`}>
                        <div class="policy-line">
                          {v && <VerdictChip verdict={v.verdict} />}
                          <span class="mono pid">{p.id}</span>
                          <span class="ptitle">{p.title}</span>
                          <Declared p={p} base={base} />
                        </div>
                        {p.status !== "ok" && (
                          <p class="msg-red" dir="ltr">
                            {p.reason}
                          </p>
                        )}
                        <div class="actions">
                          <span class="mono muted">{p.cite}</span>
                          {draft && (
                            <button type="button" onClick={() => setEditing(i)} data-testid={`pol-edit-${p.id}`}>
                              {t("pol.edit")}
                            </button>
                          )}
                          {!draft && <span class="muted">{t("pol.rawOnly")}</span>}
                          <button type="button" onClick={() => setRemoving(i)} data-testid={`pol-remove-${p.id}`}>
                            {t("pol.remove")}
                          </button>
                        </div>
                        {editing === i && draft && <PolicyForm initial={draft} isNew={false} onCancel={() => setEditing(null)} onSubmit={(d) => void apply(editFromDraft(text, config, i, d), "pol.saved")} />}
                        {removing === i && (
                          <div class="card confirm" role="alertdialog" aria-labelledby={`rm-${p.id}`} data-testid="pol-remove-confirm">
                            <p id={`rm-${p.id}`}>{fill(t("pol.removeAsk"), { id: p.id, date: asOf })}</p>
                            {v && (
                              <p class="mono" dir="ltr">
                                {verdictLine(v, base, asOf)}
                              </p>
                            )}
                            {v && v.findings.length > 0 && (
                              <>
                                <p>{t("pol.removeFindings")}</p>
                                <ul>
                                  {v.findings.map((f, k) => (
                                    <li key={k} class="mono" dir="ltr">
                                      {f.code} {f.reason}
                                    </li>
                                  ))}
                                </ul>
                              </>
                            )}
                            {(() => {
                              const refs = household.decisions.filter((d) => d.policy === p.id || d.closes === p.id).map((d) => d.id);
                              return refs.length > 0 ? <p class="msg-red">{fill(t("pol.removeRefs"), { id: p.id, ids: refs.join(", ") })}</p> : null;
                            })()}
                            <div class="actions">
                              <button type="button" class="primary" onClick={() => void apply(removeAt(text, config, i), "pol.removed")} data-testid="pol-remove-yes">
                                {fill(t("pol.removeYes"), { id: p.id })}
                              </button>
                              <button type="button" onClick={() => setRemoving(null)}>
                                {t("pol.cancel")}
                              </button>
                            </div>
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </section>
            ))}
        </>
      )}
      <RawPanel file="policies.yml" check={(x) => parsePolicies(x).problems} />
    </section>
  );
}
