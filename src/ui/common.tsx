// Pieces the data screens share: the verdict chip (a word, coloured), the
// as-of date (persisted in meta, default today), a list of loader problems,
// and the raw-text panel that edits a whole file, shows its problems by
// line and saves only when no line is invalid.
import { useEffect, useState } from "preact/hooks";
import { isValidDate } from "../engine/dates";
import type { FileName, Problem } from "../engine/types";
import { useT, type StringKey } from "../i18n";
import type { VerdictName } from "../engine/rules";
import { useApp } from "./context";
import { blocking, todayIso } from "./model";

/** Fill {name} slots of a translated string. */
export function fill(text: string, values: Record<string, string | number>): string {
  return text.replace(/\{(\w+)\}/g, (m, k: string) => (k in values ? String(values[k]) : m));
}

/** Red for every verdict but hold: the CLI's green is every policy hold. */
export function VerdictChip({ verdict }: { verdict: VerdictName | string }) {
  const t = useT();
  const cls = verdict === "hold" ? "chip chip-hold" : "chip chip-red";
  return (
    <span class={cls} data-verdict={verdict}>
      {t(`verdict.${verdict}` as StringKey) ?? verdict}
    </span>
  );
}

/** The as-of date every screen judges at: meta.asOf, or today. */
export function useAsOf(): string {
  const { snap } = useApp();
  return snap.meta.asOf ?? todayIso();
}

/**
 * A date as ISO text (YYYY-MM-DD), the way the files write it, in Latin
 * digits whatever the language; a native date picker would show the
 * browser's locale instead. onDate fires for every valid date typed.
 */
export function IsoDateInput({ value, onDate, testid, required = true }: { value: string; onDate: (iso: string) => void; testid: string; required?: boolean }) {
  const [text, setText] = useState(value);
  useEffect(() => setText(value), [value]);
  const valid = isValidDate(text);
  return (
    <input
      type="text"
      inputMode="numeric"
      dir="ltr"
      size={11}
      maxLength={10}
      placeholder="YYYY-MM-DD"
      pattern="\d{4}-\d{2}-\d{2}"
      required={required}
      value={text}
      aria-invalid={!valid}
      onInput={(e) => {
        const v = (e.currentTarget as HTMLInputElement).value.trim();
        setText(v);
        if (isValidDate(v)) onDate(v);
      }}
      data-testid={testid}
    />
  );
}

export function AsOfInput() {
  const t = useT();
  const { store, snap } = useApp();
  const asOf = useAsOf();
  return (
    <div class="actions">
      <label>
        {t("dash.asOf")} <IsoDateInput value={asOf} onDate={(v) => void store.setMeta({ asOf: v })} testid="as-of" />
      </label>
      <button type="button" onClick={() => void store.setMeta({ asOf: null })} disabled={snap.meta.asOf === null}>
        {t("dash.today")}
      </button>
    </div>
  );
}

export function problemText(p: Problem): string {
  return `${p.line ? `${p.file}:${p.line}` : p.file} ${p.code}: ${p.reason}`;
}

export function ProblemList({ problems, testid }: { problems: readonly Problem[]; testid?: string }) {
  return (
    <ul class="problems" data-testid={testid}>
      {problems.map((p, i) => (
        <li key={i} class={p.class === "warn" ? "warn" : "red"}>
          <span class="mono">{problemText(p)}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * Edit a whole file as text. The problems are the engine loader's, by
 * line; Save writes the text as typed, and only when no line is invalid.
 */
export function RawPanel({ file, check }: { file: FileName; check: (text: string) => Problem[] }) {
  const t = useT();
  const { store, snap } = useApp();
  const stored = snap.files[file] ?? "";
  const [text, setText] = useState(stored);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    setText(stored);
  }, [stored]);
  const problems = check(text);
  const bad = blocking(problems);
  const changed = text !== stored;
  return (
    <details class="card raw" data-testid={`raw-${file}`}>
      <summary>
        {t("raw.show")} <span class="mono">{file}</span>
      </summary>
      <label>
        <span class="visually-hidden">
          {t("raw.title")} {file}
        </span>
        <textarea
          rows={14}
          value={text}
          spellcheck={false}
          dir="ltr"
          onInput={(e) => {
            setText((e.currentTarget as HTMLTextAreaElement).value);
            setSaved(false);
          }}
          data-testid={`raw-text-${file}`}
        />
      </label>
      <h4>{t("raw.problems")}</h4>
      {problems.length === 0 ? <p class="muted">{t("raw.noProblems")}</p> : <ProblemList problems={problems} testid={`raw-problems-${file}`} />}
      <div class="actions">
        <button
          type="button"
          class="primary"
          disabled={!changed || bad.length > 0}
          onClick={async () => {
            await store.setFiles({ [file]: text });
            setSaved(true);
          }}
          data-testid={`raw-save-${file}`}
        >
          {t("raw.save")}
        </button>
        <button type="button" disabled={!changed} onClick={() => setText(stored)}>
          {t("raw.reset")}
        </button>
        {changed && bad.length > 0 && <span class="muted">{t("raw.blocked")}</span>}
        {saved && !changed && <span role="status">{t("raw.saved")}</span>}
      </div>
    </details>
  );
}
