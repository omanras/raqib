// The household files in the shell: their row counts (the CLI's `files`
// counts) in the side bar, and the Files page with import (per file, several
// at once, or pasted text) and export (copy, download) of each file.
import { useState } from "preact/hooks";
import type { Household } from "../engine/household";
import { FILE_NAMES, type FileName, type HouseholdText } from "../engine/types";
import { useT, type StringKey, type T } from "../i18n";
import { hasAnyFile } from "../store/household";
import { checkFileBytes, checkImport, type Checked, type Refusal } from "../store/import";
import { copyText, downloadText, mediaType } from "./clipboard";
import { useApp } from "./context";
import { hrefOf } from "./route";

/** "271 rows", "1 policy", "absent" or "not read" for one file. */
export function countText(name: FileName, files: HouseholdText, h: Household, t: T): string {
  if (files[name] === null) return t("files.absent");
  const n = h.files[name];
  if (n === undefined || n === null) return t("files.unread");
  const unit = name === "policies.yml" ? "files.policies" : name === "decisions.yml" ? "files.decisions" : "files.rows";
  return t(`${unit}.${n === 1 ? "one" : "many"}`).replace("{n}", String(n));
}

export function FileCounts() {
  const t = useT();
  const { snap, household } = useApp();
  return (
    <section aria-labelledby="counts-title">
      <h2 id="counts-title">{t("files.title")}</h2>
      <ul class="counts">
        {FILE_NAMES.map((f) => (
          <li key={f}>
            <span class="name">{f}</span>
            <span class="count" data-testid={`count-${f}`}>
              {countText(f, snap.files, household, t)}
            </span>
          </li>
        ))}
      </ul>
      {hasAnyFile(snap.files) && household.problems.length > 0 && (
        <p>
          <a href={hrefOf("files")} data-testid="problem-count">
            {t(`files.problemCount.${household.problems.length === 1 ? "one" : "many"}`).replace("{n}", String(household.problems.length))}
          </a>
        </p>
      )}
    </section>
  );
}

function RefusalText({ r, t }: { r: Refusal; t: T }) {
  if (r.kind === "wrong-header") {
    return (
      <>
        {t("files.wrongHeader")}
        <pre>
          {t("files.expected")}: {r.expected}
          {"\n"}
          {t("files.got")}: {r.got}
        </pre>
      </>
    );
  }
  if (r.kind === "not-utf8") return <>{`${t("files.notUtf8")} (${r.detail})`}</>;
  if (r.kind === "empty") return <>{t("files.empty")}</>;
  if (r.kind === "too-large") return <>{`${r.bytes} bytes`}</>;
  if (r.kind === "unknown-name") return <>{`${r.name}: ${t("files.unknownName")}`}</>;
  const p = r.problem;
  return <>{`${p.line ? `${p.file}:${p.line}` : p.file} ${p.code}: ${p.reason}`}</>;
}

export function ResultMessage({ result }: { result: Checked }) {
  const t = useT();
  if (result.ok) {
    return (
      <p class="msg-ok" role="status">
        {t("files.imported")} {result.name}
      </p>
    );
  }
  return (
    <div class="msg-red" role="alert">
      {t("files.refused")} {result.name}: <RefusalText r={result.refusal} t={t} />
    </div>
  );
}

async function readChosen(file: File, forName: FileName | null): Promise<Checked> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return checkFileBytes(file.name, bytes, forName);
}

function FileCard({ name }: { name: FileName }) {
  const t = useT();
  const { store, snap, household } = useApp();
  const [result, setResult] = useState<Checked | null>(null);
  const [copied, setCopied] = useState<"yes" | "manual" | null>(null);
  const text = snap.files[name];
  const problems = household.problemsByFile[name]?.length ?? 0;

  const onFile = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const r = await readChosen(file, name);
    setResult(r);
    if (r.ok) await store.setFiles({ [name]: r.text });
    input.value = "";
  };
  const onCopy = async () => {
    if (text === null) return;
    setCopied((await copyText(text)) ? "yes" : "manual");
  };

  const id = `file-${name.replace(".", "-")}`;
  return (
    <section class="card" aria-labelledby={id} data-testid={`file-${name}`}>
      <h3 id={id} class="mono">
        {name}
      </h3>
      <p class="muted">{t(`file.${name}` as StringKey)}</p>
      <p>
        {countText(name, snap.files, household, t)}
        {problems > 0 && ` · ${problems} ${t("files.problems")}`}
      </p>
      <div class="actions">
        <label>
          {t("files.import")} {name}{" "}
          <input type="file" accept={name.endsWith(".csv") ? ".csv,text/csv" : ".yml,.yaml"} onChange={onFile} data-testid={`import-${name}`} />
        </label>
        <button type="button" onClick={onCopy} disabled={text === null} data-testid={`copy-${name}`}>
          {t("files.copy")}
        </button>
        <button type="button" onClick={() => text !== null && downloadText(name, text, mediaType(name))} disabled={text === null} data-testid={`download-${name}`}>
          {t("files.download")}
        </button>
        {copied === "yes" && <span role="status">{t("files.copied")}</span>}
      </div>
      {copied === "manual" && text !== null && (
        <label>
          {t("files.copyManual")}
          <textarea readOnly rows={6} value={text} onFocus={(e) => (e.currentTarget as HTMLTextAreaElement).select()} />
        </label>
      )}
      {result && <ResultMessage result={result} />}
    </section>
  );
}

function ImportMany() {
  const t = useT();
  const { store } = useApp();
  const [results, setResults] = useState<Checked[]>([]);
  const onFiles = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const chosen = [...(input.files ?? [])];
    const checked = await Promise.all(chosen.map((f) => readChosen(f, null)));
    const accepted: Partial<HouseholdText> = {};
    for (const r of checked) if (r.ok) accepted[r.name] = r.text;
    if (Object.keys(accepted).length > 0) await store.setFiles(accepted);
    setResults(checked);
    input.value = "";
  };
  return (
    <section class="card" aria-labelledby="import-many">
      <h3 id="import-many">{t("files.importMany")}</h3>
      <p class="muted">{t("files.importManyNote")}</p>
      <label>
        {t("files.importMany")} <input type="file" multiple accept=".csv,.yml,.yaml" onChange={onFiles} data-testid="import-many" />
      </label>
      {results.map((r, i) => (
        <ResultMessage key={i} result={r} />
      ))}
    </section>
  );
}

function PastePanel() {
  const t = useT();
  const { store } = useApp();
  const [name, setName] = useState<FileName>("ledger.csv");
  const [text, setText] = useState("");
  const [result, setResult] = useState<Checked | null>(null);
  const onUse = async () => {
    const r = checkImport(name, text);
    setResult(r);
    if (r.ok) await store.setFiles({ [name]: r.text });
  };
  return (
    <section class="card" aria-labelledby="paste-title">
      <h3 id="paste-title">{t("files.paste")}</h3>
      <div class="actions">
        <label>
          {t("files.pasteFile")}{" "}
          <select value={name} onChange={(e) => setName((e.currentTarget as HTMLSelectElement).value as FileName)} data-testid="paste-file">
            {FILE_NAMES.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label>
        {t("files.pasteText")}
        <textarea rows={8} value={text} onInput={(e) => setText((e.currentTarget as HTMLTextAreaElement).value)} spellcheck={false} data-testid="paste-text" />
      </label>
      <div class="actions">
        <button type="button" class="primary" onClick={onUse} data-testid="paste-use">
          {t("files.pasteImport")}
        </button>
      </div>
      {result && <ResultMessage result={result} />}
    </section>
  );
}

export function FilesPage() {
  const t = useT();
  return (
    <>
      <h2 tabIndex={-1} data-screen-title>
        {t("files.title")}
      </h2>
      <p class="muted">{t("files.intro")}</p>
      {FILE_NAMES.map((f) => (
        <FileCard key={f} name={f} />
      ))}
      <ImportMany />
      <PastePanel />
    </>
  );
}
