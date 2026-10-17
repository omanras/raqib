// Settings (app ADR section 3): the base currency (declared in
// policies.yml, read only), language, theme, storage, export all and
// import all (one text bundle of the five files), erase all (two steps),
// and about.
import { useState } from "preact/hooks";
import type { HouseholdText } from "../engine/types";
import { LANGUAGES, useT, type Language } from "../i18n";
import { isTheme, type Theme } from "../store/household";
import { checkImport, decodeUtf8, type Checked } from "../store/import";
import { copyText, downloadText } from "./clipboard";
import { useApp } from "./context";
import { ResultMessage } from "./files";
import { bundleText, isFileName, readBundle } from "./textEdit";

declare const __APP_VERSION__: string;

const THEMES: readonly Theme[] = ["system", "light", "dark"];

function ImportAll() {
  const t = useT();
  const { store } = useApp();
  const [text, setText] = useState("");
  const [results, setResults] = useState<Checked[] | null>(null);
  const run = async (bundle: string) => {
    const parts = readBundle(bundle);
    const seen = new Set<string>();
    const checked: Checked[] = parts.map((p) => {
      if (seen.has(p.name)) return { ok: false, name: p.name, refusal: { kind: "unknown-name", name: `${p.name} (${t("set.bundleDup")})` } };
      seen.add(p.name);
      return isFileName(p.name) ? checkImport(p.name, p.text) : { ok: false, name: p.name, refusal: { kind: "unknown-name", name: p.name } };
    });
    const accepted: Partial<HouseholdText> = {};
    for (const r of checked) if (r.ok) accepted[r.name] = r.text;
    if (Object.keys(accepted).length > 0) await store.setFiles(accepted);
    setResults(checked);
  };
  return (
    <section class="card" aria-labelledby="import-all-title">
      <h3 id="import-all-title">{t("set.importAll")}</h3>
      <label>
        {t("set.bundle")}
        <textarea rows={6} value={text} spellcheck={false} dir="ltr" onInput={(e) => setText((e.currentTarget as HTMLTextAreaElement).value)} data-testid="bundle-text" />
      </label>
      <div class="actions">
        <button type="button" class="primary" onClick={() => void run(text)} data-testid="bundle-import">
          {t("set.importBundle")}
        </button>
        <label>
          {t("set.bundleFile")}{" "}
          <input
            type="file"
            accept=".txt,text/plain"
            onChange={async (e) => {
              const input = e.currentTarget as HTMLInputElement;
              const file = input.files?.[0];
              if (!file) return;
              const decoded = decodeUtf8(new Uint8Array(await file.arrayBuffer()));
              if (decoded.ok) {
                setText(decoded.text);
                await run(decoded.text);
              } else setResults([{ ok: false, name: file.name, refusal: { kind: "not-utf8", detail: decoded.detail } }]);
              input.value = "";
            }}
            data-testid="bundle-file"
          />
        </label>
      </div>
      {results !== null && results.length === 0 && (
        <p class="msg-red" role="alert">
          {t("set.bundleNone")}
        </p>
      )}
      {results?.map((r, i) => (
        <ResultMessage key={i} result={r} />
      ))}
    </section>
  );
}

function EraseAll() {
  const t = useT();
  const { store } = useApp();
  const [asking, setAsking] = useState(false);
  const [done, setDone] = useState(false);
  return (
    <section class="card" aria-labelledby="erase-title">
      <h3 id="erase-title">{t("set.erase")}</h3>
      <p>{t("set.eraseNote")}</p>
      {!asking && (
        <button type="button" onClick={() => setAsking(true)} data-testid="erase-ask">
          {t("set.eraseAsk")}
        </button>
      )}
      {asking && (
        <div class="actions" role="alertdialog" aria-labelledby="erase-title">
          <button
            type="button"
            class="danger"
            onClick={async () => {
              await store.erase();
              setAsking(false);
              setDone(true);
            }}
            data-testid="erase-yes"
          >
            {t("set.eraseConfirm")}
          </button>
          <button type="button" onClick={() => setAsking(false)}>
            {t("set.eraseCancel")}
          </button>
        </div>
      )}
      {done && <p role="status">{t("set.erased")}</p>}
    </section>
  );
}

export function Settings() {
  const t = useT();
  const { store, snap, household } = useApp();
  const [copied, setCopied] = useState<boolean | null>(null);
  const bundle = bundleText(snap.files);
  return (
    <section aria-labelledby="settings-title">
      <h2 id="settings-title" tabIndex={-1} data-screen-title>
        {t("nav.settings")}
      </h2>
      <dl class="facts">
        <dt>{t("set.base")}</dt>
        <dd>
          <span class="mono" data-testid="base-currency">
            {household.config?.baseCurrency ?? "-"}
          </span>{" "}
          <span class="muted">({t("set.baseNote")})</span>
        </dd>
        <dt>{t("set.storage")}</dt>
        <dd>{snap.persistent ? t("set.persistent") : t("set.memory")}</dd>
      </dl>
      <div class="actions">
        <label>
          {t("lang.label")}{" "}
          <select value={snap.meta.language} onChange={(e) => void store.setMeta({ language: (e.currentTarget as HTMLSelectElement).value as Language })} data-testid="settings-language">
            {LANGUAGES.map((l) => (
              <option key={l} value={l} lang={l}>
                {t(`lang.${l}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("theme.label")}{" "}
          <select
            value={snap.meta.theme}
            onChange={(e) => {
              const v = (e.currentTarget as HTMLSelectElement).value;
              if (isTheme(v)) void store.setMeta({ theme: v });
            }}
            data-testid="settings-theme"
          >
            {THEMES.map((th) => (
              <option key={th} value={th}>
                {t(`theme.${th}`)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <section class="card" aria-labelledby="export-all-title">
        <h3 id="export-all-title">{t("set.export")}</h3>
        <p class="muted">{t("set.exportNote")}</p>
        <div class="actions">
          <button type="button" class="primary" disabled={bundle === ""} onClick={async () => setCopied(await copyText(bundle))} data-testid="export-all">
            {t("set.copyAll")}
          </button>
          <button type="button" disabled={bundle === ""} onClick={() => downloadText("qayd-household.txt", bundle)} data-testid="download-all">
            {t("set.downloadAll")}
          </button>
          {copied === true && <span role="status">{t("files.copied")}</span>}
        </div>
        {copied === false && (
          <label>
            {t("files.copyManual")}
            <textarea readOnly rows={6} value={bundle} dir="ltr" onFocus={(e) => (e.currentTarget as HTMLTextAreaElement).select()} />
          </label>
        )}
      </section>
      <ImportAll />
      <EraseAll />
      <section class="card" aria-labelledby="about-title">
        <h3 id="about-title">{t("set.about")}</h3>
        <p>
          {t("app.title")} {t("app.version")} <span class="mono">{__APP_VERSION__}</span>
        </p>
        <p>{t("set.aboutText")}</p>
      </section>
    </section>
  );
}
