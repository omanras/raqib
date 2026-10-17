// The application shell: header (title, theme, language), the memory-only
// banner, navigation to the seven screens, the household files and their
// counts, and the empty state of a first run.
import type { ComponentChildren } from "preact";
import { FILE_NAMES } from "../engine/types";
import { LANGUAGES, useT, type Language } from "../i18n";
import { isTheme, type Theme } from "../store/household";
import { sampleHousehold } from "../store/sample";
import { useApp } from "./context";
import { FileCounts } from "./files";
import { hrefOf, SCREEN_LABEL, SCREENS, type Screen } from "./route";

declare const __APP_VERSION__: string;

const THEMES: readonly Theme[] = ["system", "light", "dark"];

function Header() {
  const t = useT();
  const { store, snap } = useApp();
  return (
    <header class="top">
      <h1>{t("app.title")}</h1>
      <span class="tagline">{t("app.tagline")}</span>
      <div class="controls">
        <label>
          {t("theme.label")}
          <select
            value={snap.meta.theme}
            onChange={(e) => {
              const v = (e.currentTarget as HTMLSelectElement).value;
              if (isTheme(v)) void store.setMeta({ theme: v });
            }}
            data-testid="theme"
          >
            {THEMES.map((th) => (
              <option key={th} value={th}>
                {t(`theme.${th}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("lang.label")}
          <select
            value={snap.meta.language}
            onChange={(e) => void store.setMeta({ language: (e.currentTarget as HTMLSelectElement).value as Language })}
            data-testid="language"
          >
            {LANGUAGES.map((l) => (
              <option key={l} value={l} lang={l}>
                {t(`lang.${l}`)}
              </option>
            ))}
          </select>
        </label>
      </div>
    </header>
  );
}

function Nav({ screen }: { screen: Screen }) {
  const t = useT();
  return (
    <nav class="nav" aria-label={t("nav.label")}>
      <ul>
        {[...SCREENS, "files" as const].map((s) => (
          <li key={s}>
            <a href={hrefOf(s)} aria-current={s === screen ? "page" : undefined}>
              {t(SCREEN_LABEL[s])}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

export function EmptyState() {
  const t = useT();
  const { store } = useApp();
  return (
    <section aria-labelledby="empty-title" data-testid="empty-state">
      <h2 id="empty-title" tabIndex={-1} data-screen-title>
        {t("empty.title")}
      </h2>
      <p>{t("empty.body")}</p>
      <ul class="file-list">
        {FILE_NAMES.map((f) => (
          <li key={f}>
            <span class="mono">{f}</span>: {t(`file.${f}`)}
          </li>
        ))}
      </ul>
      <div class="actions">
        <button type="button" class="primary" onClick={() => void store.setFiles(sampleHousehold())} data-testid="load-sample">
          {t("empty.sample")}
        </button>
        <a class="button" href={hrefOf("files")}>
          {t("empty.import")}
        </a>
      </div>
      <p class="muted">{t("empty.sampleNote")}</p>
    </section>
  );
}

export function Placeholder({ screen }: { screen: Screen }) {
  const t = useT();
  return (
    <section>
      <h2 tabIndex={-1} data-screen-title>
        {t(SCREEN_LABEL[screen])}
      </h2>
      <p class="muted">{t("screen.soon")}</p>
    </section>
  );
}

export function Shell({ screen, children }: { screen: Screen; children: ComponentChildren }) {
  const t = useT();
  const { snap } = useApp();
  return (
    <div class="app">
      <a class="skip" href="#main" onClick={(e) => {
        e.preventDefault();
        document.getElementById("main")?.focus();
      }}>
        {t("app.skip")}
      </a>
      <Header />
      {!snap.persistent && (
        <p class="banner" role="status" data-testid="memory-banner">
          {t("banner.memory")}
        </p>
      )}
      {snap.external && (
        <p class="banner" role="status" data-testid="reloaded-banner">
          {t("banner.reloaded")}
        </p>
      )}
      <div class="layout">
        <div class="side">
          <Nav screen={screen} />
          <FileCounts />
        </div>
        <main id="main" tabIndex={-1}>
          {children}
        </main>
      </div>
      <footer class="foot">
        {t("app.version")} <span data-testid="version">{__APP_VERSION__}</span> · {t("app.offline")}
      </footer>
    </div>
  );
}
