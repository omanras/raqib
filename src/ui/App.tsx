// The root: opens the store, keeps its latest snapshot, loads the household
// with the engine whenever the text changes, and applies language
// (<html lang dir>) and theme (data-theme on :root).
import { useEffect, useMemo, useState } from "preact/hooks";
import { loadHousehold } from "../engine/household";
import { dirOf, LanguageContext, translator } from "../i18n";
import { hasAnyFile, HouseholdStore, type Snapshot } from "../store/household";
import { AppContext } from "./context";
import { Dashboard } from "./dashboard";
import { FilesPage } from "./files";
import { Holdings } from "./holdings";
import { Ledger } from "./ledger";
import { useScreen, type Screen } from "./route";
import { EmptyState, Placeholder, Shell } from "./shell";

function ScreenView({ screen }: { screen: Screen }) {
  if (screen === "dashboard") return <Dashboard />;
  if (screen === "ledger") return <Ledger />;
  if (screen === "holdings") return <Holdings />;
  if (screen === "files") return <FilesPage />;
  return <Placeholder screen={screen} />;
}

export function App({ open = () => HouseholdStore.open() }: { open?: () => Promise<HouseholdStore> }) {
  const [store, setStore] = useState<HouseholdStore | null>(null);
  const [snap, setSnap] = useState<Snapshot | null>(null);
  const screen = useScreen();

  useEffect(() => {
    let opened: HouseholdStore | null = null;
    let live = true;
    void open().then((s) => {
      if (!live) return s.close();
      opened = s;
      setStore(s);
      setSnap(s.snapshot);
      s.subscribe(setSnap);
    });
    return () => {
      live = false;
      opened?.close();
    };
  }, []);

  const files = snap?.files ?? null;
  const household = useMemo(() => (files ? loadHousehold(files) : null), [files]);
  const lang = snap?.meta.language ?? "en";
  const theme = snap?.meta.theme ?? "system";

  useEffect(() => {
    const root = document.documentElement;
    root.lang = lang;
    root.dir = dirOf(lang);
  }, [lang]);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") delete root.dataset["theme"];
    else root.dataset["theme"] = theme;
  }, [theme]);
  useEffect(() => {
    // after a navigation, the new screen's heading takes the focus
    if (location.hash) document.querySelector<HTMLElement>("main [data-screen-title]")?.focus();
  }, [screen]);

  if (store === null || snap === null || household === null) {
    const t = translator(lang);
    return (
      <div class="app">
        <header class="top">
          <h1>{t("app.title")}</h1>
        </header>
        <main id="main" aria-busy="true">
          <p>{t("app.loading")}</p>
        </main>
      </div>
    );
  }

  const empty = !hasAnyFile(snap.files);
  return (
    <LanguageContext.Provider value={lang}>
      <AppContext.Provider value={{ store, snap, household }}>
        <Shell screen={screen}>{screen !== "files" && empty ? <EmptyState /> : <ScreenView screen={screen} />}</Shell>
      </AppContext.Provider>
    </LanguageContext.Provider>
  );
}
