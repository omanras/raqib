// Screens by URL hash (#/ledger), so navigation works from file:// and in
// a sandboxed frame without a server.
import { useEffect, useState } from "preact/hooks";
import type { StringKey } from "../i18n";

export const SCREENS = ["dashboard", "ledger", "holdings", "decisions", "policies", "review", "settings"] as const;
export type Screen = (typeof SCREENS)[number] | "files";

export const SCREEN_LABEL: Record<Screen, StringKey> = {
  dashboard: "nav.dashboard",
  ledger: "nav.ledger",
  holdings: "nav.holdings",
  decisions: "nav.decisions",
  policies: "nav.policies",
  review: "nav.review",
  settings: "nav.settings",
  files: "nav.files",
};

export function screenOf(hash: string): Screen {
  const name = hash.replace(/^#\/?/, "").split(/[/?]/)[0] ?? "";
  if (name === "files" || (SCREENS as readonly string[]).includes(name)) return name as Screen;
  return "dashboard";
}

export function hrefOf(screen: Screen): string {
  return `#/${screen}`;
}

export function useScreen(): Screen {
  const [screen, setScreen] = useState<Screen>(() => screenOf(location.hash));
  useEffect(() => {
    const on = () => setScreen(screenOf(location.hash));
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return screen;
}
