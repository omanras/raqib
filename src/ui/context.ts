// What every screen reads: the store (to write files and meta), its latest
// snapshot, and the household the engine loaded from the snapshot's text.
import { createContext } from "preact";
import { useContext } from "preact/hooks";
import type { Household } from "../engine/household";
import type { HouseholdStore, Snapshot } from "../store/household";

export interface AppState {
  store: HouseholdStore;
  snap: Snapshot;
  household: Household;
}

export const AppContext = createContext<AppState | null>(null);

export function useApp(): AppState {
  const s = useContext(AppContext);
  if (s === null) throw new Error("useApp outside the app");
  return s;
}
