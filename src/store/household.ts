// The household store (app ADR section 2): the five file texts and the
// meta (last as-of, language, theme) in IndexedDB, or in memory when
// IndexedDB is unavailable or throws, which the shell shows as a banner.
// Every change is written at once; with two tabs the last write wins, and
// each write is announced (BroadcastChannel, or a `storage` event) so the
// other tab reloads the latest files.
import { isValidDate } from "../engine/dates";
import { FILE_NAMES, type FileName, type HouseholdText } from "../engine/types";
import { isLanguage, type Language } from "../i18n";
import { MemoryBackend, openIndexedDb, type Backend, type FileChanges } from "./backend";

export type Theme = "system" | "light" | "dark";

export interface Meta {
  /** the as-of date last used on the dashboard; null = today */
  asOf: string | null;
  language: Language;
  theme: Theme;
}

export const DEFAULT_META: Meta = { asOf: null, language: "en", theme: "system" };

export function isTheme(x: unknown): x is Theme {
  return x === "system" || x === "light" || x === "dark";
}

export function cleanMeta(raw: unknown): Meta {
  const m = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
  return {
    asOf: typeof m["asOf"] === "string" && isValidDate(m["asOf"]) ? m["asOf"] : null,
    language: isLanguage(m["language"]) ? m["language"] : DEFAULT_META.language,
    theme: isTheme(m["theme"]) ? m["theme"] : DEFAULT_META.theme,
  };
}

export function noFiles(): HouseholdText {
  return { "policies.yml": null, "ledger.csv": null, "holdings.csv": null, "decisions.yml": null, "rates.csv": null };
}

export function hasAnyFile(files: HouseholdText): boolean {
  return FILE_NAMES.some((f) => files[f] !== null);
}

export interface Snapshot {
  files: HouseholdText;
  meta: Meta;
  /** false: memory only; the banner says nothing will persist */
  persistent: boolean;
  /** why the store is memory only */
  memoryReason: string | null;
  /** the last change came from another tab */
  external: boolean;
}

/** Announces a write to the other tabs of this browser and hears theirs. */
export interface Notifier {
  post(): void;
  listen(onChange: () => void): void;
  close(): void;
}

const CHANNEL = "qayd";
const STORAGE_KEY = "qayd:changed";

export function browserNotifier(tab: string, g: typeof globalThis = globalThis): Notifier {
  const BC = (g as { BroadcastChannel?: typeof BroadcastChannel }).BroadcastChannel;
  if (typeof BC === "function") {
    const ch = new BC(CHANNEL);
    return {
      post: () => ch.postMessage({ from: tab }),
      listen: (on) => {
        ch.onmessage = (e: MessageEvent) => {
          if ((e.data as { from?: string } | null)?.from !== tab) on();
        };
      },
      close: () => ch.close(),
    };
  }
  let storage: Storage | null = null;
  try {
    storage = (g as { localStorage?: Storage }).localStorage ?? null;
  } catch {
    storage = null;
  }
  const win = g as { addEventListener?: Window["addEventListener"]; removeEventListener?: Window["removeEventListener"] };
  if (storage === null || typeof win.addEventListener !== "function") return { post: () => {}, listen: () => {}, close: () => {} };
  let handler: ((e: StorageEvent) => void) | null = null;
  return {
    post: () => {
      try {
        storage?.setItem(STORAGE_KEY, `${tab}:${Date.now()}`);
      } catch {
        /* a full or blocked localStorage only loses the announcement */
      }
    },
    listen: (on) => {
      handler = (e: StorageEvent) => {
        if (e.key === STORAGE_KEY && typeof e.newValue === "string" && !e.newValue.startsWith(tab + ":")) on();
      };
      win.addEventListener?.("storage", handler as EventListener);
    },
    close: () => {
      if (handler) win.removeEventListener?.("storage", handler as EventListener);
    },
  };
}

export interface StoreEnv {
  /** the persistent backend, or a rejection when there is none */
  openBackend: () => Promise<Backend>;
  notifier: (tab: string) => Notifier;
}

export function browserEnv(): StoreEnv {
  let factory: IDBFactory | null = null;
  try {
    factory = typeof indexedDB === "undefined" ? null : indexedDB;
  } catch {
    factory = null; // a sandboxed frame may throw on access
  }
  return { openBackend: () => openIndexedDb(factory), notifier: (tab) => browserNotifier(tab) };
}

function reasonOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export class HouseholdStore {
  private snap: Snapshot;
  private readonly listeners = new Set<(s: Snapshot) => void>();
  private readonly notifier: Notifier;

  private constructor(
    private backend: Backend,
    stored: { files: HouseholdText; meta: Meta },
    memoryReason: string | null,
    notifier: (tab: string) => Notifier,
  ) {
    this.snap = { ...stored, persistent: backend.persistent, memoryReason, external: false };
    const tab = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    this.notifier = backend.persistent ? notifier(tab) : { post: () => {}, listen: () => {}, close: () => {} };
    this.notifier.listen(() => void this.reload(true));
  }

  /** Open IndexedDB, or fall back to memory and say why. Never rejects. */
  static async open(env: StoreEnv = browserEnv()): Promise<HouseholdStore> {
    let backend: Backend;
    let reason: string | null = null;
    try {
      backend = await env.openBackend();
    } catch (e) {
      backend = new MemoryBackend();
      reason = reasonOf(e);
    }
    let stored;
    try {
      stored = await backend.read();
    } catch (e) {
      backend = new MemoryBackend();
      reason = reasonOf(e);
      stored = await backend.read();
    }
    const files = noFiles();
    for (const f of FILE_NAMES) files[f] = stored.files[f] ?? null;
    return new HouseholdStore(backend, { files, meta: cleanMeta(stored.meta) }, reason, env.notifier);
  }

  get snapshot(): Snapshot {
    return this.snap;
  }

  subscribe(fn: (s: Snapshot) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private emit(next: Snapshot): void {
    this.snap = next;
    for (const fn of this.listeners) fn(next);
  }

  /** IndexedDB refused a write: keep the state in memory and say so. */
  private toMemory(e: unknown): void {
    const mem = new MemoryBackend();
    void mem.writeFiles({ ...this.snap.files });
    void mem.writeMeta(this.snap.meta);
    this.backend = mem;
    this.notifier.close();
    this.emit({ ...this.snap, persistent: false, memoryReason: reasonOf(e) });
  }

  private async persist(write: (b: Backend) => Promise<void>): Promise<void> {
    try {
      await write(this.backend);
      if (this.backend.persistent) this.notifier.post();
    } catch (e) {
      this.toMemory(e);
    }
  }

  /** Replace some files (null: remove one). The text is the state. */
  async setFiles(changes: FileChanges): Promise<void> {
    this.emit({ ...this.snap, files: { ...this.snap.files, ...changes }, external: false });
    await this.persist((b) => b.writeFiles(changes));
  }

  async setMeta(patch: Partial<Meta>): Promise<void> {
    const meta = cleanMeta({ ...this.snap.meta, ...patch });
    this.emit({ ...this.snap, meta, external: false });
    await this.persist((b) => b.writeMeta(meta));
  }

  /** Remove every file and the meta from this browser. */
  async erase(): Promise<void> {
    this.emit({ ...this.snap, files: noFiles(), meta: { ...DEFAULT_META }, external: false });
    await this.persist((b) => b.clear());
  }

  /** Read the stored state again (another tab wrote it). */
  async reload(external = false): Promise<void> {
    try {
      const stored = await this.backend.read();
      const files = noFiles();
      for (const f of FILE_NAMES) files[f] = stored.files[f] ?? null;
      this.emit({ ...this.snap, files, meta: cleanMeta(stored.meta), external });
    } catch (e) {
      this.toMemory(e);
    }
  }

  close(): void {
    this.notifier.close();
    this.listeners.clear();
  }
}

export type { FileName };
