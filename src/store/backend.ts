// Where the household's text lives: IndexedDB (database `qayd`, store
// `household` with one record per file, store `meta`), or memory when
// IndexedDB is unavailable or refuses (private mode, some sandboxes,
// file:// in some browsers). No network, ever (A7).
import { FILE_NAMES, type FileName } from "../engine/types";

export const DB_NAME = "qayd";
export const DB_VERSION = 1;
const FILES = "household";
const META = "meta";
const META_KEY = "meta";
/** IndexedDB that never answers is treated as unavailable after this long. */
const OPEN_TIMEOUT_MS = 4000;

export type FileChanges = Partial<Record<FileName, string | null>>;

export interface Stored {
  files: Partial<Record<FileName, string>>;
  meta: unknown;
}

export interface Backend {
  /** false: memory only, gone when the tab closes */
  readonly persistent: boolean;
  read(): Promise<Stored>;
  /** null removes a file (absent) */
  writeFiles(changes: FileChanges): Promise<void>;
  writeMeta(meta: unknown): Promise<void>;
  clear(): Promise<void>;
}

export class MemoryBackend implements Backend {
  readonly persistent = false;
  private files: Partial<Record<FileName, string>> = {};
  private meta: unknown = null;

  async read(): Promise<Stored> {
    return { files: { ...this.files }, meta: this.meta };
  }

  async writeFiles(changes: FileChanges): Promise<void> {
    for (const [name, text] of Object.entries(changes) as [FileName, string | null][]) {
      if (text === null) delete this.files[name];
      else this.files[name] = text;
    }
  }

  async writeMeta(meta: unknown): Promise<void> {
    this.meta = meta;
  }

  async clear(): Promise<void> {
    this.files = {};
    this.meta = null;
  }
}

function done<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB request failed"));
  });
}

function finished(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

export class IndexedDbBackend implements Backend {
  readonly persistent = true;
  constructor(private readonly db: IDBDatabase) {}

  async read(): Promise<Stored> {
    const tx = this.db.transaction([FILES, META], "readonly");
    const fileStore = tx.objectStore(FILES);
    // every request is issued before the first await, so the transaction stays active
    const requests = FILE_NAMES.map((name) => done(fileStore.get(name) as IDBRequest<unknown>));
    const metaRequest = done(tx.objectStore(META).get(META_KEY) as IDBRequest<unknown>);
    const [texts, meta] = await Promise.all([Promise.all(requests), metaRequest, finished(tx)]);
    const files: Partial<Record<FileName, string>> = {};
    FILE_NAMES.forEach((name, i) => {
      const t = texts[i];
      if (typeof t === "string") files[name] = t;
    });
    return { files, meta: meta ?? null };
  }

  async writeFiles(changes: FileChanges): Promise<void> {
    const tx = this.db.transaction(FILES, "readwrite");
    const store = tx.objectStore(FILES);
    for (const [name, text] of Object.entries(changes) as [FileName, string | null][]) {
      if (text === null) store.delete(name);
      else store.put(text, name);
    }
    await finished(tx);
  }

  async writeMeta(meta: unknown): Promise<void> {
    const tx = this.db.transaction(META, "readwrite");
    tx.objectStore(META).put(meta, META_KEY);
    await finished(tx);
  }

  async clear(): Promise<void> {
    const tx = this.db.transaction([FILES, META], "readwrite");
    tx.objectStore(FILES).clear();
    tx.objectStore(META).clear();
    await finished(tx);
  }
}

/** Open the database, or reject: unavailable, refused, or silent too long. */
export function openIndexedDb(factory: IDBFactory | null | undefined, name = DB_NAME): Promise<IndexedDbBackend> {
  return new Promise((resolve, reject) => {
    if (!factory) {
      reject(new Error("IndexedDB is not available"));
      return;
    }
    const timer = setTimeout(() => reject(new Error("IndexedDB did not answer")), OPEN_TIMEOUT_MS);
    let req: IDBOpenDBRequest;
    try {
      req = factory.open(name, DB_VERSION);
    } catch (e) {
      clearTimeout(timer);
      reject(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(FILES)) db.createObjectStore(FILES);
      if (!db.objectStoreNames.contains(META)) db.createObjectStore(META);
    };
    req.onsuccess = () => {
      clearTimeout(timer);
      resolve(new IndexedDbBackend(req.result));
    };
    req.onerror = () => {
      clearTimeout(timer);
      reject(req.error ?? new Error("IndexedDB open failed"));
    };
  });
}
