import { useEffect, useState } from 'preact/hooks';

/** A tiny observable value for app-wide state (no state library). */
export class Store<T> {
  private value: T;
  private readonly listeners = new Set<(v: T) => void>();

  constructor(initial: T) {
    this.value = initial;
  }

  get(): T {
    return this.value;
  }

  set(next: T): void {
    this.value = next;
    for (const l of this.listeners) l(next);
  }

  subscribe(l: (v: T) => void): () => void {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  }
}

export function useStore<T>(store: Store<T>): T {
  const [value, setValue] = useState(store.get());
  useEffect(() => {
    setValue(store.get());
    return store.subscribe(setValue);
  }, [store]);
  return value;
}

// ---------------------------------------------------------------- session

export interface User {
  id: string;
  login: string;
  displayName: string;
  createdAt: string;
}

/** undefined while the first /api/auth/me is in flight; null when signed out. */
export const session = new Store<User | null | undefined>(undefined);

// ---------------------------------------------------------------- connection (A10)

export interface ConnectionState {
  online: boolean;
  /** When a request last reached the server. */
  lastOkAt: Date | null;
}

const connectionStore = new Store<ConnectionState>({ online: true, lastOkAt: null });

export const connection = {
  store: connectionStore,
  markOnline(): void {
    connectionStore.set({ online: true, lastOkAt: new Date() });
  },
  markOffline(): void {
    connectionStore.set({ ...connectionStore.get(), online: false });
  },
};

if (typeof window !== 'undefined') {
  window.addEventListener('offline', () => connection.markOffline());
}

// ---------------------------------------------------------------- toasts

export interface Toast {
  id: number;
  kind: 'info' | 'error';
  text: string;
  requestId?: string | null;
}

export const toasts = new Store<Toast[]>([]);
let toastId = 0;

export function toast(text: string, kind: Toast['kind'] = 'info', requestId?: string | null, ms = kind === 'error' ? 9000 : 3500): void {
  toastId += 1;
  const id = toastId;
  toasts.set([...toasts.get(), { id, kind, text, requestId }]);
  setTimeout(() => dismissToast(id), ms);
}

export function dismissToast(id: number): void {
  toasts.set(toasts.get().filter((t) => t.id !== id));
}
