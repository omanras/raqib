import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { ApiError, get } from './api.js';

export interface Loaded<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  /** When this data last came from the server (A10: never shown as current without it). */
  fetchedAt: Date | null;
  reload: () => Promise<void>;
  setData: (d: T) => void;
}

/** GETs a path and keeps the last good answer, its time, and any error. */
export function useApi<T>(path: string | null): Loaded<T> {
  const [data, setDataState] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(path !== null);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);
  const current = useRef(path);
  current.current = path;

  const reload = useCallback(async () => {
    if (path === null) return;
    setLoading(true);
    try {
      const d = await get<T>(path);
      if (current.current !== path) return;
      setDataState(d);
      setError(null);
      setFetchedAt(new Date());
    } catch (e) {
      if (current.current !== path) return;
      setError(e instanceof ApiError ? e : new ApiError(0, 'error', String(e), null));
    } finally {
      if (current.current === path) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    setDataState(null);
    setError(null);
    void reload();
  }, [reload]);

  const setData = useCallback((d: T) => {
    setDataState(d);
    setFetchedAt(new Date());
  }, []);

  return { data, error, loading, fetchedAt, reload, setData };
}

/** Runs an async action with a busy flag; errors go to the caller's handler. */
export function useAction<A extends unknown[], R>(fn: (...args: A) => Promise<R>, onError?: (e: unknown) => void) {
  const [busy, setBusy] = useState(false);
  const run = useCallback(
    async (...args: A): Promise<R | undefined> => {
      setBusy(true);
      try {
        return await fn(...args);
      } catch (e) {
        if (onError) onError(e);
        else throw e;
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [fn, onError],
  );
  return { run, busy };
}

export function useTitle(title: string): void {
  useEffect(() => {
    document.title = title ? `${title} · Dawr` : 'Dawr';
  }, [title]);
}
