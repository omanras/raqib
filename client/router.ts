import { useEffect, useState } from 'preact/hooks';

/**
 * A hand-written history router. The server answers every non-API path with
 * the client (SPA fallback), so links like /join/<token> work directly.
 */
type Listener = () => void;
const listeners = new Set<Listener>();

function notify(): void {
  for (const l of listeners) l();
}

if (typeof window !== 'undefined') {
  window.addEventListener('popstate', notify);
}

export function currentPath(): string {
  return typeof window === 'undefined' ? '/' : window.location.pathname;
}

export function navigate(to: string, options: { replace?: boolean } = {}): void {
  if (to === currentPath() + window.location.search) return;
  if (options.replace) window.history.replaceState(null, '', to);
  else window.history.pushState(null, '', to);
  window.scrollTo(0, 0);
  notify();
}

export function useLocation(): string {
  const [path, setPath] = useState(currentPath());
  useEffect(() => {
    const l = (): void => setPath(currentPath());
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return path;
}

/**
 * Matches "/circles/:id/rounds/:n" against a path; returns the params or null.
 * Params are URI-decoded; a malformed escape does not match.
 */
export function matchRoute(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/').filter(Boolean);
  const s = path.split('/').filter(Boolean);
  if (p.length !== s.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < p.length; i += 1) {
    const part = p[i] as string;
    const seg = s[i] as string;
    if (part.startsWith(':')) {
      try {
        params[part.slice(1)] = decodeURIComponent(seg);
      } catch {
        return null;
      }
    } else if (part !== seg) {
      return null;
    }
  }
  return params;
}

/** Internal link: client-side navigation unless a modifier key asks for a new tab. */
export function onLinkClick(e: MouseEvent, href: string): void {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  navigate(href);
}
