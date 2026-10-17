import { Store } from './store.js';

/** 'system' follows prefers-color-scheme; 'light' and 'dark' are the manual switch. */
export type Theme = 'system' | 'light' | 'dark';
const KEY = 'dawr.theme';

function initial(): Theme {
  try {
    const v = window.localStorage.getItem(KEY);
    if (v === 'light' || v === 'dark' || v === 'system') return v;
  } catch {
    // storage unavailable
  }
  return 'system';
}

export const theme = new Store<Theme>(typeof window === 'undefined' ? 'system' : initial());

export function applyTheme(next: Theme): void {
  theme.set(next);
  if (next === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', next);
  try {
    window.localStorage.setItem(KEY, next);
  } catch {
    // ignore
  }
}

export function nextTheme(t: Theme): Theme {
  return t === 'system' ? 'light' : t === 'light' ? 'dark' : 'system';
}
