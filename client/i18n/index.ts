import { useEffect, useState } from 'preact/hooks';
import { dirOf, isLang, type Lang } from '../../shared/lang.js';
import { ar } from './ar.js';
import { en, type MessageKey } from './en.js';

export type { MessageKey };
/** Keys under a prefix, for keys built from data: `status.${status}`. */
export type MessageKeyOf<P extends string> = Extract<MessageKey, `${P}.${string}`>;

const DICTS: Record<Lang, Record<MessageKey, string>> = { en, ar };
const STORAGE_KEY = 'dawr.lang';

function initialLang(): Lang {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (isLang(stored)) return stored;
  } catch {
    // storage unavailable (private mode): fall through to the default
  }
  return 'en';
}

let lang: Lang = typeof window === 'undefined' ? 'en' : initialLang();
const listeners = new Set<() => void>();

/** Applies lang and dir to <html> so the whole layout mirrors for Arabic. */
export function applyLang(next: Lang): void {
  lang = next;
  document.documentElement.lang = next;
  document.documentElement.dir = dirOf(next);
  try {
    window.localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // ignore: the choice just will not persist
  }
  for (const l of listeners) l();
}

export function currentLang(): Lang {
  return lang;
}

export function t(key: MessageKey, params: Record<string, string | number> = {}): string {
  const template = DICTS[lang][key] ?? en[key];
  return template.replace(/\{(\w+)\}/g, (_, name: string) => {
    const v = params[name];
    return v === undefined ? `{${name}}` : String(v);
  });
}

/** Re-renders the calling component when the language changes. */
export function useLang(): Lang {
  const [value, setValue] = useState(lang);
  useEffect(() => {
    const l = (): void => setValue(lang);
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  }, []);
  return value;
}
