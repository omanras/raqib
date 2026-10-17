/** Languages the application ships, complete in both (CLAUDE.md, ADR §5). */
export const LANGS = ['en', 'ar'] as const;
export type Lang = (typeof LANGS)[number];

export function isLang(value: unknown): value is Lang {
  return value === 'en' || value === 'ar';
}

export function dirOf(lang: Lang): 'ltr' | 'rtl' {
  return lang === 'ar' ? 'rtl' : 'ltr';
}
