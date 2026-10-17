// The interface language: English or Arabic (right to left). A component
// reads its strings with useT(); the shell sets <html lang dir>.
import { createContext } from "preact";
import { useContext } from "preact/hooks";
import { STRINGS, type StringKey } from "./strings";

export type Language = "en" | "ar";

export const LANGUAGES: readonly Language[] = ["en", "ar"];

export function isLanguage(x: unknown): x is Language {
  return x === "en" || x === "ar";
}

export function dirOf(lang: Language): "ltr" | "rtl" {
  return lang === "ar" ? "rtl" : "ltr";
}

export type T = (key: StringKey) => string;

export function translator(lang: Language): T {
  const table = STRINGS[lang];
  return (key) => table[key];
}

export const LanguageContext = createContext<Language>("en");

export function useLanguage(): Language {
  return useContext(LanguageContext);
}

export function useT(): T {
  return translator(useContext(LanguageContext));
}

export type { StringKey };
