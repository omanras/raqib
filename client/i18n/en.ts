/** English strings. Every key here must exist in ar.ts (enforced by its type). */
export const en = {
  'app.name': 'Dawr',
  'app.tagline': 'A savings circle everyone can verify.',
  'app.version': 'Version {version}',
  'lang.switch': 'العربية',
  'lang.switch.label': 'Switch language to Arabic',
} as const;

export type MessageKey = keyof typeof en;
