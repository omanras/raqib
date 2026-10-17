import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'preact',
  },
  test: {
    include: [
      'tests/unit/**/*.test.ts',
      'tests/api/**/*.test.ts',
      'shared/**/*.test.ts',
      'server/**/*.test.ts',
      'client/**/*.test.{ts,tsx}',
    ],
    exclude: ['node_modules/**', 'tests/e2e/**', '**/dist/**'],
    environment: 'node',
    pool: 'forks',
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
