import { defineConfig } from "vitest/config";

// Unit and differential tests only; Playwright specs live in e2e/ (and
// tests/e2e/ until e2e/ exists) and are excluded here.
export default defineConfig({
  esbuild: {
    jsx: "automatic",
    jsxImportSource: "preact",
  },
  test: {
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
    exclude: ["node_modules", "dist", "e2e", "tests/e2e"],
    environment: "node",
  },
});
