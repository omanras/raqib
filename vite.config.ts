import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as {
  version: string;
};

// One static HTML file, no server, no network (ADR-0001-app section 1).
export default defineConfig({
  base: "./",
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  esbuild: {
    jsx: "automatic",
    jsxImportSource: "preact",
  },
  plugins: [viteSingleFile({ removeViteModuleLoader: true })],
  build: {
    target: "es2022",
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    modulePreload: false,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  preview: {
    port: 4173,
    strictPort: true,
  },
});
