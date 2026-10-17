import { readFileSync } from 'node:fs';
import preact from '@preact/preset-vite';
import { defineConfig } from 'vite';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };

// The client is built into client/dist and served by the Fastify server from
// the same origin. Nothing is inlined as a data URI and nothing is loaded from
// the web (A7, S5.1).
export default defineConfig({
  root: 'client',
  publicDir: false,
  plugins: [preact()],
  define: {
    __DAWR_VERSION__: JSON.stringify(pkg.version),
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
    target: 'es2022',
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:3000' },
  },
});
