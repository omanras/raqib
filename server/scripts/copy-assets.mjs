// Copies the server's non-TypeScript runtime assets (SQL migrations, bundled
// word lists) next to the compiled JavaScript, keeping their relative paths.
// tsc only emits .js; without this step `npm start` would not find them.
import { cpSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const serverDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(serverDir, 'dist', 'server');
const ASSET = /\.(sql|txt|json)$/;
const SKIP = new Set(['dist', 'node_modules', 'scripts']);

function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      walk(full);
    } else if (ASSET.test(name) && name !== 'tsconfig.json') {
      const target = join(outDir, relative(serverDir, full));
      mkdirSync(dirname(target), { recursive: true });
      cpSync(full, target);
    }
  }
}

walk(serverDir);
