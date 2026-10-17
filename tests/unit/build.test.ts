import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (p: string) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');
const tracked = () => execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n');

describe('S7 dependencies and build', () => {
  it('S7.1 deps.audit: the gate fails on high+ production advisories unless each is documented', () => {
    const gate = read('tools/gate.sh');
    expect(gate).toContain('npm audit --audit-level=high --omit=dev');
    expect(gate).toContain('docs/review/audit-exceptions.md');
    expect(gate).toMatch(/RED: npm audit high\+ findings/);
  });

  it('S7.2 deps.lockfile: package-lock.json is committed and installs use npm ci', () => {
    const files = tracked();
    expect(files).toContain('package-lock.json');
    const lock = JSON.parse(read('package-lock.json')) as { lockfileVersion: number; packages: Record<string, unknown> };
    expect(lock.lockfileVersion).toBeGreaterThanOrEqual(3);
    expect(Object.keys(lock.packages).length).toBeGreaterThan(50);
    expect(read('tools/gate.sh')).toContain('npm ci');
    expect(read('.github/workflows/gate.yml')).toContain('npm ci');
    // Nothing that belongs to a machine is in the tree.
    expect(files.some((f) => f.startsWith('node_modules/') || f.includes('/dist/') || f.endsWith('.sqlite'))).toBe(false);
  });

  it.skipIf(!existsSync(new URL('../../deploy/Dockerfile', import.meta.url)))(
    'S7.3 container.non-root: the image runs as a non-root user with /data as its only volume and a health check',
    () => {
      const docker = read('deploy/Dockerfile');
      const user = [...docker.matchAll(/^USER\s+(\S+)/gm)].at(-1)?.[1];
      expect(user).toBeDefined();
      expect(user).not.toMatch(/^(root|0)(:|$)/);
      expect(docker).toMatch(/^VOLUME\s+\[?"?\/data/m);
      expect(docker).toMatch(/^HEALTHCHECK\s/m);
      expect(docker).toMatch(/\/api\/health/);
      const compose = read('deploy/compose.yml');
      expect(compose).toMatch(/read_only:\s*true/);
      expect(compose).toMatch(/\/data/);
    },
  );
});
