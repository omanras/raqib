import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';

test('the app loads from its own origin only and shows the brand and version', async ({ page, baseURL }) => {
  const foreign: string[] = [];
  page.on('request', (req) => {
    const url = req.url();
    if (!url.startsWith(baseURL ?? '') && !url.startsWith('data:') && !url.startsWith('blob:')) foreign.push(url);
  });
  await page.goto('/');
  await expect(page).toHaveURL(/\/signin/);
  await expect(page.getByTestId('brand')).toHaveText('Dawr');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Sign in');
  await expect(page.getByTestId('version')).toContainText(/\d+\.\d+\.\d+/);
  expect(foreign).toEqual([]);
});

test('the built client references no remote URL', () => {
  const dist = join(process.cwd(), 'client', 'dist');
  const offenders: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (/\.(html|js|css)$/.test(name)) {
        const text = readFileSync(full, 'utf8');
        for (const m of text.matchAll(/(?:src|href|url\()\s*=?\s*["']?(https?:\/\/[^"')\s]+)/g)) offenders.push(`${name}: ${m[1]}`);
        if (/@import\s+url\(\s*["']?https?:/.test(text)) offenders.push(`${name}: @import`);
      }
    }
  };
  walk(dist);
  expect(offenders).toEqual([]);
});

test('the colour theme switches by hand (light, dark, system)', async ({ page }) => {
  await page.goto('/signin');
  const html = page.locator('html');
  await page.getByTestId('theme-switch').click();
  await expect(html).toHaveAttribute('data-theme', 'light');
  await page.getByTestId('theme-switch').click();
  await expect(html).toHaveAttribute('data-theme', 'dark');
  await page.getByTestId('theme-switch').click();
  await expect(html).not.toHaveAttribute('data-theme', /./);
});
