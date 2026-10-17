import { expect, test, type Page } from '@playwright/test';
import { createCircle, createInvite, isoDate, person, signUp, uniqueLogin } from './helpers.js';

/** Fits every free-text field (names are at most 60 characters). */
const XSS = '<img src=x onerror=window.__xss=1>';

async function assertInert(page: Page, where: string): Promise<void> {
  expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss), `script ran on ${where}`).toBeUndefined();
  expect(await page.locator('img[src="x"]').count(), `an <img> was injected on ${where}`).toBe(0);
}

test('S4.3 xss.*: payloads in every free-text field render as text and never run', async ({ browser }) => {
  const a = await person(browser);
  const b = await person(browser);
  const violations: string[] = [];
  for (const p of [a.page, b.page]) {
    p.on('console', (m) => {
      if (m.type() === 'error' && /Content Security Policy/i.test(m.text())) violations.push(m.text());
    });
  }
  // Display name, circle name, rules, a member's name in the circle, method, reference, waiver reason, payout fields.
  await signUp(a.page, uniqueLogin('xssorg'), XSS);
  const circleId = await createCircle(a.page, { name: `${XSS} circle`, amount: '5', startDate: isoDate(0), rules: `${XSS}\nline two` });
  const link = await createInvite(a.page);
  await b.page.goto(new URL(link).pathname);
  await b.page.getByRole('link', { name: 'Create an account' }).click();
  await signUp(b.page, uniqueLogin('xssmem'), `${XSS} B`, '');
  await expect(b.page.getByTestId('join-circle-name')).toHaveText(`${XSS} circle`);
  await expect(b.page.getByTestId('join-preview')).toContainText(XSS);
  await assertInert(b.page, 'join preview');
  await b.page.getByLabel('Your name in this circle').fill(`${XSS} in circle`);
  await b.page.getByRole('button', { name: 'Accept and join' }).click();

  await a.page.goto(`/circles/${circleId}/members`);
  await expect(a.page.getByTestId('member-name').filter({ hasText: `${XSS} in circle` })).toHaveCount(1);
  await a.page.getByTestId('save-order').click();
  await a.page.getByTestId('start-circle').click();
  await a.page.getByTestId('start-circle-confirm').click();
  await expect(a.page.getByTestId('round-status')).toHaveText('Open');

  await b.page.goto(`/circles/${circleId}`);
  await b.page.getByTestId('report-my-payment').click();
  await b.page.getByLabel('How it was paid').fill(XSS);
  await b.page.getByLabel('Reference').fill(`${XSS} ref`);
  await b.page.getByRole('button', { name: 'Report payment' }).click();
  await expect(b.page.getByTestId('overview-member').filter({ hasText: `${XSS} in circle` })).toHaveCount(1);

  await a.page.goto(`/circles/${circleId}/rounds/1`);
  const orgLine = a.page.getByTestId('line').first();
  await orgLine.getByTestId('waive').click();
  await a.page.getByLabel('Reason for waiving').fill(`${XSS} reason`);
  await a.page.getByRole('button', { name: 'Waive this contribution' }).click();
  await expect(a.page.getByText(`${XSS} reason`)).toBeVisible();
  await expect(a.page.getByTestId('reports')).toContainText(`${XSS} ref`);
  await a.page.getByLabel('Amount paid out').fill('5');
  await a.page.getByLabel('How it was paid', { exact: false }).last().fill(XSS);
  await a.page.getByLabel('Reference', { exact: false }).last().fill(XSS);
  await a.page.getByRole('button', { name: 'Record payout' }).click();
  await expect(a.page.getByTestId('payout-status')).toBeVisible();

  for (const [page, path] of [
    [a.page, '/circles'],
    [a.page, `/circles/${circleId}`],
    [a.page, `/circles/${circleId}/members`],
    [a.page, `/circles/${circleId}/rounds/1`],
    [a.page, `/circles/${circleId}/ledger`],
    [a.page, `/circles/${circleId}/statement`],
    [a.page, `/circles/${circleId}/settings`],
    [a.page, `/circles/${circleId}/audit`],
    [a.page, '/account'],
    [b.page, `/circles/${circleId}`],
    [b.page, `/circles/${circleId}/ledger`],
  ] as const) {
    await page.goto(path);
    await expect(page.getByTestId('brand')).toBeVisible();
    await page.waitForLoadState('networkidle');
    await assertInert(page, path);
  }
  // The payloads are on screen, as text.
  await a.page.goto(`/circles/${circleId}/ledger`);
  await expect(a.page.getByTestId('entry-summary').filter({ hasText: XSS }).first()).toBeVisible();
  await expect(a.page.getByTestId('circle-title')).toHaveText(`${XSS} circle`);
  expect(violations).toEqual([]);

  // A second circle, cancelled with a payload as the reason.
  const other = await createCircle(a.page, { name: 'Cancel me', amount: '1' });
  await a.page.goto(`/circles/${other}/settings`);
  await a.page.getByTestId('cancel-circle').click();
  await a.page.getByLabel('Reason, shown to members').fill(XSS);
  await a.page.getByTestId('cancel-circle-confirm').click();
  await a.page.goto(`/circles/${other}/ledger`);
  await expect(a.page.getByTestId('entry-summary').first()).toContainText(XSS);
  await assertInert(a.page, 'cancelled circle ledger');
  await a.context.close();
  await b.context.close();
});

test('S2.3 csrf.e2e: a mutating request without the CSRF header is 403; a cross-site form post is refused', async ({ browser }) => {
  const a = await person(browser);
  await signUp(a.page, uniqueLogin('csrfe'), 'Csrf');
  const statuses = await a.page.evaluate(async () => {
    const json = await fetch('/api/circles', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Forged', currency: 'OMR', contribution: 1000, period: 'monthly', dueDay: 1 }),
    });
    const form = await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'x=1',
    });
    return [json.status, form.status];
  });
  expect(statuses[0]).toBe(403);
  expect([403, 415]).toContain(statuses[1]);
  await a.page.goto('/circles');
  await expect(a.page.getByText('No circles yet')).toBeVisible();
  await a.context.close();
});

test('S1.4 auth.ratelimit e2e: the 31st auth request from one address in the window is 429', async ({ browser }) => {
  const a = await person(browser);
  await a.page.goto('/signin');
  const results: number[] = [];
  for (let i = 0; i < 31; i += 1) {
    const r = await a.context.request.post('/api/auth/login', { data: { login: `nobody${i}`, password: 'not the password' } });
    results.push(r.status());
  }
  expect(results.slice(0, 30).every((s) => s !== 429)).toBe(true);
  expect(results[30]).toBe(429);
  const again = await a.context.request.post('/api/auth/signup', { data: { login: 'late', displayName: 'Late', password: 'whatever passphrase' } });
  expect(again.status()).toBe(429);
  expect(Number(again.headers()['retry-after'])).toBeGreaterThan(0);
  await a.context.close();
});

test('S1.6 session.e2e: a copied cookie stops working after sign-out', async ({ browser }) => {
  const a = await person(browser);
  await signUp(a.page, uniqueLogin('copied'), 'Copied');
  const cookies = await a.context.cookies();
  expect(cookies.find((c) => c.name === 'dawr_session')?.httpOnly).toBe(true);
  expect((await a.context.request.get('/api/auth/me')).status()).toBe(200);
  await a.page.goto('/account');
  await a.page.getByTestId('signout').click();
  await expect(a.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  const thief = await browser.newContext();
  await thief.addCookies(cookies);
  expect((await thief.request.get('/api/auth/me')).status()).toBe(401);
  await thief.close();
  await a.context.close();
});

test('S3.1 idor.e2e: a member of another circle gets 404 for circle A ledger, statement, overview and audit', async ({ browser }) => {
  const a = await person(browser);
  const b = await person(browser);
  await signUp(a.page, uniqueLogin('owner'), 'Owner');
  const circleA = await createCircle(a.page, { name: 'Private circle', amount: '3' });
  await signUp(b.page, uniqueLogin('stranger'), 'Stranger');
  await createCircle(b.page, { name: 'Their own circle', amount: '3' });
  for (const path of ['', '/ledger', '/ledger?verify=1', '/statement', '/statement.csv', '/overview', '/audit', '/draw', '/invites']) {
    const r = await b.context.request.get(`/api/circles/${circleA}${path}`);
    expect(r.status(), path).toBe(404);
    expect(await r.text(), path).not.toContain('Private circle');
  }
  await b.page.goto(`/circles/${circleA}/ledger`);
  await expect(b.page.getByText('Not found. It may have been removed, or you are not a member.')).toBeVisible();
  await a.context.close();
  await b.context.close();
});
