import { expect, test, type Page } from '@playwright/test';
import { tamperLedgerPayload } from './db.js';
import { createCircle, createInvite, isoDate, person, signUp, uniqueLogin } from './helpers.js';

async function drawTab(page: Page, circleId: string): Promise<void> {
  await page.goto(`/circles/${circleId}/draw`);
  await expect(page.getByTestId('draw-phase').or(page.getByTestId('open-draw'))).toBeVisible();
}

test('three members run the draw in three browsers; the browser recomputes it; the ledger verifies, and a tamper is caught', async ({ browser }) => {
  const a = await person(browser);
  const b = await person(browser);
  const c = await person(browser);
  await signUp(a.page, uniqueLogin('amal'), 'Amal');
  const name = `Draw circle ${Date.now().toString(36)}`;
  const circleId = await createCircle(a.page, { name, amount: '10', startDate: isoDate(3) });
  for (const [p, who] of [
    [b, 'Basma'],
    [c, 'Caleb'],
  ] as const) {
    await a.page.goto(`/circles/${circleId}/members`);
    const link = await createInvite(a.page);
    await p.page.goto(new URL(link).pathname);
    await p.page.getByRole('link', { name: 'Create an account' }).click();
    await signUp(p.page, uniqueLogin(who.toLowerCase()), who, '');
    await p.page.getByRole('button', { name: 'Accept and join' }).click();
    await expect(p.page.getByTestId('circle-title')).toHaveText(name);
  }

  // The organizer opens the draw.
  await drawTab(a.page, circleId);
  await a.page.getByTestId('open-draw-submit').click();
  await expect(a.page.getByTestId('draw-phase')).toHaveText('Commitments are open');

  // Each member commits from their own browser; the secret is shown once and kept on the device.
  for (const p of [a, b, c]) {
    await drawTab(p.page, circleId);
    await p.page.getByTestId('commit').click();
    await expect(p.page.getByTestId('secret')).toHaveText(/^[0-9a-f]{64}$/);
    await p.page.getByRole('button', { name: 'Continue' }).click();
    await expect(p.page.getByText('Your commitment is recorded.').first()).toBeVisible();
  }
  // Others' secrets never appear while commitments are open.
  await drawTab(c.page, circleId);
  await expect(c.page.getByTestId('draw-status')).toContainText('3 of 3 committed');

  await drawTab(a.page, circleId);
  await a.page.getByTestId('close-commits').click();
  await expect(a.page.getByTestId('draw-phase')).toHaveText('Reveals are open');

  for (const p of [a, b, c]) {
    await drawTab(p.page, circleId);
    await expect(p.page.getByText('Your secret is saved on this device.')).toBeVisible();
    await p.page.getByTestId('reveal').click();
    await expect(p.page.getByText('Your secret is revealed.').first()).toBeVisible();
  }

  await drawTab(a.page, circleId);
  await a.page.getByTestId('finalize').click();
  await expect(a.page.getByTestId('draw-phase')).toHaveText('The order is drawn');
  await expect(a.page.getByTestId('drawn-member')).toHaveCount(3);
  await expect(a.page.getByTestId('seed')).toHaveText(/^[0-9a-f]{64}$/);

  // A member recomputes the order in their browser from the ledger's reveals.
  await drawTab(b.page, circleId);
  const order = await b.page.getByTestId('drawn-member').allTextContents();
  expect(new Set(order)).toEqual(new Set(['Amal', 'Basma', 'Caleb']));
  await b.page.getByTestId('recompute').click();
  await expect(b.page.getByTestId('recompute-result')).toHaveAttribute('data-ok', 'true');
  await expect(b.page.getByTestId('recompute-result')).toHaveText('Recomputed here from the revealed secrets: the same seed and the same order.');

  // The ledger verifies green in the browser, newest entry first, with readable summaries.
  await c.page.goto(`/circles/${circleId}/ledger`);
  await expect(c.page.getByTestId('ledger-entry').first()).toHaveAttribute('data-seq', '13');
  await expect(c.page.getByTestId('entry-summary').first()).toContainText('Turn order drawn: 1.');
  await expect(c.page.getByTestId('ledger-freshness')).toContainText('As of');
  await c.page.getByTestId('verify-chain').click();
  await expect(c.page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'true');
  await expect(c.page.getByTestId('verify-result')).toHaveText('Chain verified in this browser: 13 entries, nothing changed.');

  // Offline: the copy on screen is labelled as not current (A10).
  await c.context.setOffline(true);
  await c.page.getByTestId('ledger-refresh').click();
  await expect(c.page.getByTestId('offline-banner')).toBeVisible();
  await expect(c.page.getByTestId('ledger-freshness')).toContainText('may not be current');
  await c.context.setOffline(false);

  // Someone edits entry 2 directly in the database file: the chain breaks exactly there.
  tamperLedgerPayload(circleId, 2, (p) => p.replace('"displayName":"Amal"', '"displayName":"Amal (edited)"'));
  await c.page.getByTestId('ledger-refresh').click();
  await expect(c.page.getByTestId('ledger-freshness')).toContainText('As of');
  await c.page.getByTestId('verify-chain').click();
  await expect(c.page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'false');
  await expect(c.page.getByTestId('verify-result')).toHaveAttribute('data-seq', '2');
  await expect(c.page.getByTestId('verify-result')).toHaveText('Chain broken at entry 2: its content no longer matches its hash.');

  await a.context.close();
  await b.context.close();
  await c.context.close();
});

test('statement: whole circle and mine, ledger links, CSV download', async ({ browser }) => {
  const a = await person(browser);
  const b = await person(browser);
  await signUp(a.page, uniqueLogin('dina'), 'Dina');
  const circleId = await createCircle(a.page, { name: 'Statement circle', amount: '7.250', startDate: isoDate(0) });
  const link = await createInvite(a.page);
  await b.page.goto(new URL(link).pathname);
  await b.page.getByRole('link', { name: 'Create an account' }).click();
  await signUp(b.page, uniqueLogin('emad'), 'Emad', '');
  await b.page.getByRole('button', { name: 'Accept and join' }).click();
  await a.page.goto(`/circles/${circleId}/members`);
  await a.page.getByTestId('save-order').click();
  await a.page.getByTestId('start-circle').click();
  await a.page.getByTestId('start-circle-confirm').click();
  await expect(a.page.getByTestId('round-status')).toHaveText('Open');

  await b.page.goto(`/circles/${circleId}`);
  await b.page.getByTestId('report-my-payment').click();
  await b.page.getByRole('button', { name: 'Report payment' }).click();
  await expect(b.page.getByTestId('state-chip').last()).toBeVisible();

  await a.page.goto(`/circles/${circleId}/statement`);
  await expect(a.page.getByTestId('statement-round')).toHaveCount(2);
  await expect(a.page.getByTestId('total-expected')).toHaveText('14.500 OMR');
  await expect(a.page.getByTestId('total-outstanding')).toHaveText('14.500 OMR');
  const emad = a.page.getByTestId('statement-round').first().getByTestId('statement-line').filter({ hasText: 'Emad' });
  await expect(emad.getByTestId('state-chip')).toHaveText('Reported');
  await emad.getByTestId('seq-links').getByRole('link').first().click();
  await expect(a.page).toHaveURL(/\/ledger#seq-\d+$/);
  await expect(a.page.locator('[data-testid="ledger-entry"].highlight')).toContainText('Payment reported');

  await a.page.goto(`/circles/${circleId}/statement`);
  const download = a.page.waitForEvent('download');
  await a.page.getByTestId('statement-csv').click();
  const file = await download;
  expect(file.suggestedFilename()).toBe(`dawr-statement-${circleId}.csv`);

  await b.page.goto(`/circles/${circleId}/statement`);
  await b.page.getByRole('button', { name: 'Mine' }).click();
  await expect(b.page.getByTestId('statement-line')).toHaveCount(2);
  await expect(b.page.getByTestId('statement-line').first()).toContainText('Emad');
  await a.context.close();
  await b.context.close();
});
