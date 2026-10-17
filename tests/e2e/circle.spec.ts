import { expect, test, type Page } from '@playwright/test';
import { createCircle, createInvite, isoDate, person, signUp, uniqueLogin } from './helpers.js';

async function overview(page: Page, circleId: string): Promise<void> {
  await page.goto(`/circles/${circleId}`);
  await expect(page.getByTestId('circle-title')).toBeVisible();
}

const stateOf = (page: Page, memberName: string) =>
  page.getByTestId('overview-member').filter({ hasText: memberName }).getByTestId('state-chip');

test('organizer A and member B run round 1 from order to acknowledged payout', async ({ browser }) => {
  const a = await person(browser);
  const b = await person(browser);
  await signUp(a.page, uniqueLogin('aisha'), 'Aisha');
  const name = `Round trip ${Date.now().toString(36)}`;
  const circleId = await createCircle(a.page, { name, amount: '50', startDate: isoDate(2), rules: 'Cash to Aisha by the 5th.' });
  const link = await createInvite(a.page);
  await b.page.goto(new URL(link).pathname);
  await b.page.getByRole('link', { name: 'Create an account' }).click();
  await signUp(b.page, uniqueLogin('bilal'), 'Bilal', '');
  await b.page.getByRole('button', { name: 'Accept and join' }).click();
  await expect(b.page.getByTestId('circle-title')).toHaveText(name);

  // Before start, B's overview says what is going on.
  await overview(b.page, circleId);
  await expect(b.page.getByText('The organizer has not started the circle yet.', { exact: false })).toBeVisible();

  // A sets the order (Bilal first) and starts.
  await a.page.goto(`/circles/${circleId}/members`);
  await expect(a.page.getByTestId('order-item')).toHaveCount(2);
  await a.page.getByRole('button', { name: 'Move Bilal up' }).click();
  await expect(a.page.getByTestId('order-item').first()).toContainText('Bilal');
  await a.page.getByTestId('save-order').click();
  await expect(a.page.getByText('Turn order saved and written to the ledger.')).toBeVisible();
  await expect(a.page.getByTestId('start-card')).toContainText('Everything is ready.');
  await a.page.getByTestId('start-circle').click();
  await a.page.getByTestId('start-circle-confirm').click();
  await expect(a.page.getByTestId('round-heading')).toHaveText('Round 1 of 2');
  await expect(a.page.getByTestId('round-status')).toHaveText('Upcoming');
  await expect(a.page.getByTestId('recipient')).toHaveText('Bilal');

  // A opens round 1.
  await a.page.goto(`/circles/${circleId}/rounds/1`);
  await a.page.getByTestId('open-round').click();
  await expect(a.page.getByTestId('round-status')).toHaveText('Open');

  // B sees the open round and reports a payment from the overview.
  await overview(b.page, circleId);
  await expect(b.page.getByTestId('round-status')).toHaveText('Open');
  await expect(b.page.getByTestId('recipient')).toHaveText('Bilal');
  await expect(stateOf(b.page, 'Bilal')).toHaveText('Outstanding');
  await expect(b.page.getByTestId('pot')).toHaveText('0.000 OMR of 100.000 OMR confirmed');
  await b.page.getByTestId('report-my-payment').click();
  await expect(b.page.getByLabel('Amount', { exact: true })).toHaveValue('50.000');
  await b.page.getByLabel('How it was paid').fill('cash');
  await b.page.getByLabel('Reference').fill('envelope #7');
  await b.page.getByRole('button', { name: 'Report payment' }).click();
  await expect(stateOf(b.page, 'Bilal')).toHaveText('Reported');
  await expect(b.page.getByText('50.000 OMR reported, waiting for the organizer to confirm')).toBeVisible();

  // A confirms it on the round page.
  await a.page.goto(`/circles/${circleId}/rounds/1`);
  const bilalLine = a.page.getByTestId('line').filter({ hasText: 'Bilal' });
  await expect(bilalLine.getByTestId('reports')).toContainText('envelope #7');
  await bilalLine.getByTestId('confirm').click();
  await expect(bilalLine.getByTestId('state-chip')).toHaveText('Confirmed');
  await overview(b.page, circleId);
  await expect(stateOf(b.page, 'Bilal')).toHaveText('Confirmed');
  await expect(b.page.getByTestId('pot')).toHaveText('50.000 OMR of 100.000 OMR confirmed');

  // A records the payout; B, the recipient, acknowledges it.
  await a.page.goto(`/circles/${circleId}/rounds/1`);
  await expect(a.page.getByLabel('Amount paid out')).toHaveValue('50.000');
  await a.page.getByRole('button', { name: 'Record payout' }).click();
  await expect(a.page.getByTestId('payout-status')).toContainText('The recipient has not acknowledged it yet.');
  await overview(b.page, circleId);
  await expect(b.page.getByTestId('payout-line')).toContainText('Paid out 50.000 OMR');
  await expect(b.page.getByTestId('payout-line')).toContainText('Waiting for the recipient to acknowledge.');
  await b.page.getByTestId('ack-payout').click();
  await expect(b.page.getByTestId('payout-line')).toContainText('The recipient acknowledged receiving it.');

  // Share this round: a plain-text summary.
  await b.page.getByTestId('share-round').click();
  const shared = await b.page.evaluate(() => navigator.clipboard.readText());
  expect(shared).toContain(`${name}: round 1 of 2`);
  expect(shared).toContain('Receives: Bilal');
  expect(shared).toContain('- Bilal: Confirmed');
  expect(shared).toContain('- Aisha: Outstanding');

  // Arabic pass on the Overview.
  await b.page.getByTestId('lang-switch').click();
  await expect(b.page.locator('html')).toHaveAttribute('dir', 'rtl');
  await expect(b.page.getByTestId('round-heading')).toHaveText('الدور 1 من 2');
  await expect(b.page.getByTestId('round-status')).toHaveText('مفتوح');
  await expect(stateOf(b.page, 'Bilal')).toHaveText('مؤكَّدة');
  await expect(b.page.getByTestId('pot')).toHaveText('تأكّد 50.000 OMR من 100.000 OMR');
  await expect(b.page.getByTestId('payout-line')).toContainText('أكّد صاحب الدور الاستلام.');
  await b.page.getByTestId('lang-switch').click();

  await a.context.close();
  await b.context.close();
});

test('settings record each change; the activity log shows it; a draft cancels in two steps', async ({ browser }) => {
  const a = await person(browser);
  await signUp(a.page, uniqueLogin('hind'), 'Hind');
  const circleId = await createCircle(a.page, { name: 'Settings circle', amount: '20' });
  await a.page.goto(`/circles/${circleId}/settings`);
  await a.page.getByLabel('Rules', { exact: false }).fill('New rules: pay on Thursdays.');
  await a.page.getByRole('button', { name: 'Weekly' }).click();
  await a.page.getByRole('button', { name: 'Save changes' }).click();
  await expect(a.page.getByText('2 change(s) recorded in the ledger.')).toBeVisible();

  await a.page.goto(`/circles/${circleId}/audit`);
  await expect(a.page.getByTestId('audit-row').first()).toContainText('Rule changed');
  await expect(a.page.getByTestId('audit-row').last()).toContainText('Circle created');

  // Starting is refused with the reason shown.
  await a.page.goto(`/circles/${circleId}/members`);
  await expect(a.page.getByTestId('start-reason')).toHaveText('A circle needs at least 2 members.');

  await a.page.goto(`/circles/${circleId}/settings`);
  await a.page.getByTestId('cancel-circle').click();
  await a.page.getByLabel('Reason, shown to members').fill('Not enough people this year.');
  await a.page.getByTestId('cancel-circle-confirm').click();
  await expect(a.page.getByTestId('status-chip')).toHaveText('Cancelled');
  await a.context.close();
});
