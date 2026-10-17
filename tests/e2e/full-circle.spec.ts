import { expect, test, type Page } from '@playwright/test';
import { createCircle, createInvite, isoDate, person, signUp, uniqueLogin } from './helpers.js';

/**
 * The exit of v0.1 (docs/DEVELOPMENT_PLAN.md): a circle of four members runs
 * from sign-up to completion through the screens. Every member pays every
 * round, the organizer confirms, records the payout, the recipient
 * acknowledges, the round closes; after round 4 the circle is completed, the
 * statement balances and the ledger verifies.
 */
test('a full circle of 4 members from sign-up to completion', async ({ browser }) => {
  test.setTimeout(240_000);
  const names = ['Mariam', 'Nasser', 'Ola', 'Peter'];
  const people: { page: Page; name: string }[] = [];
  for (const name of names) people.push({ ...(await person(browser)), name });
  const [org] = people as [{ page: Page; name: string }];

  await signUp(org.page, uniqueLogin('mariam'), 'Mariam');
  const circleId = await createCircle(org.page, { name: 'Four friends', amount: '20', startDate: isoDate(0) });
  for (const p of people.slice(1)) {
    await org.page.goto(`/circles/${circleId}/members`);
    const link = await createInvite(org.page);
    await p.page.goto(new URL(link).pathname);
    await p.page.getByRole('link', { name: 'Create an account' }).click();
    await signUp(p.page, uniqueLogin(p.name.toLowerCase()), p.name, '');
    await p.page.getByRole('button', { name: 'Accept and join' }).click();
    await expect(p.page.getByTestId('circle-title')).toHaveText('Four friends');
  }

  // The order as joined: Mariam, Nasser, Ola, Peter. Start opens round 1 (start date today).
  await org.page.goto(`/circles/${circleId}/members`);
  await org.page.getByTestId('save-order').click();
  await org.page.getByTestId('start-circle').click();
  await org.page.getByTestId('start-circle-confirm').click();
  await expect(org.page.getByTestId('round-heading')).toHaveText('Round 1 of 4');

  for (let n = 1; n <= 4; n += 1) {
    const recipient = people[n - 1] as { page: Page; name: string };
    for (const p of people) {
      await p.page.goto(`/circles/${circleId}`);
      await expect(p.page.getByTestId('round-heading')).toHaveText(`Round ${n} of 4`);
      await p.page.getByTestId('report-my-payment').click();
      await p.page.getByRole('button', { name: 'Report payment' }).click();
      await expect(p.page.getByTestId('overview-member').filter({ hasText: p.name }).getByTestId('state-chip')).toHaveText('Reported');
    }
    await org.page.goto(`/circles/${circleId}/rounds/${n}`);
    for (let i = 0; i < 4; i += 1) {
      await org.page.getByTestId('confirm').first().click();
      await expect(org.page.getByTestId('confirm')).toHaveCount(3 - i);
    }
    await expect(org.page.getByTestId('round-totals')).toContainText('confirmed 80.000 OMR');
    await org.page.getByRole('button', { name: 'Record payout' }).click();
    await expect(org.page.getByTestId('payout-status')).toContainText('Paid 80.000 OMR');

    await recipient.page.goto(`/circles/${circleId}`);
    await expect(recipient.page.getByTestId('recipient')).toHaveText(recipient.name);
    await recipient.page.getByTestId('ack-payout').click();
    await expect(recipient.page.getByTestId('payout-line')).toContainText('The recipient acknowledged receiving it.');

    await org.page.goto(`/circles/${circleId}/rounds/${n}`);
    await org.page.getByTestId('close-round').click();
    await expect(org.page.getByTestId('round-status')).toHaveText('Closed');
    if (n < 4) {
      await org.page.goto(`/circles/${circleId}/rounds/${n + 1}`);
      await org.page.getByTestId('open-round').click();
      await expect(org.page.getByTestId('round-status')).toHaveText('Open');
    }
  }

  // Completed: everyone received once, nothing outstanding, the chain verifies.
  for (const p of people) {
    await p.page.goto(`/circles/${circleId}`);
    await expect(p.page.getByTestId('status-chip')).toHaveText('Completed');
    await expect(p.page.getByText('This circle is completed: every member has had their turn.')).toBeVisible();
  }
  await org.page.goto(`/circles/${circleId}/statement`);
  await expect(org.page.getByTestId('total-expected')).toHaveText('320.000 OMR');
  await expect(org.page.getByTestId('total-confirmed')).toHaveText('320.000 OMR');
  await expect(org.page.getByTestId('total-outstanding')).toHaveText('0.000 OMR');
  await expect(org.page.getByTestId('total-paid')).toHaveText('320.000 OMR');
  const last = people[3] as { page: Page };
  await last.page.goto(`/circles/${circleId}/ledger`);
  await last.page.getByTestId('verify-chain').click();
  await expect(last.page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'true');
  await expect(last.page.getByTestId('entry-summary').first()).toContainText('The circle completed after 4 rounds.');
  for (const p of people) await p.page.context().close();
});
