import { expect, test } from '@playwright/test';
import { createCircle, createInvite, person, signUp, uniqueLogin } from './helpers.js';

test('two people: A creates a circle and invites, B joins from the link, both see it; Arabic is RTL', async ({ browser }) => {
  const a = await person(browser);
  const b = await person(browser);
  const aLogin = uniqueLogin('amna');
  const bLogin = uniqueLogin('badr');

  // A signs up (the 8 recovery codes are shown once), lands on an empty My circles.
  const codes = await signUp(a.page, aLogin, 'Amna');
  expect(new Set(codes).size).toBe(8);
  await expect(a.page.getByRole('heading', { name: 'Your circles' })).toBeVisible();
  await expect(a.page.getByText('No circles yet')).toBeVisible();

  // A creates a circle and an invitation link.
  const name = `Neighbours ${aLogin.slice(-4)}`;
  const circleId = await createCircle(a.page, { name, amount: '25.500', rules: 'Pay by the 5th.' });
  await expect(a.page.getByTestId('status-chip')).toHaveText('Draft');
  const link = await createInvite(a.page);
  expect(link).toMatch(new RegExp(`/join/[A-Za-z0-9_-]{43}$`));

  // B opens the link signed out, is asked to sign up, and comes back to the invitation.
  await b.page.goto(new URL(link).pathname);
  await expect(b.page.getByText('Sign in or create an account to see this invitation.')).toBeVisible();
  await b.page.getByRole('link', { name: 'Create an account' }).click();
  await signUp(b.page, bLogin, 'Badr', '');
  await expect(b.page.getByTestId('join-circle-name')).toHaveText(name);
  await expect(b.page.getByTestId('join-preview')).toContainText('25.500 OMR');
  await expect(b.page.getByTestId('join-preview')).toContainText('Pay by the 5th.');
  await b.page.getByRole('button', { name: 'Accept and join' }).click();
  await expect(b.page.getByTestId('circle-title')).toHaveText(name);
  await expect(b.page).toHaveURL(new RegExp(`/circles/${circleId}$`));

  // Both see the circle and both members.
  await b.page.goto('/circles');
  await expect(b.page.getByTestId('circle-name')).toHaveText([name]);
  await expect(b.page.getByTestId('role-chip')).toHaveText(['Member']);
  await a.page.reload();
  await expect(a.page.getByTestId('member-name')).toHaveCount(2);
  await a.page.goto('/circles');
  await expect(a.page.getByTestId('role-chip')).toHaveText(['Organizer']);

  // The same link does not work twice.
  await b.page.goto(new URL(link).pathname);
  await expect(b.page.getByText('This invitation does not work')).toBeVisible();

  // The Arabic switch mirrors the layout.
  await a.page.getByTestId('lang-switch').click();
  await expect(a.page.locator('html')).toHaveAttribute('dir', 'rtl');
  await expect(a.page.locator('html')).toHaveAttribute('lang', 'ar');
  await expect(a.page.getByRole('heading', { level: 1 })).toHaveText('جمعياتك');
  await expect(a.page.getByTestId('status-chip')).toHaveText('مسودة');
  // Numbers stay in Latin digits.
  await expect(a.page.getByTestId('circle-list')).toContainText('25.500 OMR');
  await a.page.getByTestId('lang-switch').click();
  await expect(a.page.locator('html')).toHaveAttribute('dir', 'ltr');

  await a.context.close();
  await b.context.close();
});

test('sign in, account, sessions and sign out everywhere', async ({ browser }) => {
  const a = await person(browser);
  const login = uniqueLogin('salma');
  await signUp(a.page, login, 'Salma');
  await a.page.getByRole('link', { name: 'Account' }).first().click();
  await expect(a.page.getByRole('heading', { name: 'Account' })).toBeVisible();
  await expect(a.page.getByTestId('codes-remaining')).toHaveText('8 unused recovery code(s) left.');
  await expect(a.page.getByTestId('sessions').getByRole('listitem')).toHaveCount(1);

  await a.page.getByRole('textbox', { name: 'Your name' }).fill('Salma H.');
  await a.page.getByRole('button', { name: 'Save' }).click();
  await expect(a.page.getByText('Your name is saved.')).toBeVisible();

  // A second device signs in; the first one sees it and signs out everywhere.
  const phone = await person(browser);
  await phone.page.goto('/signin');
  await phone.page.getByLabel('Login', { exact: true }).fill(login);
  await phone.page.getByLabel('Password', { exact: true }).fill('wrong password here');
  await phone.page.getByRole('button', { name: 'Sign in' }).click();
  await expect(phone.page.getByTestId('form-error')).toHaveText('The login or the password is not correct.');
  await phone.page.getByLabel('Password', { exact: true }).fill('correct horse battery 2026');
  await phone.page.getByRole('button', { name: 'Sign in' }).click();
  await expect(phone.page.getByRole('heading', { name: 'Your circles' })).toBeVisible();

  await a.page.reload();
  await expect(a.page.getByTestId('sessions').getByRole('listitem')).toHaveCount(2);
  await a.page.getByTestId('signout-everywhere').click();
  await expect(a.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await phone.page.goto('/account');
  await expect(phone.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(phone.page).toHaveURL(/\/signin\?next=%2Faccount$/);

  await a.context.close();
  await phone.context.close();
});

test('the create form explains amounts in the currency minor unit', async ({ browser }) => {
  const a = await person(browser);
  await signUp(a.page, uniqueLogin('noor'), 'Noor');
  await a.page.goto('/circles/new');
  const amount = a.page.getByLabel('Contribution per member');
  await amount.fill('12.3456');
  await expect(a.page.getByText('OMR has 3 decimal(s).')).toBeVisible();
  await a.page.getByLabel('Currency').selectOption('USD');
  await expect(a.page.getByText('USD has 2 decimal(s).')).toBeVisible();
  await amount.fill('-5');
  await expect(a.page.getByText('Amounts are never negative.')).toBeVisible();
  await amount.fill('1,250.50');
  await expect(a.page.getByTestId('create-summary')).toContainText('1,250.50 USD');
  await a.context.close();
});
