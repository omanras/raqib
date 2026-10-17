import { expect, type Browser, type BrowserContext, type Page } from '@playwright/test';

export const PASSWORD = 'correct horse battery 2026';

let counter = 0;
const run = Math.floor(Math.random() * 200) + 20;

/**
 * One person = one browser context with its own address (X-Forwarded-For,
 * trusted by the e2e server like a reverse proxy) and its own cookies.
 */
export async function person(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  counter += 1;
  const context = await browser.newContext({
    extraHTTPHeaders: { 'x-forwarded-for': `198.18.${run}.${counter}` },
  });
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const page = await context.newPage();
  return { context, page };
}

export function uniqueLogin(prefix: string): string {
  counter += 1;
  return `${prefix}${Date.now().toString(36)}${counter}`.toLowerCase().slice(0, 32);
}

/** Signs up through the screens, saves the codes and lands on the next page. */
export async function signUp(page: Page, login: string, name: string, startAt = '/signup'): Promise<string[]> {
  if (startAt) await page.goto(startAt);
  await page.getByLabel('Your name').fill(name);
  await page.getByLabel('Login', { exact: true }).fill(login);
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  const codes = page.getByTestId('recovery-code');
  await expect(codes).toHaveCount(8);
  const list = await codes.allTextContents();
  const cont = page.getByRole('button', { name: 'Continue to Dawr' });
  await expect(cont).toBeDisabled();
  await page.getByLabel('I saved these codes somewhere safe').check();
  await cont.click();
  return list;
}

export async function signIn(page: Page, login: string, password = PASSWORD): Promise<void> {
  await page.goto('/signin');
  await page.getByLabel('Login', { exact: true }).fill(login);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

/** Creates a circle through the form and returns its id. */
export async function createCircle(
  page: Page,
  options: { name: string; amount?: string; currency?: string; startDate?: string; rules?: string; period?: string },
): Promise<string> {
  await page.goto('/circles/new');
  await page.getByLabel('Name of the circle').fill(options.name);
  if (options.currency) await page.getByLabel('Currency').selectOption(options.currency);
  await page.getByLabel('Contribution per member').fill(options.amount ?? '50');
  if (options.period) await page.getByRole('button', { name: options.period }).click();
  if (options.startDate) await page.getByLabel('Start date').fill(options.startDate);
  if (options.rules) await page.getByLabel('Rules').fill(options.rules);
  await page.getByRole('button', { name: 'Create circle' }).click();
  await expect(page.getByTestId('circle-title')).toHaveText(options.name);
  const id = new URL(page.url()).pathname.split('/')[2];
  if (!id) throw new Error(`no circle id in ${page.url()}`);
  return id;
}

/** The organizer creates an invitation link on the circle page and reads it. */
export async function createInvite(page: Page): Promise<string> {
  await page.getByTestId('create-invite').click();
  const link = page.getByTestId('invite-link');
  await expect(link).toBeVisible();
  return (await link.textContent())?.trim() ?? '';
}

export function isoDate(offsetDays = 0): string {
  return new Date(Date.now() + offsetDays * 86_400_000).toISOString().slice(0, 10);
}
