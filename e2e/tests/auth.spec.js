// @ts-check
const { test, expect } = require('@playwright/test');

const BASE = 'http://localhost:4101'; // APP_PASSWORD=e2e-test-password (see playwright.config.js)

test.describe('opt-in authentication, in a real browser', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
  });

  test('requires login, rejects a wrong password, then accepts the right one and allows logout', async ({ page }) => {
    await page.goto(BASE);

    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    // The rest of the app must not be usable behind the login screen.
    await expect(page.locator('.tab-btn')).toHaveCount(0);

    await page.locator('#loginPassword').fill('the-wrong-password');
    await page.locator('#loginBtn').click();

    const errorBox = page.locator('#loginError .error-box');
    await expect(errorBox).toBeVisible();
    await expect(errorBox).toHaveText('Incorrect password.');
    // Still on the login screen - a failed attempt must not grant access.
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

    await page.locator('#loginPassword').fill('e2e-test-password');
    await page.locator('#loginBtn').click();

    // A successful login renders the real app and shows the logout control.
    await expect(page.getByRole('heading', { name: 'SOC Detection Copilot' })).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#logoutBtn')).toBeVisible();

    // The session cookie persists across a reload - no re-login required.
    await page.reload();
    await expect(page.getByRole('heading', { name: 'SOC Detection Copilot' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Sign in' })).toHaveCount(0);

    // Logging out clears the session (and reloads the page), so the login
    // screen appears again instead of the app.
    await page.locator('#logoutBtn').click();
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 10000 });
  });

  test('pressing Enter in the password field submits the form', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('#loginPassword').fill('e2e-test-password');
    await page.locator('#loginPassword').press('Enter');
    await expect(page.getByRole('heading', { name: 'SOC Detection Copilot' })).toBeVisible({ timeout: 10000 });
  });
});
