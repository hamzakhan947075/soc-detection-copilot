// @ts-check
const { test, expect } = require('@playwright/test');

const BASE = 'http://localhost:4100';

test.describe('frontend error handling, in a real browser', () => {
  test('a disallowed file extension shows a visible, safely-escaped error box (no fetch involved)', async ({ page }) => {
    let dialogFired = false;
    page.on('dialog', () => {
      dialogFired = true;
    });

    await page.goto(BASE);
    await page.locator('.tab-btn[data-tab="ingestion"]').click();

    // The filename itself carries an HTML-injection attempt; handleFile()'s
    // extension check runs entirely client-side (no network round trip) and
    // showIngestError() must render it through escapeHtml, not raw innerHTML.
    const maliciousName = '<img src=x onerror=alert(1)>evil.exe';
    await page.locator('#fileInput').setInputFiles({
      name: maliciousName,
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('not a real executable'),
    });

    const errorBox = page.locator('#ingestResult .error-box');
    await expect(errorBox).toBeVisible();
    await expect(errorBox).toContainText('.exe" is not allowed');
    // The <img> must never become a real element in the DOM.
    await expect(errorBox.locator('img')).toHaveCount(0);
    expect(dialogFired).toBe(false);

    // Footer status also reflects the error, in red.
    await expect(page.locator('#statusMessage')).toContainText('is not allowed');
  });

  test('an empty paste shows a client-side validation message without hitting the API', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.tab-btn[data-tab="ingestion"]').click();

    let requestFired = false;
    await page.route('**/api/sessions', (route) => {
      requestFired = true;
      route.continue();
    });

    await page.locator('#pasteSubmit').click();
    await expect(page.locator('#statusMessage')).toContainText('Paste some log content first.');
    expect(requestFired).toBe(false);
  });

  test('empty tabs before any session show their guidance text, not a crash', async ({ page }) => {
    await page.goto(BASE);
    for (const tabId of ['fields', 'ecs', 'detection', 'rules', 'testing', 'falsepositive', 'tuning', 'reports']) {
      await page.locator(`.tab-btn[data-tab="${tabId}"]`).click();
      await expect(page.locator('#content .card')).toBeVisible();
      await expect(page.locator('#content .error-box')).toHaveCount(0);
    }
  });
});
