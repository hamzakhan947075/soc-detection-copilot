// @ts-check
const { test, expect } = require('@playwright/test');

const BASE = 'http://localhost:4102'; // AI_PROVIDER=custom pointed at fixtures/fake-ai-server.js (see playwright.config.js)

test.describe('AI-suggested detections, in a real browser against a real (stubbed) AI provider', () => {
  test('is additive to the deterministic results, clearly labeled, and survives a real network round trip', async ({ page }) => {
    await page.goto(BASE);

    await page.locator('.tab-btn[data-tab="ingestion"]').click();
    await page.locator('.sample-chip[data-name="ssh_auth"]').click();
    await expect(page.locator('.tab-btn[data-tab="fields"].active')).toBeVisible();

    await page.locator('.tab-btn[data-tab="ecs"]').click();
    await page.locator('#approveBtn').click();
    await expect(page.locator('#normalizedPreview')).toContainText('Normalized Event Preview', { timeout: 15000 });

    await page.locator('.tab-btn[data-tab="detection"]').click();

    // With a real AI provider configured (even a stubbed one), the button
    // must actually be offered - this is the opt-in, additive feature, not
    // a hidden/disabled one once AI is available.
    const suggestAiBtn = page.locator('#suggestAiBtn');
    await expect(suggestAiBtn).toBeVisible();

    await page.locator('#runDetectBtn').click();
    await expect(page.locator('#detectionResults .detection-card').first()).toBeVisible({ timeout: 15000 });
    const deterministicCount = await page.locator('#detectionResults .detection-card').count();
    expect(deterministicCount).toBeGreaterThan(0);
    await expect(page.locator('.badge.ai-suggested')).toHaveCount(0);

    await suggestAiBtn.click();
    await expect(page.locator('#statusMessage')).toContainText('verified against your real data', { timeout: 15000 });

    // Additive: the deterministic cards are still there, plus exactly one
    // new, clearly-labeled AI-suggested card.
    const totalCount = await page.locator('#detectionResults .detection-card').count();
    expect(totalCount).toBe(deterministicCount + 1);
    const aiCard = page.locator('#detectionResults .detection-card').filter({ has: page.locator('.badge.ai-suggested') });
    await expect(aiCard).toHaveCount(1);
    await expect(aiCard).toContainText('AI-observed repeated auth failures (stub)');
    await expect(page.locator('#detectionResults .error-box')).toHaveCount(0);

    // Re-running the deterministic analysis must not wipe out the AI card.
    await page.locator('#runDetectBtn').click();
    await expect(page.locator('#detectionResults .detection-card').first()).toBeVisible({ timeout: 15000 });
    await expect(page.locator('.badge.ai-suggested')).toHaveCount(1);
  });

  test('AI-suggested detections are unavailable and clearly explained (not hidden) when AI is not configured', async ({ page }) => {
    await page.goto('http://localhost:4100'); // the no-auth, no-AI server from playwright.config.js
    await page.locator('.tab-btn[data-tab="ingestion"]').click();
    await page.locator('.sample-chip[data-name="ssh_auth"]').click();
    await page.locator('.tab-btn[data-tab="ecs"]').click();
    await page.locator('#approveBtn').click();
    await expect(page.locator('#normalizedPreview')).toContainText('Normalized Event Preview', { timeout: 15000 });

    await page.locator('.tab-btn[data-tab="detection"]').click();
    await expect(page.locator('#suggestAiBtn')).toHaveCount(0);
    await expect(page.locator('#content')).toContainText('AI-suggested detections need AI configured');
  });
});
