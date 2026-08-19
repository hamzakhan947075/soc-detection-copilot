// @ts-check
const { test, expect } = require('@playwright/test');

const BASE = 'http://localhost:4100';

test.describe('golden path: sample dataset through to a report, in a real browser', () => {
  test('walks the full pipeline end-to-end', async ({ page }) => {
    await page.goto(BASE);

    // Overview, with no session yet, shows the "get started" empty state.
    await expect(page.locator('.app-shell')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'SOC Detection Copilot' })).toBeVisible();

    // --- Ingestion: load a bundled sample dataset ---
    await page.locator('.tab-btn[data-tab="ingestion"]').click();
    const sshChip = page.locator('.sample-chip[data-name="ssh_auth"]');
    await expect(sshChip).toBeVisible();
    await sshChip.click();

    // A successful ingest auto-navigates to Field Discovery.
    await expect(page.locator('.tab-btn[data-tab="fields"].active')).toBeVisible();
    await expect(page.locator('#sessionLabel')).toContainText('events');
    await expect(page.locator('#statusMessage')).toContainText('Ingested');
    await expect(page.locator('#content table').first()).toBeVisible();

    // --- ECS Mapping: approve the suggested mappings ---
    await page.locator('.tab-btn[data-tab="ecs"]').click();
    await expect(page.getByRole('heading', { name: 'ECS Mapping Engine' })).toBeVisible();
    await expect(page.locator('#mappingBody tr').first()).toBeVisible();
    await page.locator('#approveBtn').click();
    await expect(page.locator('#normalizedPreview')).toContainText('Normalized Event Preview', { timeout: 15000 });
    await expect(page.locator('#normalizedPreview .error-box')).toHaveCount(0);

    // --- Detection Engineering ---
    await page.locator('.tab-btn[data-tab="detection"]').click();
    await page.locator('#runDetectBtn').click();
    await expect(page.locator('#detectionResults .detection-card').first()).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#detectionResults .error-box')).toHaveCount(0);
    const detectionCount = await page.locator('#detectionResults .detection-card').count();
    expect(detectionCount).toBeGreaterThan(0);

    // --- Rule Builder ---
    await page.locator('.tab-btn[data-tab="rules"]').click();
    await expect(page.getByRole('heading', { name: 'Detection Rule Generator' })).toBeVisible();
    await page.locator('#generateBtn').click();
    await expect(page.locator('#ruleOutput pre')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#ruleOutput .error-box')).toHaveCount(0);

    // --- Rule Testing ---
    await page.locator('.tab-btn[data-tab="testing"]').click();
    await expect(page.getByRole('heading', { name: 'Rule Testing' })).toBeVisible();
    await page.locator('#runTestBtn').click();
    await expect(page.locator('#testOutput .stat-card').first()).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#testOutput .error-box')).toHaveCount(0);

    // --- False Positive Analysis ---
    await page.locator('.tab-btn[data-tab="falsepositive"]').click();
    await expect(page.getByRole('heading', { name: 'False Positive Analysis' })).toBeVisible();
    await expect(page.locator('.card .error-box')).toHaveCount(0);

    // --- Detection Tuning ---
    await page.locator('.tab-btn[data-tab="tuning"]').click();
    await expect(page.getByRole('heading', { name: 'Detection Tuning' })).toBeVisible();
    const tuneBtn = page.locator('#tuneBtn');
    if (await tuneBtn.count()) {
      await tuneBtn.click();
      await expect(page.locator('#tuningOutput')).not.toBeEmpty({ timeout: 15000 });
      await expect(page.locator('#tuningOutput .error-box')).toHaveCount(0);
    }

    // --- Reports: render, then export JSON via a real browser download ---
    await page.locator('.tab-btn[data-tab="reports"]').click();
    await expect(page.getByRole('heading', { name: 'Detection Engineering Report' })).toBeVisible();
    await expect(page.locator('.card .error-box')).toHaveCount(0);

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#exportJson').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.json$/);

    // --- MITRE and Settings should also render cleanly with real session data ---
    await page.locator('.tab-btn[data-tab="mitre"]').click();
    await expect(page.getByRole('heading', { name: 'MITRE ATT&CK Mapping' })).toBeVisible();
    await expect(page.locator('#mitreDict table')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('.error-box')).toHaveCount(0);

    await page.locator('.tab-btn[data-tab="settings"]').click();
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
    await expect(page.locator('.error-box')).toHaveCount(0);

    // --- Overview dashboard reflects the completed session ---
    await page.locator('.tab-btn[data-tab="overview"]').click();
    await expect(page.getByRole('heading', { name: 'Detection Dashboard' })).toBeVisible();
    await expect(page.locator('.error-box')).toHaveCount(0);
  });
});
