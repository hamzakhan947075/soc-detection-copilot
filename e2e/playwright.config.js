// @ts-check
const { defineConfig } = require('@playwright/test');

// Two real backend instances: one with no auth (golden-path/error-handling
// specs) and one with APP_PASSWORD set (auth spec) - each on its own port,
// each with an in-memory detection DB so a run never touches
// backend/data/detections.sqlite or leaves lifecycle rows behind.
module.exports = defineConfig({
  testDir: './tests',
  timeout: 30000,
  expect: { timeout: 10000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: 'node src/server.js',
      cwd: '../backend',
      url: 'http://localhost:4100/health',
      env: { PORT: '4100', DETECTION_DB_PATH: ':memory:' },
      reuseExistingServer: false,
      timeout: 30000,
    },
    {
      command: 'node src/server.js',
      cwd: '../backend',
      url: 'http://localhost:4101/health',
      env: { PORT: '4101', APP_PASSWORD: 'e2e-test-password', DETECTION_DB_PATH: ':memory:' },
      reuseExistingServer: false,
      timeout: 30000,
    },
  ],
});
