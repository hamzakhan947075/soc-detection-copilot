// @ts-check
const { defineConfig } = require('@playwright/test');

// Three real backend instances - one with no auth (golden-path/
// error-handling specs), one with APP_PASSWORD set (auth spec), and one
// with a fake AI provider configured (ai-detections spec) - each on its own
// port, each with an in-memory detection DB so a run never touches
// backend/data/detections.sqlite or leaves lifecycle rows behind. The fake
// AI server (fixtures/fake-ai-server.js) is itself started as a webServer
// entry so Playwright waits for it to be healthy before any test runs.
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
    {
      command: 'node fixtures/fake-ai-server.js',
      cwd: '.',
      url: 'http://localhost:4200/health',
      env: { FAKE_AI_PORT: '4200' },
      reuseExistingServer: false,
      timeout: 30000,
    },
    {
      command: 'node src/server.js',
      cwd: '../backend',
      url: 'http://localhost:4102/health',
      env: {
        PORT: '4102',
        DETECTION_DB_PATH: ':memory:',
        AI_PROVIDER: 'custom',
        AI_API_KEY: 'stub-key',
        AI_BASE_URL: 'http://127.0.0.1:4200',
        AI_MODEL: 'stub-model',
      },
      reuseExistingServer: false,
      timeout: 30000,
    },
  ],
});
