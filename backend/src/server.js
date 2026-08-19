'use strict';

const { createApp } = require('./app');
const config = require('./config/env');
const { sweepExpiredSessions } = require('./pipeline/sessionStore');
const { isAuthConfigured } = require('./auth/authMiddleware');

const app = createApp();

const server = app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`SOC Detection Copilot backend listening on port ${config.port} (env: ${config.nodeEnv})`);
  if (isAuthConfigured()) {
    // eslint-disable-next-line no-console
    console.log('Authentication is ENABLED (APP_PASSWORD is set) - the API and UI require login.');
  } else {
    // eslint-disable-next-line no-console
    console.warn(
      'Authentication is DISABLED (APP_PASSWORD is not set) - anyone who can reach this server has full read/write access. ' +
        'Set APP_PASSWORD before exposing this deployment beyond your own machine.'
    );
  }
});

const sweepInterval = setInterval(sweepExpiredSessions, 10 * 60 * 1000);
sweepInterval.unref();

module.exports = server;
