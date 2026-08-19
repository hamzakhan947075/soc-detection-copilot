'use strict';

const { createApp } = require('./app');
const config = require('./config/env');
const { sweepExpiredSessions } = require('./pipeline/sessionStore');

const app = createApp();

const server = app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`SOC Detection Copilot backend listening on port ${config.port} (env: ${config.nodeEnv})`);
});

const sweepInterval = setInterval(sweepExpiredSessions, 10 * 60 * 1000);
sweepInterval.unref();

module.exports = server;
