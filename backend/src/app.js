'use strict';

const express = require('express');
const cors = require('cors');
const path = require('path');

const config = require('./config/env');
const apiRouter = require('./routes/api');
const { securityHeaders, apiRateLimiter, errorHandler } = require('./security/middleware');

function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(securityHeaders());
  app.use(cors({ origin: config.nodeEnv === 'production' ? false : true }));
  app.use(express.json({ limit: config.upload.maxPasteBytes }));
  app.use('/api', apiRateLimiter());
  app.use('/api', apiRouter);

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  const frontendDir = path.join(__dirname, '..', '..', 'frontend');
  app.use(express.static(frontendDir));
  app.get('/', (_req, res) => res.sendFile(path.join(frontendDir, 'index.html')));

  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
