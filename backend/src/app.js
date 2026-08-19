'use strict';

const express = require('express');
const cors = require('cors');
const path = require('path');

const config = require('./config/env');
const apiRouter = require('./routes/api');
const authRouter = require('./routes/authRoutes');
const { requireAuth, isAuthConfigured } = require('./auth/authMiddleware');
const { securityHeaders, apiRateLimiter, errorHandler } = require('./security/middleware');

function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(securityHeaders());
  app.use(cors({ origin: config.nodeEnv === 'production' ? false : true }));
  app.use(express.json({ limit: config.upload.maxPasteBytes }));
  app.use('/api', apiRateLimiter());
  // /api/auth/* (login/logout/status) is always reachable - everything else
  // under /api requires a valid session once APP_PASSWORD is configured.
  // isAuthConfigured() false makes requireAuth a no-op, so local/dev use
  // without APP_PASSWORD set is unaffected.
  app.use('/api/auth', authRouter);
  app.use('/api', requireAuth);
  app.use('/api', apiRouter);

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/ready', (_req, res) => res.json({ status: 'ready', authRequired: isAuthConfigured() }));

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
