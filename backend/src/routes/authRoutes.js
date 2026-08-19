'use strict';

const express = require('express');
const crypto = require('crypto');
const config = require('../config/env');
const { isAuthConfigured, isAuthenticated } = require('../auth/authMiddleware');
const { COOKIE_NAME, SESSION_TTL_MS, createSessionToken } = require('../auth/session');

const router = express.Router();

function cookieHeader(token, maxAgeSeconds) {
  const secure = config.nodeEnv === 'production' ? '; Secure' : '';
  return `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${secure}`;
}

/** Whether a login is required, and whether this request already has one - the frontend uses this to decide whether to show a login screen. Never reveals anything about the configured password itself. */
router.get('/status', (req, res) => {
  res.json({ authRequired: isAuthConfigured(), authenticated: isAuthenticated(req) });
});

router.post('/login', (req, res) => {
  if (!isAuthConfigured()) {
    res.json({ success: true, authRequired: false });
    return;
  }
  const { password } = req.body || {};
  const provided = Buffer.from(String(password || ''));
  const expected = Buffer.from(config.auth.password);
  // Constant-time comparison so response timing can't be used to guess the
  // password character-by-character; length is checked first since
  // timingSafeEqual requires equal-length buffers (that check alone isn't
  // timing-sensitive information worth hiding - it doesn't reveal content).
  const valid = provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
  if (!valid) {
    res.status(401).json({ success: false, error: 'Incorrect password.' });
    return;
  }
  res.setHeader('Set-Cookie', cookieHeader(createSessionToken(), Math.floor(SESSION_TTL_MS / 1000)));
  res.json({ success: true, authRequired: true });
});

router.post('/logout', (_req, res) => {
  res.setHeader('Set-Cookie', cookieHeader('', 0));
  res.json({ success: true });
});

module.exports = router;
