'use strict';

const config = require('../config/env');
const { COOKIE_NAME, verify, parseCookies } = require('./session');

/**
 * Whether a login is required at all. Deliberately opt-in (set
 * APP_PASSWORD) rather than opt-out, so local single-analyst use stays
 * zero-config - but see server.js for the startup warning logged either
 * way, so an unauthenticated deployment is never silent about it.
 */
function isAuthConfigured() {
  return Boolean(config.auth.password);
}

/** True if the request carries a valid, unexpired session cookie. Always true when auth isn't configured. */
function isAuthenticated(req) {
  if (!isAuthConfigured()) return true;
  const cookies = parseCookies(req.headers.cookie);
  return verify(cookies[COOKIE_NAME]) !== null;
}

/** Express middleware: blocks the request with 401 unless authenticated. A no-op when auth isn't configured. */
function requireAuth(req, res, next) {
  if (isAuthenticated(req)) {
    next();
    return;
  }
  res.status(401).json({ error: 'Authentication required.', code: 'unauthenticated' });
}

module.exports = { isAuthConfigured, isAuthenticated, requireAuth };
