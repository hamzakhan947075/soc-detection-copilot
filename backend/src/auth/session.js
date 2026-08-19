'use strict';

const crypto = require('crypto');
const config = require('../config/env');

/**
 * Minimal signed session token - no database, no third-party session store.
 * A session is just `{payload}.{hmac}` where the HMAC is over the base64url
 * payload using config.auth.sessionSecret. Verifying re-computes the HMAC
 * and compares it in constant time, then checks expiry. There is nothing to
 * revoke server-side (no session table) - logout simply clears the cookie,
 * and a token stops validating entirely once SESSION_SECRET changes (e.g.
 * on a restart, if one wasn't explicitly configured).
 */

const COOKIE_NAME = 'soc_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', config.auth.sessionSecret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/** Returns the decoded payload if `token` is a validly-signed, unexpired session, else null. */
function verify(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;

  const expectedSig = crypto.createHmac('sha256', config.auth.sessionSecret).update(body).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    return payload;
  } catch (_err) {
    return null;
  }
}

function createSessionToken() {
  return sign({ iat: Date.now(), exp: Date.now() + SESSION_TTL_MS });
}

/** Parses a `Cookie` request header into a plain {name: value} map. No dependency on a cookie-parsing library for one cookie. */
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(value);
    } catch (_err) {
      out[name] = value;
    }
  }
  return out;
}

module.exports = { COOKIE_NAME, SESSION_TTL_MS, createSessionToken, verify, parseCookies };
