'use strict';

const request = require('supertest');
const config = require('../src/config/env');
const { createApp } = require('../src/app');
const { createSessionToken, verify, COOKIE_NAME } = require('../src/auth/session');
const { isAuthConfigured, isAuthenticated, requireAuth } = require('../src/auth/authMiddleware');

describe('auth/session - signed session tokens', () => {
  const originalSecret = config.auth.sessionSecret;
  afterEach(() => {
    config.auth.sessionSecret = originalSecret;
  });

  test('a freshly created token verifies successfully', () => {
    const token = createSessionToken();
    expect(verify(token)).not.toBeNull();
  });

  test('a tampered signature is rejected', () => {
    const token = createSessionToken();
    const [body] = token.split('.');
    expect(verify(`${body}.not-the-real-signature`)).toBeNull();
  });

  test('a token signed with a different secret is rejected (e.g. after a restart with no fixed SESSION_SECRET)', () => {
    const token = createSessionToken();
    config.auth.sessionSecret = 'a-completely-different-secret';
    expect(verify(token)).toBeNull();
  });

  test('an expired token is rejected even with a valid signature', () => {
    // Build a token identical to createSessionToken() but already expired.
    const crypto = require('crypto');
    const payload = { iat: Date.now() - 1000, exp: Date.now() - 500 };
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', config.auth.sessionSecret).update(body).digest('base64url');
    expect(verify(`${body}.${sig}`)).toBeNull();
  });

  test('garbage input never throws', () => {
    expect(verify(undefined)).toBeNull();
    expect(verify(null)).toBeNull();
    expect(verify('not-a-token')).toBeNull();
    expect(verify('..')).toBeNull();
  });
});

describe('authMiddleware - no-op when auth is not configured', () => {
  const originalPassword = config.auth.password;
  afterEach(() => {
    config.auth.password = originalPassword;
  });

  test('isAuthConfigured/isAuthenticated/requireAuth all behave as open access with no APP_PASSWORD', () => {
    config.auth.password = '';
    expect(isAuthConfigured()).toBe(false);
    expect(isAuthenticated({ headers: {} })).toBe(true);

    const next = jest.fn();
    requireAuth({ headers: {} }, { status: () => ({ json: () => {} }) }, next);
    expect(next).toHaveBeenCalledTimes(1);
  });
});

describe('Auth API (end-to-end via the real app)', () => {
  const originalPassword = config.auth.password;
  let app;

  beforeEach(() => {
    config.auth.password = 'correct-horse-battery-staple';
    app = createApp();
  });

  afterEach(() => {
    config.auth.password = originalPassword;
  });

  test('GET /api/auth/status reports authRequired:true and authenticated:false with no cookie', async () => {
    const res = await request(app).get('/api/auth/status');
    expect(res.body).toEqual({ authRequired: true, authenticated: false });
  });

  test('a protected route 401s with no session cookie', async () => {
    const res = await request(app).get('/api/pipeline');
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('unauthenticated');
  });

  test('POST /api/auth/login with the wrong password is rejected and sets no cookie', async () => {
    const res = await request(app).post('/api/auth/login').send({ password: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  test('logging in with the correct password grants access to a protected route via the session cookie', async () => {
    const loginRes = await request(app).post('/api/auth/login').send({ password: 'correct-horse-battery-staple' });
    expect(loginRes.status).toBe(200);
    const setCookie = loginRes.headers['set-cookie'];
    expect(setCookie).toBeDefined();
    expect(setCookie[0]).toMatch(new RegExp(`^${COOKIE_NAME}=`));
    expect(setCookie[0]).toMatch(/HttpOnly/);

    const cookie = setCookie[0].split(';')[0];
    const protectedRes = await request(app).get('/api/pipeline').set('Cookie', cookie);
    expect(protectedRes.status).toBe(200);

    const statusRes = await request(app).get('/api/auth/status').set('Cookie', cookie);
    expect(statusRes.body).toEqual({ authRequired: true, authenticated: true });
  });

  test('logging out clears the cookie and access is denied again', async () => {
    const loginRes = await request(app).post('/api/auth/login').send({ password: 'correct-horse-battery-staple' });
    const cookie = loginRes.headers['set-cookie'][0].split(';')[0];

    const logoutRes = await request(app).post('/api/auth/logout').set('Cookie', cookie);
    expect(logoutRes.status).toBe(200);
    const clearedCookie = logoutRes.headers['set-cookie'][0];
    expect(clearedCookie).toMatch(/Max-Age=0/);
  });

  test('never leaks or echoes the configured password anywhere in a response', async () => {
    const res = await request(app).post('/api/auth/login').send({ password: 'wrong-guess' });
    expect(JSON.stringify(res.body)).not.toContain('correct-horse-battery-staple');
  });

  test('/health and /ready remain reachable without authentication', async () => {
    const health = await request(app).get('/health');
    expect(health.status).toBe(200);
    const ready = await request(app).get('/ready');
    expect(ready.status).toBe(200);
    expect(ready.body.authRequired).toBe(true);
  });
});

describe('Auth API - disabled (no APP_PASSWORD configured)', () => {
  const originalPassword = config.auth.password;
  let app;

  beforeEach(() => {
    config.auth.password = '';
    app = createApp();
  });

  afterEach(() => {
    config.auth.password = originalPassword;
  });

  test('every API route is reachable with no login at all', async () => {
    const res = await request(app).get('/api/pipeline');
    expect(res.status).toBe(200);
  });

  test('GET /api/auth/status reports authRequired:false, authenticated:true', async () => {
    const res = await request(app).get('/api/auth/status');
    expect(res.body).toEqual({ authRequired: false, authenticated: true });
  });
});
