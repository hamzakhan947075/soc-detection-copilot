'use strict';

const express = require('express');
const request = require('supertest');
const { requestLogger } = require('../src/observability/requestLogger');

function buildTestApp() {
  const app = express();
  app.use(requestLogger());
  app.use(express.json());

  app.post('/echo', (req, res) => {
    res.status(200).json({ ok: true });
  });

  app.get('/boom', (_req, res, next) => {
    next(new Error('should never reach the log'));
  });

  app.use((err, _req, res, _next) => {
    res.locals.errorMessage = 'An internal error occurred while processing the request.';
    res.status(500).json({ error: res.locals.errorMessage });
  });

  return app;
}

describe('requestLogger', () => {
  let logSpy;

  beforeEach(() => {
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  test('logs one structured JSON line per request with the expected shape', async () => {
    const app = buildTestApp();
    await request(app).get('/echo?foo=bar').send();

    expect(logSpy).toHaveBeenCalledTimes(1);
    const logged = JSON.parse(logSpy.mock.calls[0][0]);

    expect(typeof logged.request_id).toBe('string');
    expect(logged.request_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(typeof logged.timestamp).toBe('string');
    expect(new Date(logged.timestamp).toString()).not.toBe('Invalid Date');
    expect(logged.method).toBe('GET');
    // Query string is stripped from the logged route.
    expect(logged.route).toBe('/echo');
    expect(logged.status).toBe(404);
    expect(typeof logged.duration_ms).toBe('number');
    expect(logged.duration_ms).toBeGreaterThanOrEqual(0);
  });

  test('sets an X-Request-Id response header matching the logged request_id', async () => {
    const app = buildTestApp();
    const res = await request(app).post('/echo').send({});

    expect(res.headers['x-request-id']).toBeDefined();
    const logged = JSON.parse(logSpy.mock.calls[0][0]);
    expect(res.headers['x-request-id']).toBe(logged.request_id);
  });

  test('includes the sanitized error message set on res.locals for a failed request', async () => {
    const app = buildTestApp();
    await request(app).get('/boom').send();

    const logged = JSON.parse(logSpy.mock.calls[0][0]);
    expect(logged.status).toBe(500);
    expect(logged.error).toBe('An internal error occurred while processing the request.');
    expect(logged.error).not.toMatch(/should never reach the log/);
  });

  test('never includes a submitted password or API key anywhere in the logged line', async () => {
    const app = buildTestApp();
    const secretPassword = 'S3cretPassw0rd!';
    const secretApiKey = 'sk-live-abcdef123456';

    await request(app)
      .post('/echo')
      .send({ password: secretPassword, apiKey: secretApiKey, nested: { token: secretApiKey } });

    expect(logSpy).toHaveBeenCalledTimes(1);
    const rawLine = logSpy.mock.calls[0][0];

    expect(rawLine).not.toContain(secretPassword);
    expect(rawLine).not.toContain(secretApiKey);

    const logged = JSON.parse(rawLine);
    expect(logged).not.toHaveProperty('body');
    expect(logged).not.toHaveProperty('password');
    expect(logged).not.toHaveProperty('apiKey');
  });

  test('omits the error field entirely for a successful request', async () => {
    const app = buildTestApp();
    await request(app).post('/echo').send({ hello: 'world' });

    const logged = JSON.parse(logSpy.mock.calls[0][0]);
    expect(logged.status).toBe(200);
    expect(logged).not.toHaveProperty('error');
  });
});
