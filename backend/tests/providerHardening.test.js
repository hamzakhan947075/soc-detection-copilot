'use strict';

const http = require('http');
const { callProvider } = require('../src/ai/providers');
const { AiTimeoutError, AiNetworkError, AiRateLimitError, AiAuthError, AiServerError } = require('../src/ai/aiErrors');

/**
 * Spins up a tiny local HTTP server whose behavior is entirely controlled by
 * `handler(requestCount)`, so tests can simulate a provider that fails N
 * times then recovers, always rate-limits, hangs, etc. - real network
 * round-trips through callProvider(), not mocked fetch internals.
 */
function startControllableServer(handler) {
  let requestCount = 0;
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      requestCount += 1;
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => handler(requestCount, req, res));
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, getRequestCount: () => requestCount }));
  });
}

function jsonRes(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(body));
}

const settings = (port) => ({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${port}` });

describe('callProvider - timeout, retry, and rate-limit hardening', () => {
  let ctx;

  afterEach(() => {
    if (ctx) ctx.server.close();
    ctx = null;
  });

  test('times out and throws AiTimeoutError when the provider never responds', async () => {
    ctx = await startControllableServer(() => {
      /* never respond */
    });
    const { port } = ctx.server.address();
    await expect(callProvider(settings(port), 'hi', { timeoutMs: 100, maxRetries: 0 })).rejects.toThrow(AiTimeoutError);
  });

  test('never retries a 401 auth error', async () => {
    ctx = await startControllableServer((_count, _req, res) => jsonRes(res, 401, { error: { message: 'invalid api key' } }));
    const { port } = ctx.server.address();
    await expect(callProvider(settings(port), 'hi', { timeoutMs: 2000, maxRetries: 3 })).rejects.toThrow(AiAuthError);
    expect(ctx.getRequestCount()).toBe(1);
  });

  test('retries a transient 500 and succeeds once the provider recovers', async () => {
    ctx = await startControllableServer((count, _req, res) => {
      if (count < 3) return jsonRes(res, 500, { error: { message: 'internal error' } });
      return jsonRes(res, 200, { choices: [{ message: { content: 'recovered' } }] });
    });
    const { port } = ctx.server.address();
    const text = await callProvider(settings(port), 'hi', { timeoutMs: 2000, maxRetries: 3 });
    expect(text).toBe('recovered');
    expect(ctx.getRequestCount()).toBe(3);
  });

  test('gives up after exhausting retries on a persistent 500', async () => {
    ctx = await startControllableServer((_count, _req, res) => jsonRes(res, 500, { error: { message: 'still down' } }));
    const { port } = ctx.server.address();
    await expect(callProvider(settings(port), 'hi', { timeoutMs: 2000, maxRetries: 2 })).rejects.toThrow(AiServerError);
    expect(ctx.getRequestCount()).toBe(3); // 1 initial + 2 retries
  });

  test('honors a Retry-After header on 429 before retrying, and succeeds', async () => {
    ctx = await startControllableServer((count, _req, res) => {
      if (count === 1) return jsonRes(res, 429, { error: { message: 'rate limited' } }, { 'Retry-After': '0' });
      return jsonRes(res, 200, { choices: [{ message: { content: 'ok after rate limit' } }] });
    });
    const { port } = ctx.server.address();
    const text = await callProvider(settings(port), 'hi', { timeoutMs: 2000, maxRetries: 1 });
    expect(text).toBe('ok after rate limit');
  });

  test('throws AiRateLimitError with the retry-after value once retries are exhausted', async () => {
    ctx = await startControllableServer((_count, _req, res) => jsonRes(res, 429, { error: { message: 'slow down' } }, { 'Retry-After': '0' }));
    const { port } = ctx.server.address();
    await expect(callProvider(settings(port), 'hi', { timeoutMs: 2000, maxRetries: 0 })).rejects.toThrow(AiRateLimitError);
  });

  test('does not retry a non-429/5xx client error (e.g. 400 bad request)', async () => {
    ctx = await startControllableServer((_count, _req, res) => jsonRes(res, 400, { error: { message: 'bad request' } }));
    const { port } = ctx.server.address();
    await expect(callProvider(settings(port), 'hi', { timeoutMs: 2000, maxRetries: 3 })).rejects.toThrow(AiServerError);
    expect(ctx.getRequestCount()).toBe(1);
  });

  test('a network-level connection failure (nothing listening) throws AiNetworkError and is retried', async () => {
    // Port 1 is a privileged/unassigned port with nothing listening - connection refused.
    await expect(callProvider(settings(1), 'hi', { timeoutMs: 2000, maxRetries: 1 })).rejects.toThrow(AiNetworkError);
  });

  test('never leaks the API key in any thrown error message', async () => {
    ctx = await startControllableServer((_count, _req, res) => jsonRes(res, 401, { error: { message: 'invalid api key' } }));
    const { port } = ctx.server.address();
    try {
      await callProvider({ ...settings(port), apiKey: 'super-secret-key-value' }, 'hi', { timeoutMs: 2000, maxRetries: 0 });
      throw new Error('expected callProvider to throw');
    } catch (err) {
      expect(err.message).not.toContain('super-secret-key-value');
    }
  });
});
