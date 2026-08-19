import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { api } from '../js/api.js';

let originalFetch;
let calls;

function mockFetch(response) {
  calls = [];
  originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return response;
  };
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('api.*.handle() - success path', () => {
  test('returns the parsed JSON body on a 200', async () => {
    mockFetch(jsonResponse(200, { stages: ['ingest'] }));
    const result = await api.getPipeline();
    assert.deepEqual(result, { stages: ['ingest'] });
  });

  test('a 2xx response with a non-JSON body resolves to null rather than throwing', async () => {
    mockFetch({
      ok: true,
      status: 204,
      json: async () => {
        throw new SyntaxError('Unexpected end of JSON input');
      },
    });
    const result = await api.logout();
    assert.equal(result, null);
  });
});

describe('api.*.handle() - error path', () => {
  test('throws using the body\'s "error" field as the message', async () => {
    mockFetch(jsonResponse(400, { error: 'File extension ".sh" is not allowed.' }));
    await assert.rejects(() => api.getPipeline(), { message: 'File extension ".sh" is not allowed.' });
  });

  test('falls back to a generic status-code message when the error body has no "error" field', async () => {
    mockFetch({ ok: false, status: 500, json: async () => null });
    await assert.rejects(() => api.getPipeline(), { message: 'Request failed with status 500' });
  });

  test('attaches every other body field (e.g. code, retryable) onto the thrown Error', async () => {
    mockFetch(jsonResponse(429, { error: 'Rate limited', code: 'AI_RATE_LIMITED', retryable: true }));
    try {
      await api.testAiConfig();
      assert.fail('expected api.testAiConfig() to throw');
    } catch (err) {
      assert.equal(err.message, 'Rate limited');
      assert.equal(err.code, 'AI_RATE_LIMITED');
      assert.equal(err.retryable, true);
    }
  });

  test('does not attach the "error" field itself as a property (it becomes the message only)', async () => {
    mockFetch(jsonResponse(400, { error: 'Bad request' }));
    try {
      await api.getPipeline();
      assert.fail('expected api.getPipeline() to throw');
    } catch (err) {
      assert.equal(Object.prototype.hasOwnProperty.call(err, 'error'), false);
    }
  });
});

describe('api request construction', () => {
  test('login POSTs JSON with the password in the body', async () => {
    mockFetch(jsonResponse(200, { authRequired: true, authenticated: true }));
    await api.login('s3cret');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/api/auth/login');
    assert.equal(calls[0].options.method, 'POST');
    assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(calls[0].options.body), { password: 's3cret' });
  });

  test('loadSample URL-encodes the sample name', async () => {
    mockFetch(jsonResponse(201, { sessionId: 's1' }));
    await api.loadSample('windows security & auth');
    assert.equal(calls[0].url, '/api/samples/windows%20security%20%26%20auth/load');
  });

  test('uploadFile sends a FormData body with no explicit Content-Type header', async () => {
    mockFetch(jsonResponse(201, { sessionId: 's1' }));
    const fakeFile = { name: 'events.ndjson' };
    await api.uploadFile(fakeFile);
    assert.equal(calls[0].options.method, 'POST');
    assert.equal(calls[0].options.headers, undefined);
    assert.ok(calls[0].options.body instanceof FormData);
  });

  test('getReport with format=json goes through handle() (JSON parsing)', async () => {
    mockFetch(jsonResponse(200, { detection: 'SSH Brute Force' }));
    const result = await api.getReport('s1', 'r1', 'json');
    assert.deepEqual(result, { detection: 'SSH Brute Force' });
  });

  test('getReport with a non-json format returns raw text on success', async () => {
    mockFetch({ ok: true, status: 200, text: async () => '# Report\n\nSome markdown.' });
    const result = await api.getReport('s1', 'r1', 'markdown');
    assert.equal(result, '# Report\n\nSome markdown.');
  });

  test('getReport with a non-json format still throws on failure, instead of downloading the error body as if it were a report', async () => {
    mockFetch({ ok: false, status: 500, text: async () => '<html>Internal Server Error</html>' });
    await assert.rejects(() => api.getReport('s1', 'r1', 'markdown'), { message: 'Request failed with status 500' });
  });
});
