'use strict';

const http = require('http');
const config = require('../src/config/env');
const esClient = require('../src/ingestion/elasticsearchClient');

describe('elasticsearchClient - network error sanitization', () => {
  const originalUrl = config.elasticsearch.url;
  const originalFetch = global.fetch;

  beforeEach(() => {
    config.elasticsearch.url = 'https://es.invalid.test:9200';
  });

  afterEach(() => {
    config.elasticsearch.url = originalUrl;
    global.fetch = originalFetch;
  });

  test('testConnection never leaks the raw network error (DNS/TLS/connection detail)', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND es.invalid.test') }));
    await expect(esClient.testConnection()).rejects.toThrow('Could not reach the Elasticsearch cluster (network error)');
    try {
      await esClient.testConnection();
    } catch (err) {
      expect(err.message).not.toMatch(/ENOTFOUND|es\.invalid\.test|getaddrinfo/);
    }
  });

  test('listIndices never leaks the raw network error', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed', { cause: new Error('connect ECONNREFUSED 10.0.0.5:9200') }));
    await expect(esClient.listIndices()).rejects.toThrow('Could not reach the Elasticsearch cluster (network error)');
  });

  test('fetchLogs never leaks the raw network error', async () => {
    config.elasticsearch.index = 'logs-test';
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed', { cause: new Error('connect ECONNREFUSED 10.0.0.5:9200') }));
    await expect(esClient.fetchLogs({})).rejects.toThrow('Could not reach the Elasticsearch cluster (network error)');
    config.elasticsearch.index = '';
  });

  test('a non-2xx response (not a network error) still returns a clear, safe status message', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 401 });
    const result = await esClient.testConnection();
    expect(result.connected).toBe(false);
    expect(result.status).toBe(401);
  });
});

describe('elasticsearchClient - request timeout', () => {
  const originalUrl = config.elasticsearch.url;
  const originalTimeout = config.elasticsearch.requestTimeoutMs;
  let server;

  afterEach(async () => {
    config.elasticsearch.url = originalUrl;
    config.elasticsearch.requestTimeoutMs = originalTimeout;
    if (server) {
      await new Promise((resolve) => server.close(resolve));
      server = null;
    }
  });

  test('times out (rather than hanging indefinitely) when the ES host never responds', async () => {
    server = http.createServer(() => {
      /* never respond */
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    config.elasticsearch.url = `http://127.0.0.1:${port}`;
    config.elasticsearch.requestTimeoutMs = 100;

    await expect(esClient.testConnection()).rejects.toThrow(/timed out after 100ms/);
  });
});

describe('elasticsearchClient - safe query limits', () => {
  const originalUrl = config.elasticsearch.url;
  const originalFetch = global.fetch;
  const originalIndex = config.elasticsearch.index;

  beforeEach(() => {
    config.elasticsearch.url = 'https://es.invalid.test:9200';
    config.elasticsearch.index = 'logs-test';
  });

  afterEach(() => {
    config.elasticsearch.url = originalUrl;
    config.elasticsearch.index = originalIndex;
    global.fetch = originalFetch;
  });

  function captureRequestBody() {
    let capturedBody = null;
    global.fetch = jest.fn().mockImplementation((_url, options) => {
      capturedBody = JSON.parse(options.body);
      return Promise.resolve({ ok: true, json: async () => ({ hits: { hits: [] } }) });
    });
    return () => capturedBody;
  }

  test('clamps a requested size above the configured maximum', async () => {
    const getBody = captureRequestBody();
    await esClient.fetchLogs({ size: 999999999 });
    expect(getBody().size).toBe(config.upload.maxEventsPerDataset);
  });

  test('falls back to a safe default for a negative, zero, or non-numeric size instead of sending it through as-is', async () => {
    const getBody = captureRequestBody();
    await esClient.fetchLogs({ size: -5 });
    expect(getBody().size).toBeGreaterThan(0);

    await esClient.fetchLogs({ size: 0 });
    expect(getBody().size).toBeGreaterThan(0);

    await esClient.fetchLogs({ size: 'not-a-number' });
    expect(getBody().size).toBeGreaterThan(0);
  });

  test('passes a valid requested size through unchanged', async () => {
    const getBody = captureRequestBody();
    await esClient.fetchLogs({ size: 42 });
    expect(getBody().size).toBe(42);
  });
});
