'use strict';

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
