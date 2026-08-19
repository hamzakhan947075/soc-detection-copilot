'use strict';

const config = require('../config/env');

/**
 * Minimal Elasticsearch REST client used only for the optional "connect
 * directly to Elasticsearch" workflow. Credentials are read exclusively from
 * environment variables (ELASTICSEARCH_URL / _USERNAME / _PASSWORD /
 * _API_KEY / _INDEX) and are never logged or echoed back to the client.
 * The application is fully functional without any of this configured -
 * these functions simply throw a clear, actionable error if called while
 * unconfigured.
 */

function isConfigured() {
  return Boolean(config.elasticsearch.url);
}

function buildAuthHeader() {
  if (config.elasticsearch.apiKey) {
    return `ApiKey ${config.elasticsearch.apiKey}`;
  }
  if (config.elasticsearch.username && config.elasticsearch.password) {
    const token = Buffer.from(`${config.elasticsearch.username}:${config.elasticsearch.password}`).toString('base64');
    return `Basic ${token}`;
  }
  return null;
}

function assertConfigured() {
  if (!isConfigured()) {
    throw new Error(
      'Elasticsearch is not configured. Set ELASTICSEARCH_URL (and either ELASTICSEARCH_API_KEY or ELASTICSEARCH_USERNAME/ELASTICSEARCH_PASSWORD) as environment variables to enable this feature.'
    );
  }
}

async function testConnection() {
  assertConfigured();
  const auth = buildAuthHeader();
  const res = await fetch(new URL('/', config.elasticsearch.url), {
    headers: auth ? { Authorization: auth } : {},
  });
  if (!res.ok) {
    return { connected: false, status: res.status, message: 'Elasticsearch responded with a non-2xx status.' };
  }
  const body = await res.json();
  return { connected: true, status: res.status, clusterName: body.cluster_name, version: body.version && body.version.number };
}

async function listIndices() {
  assertConfigured();
  const auth = buildAuthHeader();
  const res = await fetch(new URL('/_cat/indices?format=json', config.elasticsearch.url), {
    headers: auth ? { Authorization: auth } : {},
  });
  if (!res.ok) throw new Error(`Failed to list indices (status ${res.status})`);
  const body = await res.json();
  return body.map((entry) => entry.index);
}

/**
 * Fetches raw documents from Elasticsearch for a given index/time range.
 * Returns raw `_source` documents exactly as stored - no assumption that
 * they are already ECS-compliant, matching every other ingestion path.
 */
async function fetchLogs({ index, from, to, size = 1000 } = {}) {
  assertConfigured();
  const targetIndex = index || config.elasticsearch.index;
  if (!targetIndex) throw new Error('No index specified and ELASTICSEARCH_INDEX is not set.');

  const auth = buildAuthHeader();
  const body = {
    size: Math.min(size, config.upload.maxEventsPerDataset),
    query: from || to ? { range: { '@timestamp': { gte: from, lte: to } } } : { match_all: {} },
    sort: [{ '@timestamp': 'desc' }],
  };

  const res = await fetch(new URL(`/${encodeURIComponent(targetIndex)}/_search`, config.elasticsearch.url), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(auth ? { Authorization: auth } : {}),
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(`Elasticsearch query failed (status ${res.status})`);
  }
  const json = await res.json();
  return (json.hits?.hits || []).map((hit) => hit._source);
}

module.exports = { isConfigured, testConnection, listIndices, fetchLogs };
