'use strict';

/**
 * Central place to read configuration from environment variables.
 * No secrets are ever hardcoded here - everything comes from process.env,
 * with safe defaults for local/sample-data usage.
 */

function toInt(value, fallback) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

const config = {
  port: toInt(process.env.PORT, 4000),
  nodeEnv: process.env.NODE_ENV || 'development',

  upload: {
    maxFileSizeBytes: toInt(process.env.MAX_UPLOAD_BYTES, 25 * 1024 * 1024), // 25MB
    maxPasteBytes: toInt(process.env.MAX_PASTE_BYTES, 10 * 1024 * 1024), // 10MB
    allowedExtensions: ['.json', '.jsonl', '.ndjson', '.txt', '.log', '.csv'],
    maxEventsPerDataset: toInt(process.env.MAX_EVENTS_PER_DATASET, 50000),
  },

  rateLimit: {
    windowMs: toInt(process.env.RATE_LIMIT_WINDOW_MS, 60 * 1000),
    max: toInt(process.env.RATE_LIMIT_MAX, 120),
  },

  elasticsearch: {
    url: process.env.ELASTICSEARCH_URL || '',
    username: process.env.ELASTICSEARCH_USERNAME || '',
    password: process.env.ELASTICSEARCH_PASSWORD || '',
    apiKey: process.env.ELASTICSEARCH_API_KEY || '',
    index: process.env.ELASTICSEARCH_INDEX || '',
  },

  ai: {
    provider: process.env.AI_PROVIDER || 'none', // 'anthropic' | 'none'
    apiKey: process.env.ANTHROPIC_API_KEY || '',
    model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5',
    enabled: Boolean(process.env.ANTHROPIC_API_KEY),
  },
};

module.exports = config;
