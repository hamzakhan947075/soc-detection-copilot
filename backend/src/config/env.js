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

  ai: resolveAiEnvConfig(),
};

/**
 * Picks an AI provider/key/model from environment variables. Priority when
 * AI_PROVIDER is unset: Anthropic, then Groq, then OpenAI, then a custom
 * OpenAI-compatible endpoint - whichever has a key actually set. This is
 * only the *default*; the Settings tab can override it at runtime for the
 * life of the process without touching these env vars (see ai/aiConfigStore.js).
 */
function resolveAiEnvConfig() {
  const explicit = (process.env.AI_PROVIDER || '').toLowerCase();

  const candidates = {
    anthropic: { apiKey: process.env.ANTHROPIC_API_KEY || '', model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5', baseUrl: '' },
    groq: { apiKey: process.env.GROQ_API_KEY || '', model: process.env.GROQ_MODEL || 'openai/gpt-oss-120b', baseUrl: '' },
    openai: { apiKey: process.env.OPENAI_API_KEY || '', model: process.env.OPENAI_MODEL || 'gpt-4o-mini', baseUrl: '' },
    custom: { apiKey: process.env.AI_API_KEY || '', model: process.env.AI_MODEL || '', baseUrl: process.env.AI_BASE_URL || '' },
  };

  const order = explicit && candidates[explicit] ? [explicit] : ['anthropic', 'groq', 'openai', 'custom'];
  const chosenProvider = order.find((p) => candidates[p].apiKey) || explicit || 'anthropic';
  const chosen = candidates[chosenProvider] || candidates.anthropic;

  return {
    provider: chosenProvider,
    apiKey: chosen.apiKey,
    model: chosen.model,
    baseUrl: chosen.baseUrl,
  };
}

module.exports = config;
