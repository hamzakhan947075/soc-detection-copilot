'use strict';

const crypto = require('crypto');

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
    requestTimeoutMs: toInt(process.env.ELASTICSEARCH_TIMEOUT_MS, 15000),
  },

  // Comma-separated CIDR list (e.g. "10.0.0.0/8,192.168.1.0/24") that
  // overrides the CIDR evaluator's default RFC1918/loopback/link-local
  // ranges for what counts as "internal" - lets an analyst reflect their own
  // network's actual internal ranges instead of a generic default.
  internalCidrRanges: (process.env.INTERNAL_CIDR_RANGES || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),

  // If APP_PASSWORD is unset, the app runs with no authentication at all -
  // fine for local single-analyst use, dangerous on a public deployment.
  // See auth/authMiddleware.js: a startup warning is logged either way, and
  // /api/auth/status tells the frontend whether a login is required.
  // SESSION_SECRET signs the session cookie; if unset, one is generated at
  // boot (sessions won't survive a restart, but nothing is silently
  // insecure - a session token from a previous boot simply stops validating).
  auth: {
    password: process.env.APP_PASSWORD || '',
    sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  },

  ai: {
    ...resolveAiEnvConfig(),
    // Provider hardening (see ai/providers.js): how long to wait for a
    // response before giving up, and how many times to retry a transient
    // failure (network error, 429, 5xx) with backoff. Never retries an
    // auth error (401/403) or a bad-request error (4xx other than 429) -
    // those aren't going to succeed on retry.
    requestTimeoutMs: toInt(process.env.AI_REQUEST_TIMEOUT_MS, 20000),
    maxRetries: toInt(process.env.AI_MAX_RETRIES, 2),
  },
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
    gemini: { apiKey: process.env.GEMINI_API_KEY || '', model: process.env.GEMINI_MODEL || 'gemini-3.6-flash', baseUrl: '' },
    custom: { apiKey: process.env.AI_API_KEY || '', model: process.env.AI_MODEL || '', baseUrl: process.env.AI_BASE_URL || '' },
  };

  const order = explicit && candidates[explicit] ? [explicit] : ['anthropic', 'groq', 'openai', 'gemini', 'custom'];
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
