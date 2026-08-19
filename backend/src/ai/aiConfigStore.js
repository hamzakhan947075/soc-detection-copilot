'use strict';

const config = require('../config/env');
const { isValidProvider, getProviderMeta } = require('./providerDefaults');
const { isValidIp, isIpInCidrList } = require('../detection-engine/evaluators/cidrEvaluator');

// AWS, Azure, and GCP all serve their instance-metadata service (IMDS) - the
// classic SSRF-to-cloud-credential-theft target - at the same well-known
// link-local address by convention (169.254.169.254; AWS also serves an
// IPv6 variant at fd00:ec2::254). A "custom AI endpoint" has no legitimate
// reason to ever be there, so it's blocked outright - unlike loopback/
// private ranges, which stay allowed since pointing at a self-hosted local
// LLM (Ollama, etc.) is an explicitly intended use of the custom provider.
const BLOCKED_AI_ENDPOINT_CIDRS = ['169.254.0.0/16', 'fd00:ec2::254/128'];
const BLOCKED_AI_ENDPOINT_HOSTNAMES = new Set(['metadata.google.internal']); // GCP's DNS alias for the same address

function isBlockedAiEndpointHost(hostname) {
  const lower = hostname.toLowerCase();
  if (BLOCKED_AI_ENDPOINT_HOSTNAMES.has(lower)) return true;
  const bare = lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;
  return isValidIp(bare) && isIpInCidrList(bare, BLOCKED_AI_ENDPOINT_CIDRS);
}

/**
 * Runtime AI configuration, settable from the Settings tab (POST
 * /api/ai/config) so an analyst can paste in a Claude/Groq/OpenAI/custom key
 * without editing environment variables. This is intentionally in-memory
 * only - never written to a file, never logged - so it lives for the
 * lifetime of this server process, the same way session state does
 * (pipeline/sessionStore.js). Env vars remain the way to configure a key
 * that survives a restart; the UI is a convenience layer on top, not a
 * replacement.
 */
let runtimeOverride = null; // { provider, apiKey, model, baseUrl } | null

const MAX_KEY_LENGTH = 512;
const MAX_MODEL_LENGTH = 200;
const MAX_URL_LENGTH = 500;

function envDefaults() {
  return {
    provider: config.ai.provider,
    apiKey: config.ai.apiKey,
    model: config.ai.model,
    baseUrl: config.ai.baseUrl,
  };
}

/** Resolves the effective AI settings: runtime override wins over env defaults. */
function getEffectiveSettings() {
  const base = envDefaults();
  if (!runtimeOverride) return base;
  return { ...base, ...runtimeOverride };
}

function isEnabled() {
  const settings = getEffectiveSettings();
  return isValidProvider(settings.provider) && Boolean(settings.apiKey);
}

function maskKey(key) {
  if (!key) return null;
  if (key.length <= 8) return '*'.repeat(key.length);
  return `${key.slice(0, 4)}${'*'.repeat(Math.max(4, key.length - 8))}${key.slice(-4)}`;
}

/** Safe-to-return-to-the-client status: never includes the raw key. */
function getPublicStatus() {
  const settings = getEffectiveSettings();
  const meta = getProviderMeta(settings.provider);
  return {
    enabled: isEnabled(),
    provider: settings.provider,
    providerLabel: meta ? meta.label : null,
    model: settings.model || (meta ? meta.defaultModel : ''),
    baseUrl: settings.provider === 'custom' ? settings.baseUrl : null,
    maskedApiKey: maskKey(settings.apiKey),
    source: runtimeOverride ? 'session' : settings.apiKey ? 'environment' : 'unconfigured',
  };
}

class AiConfigValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AiConfigValidationError';
  }
}

/** Validates and stores a runtime AI configuration. Throws AiConfigValidationError on bad input. */
function setRuntimeConfig({ provider, apiKey, model, baseUrl }) {
  if (!isValidProvider(provider)) {
    throw new AiConfigValidationError(`Unknown provider "${provider}"`);
  }
  if (typeof apiKey !== 'string' || !apiKey.trim()) {
    throw new AiConfigValidationError('An API key is required');
  }
  if (apiKey.length > MAX_KEY_LENGTH) {
    throw new AiConfigValidationError('API key is unexpectedly long');
  }
  if (model !== undefined && model !== null) {
    if (typeof model !== 'string' || model.length > MAX_MODEL_LENGTH) {
      throw new AiConfigValidationError('Model name is invalid');
    }
  }

  const meta = getProviderMeta(provider);
  let resolvedBaseUrl = '';
  if (meta.requiresBaseUrl || baseUrl) {
    if (typeof baseUrl !== 'string' || baseUrl.length > MAX_URL_LENGTH) {
      throw new AiConfigValidationError('Base URL is invalid');
    }
    let parsed;
    try {
      parsed = new URL(baseUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('bad protocol');
    } catch (_err) {
      throw new AiConfigValidationError('Base URL must be a valid http(s) URL');
    }
    if (isBlockedAiEndpointHost(parsed.hostname)) {
      throw new AiConfigValidationError('This base URL points at a cloud instance-metadata service and cannot be used as an AI endpoint.');
    }
    resolvedBaseUrl = baseUrl;
  }
  if (meta.requiresBaseUrl && !resolvedBaseUrl) {
    throw new AiConfigValidationError(`${meta.label} requires a base URL`);
  }

  runtimeOverride = {
    provider,
    apiKey: apiKey.trim(),
    model: (model || '').trim(),
    baseUrl: resolvedBaseUrl,
  };
  return getPublicStatus();
}

function clearRuntimeConfig() {
  runtimeOverride = null;
  return getPublicStatus();
}

module.exports = {
  getEffectiveSettings,
  getPublicStatus,
  setRuntimeConfig,
  clearRuntimeConfig,
  isEnabled,
  AiConfigValidationError,
};
