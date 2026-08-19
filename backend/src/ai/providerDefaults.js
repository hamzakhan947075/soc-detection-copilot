'use strict';

/**
 * Static metadata for every AI provider the app knows how to call. This is
 * data, not logic - request building lives in providers.js. "custom" covers
 * any other OpenAI-compatible API (OpenRouter, Together, a local Ollama
 * OpenAI-shim, etc.) via an analyst-supplied base URL.
 */
const PROVIDERS = {
  anthropic: {
    label: 'Anthropic (Claude)',
    api: 'anthropic-messages',
    baseUrl: 'https://api.anthropic.com',
    defaultModel: 'claude-sonnet-5',
    requiresBaseUrl: false,
  },
  groq: {
    label: 'Groq',
    api: 'openai-chat',
    baseUrl: 'https://api.groq.com/openai/v1',
    defaultModel: 'llama-3.3-70b-versatile',
    requiresBaseUrl: false,
  },
  openai: {
    label: 'OpenAI',
    api: 'openai-chat',
    baseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o-mini',
    requiresBaseUrl: false,
  },
  custom: {
    label: 'Custom (OpenAI-compatible)',
    api: 'openai-chat',
    baseUrl: '',
    defaultModel: '',
    requiresBaseUrl: true,
  },
};

const PROVIDER_IDS = Object.keys(PROVIDERS);

function isValidProvider(provider) {
  return PROVIDER_IDS.includes(provider);
}

function getProviderMeta(provider) {
  return PROVIDERS[provider] || null;
}

module.exports = { PROVIDERS, PROVIDER_IDS, isValidProvider, getProviderMeta };
