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
    defaultModel: 'openai/gpt-oss-120b',
    requiresBaseUrl: false,
  },
  openai: {
    label: 'OpenAI',
    api: 'openai-chat',
    baseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o-mini',
    requiresBaseUrl: false,
  },
  gemini: {
    label: 'Google Gemini',
    api: 'openai-chat',
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
    defaultModel: 'gemini-3.6-flash',
    requiresBaseUrl: false,
  },
  openrouter: {
    label: 'OpenRouter',
    api: 'openai-chat',
    baseUrl: 'https://openrouter.ai/api/v1',
    // No hardcoded default: OpenRouter's free (":free"-suffixed) model
    // lineup turns over quickly - see openrouter.ai/models?max_price=0 for
    // whatever is currently free, and type that exact id into the Model
    // field. Same lesson as gemini-2.0-flash getting retired underneath us.
    defaultModel: '',
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
