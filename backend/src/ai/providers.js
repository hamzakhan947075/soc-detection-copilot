'use strict';

const { getProviderMeta } = require('./providerDefaults');

class AiConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AiConfigError';
  }
}

/**
 * Builds the {url, headers, body} for a provider call without performing any
 * network I/O - kept pure so it can be unit tested without mocking fetch and
 * without ever needing a real API key.
 */
function buildRequest(settings, prompt, maxTokens) {
  const meta = getProviderMeta(settings.provider);
  if (!meta) throw new AiConfigError(`Unknown AI provider "${settings.provider}"`);
  if (!settings.apiKey) throw new AiConfigError('No API key configured for the selected AI provider');

  const baseUrl = (settings.baseUrl || meta.baseUrl || '').replace(/\/+$/, '');
  if (!baseUrl) throw new AiConfigError('A base URL is required for this provider');
  const model = settings.model || meta.defaultModel;
  if (!model) throw new AiConfigError('A model name is required for this provider');

  if (meta.api === 'anthropic-messages') {
    return {
      url: `${baseUrl}/v1/messages`,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': settings.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: {
        model,
        max_tokens: maxTokens,
        messages: [{ role: 'user', content: prompt }],
      },
    };
  }

  // openai-chat covers Groq, OpenAI, and any other OpenAI-compatible API.
  const body = {
    model,
    max_tokens: maxTokens,
    messages: [{ role: 'user', content: prompt }],
  };
  // Groq's gpt-oss models spend part of max_tokens on hidden reasoning before
  // producing message.content - on a short max_tokens budget that can burn
  // through the whole budget and leave content empty. Keeping reasoning
  // effort low avoids that without needing a very large token budget.
  if (settings.provider === 'groq' && /^openai\/gpt-oss/i.test(model)) {
    body.reasoning_effort = 'low';
  }
  return {
    url: `${baseUrl}/chat/completions`,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${settings.apiKey}`,
    },
    body,
  };
}

/**
 * Best-effort extraction of the provider's own error message (e.g. "model
 * decommissioned", "invalid api key") so failures are diagnosable instead of
 * a bare status code. This only ever reads the provider's response body -
 * never anything from our own request (API key, headers) - so it's safe to
 * surface to the analyst.
 */
async function extractErrorDetail(res) {
  let text;
  try {
    text = await res.text();
  } catch (_err) {
    return '';
  }
  if (!text) return '';
  let detail = text;
  try {
    const parsed = JSON.parse(text);
    detail = (parsed.error && (parsed.error.message || parsed.error.code || parsed.error)) || parsed.message || text;
  } catch (_err) {
    // not JSON - use the raw text as-is
  }
  detail = String(detail).trim().slice(0, 300);
  return detail ? `: ${detail}` : '';
}

/** Extracts the reply text from a provider's response JSON shape. */
function parseResponseText(provider, json) {
  const meta = getProviderMeta(provider);
  if (meta && meta.api === 'anthropic-messages') {
    return json.content?.[0]?.text || '';
  }
  return json.choices?.[0]?.message?.content || '';
}

/**
 * Performs the actual network call. Never logs or echoes the API key -
 * fetch errors are converted to plain status-code messages before being
 * thrown, so nothing from request headers can leak into an error string.
 */
async function callProvider(settings, prompt, { maxTokens = 400 } = {}) {
  const { url, headers, body } = buildRequest(settings, prompt, maxTokens);

  let res;
  try {
    res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  } catch (_err) {
    throw new Error('Could not reach the AI provider (network error).');
  }

  if (!res.ok) {
    throw new Error(`AI provider request failed with status ${res.status}${await extractErrorDetail(res)}`);
  }

  const json = await res.json();
  return parseResponseText(settings.provider, json);
}

module.exports = { buildRequest, parseResponseText, callProvider, AiConfigError };
