'use strict';

const { getProviderMeta } = require('./providerDefaults');
const config = require('../config/env');
const { AiTimeoutError, AiNetworkError, AiRateLimitError, AiAuthError, AiServerError } = require('./aiErrors');

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Exponential backoff in seconds: 0.5s, 1s, 2s, 4s (capped). */
function backoffSeconds(attempt) {
  return Math.min(4, 0.5 * 2 ** attempt);
}

function parseRetryAfterSeconds(headerValue) {
  if (!headerValue) return null;
  const n = Number(headerValue);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/** fetch() with a hard timeout, translating an abort into AiTimeoutError and any other network failure into AiNetworkError. */
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err.name === 'AbortError') throw new AiTimeoutError(timeoutMs);
    throw new AiNetworkError();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Performs the actual network call, with a request timeout and a bounded
 * retry policy for transient failures (network error, request timeout,
 * 429 rate limit, 5xx server error) using exponential backoff (or the
 * provider's own Retry-After header, when present, for 429s). Auth errors
 * (401/403) and other 4xx client errors are never retried - retrying a
 * bad API key or a malformed request cannot succeed. Never logs or echoes
 * the API key; error messages only ever include the provider's own
 * response text (see extractErrorDetail).
 */
async function callProvider(settings, prompt, { maxTokens = 400, timeoutMs, maxRetries } = {}) {
  const { url, headers, body } = buildRequest(settings, prompt, maxTokens);
  const effectiveTimeoutMs = timeoutMs ?? config.ai.requestTimeoutMs;
  const effectiveMaxRetries = maxRetries ?? config.ai.maxRetries;

  for (let attempt = 0; ; attempt++) {
    const isLastAttempt = attempt >= effectiveMaxRetries;
    try {
      const res = await fetchWithTimeout(url, { method: 'POST', headers, body: JSON.stringify(body) }, effectiveTimeoutMs);

      if (res.ok) {
        const json = await res.json();
        return parseResponseText(settings.provider, json);
      }

      const detail = await extractErrorDetail(res);
      if (res.status === 401 || res.status === 403) {
        throw new AiAuthError(res.status, detail); // never retryable
      }
      if (res.status === 429) {
        const retryAfterSeconds = parseRetryAfterSeconds(res.headers.get('retry-after'));
        if (!isLastAttempt) {
          await sleep((retryAfterSeconds ?? backoffSeconds(attempt)) * 1000);
          continue;
        }
        throw new AiRateLimitError(retryAfterSeconds, detail);
      }
      const serverError = new AiServerError(res.status, detail);
      if (serverError.retryable && !isLastAttempt) {
        await sleep(backoffSeconds(attempt) * 1000);
        continue;
      }
      throw serverError;
    } catch (err) {
      if (err.retryable && !isLastAttempt) {
        await sleep(backoffSeconds(attempt) * 1000);
        continue;
      }
      throw err;
    }
  }
}

module.exports = { buildRequest, parseResponseText, callProvider, AiConfigError };
