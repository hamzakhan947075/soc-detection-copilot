'use strict';

/**
 * Structured AI-provider error taxonomy, so callers (routes, aiAssist.js)
 * can branch on what actually happened - timeout vs rate limit vs bad key
 * vs provider outage - instead of parsing an error message string. Every
 * error also carries `retryable`, which callProvider() uses to decide
 * whether to retry automatically.
 */

class AiProviderError extends Error {
  constructor(message, { code, retryable = false, status = null } = {}) {
    super(message);
    this.name = 'AiProviderError';
    this.code = code;
    this.retryable = retryable;
    this.status = status;
  }
}

class AiTimeoutError extends AiProviderError {
  constructor(timeoutMs) {
    super(`AI provider request timed out after ${timeoutMs}ms.`, { code: 'timeout', retryable: true });
  }
}

class AiNetworkError extends AiProviderError {
  constructor() {
    super('Could not reach the AI provider (network error).', { code: 'network', retryable: true });
  }
}

class AiRateLimitError extends AiProviderError {
  constructor(retryAfterSeconds, detail = '') {
    super(`AI provider rate-limited this request${retryAfterSeconds ? ` (retry after ${retryAfterSeconds}s)` : ''}${detail}`, {
      code: 'rate_limited',
      retryable: true,
      status: 429,
    });
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

class AiAuthError extends AiProviderError {
  constructor(status, detail = '') {
    super(`AI provider rejected the request as unauthorized${detail}`, { code: 'auth', retryable: false, status });
  }
}

class AiServerError extends AiProviderError {
  constructor(status, detail = '') {
    super(`AI provider request failed with status ${status}${detail}`, { code: 'server_error', retryable: status >= 500, status });
  }
}

module.exports = { AiProviderError, AiTimeoutError, AiNetworkError, AiRateLimitError, AiAuthError, AiServerError };
