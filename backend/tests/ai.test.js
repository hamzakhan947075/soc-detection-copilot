'use strict';

const http = require('http');
const { buildRequest, parseResponseText, AiConfigError } = require('../src/ai/providers');
const aiConfigStore = require('../src/ai/aiConfigStore');
const { explainDetection } = require('../src/ai/aiAssist');

/** Spins up a tiny local OpenAI-compatible server so tests can exercise the
 * real network path (callProvider/fetch) without hitting a real AI provider. */
function startFakeOpenAiServer(responseBody) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(responseBody));
      });
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

describe('buildRequest (pure, no network)', () => {
  test('builds an Anthropic messages request', () => {
    const { url, headers, body } = buildRequest({ provider: 'anthropic', apiKey: 'sk-ant-test', model: '' }, 'hello', 100);
    expect(url).toBe('https://api.anthropic.com/v1/messages');
    expect(headers['x-api-key']).toBe('sk-ant-test');
    expect(body.model).toBe('claude-sonnet-5');
    expect(body.messages[0].content).toBe('hello');
  });

  test('builds a Groq (OpenAI-compatible) request', () => {
    const { url, headers, body } = buildRequest({ provider: 'groq', apiKey: 'gsk-test', model: '' }, 'hi', 50);
    expect(url).toBe('https://api.groq.com/openai/v1/chat/completions');
    expect(headers.Authorization).toBe('Bearer gsk-test');
    expect(body.model).toBe('openai/gpt-oss-120b');
  });

  test('builds an OpenAI request with a custom model override', () => {
    const { body } = buildRequest({ provider: 'openai', apiKey: 'sk-test', model: 'gpt-4o' }, 'hi', 50);
    expect(body.model).toBe('gpt-4o');
  });

  test('builds a custom OpenAI-compatible request using the supplied base URL', () => {
    const { url } = buildRequest({ provider: 'custom', apiKey: 'k', model: 'llama3', baseUrl: 'https://my-llm.example.com/v1' }, 'hi', 50);
    expect(url).toBe('https://my-llm.example.com/v1/chat/completions');
  });

  test('sets low reasoning effort for Groq gpt-oss models to avoid empty content', () => {
    const { body } = buildRequest({ provider: 'groq', apiKey: 'gsk-test', model: 'openai/gpt-oss-120b' }, 'hi', 50);
    expect(body.reasoning_effort).toBe('low');
  });

  test('does not set reasoning_effort for non-gpt-oss Groq models', () => {
    const { body } = buildRequest({ provider: 'groq', apiKey: 'gsk-test', model: 'llama-3.1-8b-instant' }, 'hi', 50);
    expect(body.reasoning_effort).toBeUndefined();
  });

  test('does not set reasoning_effort for other providers', () => {
    const { body } = buildRequest({ provider: 'openai', apiKey: 'sk-test', model: 'gpt-4o-mini' }, 'hi', 50);
    expect(body.reasoning_effort).toBeUndefined();
  });

  test('rejects an unknown provider', () => {
    expect(() => buildRequest({ provider: 'not-a-real-provider', apiKey: 'x' }, 'hi', 10)).toThrow(AiConfigError);
  });

  test('rejects a missing API key', () => {
    expect(() => buildRequest({ provider: 'anthropic', apiKey: '' }, 'hi', 10)).toThrow(AiConfigError);
  });

  test('rejects a custom provider with no base URL', () => {
    expect(() => buildRequest({ provider: 'custom', apiKey: 'k', model: 'x' }, 'hi', 10)).toThrow(AiConfigError);
  });
});

describe('parseResponseText', () => {
  test('extracts text from an Anthropic-shaped response', () => {
    expect(parseResponseText('anthropic', { content: [{ text: 'hello there' }] })).toBe('hello there');
  });

  test('extracts text from an OpenAI-shaped response', () => {
    expect(parseResponseText('groq', { choices: [{ message: { content: 'hi' } }] })).toBe('hi');
  });

  test('returns empty string for an unexpected shape rather than throwing', () => {
    expect(parseResponseText('anthropic', {})).toBe('');
  });
});

describe('aiAssist - empty AI response falls back to deterministic text', () => {
  let server;

  afterEach(() => {
    aiConfigStore.clearRuntimeConfig();
    if (server) {
      server.close();
      server = null;
    }
  });

  test('a blank message.content from the provider is treated as a failure, not a valid AI answer', async () => {
    server = await startFakeOpenAiServer({ choices: [{ message: { content: '   ' } }] });
    const { port } = server.address();
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${port}` });

    const result = await explainDetection({ name: 'Test Detection', category: 'auth', description: 'desc', evidence: [] });
    expect(result.source).toBe('deterministic-fallback');
    expect(result.text).toContain('Test Detection');
    expect(result.error).toMatch(/empty/i);
  });

  test('a real answer from the provider is used as-is', async () => {
    server = await startFakeOpenAiServer({ choices: [{ message: { content: 'A real explanation.' } }] });
    const { port } = server.address();
    aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'k', model: 'test-model', baseUrl: `http://127.0.0.1:${port}` });

    const result = await explainDetection({ name: 'Test Detection', category: 'auth', description: 'desc', evidence: [] });
    expect(result.source).toBe('ai');
    expect(result.text).toBe('A real explanation.');
  });
});

describe('aiConfigStore', () => {
  afterEach(() => {
    aiConfigStore.clearRuntimeConfig();
  });

  test('starts disabled with no key configured', () => {
    const status = aiConfigStore.getPublicStatus();
    expect(status.enabled).toBe(false);
    expect(status.maskedApiKey).toBeNull();
  });

  test('setRuntimeConfig validates the provider', () => {
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'bogus', apiKey: 'x' })).toThrow(aiConfigStore.AiConfigValidationError);
  });

  test('setRuntimeConfig requires an API key', () => {
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'groq', apiKey: '' })).toThrow(aiConfigStore.AiConfigValidationError);
  });

  test('setRuntimeConfig requires a valid base URL for the custom provider', () => {
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'x', model: 'llama3', baseUrl: 'not-a-url' })).toThrow(
      aiConfigStore.AiConfigValidationError
    );
  });

  test('requires an explicit model for a provider with no default model (openrouter, custom) - catches it at save time, not on first use', () => {
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'openrouter', apiKey: 'sk-or-abc' })).toThrow(aiConfigStore.AiConfigValidationError);
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'openrouter', apiKey: 'sk-or-abc', model: '  ' })).toThrow(aiConfigStore.AiConfigValidationError);
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'openrouter', apiKey: 'sk-or-abc', model: 'meta-llama/llama-3.3-70b-instruct:free' })).not.toThrow();
  });

  test('does not require an explicit model for a provider with a built-in default (e.g. groq)', () => {
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'groq', apiKey: 'gsk-abc' })).not.toThrow();
  });

  test('rejects a custom base URL pointing at a cloud instance-metadata service (SSRF)', () => {
    expect(() =>
      aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'x', model: 'llama3', baseUrl: 'http://169.254.169.254/latest/meta-data/' })
    ).toThrow(aiConfigStore.AiConfigValidationError);
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'x', model: 'llama3', baseUrl: 'http://metadata.google.internal/' })).toThrow(
      aiConfigStore.AiConfigValidationError
    );
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'x', model: 'llama3', baseUrl: 'http://[fd00:ec2::254]/' })).toThrow(
      aiConfigStore.AiConfigValidationError
    );
  });

  test('still allows loopback and private-network base URLs (self-hosted local LLMs are a legitimate use case)', () => {
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'x', model: 'llama3', baseUrl: 'http://127.0.0.1:11434/v1' })).not.toThrow();
    aiConfigStore.clearRuntimeConfig();
    expect(() => aiConfigStore.setRuntimeConfig({ provider: 'custom', apiKey: 'x', model: 'llama3', baseUrl: 'http://192.168.1.50:11434/v1' })).not.toThrow();
  });

  test('accepts a valid Groq configuration and masks the key in status', () => {
    const status = aiConfigStore.setRuntimeConfig({ provider: 'groq', apiKey: 'gsk-abcdefghijklmnop' });
    expect(status.enabled).toBe(true);
    expect(status.provider).toBe('groq');
    expect(status.maskedApiKey).not.toContain('abcdefghijklmnop');
    expect(status.maskedApiKey.startsWith('gsk-')).toBe(true);
    expect(status.maskedApiKey.endsWith('mnop')).toBe(true);
  });

  test('never exposes the raw key anywhere in the public status object', () => {
    aiConfigStore.setRuntimeConfig({ provider: 'anthropic', apiKey: 'sk-ant-super-secret-value' });
    const status = aiConfigStore.getPublicStatus();
    expect(JSON.stringify(status)).not.toContain('sk-ant-super-secret-value');
  });

  test('clearRuntimeConfig disables AI again (when no env var is set)', () => {
    aiConfigStore.setRuntimeConfig({ provider: 'groq', apiKey: 'gsk-test' });
    expect(aiConfigStore.isEnabled()).toBe(true);
    aiConfigStore.clearRuntimeConfig();
    // Falls back to whatever the environment provides (none in test env).
    expect(aiConfigStore.getPublicStatus().source).not.toBe('session');
  });
});
