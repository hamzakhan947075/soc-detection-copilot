'use strict';

const { buildRequest, parseResponseText, AiConfigError } = require('../src/ai/providers');
const aiConfigStore = require('../src/ai/aiConfigStore');

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
