'use strict';

const config = require('../config/env');

/**
 * Optional AI-assist layer. Every function here is additive narrative /
 * hypothesis-generation only - nothing in the deterministic pipeline
 * (parsing, ECS mapping confidence, detection thresholds, MITRE mapping,
 * rule validation, statistics) depends on this module or on the AI being
 * configured. When ANTHROPIC_API_KEY is not set, every function returns a
 * clearly-labeled deterministic fallback instead of silently failing.
 *
 * No API key is ever hardcoded - it is read only from process.env via
 * config/env.js - and network calls are only ever made if AI is enabled.
 */

async function callAnthropic(prompt, { maxTokens = 400 } = {}) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': config.ai.apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: config.ai.model,
      max_tokens: maxTokens,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  if (!res.ok) {
    throw new Error(`AI provider request failed with status ${res.status}`);
  }
  const json = await res.json();
  return json.content?.[0]?.text || '';
}

/** Produces a short analyst-facing narrative for a detection candidate. */
async function explainDetection(detection) {
  if (!config.ai.enabled) {
    return {
      source: 'deterministic',
      text: `${detection.name}: ${detection.description}`,
    };
  }
  try {
    const prompt = `You are assisting a SOC analyst. In 2-3 sentences, explain the security significance of this detection in plain language. Do not invent facts not present below.\n\nDetection: ${detection.name}\nCategory: ${detection.category}\nDescription: ${detection.description}\nEvidence: ${JSON.stringify(detection.evidence)}`;
    const text = await callAnthropic(prompt);
    return { source: 'ai', text };
  } catch (err) {
    return { source: 'deterministic-fallback', text: `${detection.name}: ${detection.description}`, error: err.message };
  }
}

/** Suggests an interpretation for a low-confidence / uncertain ECS mapping. */
async function suggestMappingNarrative(fieldMapping) {
  if (!config.ai.enabled) {
    return {
      source: 'deterministic',
      text: `Field "${fieldMapping.rawField}" has an uncertain ECS mapping (${fieldMapping.confidence * 100}% confidence). Analyst review required.`,
    };
  }
  try {
    const prompt = `A raw log field named "${fieldMapping.rawField}" was tentatively mapped to ECS field "${fieldMapping.ecsField}" with ${Math.round(
      fieldMapping.confidence * 100
    )}% confidence. In one sentence, note what an analyst should double check before approving this mapping.`;
    const text = await callAnthropic(prompt, { maxTokens: 150 });
    return { source: 'ai', text };
  } catch (err) {
    return {
      source: 'deterministic-fallback',
      text: `Field "${fieldMapping.rawField}" has an uncertain ECS mapping. Analyst review required.`,
      error: err.message,
    };
  }
}

function isEnabled() {
  return config.ai.enabled;
}

module.exports = { explainDetection, suggestMappingNarrative, isEnabled };
