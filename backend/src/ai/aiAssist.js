'use strict';

const { getEffectiveSettings, isEnabled } = require('./aiConfigStore');
const { callProvider } = require('./providers');

/**
 * Optional AI-assist layer. Every function here is additive narrative /
 * hypothesis-generation only - nothing in the deterministic pipeline
 * (parsing, ECS mapping confidence, detection thresholds, MITRE mapping,
 * rule validation, statistics) depends on this module or on AI being
 * configured. When no provider/key is configured, every function returns a
 * clearly-labeled deterministic fallback instead of silently failing.
 *
 * A key can come from environment variables (ANTHROPIC_API_KEY, GROQ_API_KEY,
 * OPENAI_API_KEY, or AI_API_KEY+AI_BASE_URL for a custom OpenAI-compatible
 * endpoint) or be entered in the Settings tab at runtime - see
 * ai/aiConfigStore.js. It is never hardcoded and never logged.
 */

async function ask(prompt, options) {
  const settings = getEffectiveSettings();
  return callProvider(settings, prompt, options);
}

/** Produces a short analyst-facing narrative for a detection candidate. */
async function explainDetection(detection) {
  if (!isEnabled()) {
    return { source: 'deterministic', text: `${detection.name}: ${detection.description}` };
  }
  try {
    const prompt = `You are assisting a SOC analyst. In 2-3 sentences, explain the security significance of this detection in plain language. Do not invent facts not present below.\n\nDetection: ${detection.name}\nCategory: ${detection.category}\nDescription: ${detection.description}\nEvidence: ${JSON.stringify(detection.evidence)}`;
    const text = await ask(prompt);
    return { source: 'ai', text };
  } catch (err) {
    return { source: 'deterministic-fallback', text: `${detection.name}: ${detection.description}`, error: err.message };
  }
}

/** Suggests an interpretation for a low-confidence / uncertain ECS mapping. */
async function suggestMappingNarrative(fieldMapping) {
  if (!isEnabled()) {
    return {
      source: 'deterministic',
      text: `Field "${fieldMapping.rawField}" has an uncertain ECS mapping (${Math.round(fieldMapping.confidence * 100)}% confidence). Analyst review required.`,
    };
  }
  try {
    const prompt = `A raw log field named "${fieldMapping.rawField}" was tentatively mapped to ECS field "${fieldMapping.ecsField}" with ${Math.round(
      fieldMapping.confidence * 100
    )}% confidence. In one sentence, note what an analyst should double check before approving this mapping.`;
    const text = await ask(prompt, { maxTokens: 150 });
    return { source: 'ai', text };
  } catch (err) {
    return {
      source: 'deterministic-fallback',
      text: `Field "${fieldMapping.rawField}" has an uncertain ECS mapping. Analyst review required.`,
      error: err.message,
    };
  }
}

/** Produces a short narrative on likely false-positive causes for a tested rule. */
async function explainFalsePositives(rule, fpAnalysis) {
  const fallbackText = `False-positive rate: ${fpAnalysis.falsePositiveRatePercent}% (${fpAnalysis.riskLevel} risk). See the static guidance below for common causes.`;
  if (!isEnabled()) {
    return { source: 'deterministic', text: fallbackText };
  }
  try {
    const prompt = `A SOC detection rule named "${rule.ruleName}" was tested against real logs. Events tested: ${fpAnalysis.eventsTested}, matched: ${fpAnalysis.eventsMatched}, potential false positives: ${fpAnalysis.potentialFalsePositiveCount} (${fpAnalysis.falsePositiveRatePercent}%). Known false-positive scenarios for this detection type: ${JSON.stringify(
      rule.falsePositiveScenarios
    )}. In 2-3 sentences, advise the analyst on whether this false-positive rate is concerning and what to check first. Do not invent numbers not given above.`;
    const text = await ask(prompt, { maxTokens: 250 });
    return { source: 'ai', text };
  } catch (err) {
    return { source: 'deterministic-fallback', text: fallbackText, error: err.message };
  }
}

module.exports = { explainDetection, suggestMappingNarrative, explainFalsePositives, isEnabled };
