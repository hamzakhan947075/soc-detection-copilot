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
  const text = await callProvider(settings, prompt, options);
  if (!text || !text.trim()) {
    // Some models (e.g. reasoning models on a tight token budget) can return
    // a technically-successful response with no usable content. Treat that
    // as a failure so callers fall back to their deterministic text instead
    // of showing a blank "AI" answer.
    throw new Error('AI provider returned an empty response.');
  }
  return text;
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

/** Suggests an interpretation for a low-confidence, unmapped, or uncertain ECS mapping. */
async function suggestMappingNarrative(fieldMapping) {
  const { rawField, ecsField, confidence, exampleValues } = fieldMapping;
  const examplesText = Array.isArray(exampleValues) && exampleValues.length ? ` Example value(s): ${JSON.stringify(exampleValues.slice(0, 3))}.` : '';

  const fallbackText = ecsField
    ? `Field "${rawField}" has an uncertain ECS mapping (${Math.round((confidence || 0) * 100)}% confidence). Analyst review required.`
    : `Field "${rawField}" has no ECS candidate. It may be a custom application field, or the ECS schema dictionary may not yet cover it - review manually.`;

  if (!isEnabled()) {
    return { source: 'deterministic', text: fallbackText };
  }
  try {
    const prompt = ecsField
      ? `A raw log field named "${rawField}" was tentatively mapped to ECS field "${ecsField}" with ${Math.round(
          (confidence || 0) * 100
        )}% confidence.${examplesText} In one sentence, note what an analyst should double check before approving this mapping.`
      : `A raw log field named "${rawField}" from a security log could not be automatically mapped to any ECS (Elastic Common Schema) field.${examplesText} In one or two sentences, suggest the most likely ECS field it should map to (if any), or state that it is likely a custom, non-ECS field. Do not invent an ECS field name that does not exist in the real ECS spec.`;
    const text = await ask(prompt, { maxTokens: 400 });
    return { source: 'ai', text };
  } catch (err) {
    return { source: 'deterministic-fallback', text: fallbackText, error: err.message };
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
    const text = await ask(prompt, { maxTokens: 500 });
    return { source: 'ai', text };
  } catch (err) {
    return { source: 'deterministic-fallback', text: fallbackText, error: err.message };
  }
}

/**
 * Asks the AI to propose candidate detection patterns from a real sample of
 * this dataset's normalized ECS events. Unlike every other function in this
 * file, this one has no deterministic fallback and no meaning when AI isn't
 * configured - it throws in that case, and the route surfaces that as a
 * clear "AI not configured" error rather than returning a fake result.
 *
 * The response is untrusted model output: this function only parses the
 * JSON text back out. It does NOT decide what becomes a real Detection
 * Candidate - see detection-engine/aiDetectionSuggestor.js, which validates
 * every field against a known allowlist and then re-verifies each proposed
 * ruleConditions set against the real events with the same matcher every
 * other rule in this app is tested with, before anything from here reaches
 * session.detections. This function is the only untrusted step in that
 * pipeline; everything downstream of it is deterministic.
 */
async function suggestDetectionPatterns({ fields, sampleEvents, validCategories, validMitreHints }) {
  if (!isEnabled()) {
    throw new Error('AI is not configured. Set an API key in Settings or via an environment variable to use AI-suggested detections.');
  }
  const prompt = `You are assisting a SOC detection engineer. Below is a sample of real, already ECS-normalized security log events (dotted field paths) from one dataset, and the full list of ECS fields present anywhere in it.

Known ECS fields in this dataset (only use these - never invent a field name): ${JSON.stringify(fields)}

Sample normalized events (${sampleEvents.length} of the full dataset):
${JSON.stringify(sampleEvents)}

Look for concrete suspicious patterns actually visible in this sample (repeated failures, unusual value combinations, rare/anomalous values, known-bad indicators, etc.) - not generic textbook detections unrelated to what's here. Propose at most 5 candidate detections.

Respond with ONLY a JSON array (no markdown fences, no prose), where each item has exactly these fields:
- "name": short detection name (string)
- "category": one of ${JSON.stringify(validCategories)} (pick the closest fit)
- "severity": one of "low", "medium", "high", "critical"
- "confidence": number from 0 to 1, how confident you are this is a real, actionable pattern in THIS sample
- "description": 1-2 sentences explaining the specific pattern you found
- "mitreHint": one of ${JSON.stringify(validMitreHints)}, or null if none fit
- "evidence": array of up to 4 short strings citing the specific values/counts you observed
- "ruleConditions": array of 1-3 objects, each EXACTLY one of:
  - {"field": "<one of the known ECS fields above>", "exists": true}
  - {"field": "<one of the known ECS fields above>", "value": "<value>", "exact": true|false}
  - {"field": "<one of the known ECS fields above>", "values": ["<value1>", "<value2>"], "exact": true|false}
  Use "exact": true for identity/enum-like fields (user.name, process.name, ports, status codes) and "exact": false for free-text substring fields (message, process.command_line, url.original).

If you cannot find any real pattern worth flagging in this sample, respond with an empty JSON array: []`;

  // At most 5 short JSON objects come back - 1200 completion tokens is
  // generous for that and leaves more of a low-TPM free tier's budget
  // (e.g. Groq's 8000 TPM) for the prompt itself.
  const text = await ask(prompt, { maxTokens: 1200 });
  const jsonText = extractJsonArray(text);
  let parsed;
  try {
    parsed = JSON.parse(jsonText);
  } catch (err) {
    throw new Error(`AI response was not valid JSON: ${err.message}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error('AI response was not a JSON array.');
  }
  return parsed;
}

/** Strips a leading/trailing markdown code fence, if the model added one despite instructions not to. */
function extractJsonArray(text) {
  const trimmed = text.trim();
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  return fenced ? fenced[1].trim() : trimmed;
}

module.exports = { explainDetection, suggestMappingNarrative, explainFalsePositives, suggestDetectionPatterns, isEnabled };
