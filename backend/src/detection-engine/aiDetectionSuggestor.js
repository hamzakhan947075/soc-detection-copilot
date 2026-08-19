'use strict';

const { flattenEvent } = require('../field-discovery/flatten');
const { matchesConditions } = require('../testing/ruleTester');
const { mapToMitre, MITRE_LOOKUP } = require('../mitre/mitreMap');
const { makeCandidate } = require('./candidateFactory');
const { suggestDetectionPatterns } = require('../ai/aiAssist');

const VALID_CATEGORIES = ['authentication', 'linux', 'windows', 'network', 'web', 'firewall'];
const FALLBACK_CATEGORY = 'ai-suggested';
const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];
const MAX_SAMPLE_EVENTS = 30;
const MAX_FIELD_VALUE_LENGTH = 200;
const MAX_ACCEPTED_CANDIDATES = 8;
const MAX_CONDITIONS_PER_CANDIDATE = 3;
const MIN_REAL_MATCHES = 1;

/**
 * Builds the bounded, privacy-conscious context sent to the AI: the set of
 * real ECS field names present in this dataset (so the AI is told exactly
 * what it's allowed to reference) and a capped sample of the actual
 * flattened normalized events (so it can react to real values, not guess
 * generically). Long string values are truncated to keep token usage and
 * accidental over-sharing of large blobs bounded.
 */
function buildDatasetSummary(normalizedEvents) {
  const flattened = normalizedEvents.map((e) => flattenEvent(e));
  const fieldSet = new Set();
  for (const flat of flattened) {
    for (const field of Object.keys(flat)) fieldSet.add(field);
  }

  const step = Math.max(1, Math.floor(flattened.length / MAX_SAMPLE_EVENTS));
  const sampleEvents = [];
  for (let i = 0; i < flattened.length && sampleEvents.length < MAX_SAMPLE_EVENTS; i += step) {
    sampleEvents.push(truncateValues(flattened[i]));
  }

  return { fields: [...fieldSet].sort(), sampleEvents, flattened };
}

function truncateValues(flat) {
  const out = {};
  for (const [field, value] of Object.entries(flat)) {
    if (typeof value === 'string' && value.length > MAX_FIELD_VALUE_LENGTH) {
      out[field] = `${value.slice(0, MAX_FIELD_VALUE_LENGTH)}…`;
    } else {
      out[field] = value;
    }
  }
  return out;
}

/** One condition, validated against the real field allowlist. Returns null if it doesn't conform. */
function sanitizeCondition(raw, knownFields) {
  if (!raw || typeof raw !== 'object') return null;
  const field = typeof raw.field === 'string' ? raw.field.trim() : '';
  if (!field || !knownFields.has(field)) return null;

  const exact = raw.exact === true;
  if (raw.exists === true) return { field, exists: true };

  if (Array.isArray(raw.values)) {
    const values = raw.values.filter((v) => typeof v === 'string' || typeof v === 'number').map(String).slice(0, 10);
    if (values.length === 0) return null;
    return { field, values, exact };
  }

  if (typeof raw.value === 'string' || typeof raw.value === 'number') {
    return { field, value: String(raw.value), exact };
  }

  return null;
}

/** One candidate object, validated/coerced field-by-field. Returns null if unusable (no name/description, or zero valid conditions). */
function sanitizeCandidate(raw, knownFields) {
  if (!raw || typeof raw !== 'object') return null;

  const name = typeof raw.name === 'string' ? raw.name.trim().slice(0, 200) : '';
  const description = typeof raw.description === 'string' ? raw.description.trim().slice(0, 500) : '';
  if (!name || !description) return null;

  const category = VALID_CATEGORIES.includes(raw.category) ? raw.category : FALLBACK_CATEGORY;
  const severity = VALID_SEVERITIES.includes(raw.severity) ? raw.severity : 'medium';
  const confidence = typeof raw.confidence === 'number' && Number.isFinite(raw.confidence) ? Math.max(0, Math.min(1, raw.confidence)) : 0.5;
  const mitreHint = typeof raw.mitreHint === 'string' && MITRE_LOOKUP[raw.mitreHint] ? raw.mitreHint : null;

  const evidence = Array.isArray(raw.evidence)
    ? raw.evidence.filter((e) => typeof e === 'string').map((e) => e.trim().slice(0, 200)).filter(Boolean).slice(0, 4)
    : [];

  const conditions = Array.isArray(raw.ruleConditions)
    ? raw.ruleConditions
        .map((c) => sanitizeCondition(c, knownFields))
        .filter(Boolean)
        .slice(0, MAX_CONDITIONS_PER_CANDIDATE)
    : [];
  if (conditions.length === 0) return null; // No usable, real-field-grounded condition - can't verify or turn into a rule.

  return { name, description, category, severity, confidence, mitreHint, evidence, ruleConditions: conditions };
}

/** Deterministically slugifies a name into a stable mitreHint-shaped key, used only when the AI didn't pick a real MITRE hint - keeps each distinct AI detection's lifecycle-persistence id distinct instead of every unmapped one colliding under one generic key. */
function slugify(name) {
  const slug = String(name)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 60);
  return slug || 'unnamed';
}

/**
 * Runs the full AI-suggested-detection pipeline: gets untrusted candidate
 * shapes from the model, validates/sanitizes every field against known
 * allowlists, then - critically - re-evaluates each surviving candidate's
 * ruleConditions against the real normalized events with the exact same
 * matchesConditions() used by every other rule test in this app. A
 * candidate that doesn't actually match any real event is dropped; nothing
 * reaches session.detections on the strength of the AI's own say-so alone.
 */
async function suggestAiDetections(normalizedEvents) {
  const { fields, sampleEvents, flattened } = buildDatasetSummary(normalizedEvents);
  const knownFields = new Set(fields);

  const raw = await suggestDetectionPatterns({
    fields,
    sampleEvents,
    validCategories: VALID_CATEGORIES,
    validMitreHints: Object.keys(MITRE_LOOKUP),
  });

  const rawSuggestedCount = raw.length;
  let rejectedInvalidCount = 0;
  let rejectedNoMatchCount = 0;
  const detections = [];

  for (const rawCandidate of raw) {
    const sanitized = sanitizeCandidate(rawCandidate, knownFields);
    if (!sanitized) {
      rejectedInvalidCount += 1;
      continue;
    }

    const matchedIndexes = [];
    flattened.forEach((flat, index) => {
      if (matchesConditions(flat, sanitized.ruleConditions)) matchedIndexes.push(index);
    });
    if (matchedIndexes.length < MIN_REAL_MATCHES) {
      rejectedNoMatchCount += 1;
      continue;
    }

    const mitreHint = sanitized.mitreHint || `ai_${slugify(sanitized.name)}`;
    const requiredFields = [...new Set(sanitized.ruleConditions.map((c) => c.field))];

    detections.push(
      makeCandidate({
        name: sanitized.name,
        category: sanitized.category,
        severity: sanitized.severity,
        confidence: sanitized.confidence,
        description: sanitized.description,
        requiredFields,
        mitreHint,
        matchedEventIndexes: matchedIndexes,
        evidence: [`Verified against real data: matched ${matchedIndexes.length} of ${flattened.length} normalized events.`, ...sanitized.evidence],
        ruleConditions: sanitized.ruleConditions,
        source: 'ai',
      })
    );
    if (detections.length >= MAX_ACCEPTED_CANDIDATES) break;
  }

  const withMitre = detections.map((d) => ({ ...d, mitre: mapToMitre(d.mitreHint) }));

  return {
    detections: withMitre,
    rawSuggestedCount,
    acceptedCount: withMitre.length,
    rejectedCount: rejectedInvalidCount + rejectedNoMatchCount,
    rejectedInvalidCount,
    rejectedNoMatchCount,
  };
}

module.exports = { suggestAiDetections, buildDatasetSummary, sanitizeCandidate, sanitizeCondition };
