'use strict';

const { isKnownEcsField, getEcsFieldInfo, isElasticsearchMetadataField, resolveTextMultifield } = require('./ecsSchema');
const { ALIASES, normalizeFieldName } = require('./aliasDictionary');
const { inferValueType } = require('../field-discovery/valueTypes');

const UNCERTAIN_THRESHOLD = 0.75;

/**
 * Suggests an ECS mapping for a raw field, given a handful of sample values
 * observed for that field across the dataset. Purely deterministic: name
 * matching against a curated alias dictionary, validated against the actual
 * observed value types. Returns the best candidate plus any alternates, so
 * the UI can show "uncertain - analyst review required" where appropriate.
 */
function suggestMapping(rawFieldName, sampleValues = []) {
  // Case 0: Elasticsearch's own hit metadata (_id, _index, _score, ...) -
  // never part of ECS and never log content, so this is correctly excluded
  // rather than reported as an unmapped gap.
  if (isElasticsearchMetadataField(rawFieldName)) {
    return {
      rawField: rawFieldName,
      ecsField: null,
      ecsType: null,
      confidence: null,
      reason: 'Elasticsearch hit metadata (index bookkeeping), not part of the ECS schema or the original log content.',
      transformationRequired: null,
      alternates: [],
      status: 'excluded',
    };
  }

  // Case 1: the raw field is already a recognized, well-formed ECS path.
  if (isKnownEcsField(rawFieldName)) {
    const info = getEcsFieldInfo(rawFieldName);
    return {
      rawField: rawFieldName,
      ecsField: rawFieldName,
      ecsType: info.type,
      confidence: 0.99,
      reason: `Field name already matches the ECS schema (${info.description})`,
      transformationRequired: false,
      alternates: [],
      status: 'confident',
    };
  }

  // Case 2: a Kibana/ECS `.text` multi-field alongside an already-known ECS
  // field (e.g. host.name.text next to host.name) - resolved, not unmapped.
  const textBase = resolveTextMultifield(rawFieldName);
  if (textBase) {
    const info = getEcsFieldInfo(textBase);
    return {
      rawField: rawFieldName,
      ecsField: textBase,
      ecsType: 'match_only_text',
      confidence: 0.95,
      reason: `Full-text search multi-field of the ECS field "${textBase}" (${info.description})`,
      transformationRequired: false,
      alternates: [],
      status: 'confident',
    };
  }

  const normalized = normalizeFieldName(rawFieldName);
  const candidates = ALIASES[normalized];

  if (!candidates || candidates.length === 0) {
    return {
      rawField: rawFieldName,
      ecsField: null,
      ecsType: null,
      confidence: 0,
      reason: 'No known ECS alias matches this field name; treat as a custom/non-ECS field.',
      transformationRequired: null,
      alternates: [],
      status: 'unmapped',
    };
  }

  const observedType = majorityValueType(sampleValues);
  const scored = candidates.map((c) => scoreCandidate(c, observedType)).sort((a, b) => b.confidence - a.confidence);

  const best = scored[0];
  const alternates = scored.slice(1);
  const status = best.confidence >= UNCERTAIN_THRESHOLD ? 'confident' : 'uncertain';

  return {
    rawField: rawFieldName,
    ecsField: best.ecs,
    ecsType: best.type,
    confidence: round2(best.confidence),
    reason: best.reason,
    transformationRequired: transformationNeeded(rawFieldName, best),
    alternates: alternates.map((a) => ({ ecsField: a.ecs, confidence: round2(a.confidence), reason: a.reason })),
    status,
  };
}

function scoreCandidate(candidate, observedType) {
  let confidence = candidate.confidence;
  let reason = candidate.reason;

  if (observedType && observedType !== 'null') {
    if (typesCompatible(candidate.type, observedType)) {
      confidence = Math.min(0.99, confidence + 0.03);
    } else {
      confidence = Math.max(0.05, confidence * 0.5);
      reason = `${reason} (observed values look like "${observedType}", not "${candidate.type}" - needs validation)`;
    }
  }

  return { ecs: candidate.ecs, type: candidate.type, confidence, reason };
}

function typesCompatible(expected, observed) {
  if (expected === observed) return true;
  if (expected === 'string' && ['string', 'hostname', 'email'].includes(observed)) return true;
  if (expected === 'hostname' && ['hostname', 'string'].includes(observed)) return true;
  if (expected === 'port' && observed === 'number') return true;
  if (expected === 'number' && observed === 'port') return true;
  if (expected === 'ip' && observed === 'ip') return true;
  return false;
}

function majorityValueType(sampleValues) {
  const counts = {};
  for (const v of sampleValues) {
    const t = inferValueType(v);
    if (t === 'null') continue;
    counts[t] = (counts[t] || 0) + 1;
  }
  let best = null;
  let bestCount = 0;
  for (const [type, count] of Object.entries(counts)) {
    if (count > bestCount) {
      best = type;
      bestCount = count;
    }
  }
  return best;
}

function transformationNeeded(rawFieldName, best) {
  if (rawFieldName === best.ecs) return false;
  // Renaming a field is not itself a data transformation; flag true only
  // when the ECS type implies a real conversion (e.g. string -> number/date).
  if (best.type === 'date' || best.type === 'number' || best.type === 'long' || best.type === 'port') {
    return true;
  }
  return false;
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { suggestMapping, UNCERTAIN_THRESHOLD };
