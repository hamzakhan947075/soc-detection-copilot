'use strict';

const { isKnownEcsField, getEcsFieldInfo, isElasticsearchMetadataField, resolveTextMultifield, isKnownEcsNamespace } = require('./ecsSchema');
const { ALIASES, normalizeFieldName } = require('./aliasDictionary');
const { inferValueType } = require('../field-discovery/valueTypes');

const UNCERTAIN_THRESHOLD = 0.75;

/**
 * Suggests an ECS mapping for a raw field, given a handful of sample values
 * observed for that field across the dataset. Purely deterministic: name
 * matching against a curated alias dictionary, validated against the actual
 * observed value types. Returns the best candidate plus any alternates, so
 * the UI can show "uncertain - analyst review required" where appropriate.
 *
 * `status` is one of:
 *   confident   - a specific ECS field, high confidence (exact schema match,
 *                 .text multi-field, or a strong alias match)
 *   uncertain   - a specific ECS field guessed, but confidence is low -
 *                 analyst review required before approving
 *   custom      - not ECS at all: the field's own top-level namespace isn't
 *                 a real ECS field group, so this is the analyst's own
 *                 application-specific field, not a mapping gap
 *   unsupported - a plausible ECS field name matched, but the observed
 *                 value is an array/object rather than the scalar ECS
 *                 expects - this mapper doesn't attempt structural
 *                 transformation, so it's flagged rather than guessed at
 *   excluded    - Elasticsearch's own hit metadata, never part of ECS or
 *                 log content
 *   unmapped    - no alias matched, but the field's namespace IS part of
 *                 ECS - a genuine gap in this app's ECS_FIELDS subset (or a
 *                 real ECS field this app's dictionary doesn't carry yet),
 *                 not the same thing as "custom"
 * `mappingMethod` records *how* a mapping was produced (independent of the
 * confidence-based status above): 'exact' | 'text_multifield' | 'alias' | null.
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
      mappingMethod: null,
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
      mappingMethod: 'exact',
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
      mappingMethod: 'text_multifield',
    };
  }

  const normalized = normalizeFieldName(rawFieldName);
  const candidates = ALIASES[normalized];

  if (!candidates || candidates.length === 0) {
    // Case 3: no alias candidate. Whether this is "custom" (not ECS at all)
    // or genuinely "unmapped" (part of ECS, but a gap in this app's schema
    // subset) depends on whether the field's own namespace is real ECS.
    const isCustom = !isKnownEcsNamespace(rawFieldName);
    return {
      rawField: rawFieldName,
      ecsField: null,
      ecsType: null,
      confidence: null,
      reason: isCustom
        ? `"${String(rawFieldName).split('.')[0]}" is not an ECS field group - this looks like an application-specific custom field, not an ECS mapping gap.`
        : 'No known ECS alias matches this field name, but its namespace is part of ECS - may be a real ECS field outside this app\'s current schema subset. Review manually.',
      transformationRequired: null,
      alternates: [],
      status: isCustom ? 'custom' : 'unmapped',
      mappingMethod: null,
    };
  }

  const observedType = majorityValueType(sampleValues);

  // Case 4: a name-based candidate exists, but the observed values are
  // arrays/objects rather than the scalar value ECS expects for that field.
  // Guessing a confidence-scored scalar mapping here would misrepresent
  // what's actually in the data - this mapper doesn't attempt structural
  // (array/object -> scalar) transformation, so it says so explicitly.
  if (observedType === 'array' || observedType === 'object') {
    const hint = candidates[0];
    return {
      rawField: rawFieldName,
      ecsField: null,
      ecsType: null,
      confidence: null,
      reason: `Field name suggests "${hint.ecs}", but observed values are ${observedType === 'array' ? 'arrays' : 'nested objects'}, not a scalar - this mapper does not attempt structural transformation. Review manually.`,
      transformationRequired: null,
      alternates: [],
      status: 'unsupported',
      mappingMethod: null,
    };
  }

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
    mappingMethod: 'alias',
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
