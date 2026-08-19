'use strict';

const { flattenEvent } = require('../field-discovery/flatten');
const { isIp, isTimestamp } = require('../field-discovery/valueTypes');

/**
 * Builds a normalized ECS event from a raw (flattened) event plus a set of
 * approved field mappings. Mappings are the single source of truth - this
 * function performs no guessing, only the transformation the mapping stage
 * already decided on (rename + light type coercion).
 *
 * @param {object} rawEvent - original raw event (possibly nested)
 * @param {Array<{rawField:string, ecsField:string|null, ecsType?:string}>} mappings
 */
function normalizeEvent(rawEvent, mappings) {
  const flat = flattenEvent(rawEvent);
  const normalized = {};
  const changes = [];
  const unmapped = [];

  for (const mapping of mappings) {
    const { rawField, ecsField, ecsType } = mapping;
    if (!ecsField) {
      unmapped.push(rawField);
      continue;
    }
    if (!(rawField in flat)) continue;

    const rawValue = flat[rawField];
    const { value, coerced } = coerce(rawValue, ecsType);
    setPath(normalized, ecsField, value);
    changes.push({ rawField, ecsField, valueBefore: rawValue, valueAfter: value, coerced });
  }

  inferEventSemantics(normalized, flat);

  return { normalized, changes, unmapped };
}

function coerce(value, ecsType) {
  if (value === null || value === undefined) return { value, coerced: false };

  if (ecsType === 'date') {
    if (isTimestamp(value)) return { value: toIsoString(value), coerced: typeof value !== 'string' };
    return { value, coerced: false };
  }
  if ((ecsType === 'long' || ecsType === 'port') && typeof value === 'string' && /^-?\d+$/.test(value)) {
    return { value: Number(value), coerced: true };
  }
  if (ecsType === 'ip' && typeof value === 'string' && isIp(value)) {
    return { value, coerced: false };
  }
  return { value, coerced: false };
}

function toIsoString(value) {
  try {
    if (typeof value === 'number') return new Date(value).toISOString();
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  } catch (_err) {
    // fall through
  }
  return String(value);
}

function setPath(obj, dottedPath, value) {
  const parts = dottedPath.split('.');
  let cursor = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (typeof cursor[key] !== 'object' || cursor[key] === null || Array.isArray(cursor[key])) {
      cursor[key] = {};
    }
    cursor = cursor[key];
  }
  cursor[parts[parts.length - 1]] = value;
}

/**
 * Light, conservative inference of event.category/type when the analyst has
 * mapped enough fields to make it unambiguous. Never invents values that
 * were not implied by the mapped ECS fields already present.
 */
function inferEventSemantics(normalized, _flat) {
  const hasAuthShape = normalized.user || normalized.event?.outcome;
  if (hasAuthShape && normalized.event && !normalized.event.category) {
    normalized.event.category = ['authentication'];
  }
}

module.exports = { normalizeEvent, setPath };
