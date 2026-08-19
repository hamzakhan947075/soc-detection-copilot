'use strict';

const MAX_DEPTH = 12;

/**
 * Flattens a nested event object into dotted-path leaf fields, e.g.
 * { host: { name: 'x' } } -> { 'host.name': 'x' }.
 * Arrays of primitives are kept as-is (joined for display); arrays of
 * objects are flattened with a numeric index to avoid losing data.
 */
function flattenEvent(event, prefix = '', depth = 0, out = {}) {
  if (depth > MAX_DEPTH || event === null || event === undefined) {
    if (prefix) out[prefix] = event;
    return out;
  }

  if (Array.isArray(event)) {
    const allPrimitive = event.every((v) => typeof v !== 'object' || v === null);
    if (allPrimitive) {
      out[prefix] = event;
    } else {
      event.forEach((item, idx) => flattenEvent(item, `${prefix}[${idx}]`, depth + 1, out));
    }
    return out;
  }

  if (typeof event === 'object') {
    const keys = Object.keys(event);
    if (keys.length === 0 && prefix) {
      out[prefix] = event;
      return out;
    }
    for (const key of keys) {
      const path = prefix ? `${prefix}.${key}` : key;
      flattenEvent(event[key], path, depth + 1, out);
    }
    return out;
  }

  out[prefix] = event;
  return out;
}

module.exports = { flattenEvent };
