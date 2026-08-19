'use strict';

/**
 * Shared guard against prototype pollution (CWE-1321) for every place in
 * this app that writes into a plain object by a dotted field path built
 * from external input - most importantly ecsField, which is fully
 * analyst-editable via `PUT /sessions/:id/mappings` and, on a deployment
 * with no authentication yet (see README's Known limitations), reachable
 * by anyone with the URL.
 *
 * A dotted path containing "__proto__", "constructor", or "prototype" as
 * any segment can walk a naive `cursor[key] = {}; cursor = cursor[key]`
 * loop onto the real, shared Object.prototype (or Function.prototype via
 * constructor.prototype) and let the final assignment write an arbitrary
 * property onto it - polluting every plain object in the running process,
 * not just the one being built, until restart. Used by
 * normalization/normalizer.js and testing/testCaseGenerator.js, and
 * checked again at the API boundary in routes/api.js so a dangerous
 * ecsField is rejected outright rather than silently dropped deep inside
 * normalization.
 */
const DANGEROUS_PATH_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

/** True if every segment of a dotted path is safe to walk/write on a plain object. */
function isSafeDottedPath(dottedPath) {
  if (typeof dottedPath !== 'string' || !dottedPath) return false;
  return dottedPath.split('.').every((segment) => !DANGEROUS_PATH_SEGMENTS.has(segment));
}

module.exports = { isSafeDottedPath, DANGEROUS_PATH_SEGMENTS };
