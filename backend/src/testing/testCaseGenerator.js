'use strict';

const { valuesOf, cidrRangesOf } = require('../rule-generation/queryLanguages');
const { isSafeDottedPath } = require('../utils/safePath');

/**
 * Generates a default set of positive/negative/edge test cases directly
 * from a rule's own structured conditions, so every detection gets real
 * regression coverage without requiring an analyst to hand-author cases
 * from nothing. Analyst-supplied cases (see routes/api.js's /testsuite
 * endpoint) are always additive to these, never a replacement - and if a
 * real matched event from an actual test run is available, it's used as
 * the positive base case instead of a synthetic one, since real evidence
 * is strictly better than a fabricated example.
 */

const OUTSIDE_TEST_IP = '203.0.113.10'; // TEST-NET-3 (RFC 5737) - never RFC1918/loopback/link-local
const NEGATIVE_MARKER = '__negative_test_value__';

// Condition field names come from the detection engine today, but this
// walks/writes a plain object by dotted path the same way
// normalization/normalizer.js's setPath does - see utils/safePath.js for why
// the same guard applies here too.
function setPath(obj, dottedField, value) {
  if (!isSafeDottedPath(dottedField)) return;
  const parts = String(dottedField).split('.');
  let node = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof node[parts[i]] !== 'object' || node[parts[i]] === null) node[parts[i]] = {};
    node = node[parts[i]];
  }
  node[parts[parts.length - 1]] = value;
}

function deletePath(obj, dottedField) {
  if (!isSafeDottedPath(dottedField)) return;
  const parts = String(dottedField).split('.');
  let node = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof node[parts[i]] !== 'object' || node[parts[i]] === null) return;
    node = node[parts[i]];
  }
  delete node[parts[parts.length - 1]];
}

/** A value that satisfies `condition` in isolation, used to build a synthetic positive base event. */
function satisfyingValue(condition) {
  if (condition.exists) return 'present-value';
  if (condition.cidr) {
    const ranges = cidrRangesOf(condition);
    if (condition.cidr.mode === 'not_in') return OUTSIDE_TEST_IP;
    const firstRange = ranges[0] || '10.0.0.0/8';
    return firstRange.split('/')[0]; // a range's own network address is always inside it
  }
  return valuesOf(condition)[0];
}

function buildSyntheticPositiveEvent(conditions) {
  const event = {};
  for (const c of conditions) setPath(event, c.field, satisfyingValue(c));
  return event;
}

/** Deep-clones a plain JSON-shaped event (sufficient for the flattened ECS-style events this app works with). */
function cloneEvent(event) {
  return JSON.parse(JSON.stringify(event || {}));
}

/**
 * @param {object[]} conditions
 * @param {object} [samplePositiveEvent] - a real event known to match, from a prior testRule() run. Preferred over a synthetic one.
 * @returns {{ positive: object[], negative: object[], edge: object[] }}
 */
function generateDefaultTestCases(conditions, samplePositiveEvent) {
  if (!Array.isArray(conditions) || conditions.length === 0) {
    return { positive: [], negative: [], edge: [] };
  }

  const positiveEvent = samplePositiveEvent ? cloneEvent(samplePositiveEvent) : buildSyntheticPositiveEvent(conditions);
  const positiveSource = samplePositiveEvent ? 'a real event that matched this rule during dataset testing' : 'synthesized directly from the rule\'s own conditions';

  const positive = [
    {
      id: 'positive-1',
      type: 'positive',
      expectedMatch: true,
      description: `Baseline positive case, ${positiveSource}.`,
      event: positiveEvent,
    },
  ];

  // Negative: flip the first non-exists condition's value so exactly one
  // required condition fails - proves the rule doesn't match everything.
  const negativeEvent = cloneEvent(positiveEvent);
  const flipTarget = conditions.find((c) => !c.exists) || conditions[0];
  if (flipTarget.exists) {
    deletePath(negativeEvent, flipTarget.field);
  } else if (flipTarget.cidr) {
    setPath(negativeEvent, flipTarget.field, flipTarget.cidr.mode === 'not_in' ? (cidrRangesOf(flipTarget)[0] || '10.0.0.0/8').split('/')[0] : OUTSIDE_TEST_IP);
  } else {
    setPath(negativeEvent, flipTarget.field, NEGATIVE_MARKER);
  }
  const negative = [
    {
      id: 'negative-1',
      type: 'negative',
      expectedMatch: false,
      description: `Otherwise-identical event with "${flipTarget.field}" changed so it should not match.`,
      event: negativeEvent,
    },
  ];

  // Edge cases: one deterministic mutation per condition field - missing,
  // null, and (for cidr conditions specifically) malformed value. Every one
  // of these must resolve to expectedMatch: false, because each removes or
  // corrupts a field at least one AND'd condition depends on.
  const edge = [];
  conditions.forEach((c, i) => {
    const missing = cloneEvent(positiveEvent);
    deletePath(missing, c.field);
    edge.push({
      id: `edge-missing-${i}`,
      type: 'edge',
      expectedMatch: false,
      description: `Required field "${c.field}" is missing entirely.`,
      event: missing,
    });

    const nulled = cloneEvent(positiveEvent);
    setPath(nulled, c.field, null);
    edge.push({
      id: `edge-null-${i}`,
      type: 'edge',
      expectedMatch: false,
      description: `Required field "${c.field}" is explicitly null.`,
      event: nulled,
    });

    if (c.cidr) {
      const malformed = cloneEvent(positiveEvent);
      setPath(malformed, c.field, 'not-a-valid-ip');
      edge.push({
        id: `edge-malformed-ip-${i}`,
        type: 'edge',
        expectedMatch: false,
        description: `Field "${c.field}" holds a malformed IP address, in either cidr mode.`,
        event: malformed,
      });
    }
  });

  // Duplicate-event edge case: the matcher evaluates each event
  // independently, so two identical copies of the positive event must both
  // still match - proving duplicates aren't silently suppressed or double
  // counted differently than a single occurrence.
  edge.push({
    id: 'edge-duplicate',
    type: 'edge',
    expectedMatch: true,
    description: 'An exact duplicate of the positive event still matches independently (duplicates are not silently suppressed).',
    event: cloneEvent(positiveEvent),
  });

  // Unusual timestamp: matching must not depend on @timestamp being
  // present or well-formed, since none of these query languages filter on
  // time inside the structured conditions themselves.
  const noTimestamp = cloneEvent(positiveEvent);
  deletePath(noTimestamp, '@timestamp');
  edge.push({
    id: 'edge-missing-timestamp',
    type: 'edge',
    expectedMatch: true,
    description: 'Missing @timestamp does not affect whether the other conditions match.',
    event: noTimestamp,
  });

  return { positive, negative, edge };
}

module.exports = { generateDefaultTestCases };
