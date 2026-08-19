'use strict';

const { flattenEvent } = require('../field-discovery/flatten');
const { groupBy } = require('../detection-engine/utils');
const { isIpInCidrList, isValidIp } = require('../detection-engine/evaluators/cidrEvaluator');

/**
 * Executes a generated rule's structured `conditions` (and optional
 * threshold/grouping) against normalized events. This deliberately never
 * parses or evaluates the rule's textual query (KQL/EQL/ES|QL/Sigma) - it
 * matches against the same structured filter data the query was rendered
 * from, so there is no query-language interpreter and no eval() involved.
 */
function testRule(rule, normalizedEvents) {
  const events = normalizedEvents.map((normalized, index) => ({ index, normalized, flat: flattenEvent(normalized) }));
  const conditionMatches = events.filter((e) => matchesConditions(e.flat, rule.conditions));

  let finalMatches = conditionMatches;
  let groupingSummary = null;

  if (rule.threshold && rule.groupingFields && rule.groupingFields.length > 0) {
    const groupField = rule.groupingFields[0];
    const distinctField = rule.threshold.distinctField;
    const groups = groupBy(conditionMatches, (e) => e.flat[groupField]);
    finalMatches = [];
    groupingSummary = [];
    for (const [key, group] of groups.entries()) {
      const measure = distinctField
        ? new Set(group.map((e) => e.flat[distinctField]).filter((v) => v !== undefined && v !== null && v !== '')).size
        : group.length;
      const passes = measure >= rule.threshold.count;
      groupingSummary.push({ groupValue: key, eventCount: group.length, measuredCount: measure, passesThreshold: passes });
      if (passes) finalMatches.push(...group);
    }
  }

  const eventsTested = events.length;
  const eventsMatched = finalMatches.length;
  const matchRate = eventsTested > 0 ? round2((eventsMatched / eventsTested) * 100) : 0;

  return {
    eventsTested,
    eventsMatched,
    matchRatePercent: matchRate,
    groupingSummary,
    matchedEvents: finalMatches.slice(0, 200).map((e) => ({
      index: e.index,
      matchedFields: rule.conditions.map((c) => ({ field: c.field, value: e.flat[c.field] })),
      event: e.normalized,
    })),
  };
}

function matchesConditions(flat, conditions) {
  return conditions.every((c) => {
    const value = flat[c.field];
    if (value === undefined || value === null || value === '') return false;
    if (c.exists) return true;
    if (c.cidr) {
      // A malformed/unparseable value is neither confirmed inside nor
      // outside any range - it must fail the condition either way, not be
      // treated as "confirmed external" just because it didn't match any
      // range. (Regression: previously a garbage/missing IP on a "not_in"
      // condition evaluated to true, since !isIpInCidrList(...) is true for
      // any unparseable input.)
      if (!isValidIp(String(value))) return false;
      const ranges = Array.isArray(c.cidr.ranges) ? c.cidr.ranges : [];
      const inRange = isIpInCidrList(String(value), ranges);
      return c.cidr.mode === 'not_in' ? !inRange : inRange;
    }
    const haystack = String(value).toLowerCase();
    const candidates = Array.isArray(c.values) && c.values.length > 0 ? c.values : [c.value];
    // Most conditions intentionally match as a substring/term search - they
    // come from a regex- or stem-based detection over free text (message,
    // process.command_line) or a deliberately partial match (e.g. "den" to
    // catch "denied"/"deny"). A condition can opt into `exact: true` for
    // fields where a partial match is a false positive by definition - an
    // identity field (user.name, process.name) or a numeric field
    // (destination.port), where "root" matching "rootkit" or port 4444
    // matching 14444 would be wrong, not lenient.
    if (c.exact) return candidates.some((v) => haystack === String(v).toLowerCase());
    return candidates.some((v) => haystack.includes(String(v).toLowerCase()));
  });
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { testRule, matchesConditions };
