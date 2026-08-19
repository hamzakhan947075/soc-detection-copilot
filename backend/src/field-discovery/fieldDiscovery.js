'use strict';

const { flattenEvent } = require('./flatten');
const { inferValueType } = require('./valueTypes');
const { suggestMapping } = require('../ecs-mapping/ecsMapper');

const SECURITY_RELEVANT_HINTS = [
  'ip', 'user', 'account', 'port', 'action', 'outcome', 'status', 'result',
  'process', 'command', 'file', 'hash', 'url', 'method', 'query', 'severity',
  'rule', 'signature', 'protocol', 'host', 'domain', 'auth',
];

/**
 * Runs field discovery over a parsed event set. Every event is flattened to
 * dotted field paths first, then statistics are computed per field:
 * type, example values, frequency, null percentage, ECS candidate mapping,
 * and a simple security-relevance heuristic based on the field name.
 */
function discoverFields(events) {
  const total = events.length;
  const fieldStats = new Map();

  for (const event of events) {
    const flat = flattenEvent(event);
    const seenInThisEvent = new Set();
    for (const [field, value] of Object.entries(flat)) {
      seenInThisEvent.add(field);
      if (!fieldStats.has(field)) {
        fieldStats.set(field, { count: 0, nullCount: 0, values: [], typeCounts: {} });
      }
      const stat = fieldStats.get(field);
      stat.count += 1;
      const isNullish = value === null || value === undefined || value === '';
      if (isNullish) {
        stat.nullCount += 1;
      } else if (stat.values.length < 10) {
        stat.values.push(value);
      }
      const t = inferValueType(value);
      stat.typeCounts[t] = (stat.typeCounts[t] || 0) + 1;
    }
  }

  const fields = [];
  for (const [field, stat] of fieldStats.entries()) {
    const dominantType = dominantOf(stat.typeCounts);
    const mapping = suggestMapping(field, stat.values);
    fields.push({
      field,
      type: dominantType,
      exampleValues: stat.values.slice(0, 5),
      frequency: total > 0 ? round2((stat.count / total) * 100) : 0,
      nullPercentage: stat.count > 0 ? round2((stat.nullCount / stat.count) * 100) : 0,
      occurrences: stat.count,
      ecsCandidate: mapping.ecsField,
      ecsConfidence: mapping.confidence,
      ecsStatus: mapping.status,
      securityRelevance: securityRelevance(field),
    });
  }

  fields.sort((a, b) => b.frequency - a.frequency || a.field.localeCompare(b.field));

  return {
    totalEvents: total,
    uniqueFieldCount: fields.length,
    fields,
  };
}

function dominantOf(typeCounts) {
  let best = 'string';
  let bestCount = -1;
  for (const [type, count] of Object.entries(typeCounts)) {
    if (count > bestCount) {
      best = type;
      bestCount = count;
    }
  }
  return best;
}

function securityRelevance(fieldName) {
  const lower = fieldName.toLowerCase();
  const hit = SECURITY_RELEVANT_HINTS.some((hint) => lower.includes(hint));
  if (hit) return 'high';
  if (lower.includes('time') || lower.includes('date') || lower === 'message') return 'medium';
  return 'low';
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { discoverFields };
