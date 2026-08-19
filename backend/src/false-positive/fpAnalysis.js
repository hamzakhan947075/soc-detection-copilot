'use strict';

const { flattenEvent } = require('../field-discovery/flatten');

/**
 * Computes false-positive statistics for a tested rule by comparing the
 * rule's matched events against the originating detection's own evidence
 * (the events the detection engine already identified as the behavior of
 * interest). Events matched by the broader rule query but NOT part of the
 * original detection's evidence are flagged as potential false positives
 * requiring analyst review - this is a heuristic cross-check, not a claim
 * of certainty, and is always reported as such.
 *
 * Beyond the aggregate rate, this also breaks down *what* the potential
 * false positives actually have in common (top recurring field/value pairs,
 * plus a few common dimensions analysts usually ask about first: users,
 * hosts, processes, destinations) and turns a strong pattern into a
 * suggested exclusion - never applied automatically, only surfaced for an
 * analyst to approve.
 */

const DIMENSION_FIELDS = {
  topUsers: 'user.name',
  topHosts: 'host.name',
  topProcesses: 'process.name',
  topDestinations: 'destination.ip',
};

// Free-text/always-unique fields would dominate a "top values" ranking
// without meaning anything (every event has a different message/timestamp).
const NOISY_FIELDS = new Set(['@timestamp', 'event.original', 'message', 'log.original', 'event.id']);

const RECOMMENDATION_THRESHOLD_PERCENT = 50;

function analyzeFalsePositives(testResult, detection) {
  const originalEvidenceSet = new Set(detection.matchedEventIndexes || []);
  const matched = testResult.matchedEvents || [];

  const likelyTruePositives = matched.filter((m) => originalEvidenceSet.has(m.index));
  const potentialFalsePositives = matched.filter((m) => !originalEvidenceSet.has(m.index));

  const total = matched.length;
  const fpRate = total > 0 ? round2((potentialFalsePositives.length / total) * 100) : 0;

  const fieldValueCounts = countFieldValues(potentialFalsePositives);
  const rankedPairs = rankFieldValuePairs(fieldValueCounts, potentialFalsePositives.length);
  const topFalsePositiveFields = rankedPairs.slice(0, 10);

  const dimensions = {};
  for (const [key, field] of Object.entries(DIMENSION_FIELDS)) {
    dimensions[key] = rankedPairs.filter((p) => p.field === field).slice(0, 5);
  }

  return {
    eventsTested: testResult.eventsTested,
    eventsMatched: testResult.eventsMatched,
    nonMatchedEvents: Math.max(0, testResult.eventsTested - testResult.eventsMatched),
    matchRatePercent: testResult.matchRatePercent,
    likelyTruePositiveCount: likelyTruePositives.length,
    potentialFalsePositiveCount: potentialFalsePositives.length,
    falsePositiveRatePercent: fpRate,
    riskLevel: classifyRisk(fpRate),
    potentialFalsePositiveIndexes: potentialFalsePositives.slice(0, 50).map((m) => m.index),
    topFalsePositiveFields,
    ...dimensions,
    recommendedExclusions: buildRecommendations(topFalsePositiveFields),
    note: 'Classification is heuristic: events outside the detection engine\'s original evidence set are flagged as "potential" false positives for analyst review, not confirmed false positives. Recommended exclusions are suggestions only - nothing is ever excluded automatically.',
  };
}

/**
 * Counts how often each (field, value) pair appears across a set of
 * matched-event entries ({event: normalizedEvent}). Keyed as
 * Map<field, Map<value, count>> rather than a joined string key, so a
 * value that happens to contain whitespace or any other delimiter can
 * never be mis-split back apart when read.
 */
function countFieldValues(matchedEntries) {
  const counts = new Map();
  for (const entry of matchedEntries) {
    const flat = flattenEvent(entry.event || {});
    for (const [field, value] of Object.entries(flat)) {
      if (NOISY_FIELDS.has(field)) continue;
      if (value === null || value === undefined || value === '') continue;
      if (Array.isArray(value) || typeof value === 'object') continue; // ranking scalar values only
      if (!counts.has(field)) counts.set(field, new Map());
      const perValue = counts.get(field);
      const valueKey = String(value);
      perValue.set(valueKey, (perValue.get(valueKey) || 0) + 1);
    }
  }
  return counts;
}

function rankFieldValuePairs(counts, totalPotentialFPs) {
  const pairs = [];
  for (const [field, perValue] of counts.entries()) {
    for (const [value, count] of perValue.entries()) {
      pairs.push({
        field,
        value,
        count,
        percentOfPotentialFPs: totalPotentialFPs > 0 ? round2((count / totalPotentialFPs) * 100) : 0,
      });
    }
  }
  return pairs.sort((a, b) => b.count - a.count || a.field.localeCompare(b.field));
}

/** A field/value pair shared by most potential FPs is worth surfacing as a candidate exclusion - never applied without analyst approval. */
function buildRecommendations(rankedPairs) {
  return rankedPairs
    .filter((p) => p.percentOfPotentialFPs >= RECOMMENDATION_THRESHOLD_PERCENT)
    .slice(0, 5)
    .map((p) => ({
      field: p.field,
      value: p.value,
      percentOfPotentialFPs: p.percentOfPotentialFPs,
      recommendation: `Consider excluding: ${p.field} = ${p.value}`,
      reason: `${p.percentOfPotentialFPs}% of potential false positives share this value.`,
    }));
}

function classifyRisk(fpRatePercent) {
  if (fpRatePercent >= 40) return 'high';
  if (fpRatePercent >= 15) return 'medium';
  return 'low';
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { analyzeFalsePositives };
