'use strict';

/**
 * Computes false-positive statistics for a tested rule by comparing the
 * rule's matched events against the originating detection's own evidence
 * (the events the detection engine already identified as the behavior of
 * interest). Events matched by the broader rule query but NOT part of the
 * original detection's evidence are flagged as potential false positives
 * requiring analyst review - this is a heuristic cross-check, not a claim
 * of certainty, and is always reported as such.
 */
function analyzeFalsePositives(testResult, detection) {
  const originalEvidenceSet = new Set(detection.matchedEventIndexes || []);
  const matchedIndexes = testResult.matchedEvents.map((m) => m.index);

  const likelyTruePositives = matchedIndexes.filter((idx) => originalEvidenceSet.has(idx));
  const potentialFalsePositives = matchedIndexes.filter((idx) => !originalEvidenceSet.has(idx));

  const total = matchedIndexes.length;
  const fpRate = total > 0 ? round2((potentialFalsePositives.length / total) * 100) : 0;

  return {
    eventsTested: testResult.eventsTested,
    eventsMatched: testResult.eventsMatched,
    matchRatePercent: testResult.matchRatePercent,
    likelyTruePositiveCount: likelyTruePositives.length,
    potentialFalsePositiveCount: potentialFalsePositives.length,
    falsePositiveRatePercent: fpRate,
    riskLevel: classifyRisk(fpRate),
    potentialFalsePositiveIndexes: potentialFalsePositives.slice(0, 50),
    note: 'Classification is heuristic: events outside the detection engine\'s original evidence set are flagged as "potential" false positives for analyst review, not confirmed false positives.',
  };
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
