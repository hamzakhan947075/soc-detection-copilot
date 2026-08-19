'use strict';

let counter = 0;

/**
 * Builds a normalized "Detection Candidate" object shared by every behavior
 * module in detection-engine/behaviors/*. MITRE mapping is attached later by
 * detectionEngine.js (via the mitre module) so behavior modules never need
 * to know MITRE technique IDs directly - they only declare a `mitreHint`
 * lookup key.
 */
function makeCandidate({
  name,
  category,
  severity,
  confidence,
  description,
  requiredFields,
  mitreHint,
  recommendedThreshold,
  matchedEventIndexes,
  evidence,
  ruleConditions,
  evaluatorResult,
}) {
  counter += 1;
  return {
    id: `det-${Date.now().toString(36)}-${counter}`,
    name,
    category,
    severity,
    confidence: Math.round(confidence * 100) / 100,
    description,
    requiredFields,
    mitreHint,
    recommendedThreshold: recommendedThreshold || null,
    matchedEventIndexes: matchedEventIndexes || [],
    evidence: evidence || [],
    // The exact {field, value} filter(s) that reproduce this behavior's own
    // matching logic, so a generated rule's "test against sample logs"
    // reflects what was actually detected rather than a generic category
    // guess. Falls back to the mitreHint dictionary in queryConditions.js
    // when a behavior does not set this explicitly.
    ruleConditions: ruleConditions || null,
    // Optional: the structured {matched, score, reasons, evidence} output of
    // a deterministic evaluator (detection-engine/evaluators/*.js), for
    // detections whose signal is a computed score rather than a simple
    // field/value match (CIDR direction, DNS-label entropy, C2 timing
    // regularity). null for detections that don't use one.
    evaluatorResult: evaluatorResult || null,
  };
}

module.exports = { makeCandidate };
