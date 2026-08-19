'use strict';

/**
 * Shared result contract for deterministic "evaluator" functions - the kind
 * used by signal-based detections that compute a real score rather than a
 * simple field/value match (CIDR membership, DNS-label entropy, C2 timing
 * regularity). Every evaluator answers the same three questions in the same
 * shape, regardless of what it measures: did this match, how strongly, and
 * why - so results from different evaluators can be rendered/aggregated
 * uniformly instead of each behavior file inventing its own ad hoc result
 * object.
 *
 * This is a shared contract, not a shared implementation - each evaluator's
 * actual math (CIDR membership, Shannon entropy, timing regularity) is
 * necessarily specific to what it measures. See detection-engine/behaviors/
 * for the evaluators that build results through this helper.
 */
function makeEvaluatorResult({ matched, score = null, reasons = [], evidence = {} }) {
  if (typeof matched !== 'boolean') {
    throw new TypeError('makeEvaluatorResult requires a boolean "matched"');
  }
  return {
    matched,
    score: score === null || score === undefined ? null : Math.round(score * 1000) / 1000,
    reasons: Array.isArray(reasons) ? reasons : [reasons].filter(Boolean),
    evidence: evidence || {},
  };
}

module.exports = { makeEvaluatorResult };
