'use strict';

const { testRule } = require('../testing/ruleTester');
const { analyzeFalsePositives } = require('../false-positive/fpAnalysis');

/**
 * Computes a tuning recommendation for a threshold-based rule using the
 * measured false-positive rate. The suggested threshold increase is
 * proportional to the excess false-positive rate above the acceptable
 * ceiling (10%) - but that formula is a starting guess, not the claim. The
 * claim is only made after re-running the rule at the suggested threshold
 * AND re-computing the false-positive rate at that threshold (when the
 * original detection is available) - so "this improves things" is measured,
 * never assumed from the formula alone.
 */
const ACCEPTABLE_FP_RATE = 10;

function recommendTuning(rule, fpAnalysis, normalizedEvents, detection) {
  if (!rule.threshold) {
    return {
      applicable: false,
      reason: 'This rule has no threshold/grouping configuration to tune.',
    };
  }

  const currentThreshold = rule.threshold.count;
  const fpRate = fpAnalysis.falsePositiveRatePercent;

  if (fpRate <= ACCEPTABLE_FP_RATE) {
    return {
      applicable: true,
      currentThreshold,
      suggestedThreshold: currentThreshold,
      reason: `Current false-positive rate (${fpRate}%) is within the acceptable ceiling (${ACCEPTABLE_FP_RATE}%); no change recommended.`,
      before: { eventsMatched: fpAnalysis.eventsMatched, falsePositiveRatePercent: fpRate },
      after: null,
      verifiedImprovement: null,
    };
  }

  const excessRatio = fpRate / ACCEPTABLE_FP_RATE;
  const rawSuggestion = Math.max(currentThreshold + 1, Math.round(currentThreshold * excessRatio));
  // The proportional formula above can overshoot badly on a small dataset
  // (e.g. a 45%-over-ceiling FP rate on a handful of events projects a
  // threshold high enough to match nothing at all, "solving" the FP rate
  // by destroying every true positive too). Capping at the original
  // detection's own evidence count keeps the suggestion from ever exceeding
  // the one group size known to be real signal.
  const evidenceCount = detection && Array.isArray(detection.matchedEventIndexes) ? detection.matchedEventIndexes.length : null;
  const suggestedThreshold = evidenceCount ? Math.min(rawSuggestion, evidenceCount) : rawSuggestion;

  const adjustedRule = { ...rule, threshold: { ...rule.threshold, count: suggestedThreshold } };
  const afterTest = testRule(adjustedRule, normalizedEvents);
  // Re-derive the FP rate (and true-positive count) at the new threshold
  // from the same real evidence-based comparison fpAnalysis.js always uses -
  // not inferred from the formula above, which is only ever a starting guess.
  const afterFpAnalysis = detection ? analyzeFalsePositives(afterTest, detection) : null;
  const afterFpRate = afterFpAnalysis ? afterFpAnalysis.falsePositiveRatePercent : null;
  const afterTruePositives = afterFpAnalysis ? afterFpAnalysis.likelyTruePositiveCount : null;
  // Hitting the FP-rate ceiling by matching nothing at all is not an
  // improvement - it just means the rule no longer catches its own
  // original evidence either. Only a real, non-empty true-positive count
  // at the new threshold counts as a verified improvement.
  const destroysTruePositives = evidenceCount !== null && evidenceCount > 0 && afterTruePositives === 0;
  const verifiedImprovement = afterFpRate !== null ? afterFpRate <= ACCEPTABLE_FP_RATE && !destroysTruePositives : null;
  const fpRateReductionPercent = afterFpRate !== null && fpRate > 0 ? Math.round((1 - afterFpRate / fpRate) * 10000) / 100 : null;

  let reason;
  if (afterFpRate === null) {
    reason = `Current threshold generated a ${fpRate}% potential false-positive rate, above the ${ACCEPTABLE_FP_RATE}% ceiling. Raising the threshold reduces low-confidence matches (false-positive rate at the new threshold could not be re-verified - original detection evidence unavailable).`;
  } else if (destroysTruePositives) {
    reason = `Raising the threshold to ${suggestedThreshold} would bring the false-positive rate to ${afterFpRate}%, but only because it also eliminates every one of this detection's own true positives - not a usable tuning. A different approach (e.g. grouping by an additional field, or a shorter time window) is needed instead of a blanket higher threshold.`;
  } else if (verifiedImprovement) {
    reason = `Raising the threshold to ${suggestedThreshold} is verified to bring the false-positive rate from ${fpRate}% to ${afterFpRate}%, within the ${ACCEPTABLE_FP_RATE}% ceiling, while still matching ${afterTruePositives} true positive(s).`;
  } else {
    reason = `Raising the threshold to ${suggestedThreshold} reduces the false-positive rate from ${fpRate}% to ${afterFpRate}%, but this is still above the ${ACCEPTABLE_FP_RATE}% ceiling - a further increase or a different tuning approach may be needed.`;
  }

  return {
    applicable: true,
    currentThreshold,
    suggestedThreshold,
    reason,
    before: { eventsMatched: fpAnalysis.eventsMatched, falsePositiveRatePercent: fpRate },
    after: { eventsMatched: afterTest.eventsMatched, matchRatePercent: afterTest.matchRatePercent, falsePositiveRatePercent: afterFpRate, truePositiveCount: afterTruePositives },
    verifiedImprovement,
    falsePositiveRateReductionPercent: fpRateReductionPercent,
  };
}

module.exports = { recommendTuning, ACCEPTABLE_FP_RATE };
