'use strict';

const { testRule } = require('../testing/ruleTester');

/**
 * Computes a tuning recommendation for a threshold-based rule using the
 * measured false-positive rate. The suggested threshold increase is
 * proportional to the excess false-positive rate above the acceptable
 * ceiling (10%), then validated by re-running the rule at the suggested
 * threshold so the analyst sees real before/after match counts - not a
 * blind guess.
 */
const ACCEPTABLE_FP_RATE = 10;

function recommendTuning(rule, fpAnalysis, normalizedEvents) {
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
    };
  }

  const excessRatio = fpRate / ACCEPTABLE_FP_RATE;
  const suggestedThreshold = Math.max(currentThreshold + 1, Math.round(currentThreshold * excessRatio));

  const adjustedRule = { ...rule, threshold: { ...rule.threshold, count: suggestedThreshold } };
  const afterTest = testRule(adjustedRule, normalizedEvents);

  return {
    applicable: true,
    currentThreshold,
    suggestedThreshold,
    reason: `Current threshold generated a ${fpRate}% potential false-positive rate, above the ${ACCEPTABLE_FP_RATE}% ceiling. Raising the threshold reduces low-confidence matches.`,
    before: { eventsMatched: fpAnalysis.eventsMatched, falsePositiveRatePercent: fpRate },
    after: { eventsMatched: afterTest.eventsMatched, matchRatePercent: afterTest.matchRatePercent },
  };
}

module.exports = { recommendTuning, ACCEPTABLE_FP_RATE };
