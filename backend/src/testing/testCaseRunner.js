'use strict';

const { flattenEvent } = require('../field-discovery/flatten');
const { matchesConditions } = require('./ruleTester');

/**
 * Executes a labeled set of test cases (events with a known expected
 * outcome) against a rule's structured conditions - the same
 * matchesConditions() used by ruleTester.js's "test against loaded data",
 * so a test case's PASS/FAIL means the same thing a real dataset match
 * would. This is a different question than testRule(): testRule asks "how
 * many of my real events does this rule match", this asks "does this rule's
 * logic correctly classify a known-good/known-bad/edge-case event" -
 * regression coverage for the rule itself, independent of any one dataset.
 */

/**
 * @param {object[]} conditions - a rule's structured conditions
 * @param {object} testCase - { id, type: 'positive'|'negative'|'edge', event, expectedMatch, description, skip? }
 */
function runTestCase(conditions, testCase) {
  const base = { id: testCase.id, type: testCase.type, description: testCase.description || '', expectedMatch: testCase.expectedMatch };

  if (testCase.skip) {
    return { ...base, actualMatch: null, outcome: 'SKIPPED', error: null };
  }

  try {
    const flat = flattenEvent(testCase.event ?? {});
    const actualMatch = matchesConditions(flat, conditions);
    const outcome = actualMatch === testCase.expectedMatch ? 'PASS' : 'FAIL';
    return { ...base, actualMatch, outcome, error: null };
  } catch (err) {
    return { ...base, actualMatch: null, outcome: 'ERROR', error: err.message };
  }
}

/** Ratio guarded against a zero denominator - returns null (not NaN/Infinity) when the metric is undefined, per "no fake accuracy". */
function safeRatio(numerator, denominator) {
  if (denominator === 0) return null;
  return Math.round((numerator / denominator) * 1000) / 1000;
}

/**
 * Runs every test case and computes a confusion matrix + classification
 * metrics from it. Only PASS/FAIL-classifiable cases (not ERROR/SKIPPED)
 * contribute to the confusion matrix - an errored case didn't produce a
 * true/false answer to classify.
 */
function runTestSuite(conditions, testCases) {
  const results = (testCases || []).map((tc) => runTestCase(conditions, tc));

  let truePositives = 0;
  let falsePositives = 0;
  let trueNegatives = 0;
  let falseNegatives = 0;

  for (const r of results) {
    if (r.outcome === 'ERROR' || r.outcome === 'SKIPPED') continue;
    if (r.expectedMatch === true) {
      if (r.actualMatch === true) truePositives += 1;
      else falseNegatives += 1;
    } else {
      if (r.actualMatch === false) trueNegatives += 1;
      else falsePositives += 1;
    }
  }

  const precision = safeRatio(truePositives, truePositives + falsePositives);
  const recall = safeRatio(truePositives, truePositives + falseNegatives); // == detection rate
  const f1Score = precision !== null && recall !== null && precision + recall > 0 ? safeRatio(2 * precision * recall, precision + recall) : null;
  const falsePositiveRate = safeRatio(falsePositives, falsePositives + trueNegatives);

  const counts = {
    total: results.length,
    pass: results.filter((r) => r.outcome === 'PASS').length,
    fail: results.filter((r) => r.outcome === 'FAIL').length,
    error: results.filter((r) => r.outcome === 'ERROR').length,
    skipped: results.filter((r) => r.outcome === 'SKIPPED').length,
  };

  return {
    results,
    counts,
    confusionMatrix: { truePositives, falsePositives, trueNegatives, falseNegatives },
    metrics: {
      precision,
      recall,
      detectionRate: recall,
      f1Score,
      falsePositiveRate,
    },
  };
}

module.exports = { runTestCase, runTestSuite };
