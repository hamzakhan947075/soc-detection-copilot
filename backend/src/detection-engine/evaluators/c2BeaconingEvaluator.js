'use strict';

const { makeEvaluatorResult } = require('../../detections/evaluatorTypes');

/**
 * Deterministic C2-beaconing timing evaluator. Given the sorted timestamps
 * of connections to one repeated destination (optionally + port), scores
 * how regular the inter-arrival intervals are - the classic beaconing
 * signal, independent of any single event's content. No LLM involved.
 */

const DEFAULT_OPTIONS = {
  minSamples: 6, // need enough connections to say anything about regularity
  maxMeanIntervalMs: 30 * 60 * 1000, // beaconing is normally minutes, not hours, apart
  maxCoefficientOfVariation: 0.15, // stddev/mean below this = "highly regular" timing
};

/**
 * @param {number[]} timestampsMs - epoch-ms timestamps of connections to one destination (any order)
 * @param {object} [context] - descriptive fields carried into the evidence only (destination, destinationPort)
 * @param {object} [options] - overrides for DEFAULT_OPTIONS
 */
function evaluateBeaconing(timestampsMs, context = {}, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const sorted = (timestampsMs || []).filter((t) => Number.isFinite(t)).sort((a, b) => a - b);
  const sampleCount = sorted.length;

  const baseEvidence = {
    destination: context.destination || null,
    destinationPort: context.destinationPort !== undefined ? context.destinationPort : null,
    sampleCount,
    intervalMeanMs: null,
    intervalStdDevMs: null,
    coefficientOfVariation: null,
    jitterMs: null,
  };

  if (sampleCount < opts.minSamples) {
    return makeEvaluatorResult({ matched: false, score: 0, reasons: [], evidence: baseEvidence });
  }

  const intervals = [];
  for (let i = 1; i < sorted.length; i++) intervals.push(sorted[i] - sorted[i - 1]);
  const intervalMean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.length > 0 ? intervals.reduce((sum, v) => sum + (v - intervalMean) ** 2, 0) / intervals.length : 0;
  const intervalStdDev = Math.sqrt(variance);
  const coefficientOfVariation = intervalMean > 0 ? intervalStdDev / intervalMean : Infinity;

  const matched = intervalMean > 0 && intervalMean <= opts.maxMeanIntervalMs && coefficientOfVariation <= opts.maxCoefficientOfVariation;
  // 1.0 = perfectly regular (CoV of 0); 0 = at or beyond the "regular" threshold. Never negative or >1.
  const regularityScore = intervalMean > 0 ? Math.max(0, Math.min(1, 1 - coefficientOfVariation / opts.maxCoefficientOfVariation)) : 0;

  const reasons = matched
    ? [
        `${sampleCount} connections${context.destination ? ` to ${context.destination}` : ''} at highly regular intervals ` +
          `(avg ${Math.round(intervalMean / 1000)}s, stddev ${Math.round(intervalStdDev / 1000)}s, coefficient of variation ${coefficientOfVariation.toFixed(2)})`,
      ]
    : [];

  return makeEvaluatorResult({
    matched,
    score: Math.round(regularityScore * 1000) / 1000,
    reasons,
    evidence: {
      ...baseEvidence,
      intervalMeanMs: Math.round(intervalMean),
      intervalStdDevMs: Math.round(intervalStdDev),
      coefficientOfVariation: Number.isFinite(coefficientOfVariation) ? Math.round(coefficientOfVariation * 1000) / 1000 : null,
      jitterMs: Math.round(intervalStdDev),
    },
  });
}

module.exports = { evaluateBeaconing, DEFAULT_OPTIONS };
