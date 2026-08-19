'use strict';

const { shannonEntropy } = require('../utils');
const { makeEvaluatorResult } = require('../../detections/evaluatorTypes');

/**
 * Deterministic DNS-tunneling signal evaluator. No LLM involved - every
 * number here is computed directly from the query name string(s). Replaces
 * the previous single length+entropy inline check in networkBehaviors.js
 * with a documented, independently testable module that also considers
 * character distribution, subdomain depth, and whether a group of queries
 * shows a *consistent* pattern rather than one unusual outlier.
 */

const DEFAULT_OPTIONS = {
  longLabelThreshold: 35, // a legitimate subdomain label is rarely this long
  highEntropyThreshold: 3.8, // bits/char; real words score ~2.5-3.5, base32/64-style payloads score higher
  highDigitRatioThreshold: 0.3, // encoded payloads mix digits/letters far more than real hostnames
  deepSubdomainThreshold: 5, // label count (dots + 1)
  minGroupSize: 3, // don't flag a single one-off long query
  suspiciousRatioThreshold: 0.6, // fraction of queries in the group that must themselves look suspicious
};

/** Scores a single DNS query name in isolation. Pure function, no side effects. */
function scoreDnsQuery(name, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const fqdn = String(name || '');
  const labels = fqdn.split('.').filter(Boolean);
  const longestLabel = labels.reduce((longest, l) => (l.length > longest.length ? l : longest), '');
  const entropy = shannonEntropy(longestLabel);
  const digitRatio = longestLabel.length ? (longestLabel.match(/[0-9]/g) || []).length / longestLabel.length : 0;
  const subdomainDepth = labels.length;

  const reasons = [];
  let points = 0;

  if (longestLabel.length >= opts.longLabelThreshold) {
    reasons.push(`Unusually long DNS label (${longestLabel.length} chars)`);
    points += 1;
  }
  if (entropy >= opts.highEntropyThreshold) {
    reasons.push(`High DNS label entropy (${entropy.toFixed(2)} bits/char)`);
    points += 1;
  }
  if (digitRatio >= opts.highDigitRatioThreshold) {
    reasons.push(`Unusual character distribution (${Math.round(digitRatio * 100)}% digits in the longest label)`);
    points += 1;
  }
  if (subdomainDepth >= opts.deepSubdomainThreshold) {
    reasons.push(`Excessive subdomain depth (${subdomainDepth} labels)`);
    points += 1;
  }

  return {
    query: fqdn,
    longestLabel,
    longestLabelLength: longestLabel.length,
    entropy: Math.round(entropy * 1000) / 1000,
    digitRatio: Math.round(digitRatio * 1000) / 1000,
    subdomainDepth,
    suspicious: points >= 2, // any single signal alone is common noise; two or more together is the actual signal
    reasons,
  };
}

/**
 * Evaluates a group of DNS query names (typically all queries under one
 * registered domain) for a tunneling/exfiltration pattern. Requires the
 * pattern to be *consistent* across the group, not just one long query, so
 * a single legitimate long CDN/tracking hostname doesn't trigger this on
 * its own.
 */
function evaluateDnsTunneling(names, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const queries = (names || []).filter(Boolean).map((n) => scoreDnsQuery(n, opts));
  const sampleCount = queries.length;
  const suspiciousQueries = queries.filter((q) => q.suspicious);
  const suspiciousCount = suspiciousQueries.length;
  const suspiciousRatio = sampleCount > 0 ? suspiciousCount / sampleCount : 0;

  const matched = sampleCount >= opts.minGroupSize && suspiciousRatio >= opts.suspiciousRatioThreshold;

  const reasons = [];
  if (matched) {
    reasons.push(`${suspiciousCount}/${sampleCount} DNS queries in this group show length/entropy/character-distribution signals consistent with tunneling`);
    const allReasons = new Set(suspiciousQueries.flatMap((q) => q.reasons));
    reasons.push(...allReasons);
  }

  const meanEntropy = sampleCount > 0 ? queries.reduce((sum, q) => sum + q.entropy, 0) / sampleCount : 0;
  const maxLabelLength = queries.reduce((max, q) => Math.max(max, q.longestLabelLength), 0);
  const maxSubdomainDepth = queries.reduce((max, q) => Math.max(max, q.subdomainDepth), 0);

  return makeEvaluatorResult({
    matched,
    score: matched ? Math.round(suspiciousRatio * 1000) / 1000 : suspiciousRatio,
    reasons,
    evidence: {
      sampleCount,
      suspiciousCount,
      suspiciousRatio: Math.round(suspiciousRatio * 1000) / 1000,
      meanEntropy: Math.round(meanEntropy * 1000) / 1000,
      maxLabelLength,
      maxSubdomainDepth,
      exampleQueries: suspiciousQueries.slice(0, 5).map((q) => q.query),
    },
  });
}

module.exports = { scoreDnsQuery, evaluateDnsTunneling, DEFAULT_OPTIONS };
