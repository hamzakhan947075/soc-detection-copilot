'use strict';

const { SOURCE_DEFINITIONS } = require('./sourceDefinitions');
const { flattenEvent } = require('../field-discovery/flatten');
const { extractPrimaryMessage } = require('../parsing/parsers');

const SAMPLE_SIZE = 50;
const CONFIDENT_FLOOR = 0.3;

/**
 * Identifies the most likely log source for a dataset by scoring every
 * candidate signature against a sample of events, then normalizing scores
 * into a 0-100% confidence. Deterministic and explainable: every point of
 * confidence traces back to a specific field or message pattern match.
 */
function identifyLogSource(events, filenameHint = '') {
  const sample = events.slice(0, SAMPLE_SIZE);
  if (sample.length === 0) {
    return {
      source: 'Unknown',
      confidence: 0,
      reason: 'No events available to analyze.',
      recommendedDataset: null,
      importantFields: [],
      candidates: [],
    };
  }

  const scored = SOURCE_DEFINITIONS.map((def) => scoreDefinition(def, sample, filenameHint));
  scored.sort((a, b) => b.rawScore - a.rawScore);

  const totalScore = scored.reduce((sum, s) => sum + s.rawScore, 0) || 1;
  const ranked = scored.map((s) => ({
    source: s.def.name,
    confidence: round2((s.rawScore / totalScore) * 100),
    matchedReasons: s.reasons,
    recommendedDataset: s.def.recommendedDataset,
    importantFields: s.def.importantFields,
  }));

  const top = ranked[0];
  const confidencePct = top.confidence;
  const isConfident = confidencePct >= CONFIDENT_FLOOR * 100 && top.matchedReasons.length > 0;

  return {
    source: isConfident ? top.source : 'Unknown / Custom',
    confidence: isConfident ? confidencePct : Math.min(confidencePct, 40),
    reason: isConfident
      ? top.matchedReasons.join('; ')
      : 'No strong signature match found; dataset may be a custom or unrecognized application log. Analyst review recommended.',
    recommendedDataset: isConfident ? top.recommendedDataset : null,
    importantFields: isConfident ? top.importantFields : ['message', '@timestamp'],
    candidates: ranked.slice(0, 5),
  };
}

function scoreDefinition(def, sample, filenameHint = '') {
  let score = 0;
  const reasons = [];
  let fieldHits = 0;
  let messageHits = 0;
  let datasetHits = 0;

  const lowerFilename = filenameHint.toLowerCase();
  if (lowerFilename && def.fieldHints.some((hint) => lowerFilename.includes(hint))) {
    score += 4 * def.weight;
    reasons.push(`Filename "${filenameHint}" is characteristic of ${def.name}`);
  }

  for (const event of sample) {
    const flat = flattenEvent(event);
    const flatKeysLower = Object.keys(flat).join(' ').toLowerCase();
    const flatValuesLower = Object.values(flat)
      .filter((v) => typeof v === 'string')
      .join(' ')
      .toLowerCase();
    const message = extractPrimaryMessage(event);

    const datasetValue = String(flat['event.dataset'] || flat['event.module'] || '').toLowerCase();
    if (def.datasetHints.some((hint) => datasetValue.includes(hint))) {
      datasetHits += 1;
    }

    if (def.fieldHints.some((hint) => flatKeysLower.includes(hint) || flatValuesLower.includes(hint))) {
      fieldHits += 1;
    }

    if (def.messagePatterns.some((re) => re.test(message))) {
      messageHits += 1;
    }
  }

  if (datasetHits > 0) {
    score += datasetHits * 5 * def.weight;
    reasons.push(`event.dataset/module matched ${def.name} in ${datasetHits}/${sample.length} sampled events`);
  }
  if (messageHits > 0) {
    score += messageHits * 3 * def.weight;
    reasons.push(`Message patterns for ${def.name} matched in ${messageHits}/${sample.length} sampled events`);
  }
  if (fieldHits > 0) {
    score += fieldHits * 2 * def.weight;
    reasons.push(`Field names/values characteristic of ${def.name} found in ${fieldHits}/${sample.length} sampled events`);
  }

  // Custom Application acts as a tiny non-zero floor so ranking always has
  // a fallback candidate rather than every score being exactly zero.
  if (def.name === 'Custom Application') {
    score += 0.05;
  }

  return { def, rawScore: score, reasons };
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { identifyLogSource };
