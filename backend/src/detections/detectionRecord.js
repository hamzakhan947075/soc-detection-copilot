'use strict';

const { getFpGuidance } = require('../false-positive/fpGuidance');

/**
 * Canonical Detection record - additive layer on top of the existing
 * Detection Candidate (detection-engine/candidateFactory.js) and generated
 * Rule (rule-generation/ruleBuilder.js). Nothing in the pipeline is changed
 * by this module: rule generation, testing, FP analysis, and tuning all
 * continue to run exactly as before, against the candidate/rule shapes they
 * already use. This module only assembles a single, explainable view of
 * "everything currently known about one detection in this session" - the
 * shape a future persisted DetectionStore (see ARCHITECTURE_AUDIT.md §10)
 * would store.
 *
 * Honesty note: `status` here reflects session progress (draft -> generated
 * -> tested -> tuned), not a persisted approval workflow - there is no
 * database yet, so "approved"/"production"/"deprecated" states and real
 * version history don't exist until a DetectionStore is built. Don't read
 * more into `status`/`version` than that.
 */
function createDetectionRecord(candidate, context = {}) {
  const { logSource = null, rule = null } = context;
  const testResult = rule ? rule.lastTestResult || null : null;
  const fpAnalysis = rule ? rule.lastFpAnalysis || null : null;
  const tuning = context.tuning || null;
  const now = new Date().toISOString();

  return {
    id: candidate.id,
    name: candidate.name,
    description: candidate.description,
    status: deriveStatus({ rule, testResult, tuning }),
    severity: candidate.severity,
    confidence: candidate.confidence,
    dataSources: [candidate.category],
    logSource: logSource ? { source: logSource.source, confidence: logSource.confidence } : null,
    ecsRequirements: candidate.requiredFields || [],
    ruleConditions: candidate.ruleConditions || null,
    evaluator: {
      // The current generation of evaluators are plain functions inside
      // detection-engine/behaviors/*.js, keyed by mitreHint rather than
      // self-reporting a first-class evaluator id. This is a stable derived
      // identifier until each behavior module reports one directly.
      id: `${candidate.category}.${candidate.mitreHint || 'generic'}`,
      kind: candidate.ruleConditions ? 'structured' : 'heuristic',
    },
    detectionLogic: candidate.description,
    mitre: buildMitre(candidate.mitre),
    query: (rule && rule.query) || null,
    queryLanguage: (rule && rule.ruleType) || null,
    testCases: { positive: [], negative: [], edge: [] },
    testResult,
    falsePositiveProfile: {
      staticGuidance: getFpGuidance(candidate.mitreHint),
      dynamic: fpAnalysis,
    },
    tuning,
    metadata: {
      generatedAt: now,
      source: 'behavior-engine',
    },
    version: 1,
  };
}

function buildMitre(mitre) {
  if (!mitre || !mitre.techniqueId) {
    return {
      tactic: null,
      technique: null,
      subTechnique: null,
      confidence: mitre ? mitre.confidence : 0,
      certain: false,
      note: (mitre && mitre.note) || 'No MITRE mapping available for this detection type.',
    };
  }
  // The current MITRE dictionary (mitre/mitreMap.js) folds the sub-technique
  // into a single dotted techniqueId (e.g. "T1110.001") with one combined
  // name - there is no separately-tracked parent-technique name today, so
  // `technique.name` reuses the same name for a sub-technique entry. This is
  // a real gap, not a display bug: a richer MITRE dictionary would carry
  // both names independently.
  const isSubTechnique = mitre.techniqueId.includes('.');
  return {
    tactic: mitre.tacticId ? { id: mitre.tacticId, name: mitre.tacticName } : null,
    technique: { id: isSubTechnique ? mitre.techniqueId.split('.')[0] : mitre.techniqueId, name: mitre.techniqueName },
    subTechnique: isSubTechnique ? { id: mitre.techniqueId, name: mitre.techniqueName } : null,
    confidence: mitre.confidence,
    certain: mitre.certain,
    note: mitre.note,
  };
}

function deriveStatus({ rule, testResult, tuning }) {
  if (tuning) return 'tuned';
  if (testResult) return 'tested';
  if (rule) return 'generated';
  return 'draft';
}

module.exports = { createDetectionRecord };
