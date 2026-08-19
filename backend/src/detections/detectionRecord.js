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
 * Honesty note: when no `persisted` context is supplied, `status` reflects
 * session progress only (draft -> generated -> tested -> tuned) and
 * `version` is always 1 - there's no durable lifecycle without a
 * DetectionStore behind it. Pass `context.persisted` (a record from
 * persistence/detectionStore.js) once a detection has actually been
 * persisted, and its real status/version/author/history take over - that's
 * the only way "approved"/"production"/"deprecated" become meaningful
 * rather than a label that vanishes on restart.
 */
function createDetectionRecord(candidate, context = {}) {
  const { logSource = null, rule = null, persisted = null } = context;
  const testResult = rule ? rule.lastTestResult || null : null;
  const fpAnalysis = rule ? rule.lastFpAnalysis || null : null;
  const tuning = context.tuning || null;
  const now = new Date().toISOString();

  return {
    id: candidate.id,
    name: candidate.name,
    description: candidate.description,
    status: persisted ? persisted.status : deriveStatus({ rule, testResult, tuning }),
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
      // identifier until each behavior module reports one directly. It also
      // doubles as the persistence key (persistence/detectionStore.js) -
      // the same detection *type* stays the same row across every session
      // and every re-run of /detect.
      id: `${candidate.category}.${candidate.mitreHint || 'generic'}`,
      kind: candidate.ruleConditions ? 'structured' : 'heuristic',
    },
    detectionLogic: candidate.description,
    mitre: buildMitre(candidate.mitre),
    query: (rule && rule.query) || (persisted && persisted.query) || null,
    queryLanguage: (rule && rule.ruleType) || (persisted && persisted.queryLanguage) || null,
    queryGeneratedAt: (rule && rule.generatedAt) || null,
    queryValidation: rule
      ? { valid: rule.queryValid, errors: rule.queryValidationErrors || [], warnings: rule.queryValidationWarnings || [] }
      : null,
    testCases: (rule && rule.lastTestCases) || { positive: [], negative: [], edge: [] },
    testSuiteResult: (rule && rule.lastTestSuite) || null,
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
    version: persisted ? persisted.version : 1,
    lifecycle: persisted
      ? { persisted: true, author: persisted.author, createdAt: persisted.createdAt, updatedAt: persisted.updatedAt }
      : { persisted: false },
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
  if (tuning && tuning.applicable) return 'tuned';
  if (testResult) return 'tested';
  if (rule) return 'generated';
  return 'draft';
}

module.exports = { createDetectionRecord };
