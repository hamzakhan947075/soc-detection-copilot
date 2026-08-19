'use strict';

const { createDetectionRecord } = require('../src/detections/detectionRecord');
const { makeEvaluatorResult } = require('../src/detections/evaluatorTypes');

function baseCandidate(overrides = {}) {
  return {
    id: 'det-abc-1',
    name: 'SSH/Authentication Brute Force',
    category: 'authentication',
    severity: 'high',
    confidence: 0.87,
    description: 'Multiple failed authentication attempts.',
    requiredFields: ['source.ip', 'user.name', 'event.outcome'],
    mitreHint: 'brute_force',
    ruleConditions: [{ field: 'event.outcome', value: 'failure' }],
    mitre: {
      techniqueId: 'T1110.001',
      techniqueName: 'Password Guessing',
      tacticId: 'TA0006',
      tacticName: 'Credential Access',
      confidence: 0.9,
      certain: true,
      note: null,
    },
    ...overrides,
  };
}

describe('createDetectionRecord', () => {
  test('carries the core fields straight through from the candidate', () => {
    const record = createDetectionRecord(baseCandidate());
    expect(record.id).toBe('det-abc-1');
    expect(record.name).toBe('SSH/Authentication Brute Force');
    expect(record.severity).toBe('high');
    expect(record.confidence).toBe(0.87);
    expect(record.dataSources).toEqual(['authentication']);
    expect(record.ecsRequirements).toEqual(['source.ip', 'user.name', 'event.outcome']);
    expect(record.ruleConditions).toEqual([{ field: 'event.outcome', value: 'failure' }]);
  });

  test('splits a dotted MITRE technique id into technique + sub-technique', () => {
    const record = createDetectionRecord(baseCandidate());
    expect(record.mitre.tactic).toEqual({ id: 'TA0006', name: 'Credential Access' });
    expect(record.mitre.technique.id).toBe('T1110');
    expect(record.mitre.subTechnique.id).toBe('T1110.001');
    expect(record.mitre.certain).toBe(true);
  });

  test('does not split a base (non-sub) technique id', () => {
    const record = createDetectionRecord(baseCandidate({ mitre: { techniqueId: 'T1595', techniqueName: 'Active Scanning', tacticId: 'TA0043', tacticName: 'Reconnaissance', confidence: 0.4, certain: false, note: 'uncertain' } }));
    expect(record.mitre.technique.id).toBe('T1595');
    expect(record.mitre.subTechnique).toBeNull();
  });

  test('marks MITRE as absent rather than fabricating a mapping when none exists', () => {
    const record = createDetectionRecord(baseCandidate({ mitre: { techniqueId: null, techniqueName: null, tacticId: null, tacticName: null, confidence: 0, certain: false, note: 'No MITRE mapping available for this detection type.' } }));
    expect(record.mitre.tactic).toBeNull();
    expect(record.mitre.technique).toBeNull();
    expect(record.mitre.certain).toBe(false);
    expect(record.mitre.note).toMatch(/No MITRE mapping/);
  });

  test('status starts at "draft" with no rule, and advances as rule/test/tuning context is supplied', () => {
    const candidate = baseCandidate();
    expect(createDetectionRecord(candidate).status).toBe('draft');
    expect(createDetectionRecord(candidate, { rule: { query: 'x' } }).status).toBe('generated');
    expect(createDetectionRecord(candidate, { rule: { query: 'x', lastTestResult: { eventsMatched: 3 } } }).status).toBe('tested');
    expect(createDetectionRecord(candidate, { rule: { query: 'x', lastTestResult: { eventsMatched: 3 } }, tuning: { applicable: true } }).status).toBe('tuned');
  });

  test('defaults testCases/testSuiteResult when no rule has run a test suite', () => {
    const record = createDetectionRecord(baseCandidate());
    expect(record.testCases).toEqual({ positive: [], negative: [], edge: [] });
    expect(record.testSuiteResult).toBeNull();
  });

  test('surfaces the rule\'s test cases and suite result once a test suite has run', () => {
    const rule = {
      lastTestCases: { positive: [{ id: 'p1' }], negative: [{ id: 'n1' }], edge: [] },
      lastTestSuite: { counts: { total: 2, pass: 2, fail: 0, error: 0, skipped: 0 }, metrics: { precision: 1 } },
    };
    const record = createDetectionRecord(baseCandidate(), { rule });
    expect(record.testCases.positive).toHaveLength(1);
    expect(record.testSuiteResult.metrics.precision).toBe(1);
  });

  test('surfaces the rule\'s query validation status and generation timestamp', () => {
    const rule = { query: 'x', ruleType: 'kql', generatedAt: '2026-08-19T12:00:00Z', queryValid: false, queryValidationErrors: ['bad'], queryValidationWarnings: ['careful'] };
    const record = createDetectionRecord(baseCandidate(), { rule });
    expect(record.queryGeneratedAt).toBe('2026-08-19T12:00:00Z');
    expect(record.queryValidation).toEqual({ valid: false, errors: ['bad'], warnings: ['careful'] });
  });

  test('queryValidation is null when no rule has been generated', () => {
    const record = createDetectionRecord(baseCandidate());
    expect(record.queryValidation).toBeNull();
    expect(record.queryGeneratedAt).toBeNull();
  });

  test('includes the rule query/language and false-positive profile when a rule is supplied', () => {
    const candidate = baseCandidate();
    const rule = { query: 'event.outcome:"failure"', ruleType: 'kql', lastTestResult: { eventsMatched: 5 }, lastFpAnalysis: { falsePositiveRatePercent: 10 } };
    const record = createDetectionRecord(candidate, { rule });
    expect(record.query).toBe('event.outcome:"failure"');
    expect(record.queryLanguage).toBe('kql');
    expect(record.testResult).toEqual({ eventsMatched: 5 });
    expect(record.falsePositiveProfile.dynamic).toEqual({ falsePositiveRatePercent: 10 });
    expect(record.falsePositiveProfile.staticGuidance).toBeDefined();
  });

  test('uses the persisted lifecycle status/version over the session-derived guess when supplied', () => {
    const candidate = baseCandidate();
    const persisted = { status: 'approved', version: 2, author: 'alice', query: 'event.outcome:"failure"', queryLanguage: 'kql', createdAt: '2026-08-01T00:00:00Z', updatedAt: '2026-08-19T00:00:00Z' };
    const record = createDetectionRecord(candidate, { persisted });
    expect(record.status).toBe('approved');
    expect(record.version).toBe(2);
    expect(record.query).toBe('event.outcome:"failure"');
    expect(record.lifecycle).toEqual({ persisted: true, author: 'alice', createdAt: '2026-08-01T00:00:00Z', updatedAt: '2026-08-19T00:00:00Z' });
  });

  test('marks lifecycle as not persisted when no persisted context is supplied', () => {
    const record = createDetectionRecord(baseCandidate());
    expect(record.lifecycle).toEqual({ persisted: false });
    expect(record.version).toBe(1);
  });

  test('carries the log source through when supplied', () => {
    const record = createDetectionRecord(baseCandidate(), { logSource: { source: 'Linux SSH', confidence: 92 } });
    expect(record.logSource).toEqual({ source: 'Linux SSH', confidence: 92 });
  });

  test('evaluator id is derived deterministically from category + mitreHint', () => {
    const record = createDetectionRecord(baseCandidate());
    expect(record.evaluator.id).toBe('authentication.brute_force');
    expect(record.evaluator.kind).toBe('structured');
  });

  test('evaluator kind is "heuristic" when the candidate has no structured ruleConditions', () => {
    const record = createDetectionRecord(baseCandidate({ ruleConditions: null }));
    expect(record.evaluator.kind).toBe('heuristic');
  });
});

describe('makeEvaluatorResult', () => {
  test('normalizes a matched result with a rounded score', () => {
    const result = makeEvaluatorResult({ matched: true, score: 0.912345, reasons: ['High entropy'], evidence: { entropy: 4.1 } });
    expect(result).toEqual({ matched: true, score: 0.912, reasons: ['High entropy'], evidence: { entropy: 4.1 } });
  });

  test('defaults score to null and reasons/evidence to empty when omitted', () => {
    const result = makeEvaluatorResult({ matched: false });
    expect(result).toEqual({ matched: false, score: null, reasons: [], evidence: {} });
  });

  test('wraps a single string reason into an array', () => {
    const result = makeEvaluatorResult({ matched: true, reasons: 'single reason' });
    expect(result.reasons).toEqual(['single reason']);
  });

  test('requires a boolean "matched"', () => {
    expect(() => makeEvaluatorResult({ matched: 'yes' })).toThrow(TypeError);
  });
});
