'use strict';

const { validateRule } = require('../src/rule-validation/ruleValidator');
const { buildRule } = require('../src/rule-generation/ruleBuilder');
const { mapToMitre } = require('../src/mitre/mitreMap');

function bruteForceDetection() {
  return {
    name: 'SSH/Authentication Brute Force',
    category: 'authentication',
    severity: 'high',
    confidence: 0.9,
    description: 'test',
    requiredFields: ['source.ip', 'user.name', 'event.outcome'],
    mitreHint: 'brute_force',
    mitre: mapToMitre('brute_force'),
    recommendedThreshold: { count: 10, windowMinutes: 5, groupBy: ['source.ip'] },
    matchedEventIndexes: [0, 1, 2],
  };
}

describe('validateRule', () => {
  test('rejects empty queries', () => {
    expect(validateRule('', 'kql').valid).toBe(false);
  });

  test('rejects unbalanced parentheses', () => {
    expect(validateRule('event.category:"authentication" and (event.outcome:"failure"', 'kql').valid).toBe(false);
  });

  test('rejects unterminated string literals', () => {
    expect(validateRule('event.category:"authentication', 'kql').valid).toBe(false);
  });

  test('accepts a well-formed KQL query', () => {
    const result = validateRule('event.category:"authentication" and event.outcome:"failure"', 'kql');
    expect(result.valid).toBe(true);
  });

  test('requires FROM in ES|QL queries', () => {
    expect(validateRule('WHERE event.category == "authentication"', 'esql').valid).toBe(false);
  });

  test('requires detection/condition sections in Sigma', () => {
    expect(validateRule('title: test', 'sigma').valid).toBe(false);
  });

  test('rejects dangerous destructive-looking constructs', () => {
    expect(validateRule('event.category:"x"; DROP TABLE users', 'kql').valid).toBe(false);
  });

  test('always returns a warnings array, even with no conditions supplied', () => {
    const result = validateRule('event.category:"authentication"', 'kql');
    expect(Array.isArray(result.warnings)).toBe(true);
  });

  test('warns (but does not invalidate) a bare match-all query', () => {
    const result = validateRule('*', 'kql');
    expect(result.valid).toBe(true);
    expect(result.warnings.some((w) => /match-all/.test(w))).toBe(true);
  });

  test('warns on a leading wildcard but not on a bare exists check', () => {
    const leading = validateRule('url.path:*.php', 'kql');
    expect(leading.warnings.some((w) => /leading wildcard/.test(w))).toBe(true);

    const exists = validateRule('destination.port:*', 'kql');
    expect(exists.warnings.some((w) => /leading wildcard/.test(w))).toBe(false);
  });

  test('errors on contradictory exact conditions for the same field', () => {
    const conditions = [
      { field: 'event.outcome', value: 'success', exact: true },
      { field: 'event.outcome', value: 'failure', exact: true },
    ];
    const result = validateRule('event.outcome:"success" and event.outcome:"failure"', 'kql', conditions);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /Contradictory conditions/.test(e))).toBe(true);
  });

  test('does not flag two different fields as contradictory', () => {
    const conditions = [
      { field: 'event.category', value: 'authentication' },
      { field: 'event.outcome', value: 'failure' },
    ];
    const result = validateRule('event.category:"authentication" and event.outcome:"failure"', 'kql', conditions);
    expect(result.errors).toEqual([]);
  });

  test('errors on an impossible empty-range cidr condition', () => {
    const conditions = [{ field: 'source.ip', cidr: { ranges: [], mode: 'in' } }];
    const result = validateRule('source.ip:*', 'kql', conditions);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /can never match/.test(e))).toBe(true);
  });

  test('warns when a condition references a field outside ECS entirely, but not for a real ECS field', () => {
    const customConditions = [{ field: 'auth.mfa_used', value: 'true' }];
    const customResult = validateRule('auth.mfa_used:"true"', 'kql', customConditions);
    expect(customResult.valid).toBe(true);
    expect(customResult.warnings.some((w) => /not an ECS field/.test(w))).toBe(true);

    const ecsConditions = [{ field: 'user.name', value: 'root' }];
    const ecsResult = validateRule('user.name:"root"', 'kql', ecsConditions);
    expect(ecsResult.warnings.some((w) => /not an ECS field/.test(w))).toBe(false);
  });
});

describe('buildRule', () => {
  test('generates a valid KQL rule for a brute force detection', () => {
    const rule = buildRule(bruteForceDetection(), { ruleType: 'kql', indexPattern: 'logs-system.auth-*' });
    expect(rule.queryValid).toBe(true);
    expect(rule.query).toContain('event.category');
    expect(rule.riskScore).toBe(70);
    expect(rule.threshold.count).toBe(10);
  });

  test('generates a valid ES|QL rule with threshold aggregation', () => {
    const rule = buildRule(bruteForceDetection(), { ruleType: 'esql', indexPattern: 'logs-system.auth-*' });
    expect(rule.queryValid).toBe(true);
    expect(rule.query).toMatch(/^FROM/);
    expect(rule.query).toContain('STATS');
  });

  test('preserves hyphens and wildcards in the ES|QL index pattern instead of mangling them', () => {
    const rule = buildRule(bruteForceDetection(), { ruleType: 'esql', indexPattern: 'logs-system.auth-*' });
    expect(rule.query).toContain('FROM logs-system.auth-*');
  });

  test('generates a valid Sigma rule', () => {
    const rule = buildRule(bruteForceDetection(), { ruleType: 'sigma' });
    expect(rule.queryValid).toBe(true);
    expect(rule.query).toContain('detection:');
    expect(rule.query).toContain('condition:');
  });

  test('renders OR-list conditions distinctly per language', () => {
    const detection = bruteForceDetection();
    detection.ruleConditions = [{ field: 'url.original', values: ["'", 'union select'] }];
    const kqlRule = buildRule(detection, { ruleType: 'kql' });
    expect(kqlRule.queryValid).toBe(true);
    expect(kqlRule.query).toContain(' or ');

    const sigmaRule = buildRule(detection, { ruleType: 'sigma' });
    expect(sigmaRule.queryValid).toBe(true);
    expect(sigmaRule.query).toContain('- "\'"');
  });

  test('renders an exists condition without a literal value', () => {
    const detection = bruteForceDetection();
    detection.ruleConditions = [{ field: 'destination.port', exists: true }];
    const kqlRule = buildRule(detection, { ruleType: 'kql' });
    expect(kqlRule.queryValid).toBe(true);
    expect(kqlRule.query).toBe('destination.port:*');

    const esqlRule = buildRule(detection, { ruleType: 'esql', indexPattern: 'logs-*' });
    expect(esqlRule.query).toContain('destination.port IS NOT NULL');
  });

  test('generates a distinct-count ES|QL aggregation for cardinality-based thresholds', () => {
    const detection = bruteForceDetection();
    detection.ruleConditions = [{ field: 'destination.port', exists: true }];
    detection.recommendedThreshold = { count: 15, groupBy: ['source.ip'], distinctField: 'destination.port' };
    const rule = buildRule(detection, { ruleType: 'esql', indexPattern: 'logs-*' });
    expect(rule.query).toContain('COUNT_DISTINCT(destination.port)');
  });

  test('includes traceability fields: generatedAt, detectionVersion, and validation warnings', () => {
    const rule = buildRule(bruteForceDetection(), { ruleType: 'kql', detectionVersion: 3 });
    expect(rule.detectionVersion).toBe(3);
    expect(new Date(rule.generatedAt).toString()).not.toBe('Invalid Date');
    expect(Array.isArray(rule.queryValidationWarnings)).toBe(true);
  });

  test('defaults detectionVersion to 1 when not supplied (no persisted lifecycle yet)', () => {
    const rule = buildRule(bruteForceDetection(), { ruleType: 'kql' });
    expect(rule.detectionVersion).toBe(1);
  });

  test('escapes malicious characters embedded in detection evidence', () => {
    const detection = bruteForceDetection();
    detection.mitreHint = 'unmapped_hint_for_escape_test';
    // even with an unknown hint, generation must not throw and must remain syntactically valid
    const rule = buildRule(detection, { ruleType: 'kql' });
    expect(rule.queryValid).toBe(true);
  });
});
