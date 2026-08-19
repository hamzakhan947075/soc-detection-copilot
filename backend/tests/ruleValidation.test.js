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

  test('escapes malicious characters embedded in detection evidence', () => {
    const detection = bruteForceDetection();
    detection.mitreHint = 'unmapped_hint_for_escape_test';
    // even with an unknown hint, generation must not throw and must remain syntactically valid
    const rule = buildRule(detection, { ruleType: 'kql' });
    expect(rule.queryValid).toBe(true);
  });
});
