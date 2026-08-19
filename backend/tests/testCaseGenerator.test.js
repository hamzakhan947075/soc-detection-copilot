'use strict';

const { generateDefaultTestCases } = require('../src/testing/testCaseGenerator');
const { runTestSuite } = require('../src/testing/testCaseRunner');

/** The real proof a generated set of cases is correct: every one of them, run through the
 * exact same matcher testRule() uses, must PASS - i.e. its expectedMatch must be honest. */
function allCasesPass(conditions, generated) {
  const all = [...generated.positive, ...generated.negative, ...generated.edge];
  const suite = runTestSuite(conditions, all);
  return { suite, all };
}

describe('generateDefaultTestCases', () => {
  test('returns nothing for a rule with no conditions', () => {
    const generated = generateDefaultTestCases([]);
    expect(generated).toEqual({ positive: [], negative: [], edge: [] });
  });

  test('a synthetic positive/negative/edge set for a plain value condition is internally consistent', () => {
    const conditions = [
      { field: 'event.category', value: 'authentication' },
      { field: 'event.outcome', value: 'failure' },
    ];
    const generated = generateDefaultTestCases(conditions);
    expect(generated.positive).toHaveLength(1);
    expect(generated.negative).toHaveLength(1);
    expect(generated.edge.length).toBeGreaterThan(0);

    const { suite } = allCasesPass(conditions, generated);
    expect(suite.counts.fail).toBe(0);
    expect(suite.counts.error).toBe(0);
  });

  test('handles an exists condition (missing field is the natural negative)', () => {
    const conditions = [{ field: 'destination.port', exists: true }];
    const generated = generateDefaultTestCases(conditions);
    const { suite } = allCasesPass(conditions, generated);
    expect(suite.counts.fail).toBe(0);
    expect(suite.counts.error).toBe(0);
  });

  test('handles an exact numeric condition without a false negative/positive', () => {
    const conditions = [{ field: 'destination.port', values: ['4444', '1337'], exact: true }];
    const generated = generateDefaultTestCases(conditions);
    const { suite } = allCasesPass(conditions, generated);
    expect(suite.counts.fail).toBe(0);
    expect(suite.counts.error).toBe(0);
  });

  test('handles a combined "in"/"not_in" cidr pair (internal-to-external pattern), including the malformed-IP edge cases', () => {
    const conditions = [
      { field: 'source.ip', cidr: { ranges: ['10.0.0.0/8'], mode: 'in' } },
      { field: 'destination.ip', cidr: { ranges: ['10.0.0.0/8'], mode: 'not_in' } },
    ];
    const generated = generateDefaultTestCases(conditions);
    const malformedCases = generated.edge.filter((e) => e.id.startsWith('edge-malformed-ip'));
    expect(malformedCases.length).toBe(2); // one per cidr condition

    const { suite } = allCasesPass(conditions, generated);
    expect(suite.counts.fail).toBe(0);
    expect(suite.counts.error).toBe(0);
  });

  test('prefers a real sample positive event over a synthetic one when supplied', () => {
    const conditions = [{ field: 'user.name', value: 'root', exact: true }];
    const realEvent = { '@timestamp': '2026-08-19T10:00:00Z', user: { name: 'root' }, source: { ip: '10.0.0.5' } };
    const generated = generateDefaultTestCases(conditions, realEvent);
    expect(generated.positive[0].event.source.ip).toBe('10.0.0.5'); // carried over from the real event, not synthesized
    expect(generated.positive[0].description).toMatch(/real event/);

    const { suite } = allCasesPass(conditions, generated);
    expect(suite.counts.fail).toBe(0);
  });

  test('the duplicate-event edge case expects a match, and the missing-timestamp edge case does not affect matching', () => {
    const conditions = [{ field: 'event.outcome', value: 'failure' }];
    const generated = generateDefaultTestCases(conditions);
    const duplicate = generated.edge.find((e) => e.id === 'edge-duplicate');
    const noTimestamp = generated.edge.find((e) => e.id === 'edge-missing-timestamp');
    expect(duplicate.expectedMatch).toBe(true);
    expect(noTimestamp.expectedMatch).toBe(true);
    expect(noTimestamp.event['@timestamp']).toBeUndefined();
  });
});
