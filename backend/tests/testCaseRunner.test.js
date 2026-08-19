'use strict';

const { runTestCase, runTestSuite } = require('../src/testing/testCaseRunner');

const conditions = [{ field: 'user.name', value: 'root', exact: true }];

describe('runTestCase', () => {
  test('PASS: a positive case that actually matches', () => {
    const result = runTestCase(conditions, { id: 'p1', type: 'positive', expectedMatch: true, event: { user: { name: 'root' } } });
    expect(result.outcome).toBe('PASS');
    expect(result.actualMatch).toBe(true);
  });

  test('FAIL: a positive case that does not match (a real regression, e.g. a broken condition)', () => {
    const result = runTestCase(conditions, { id: 'p2', type: 'positive', expectedMatch: true, event: { user: { name: 'somebody-else' } } });
    expect(result.outcome).toBe('FAIL');
    expect(result.actualMatch).toBe(false);
  });

  test('PASS: a negative case that correctly does not match', () => {
    const result = runTestCase(conditions, { id: 'n1', type: 'negative', expectedMatch: false, event: { user: { name: 'rootkit' } } });
    expect(result.outcome).toBe('PASS');
    expect(result.actualMatch).toBe(false);
  });

  test('FAIL: a negative case that incorrectly matches (a real false positive)', () => {
    const result = runTestCase(conditions, { id: 'n2', type: 'negative', expectedMatch: false, event: { user: { name: 'root' } } });
    expect(result.outcome).toBe('FAIL');
    expect(result.actualMatch).toBe(true);
  });

  test('SKIPPED: a case explicitly marked skip is never evaluated', () => {
    const result = runTestCase(conditions, { id: 's1', type: 'edge', expectedMatch: true, event: { user: { name: 'root' } }, skip: true });
    expect(result.outcome).toBe('SKIPPED');
    expect(result.actualMatch).toBeNull();
  });

  test('ERROR: malformed conditions (e.g. a corrupted rule) are reported as ERROR, never silently miscounted as a match/non-match', () => {
    const result = runTestCase(null, { id: 'e1', type: 'edge', expectedMatch: false, event: { user: { name: 'root' } } });
    expect(result.outcome).toBe('ERROR');
    expect(result.actualMatch).toBeNull();
    expect(result.error).toBeTruthy();
  });
});

describe('runTestSuite', () => {
  test('computes a perfect confusion matrix and metrics of 1.0 when every case passes', () => {
    const testCases = [
      { id: 'p1', type: 'positive', expectedMatch: true, event: { user: { name: 'root' } } },
      { id: 'p2', type: 'positive', expectedMatch: true, event: { user: { name: 'root' } } },
      { id: 'n1', type: 'negative', expectedMatch: false, event: { user: { name: 'someone' } } },
    ];
    const suite = runTestSuite(conditions, testCases);
    expect(suite.counts).toEqual({ total: 3, pass: 3, fail: 0, error: 0, skipped: 0 });
    expect(suite.confusionMatrix).toEqual({ truePositives: 2, falsePositives: 0, trueNegatives: 1, falseNegatives: 0 });
    expect(suite.metrics.precision).toBe(1);
    expect(suite.metrics.recall).toBe(1);
    expect(suite.metrics.f1Score).toBe(1);
    expect(suite.metrics.falsePositiveRate).toBe(0);
  });

  test('a false positive lowers precision and raises the false-positive rate, not recall', () => {
    const testCases = [
      { id: 'p1', type: 'positive', expectedMatch: true, event: { user: { name: 'root' } } },
      { id: 'n1', type: 'negative', expectedMatch: false, event: { user: { name: 'root' } } }, // incorrectly matches -> FP
    ];
    const suite = runTestSuite(conditions, testCases);
    expect(suite.confusionMatrix).toEqual({ truePositives: 1, falsePositives: 1, trueNegatives: 0, falseNegatives: 0 });
    expect(suite.metrics.precision).toBe(0.5);
    expect(suite.metrics.recall).toBe(1);
    expect(suite.metrics.falsePositiveRate).toBe(1);
  });

  test('a false negative lowers recall, not precision', () => {
    const testCases = [{ id: 'p1', type: 'positive', expectedMatch: true, event: { user: { name: 'somebody-else' } } }]; // fails to match -> FN
    const suite = runTestSuite(conditions, testCases);
    expect(suite.confusionMatrix.falseNegatives).toBe(1);
    expect(suite.metrics.precision).toBeNull(); // no positive predictions at all - precision is undefined, not 0
    expect(suite.metrics.recall).toBe(0);
  });

  test('metrics are null (not NaN/Infinity) rather than fake when the denominator is zero', () => {
    const suite = runTestSuite(conditions, []);
    expect(suite.metrics.precision).toBeNull();
    expect(suite.metrics.recall).toBeNull();
    expect(suite.metrics.f1Score).toBeNull();
    expect(suite.metrics.falsePositiveRate).toBeNull();
  });

  test('ERROR and SKIPPED cases are excluded from the confusion matrix entirely', () => {
    const poisoned = {};
    Object.defineProperty(poisoned, 'user', { enumerable: true, get() { throw new Error('simulated malformed event'); } });
    const testCases = [
      { id: 'p1', type: 'positive', expectedMatch: true, event: { user: { name: 'root' } } },
      { id: 'e1', type: 'edge', expectedMatch: true, event: poisoned },
      { id: 's1', type: 'edge', expectedMatch: true, event: { user: { name: 'root' } }, skip: true },
    ];
    const suite = runTestSuite(conditions, testCases);
    expect(suite.counts).toEqual({ total: 3, pass: 1, fail: 0, error: 1, skipped: 1 });
    expect(suite.confusionMatrix).toEqual({ truePositives: 1, falsePositives: 0, trueNegatives: 0, falseNegatives: 0 });
  });
});
