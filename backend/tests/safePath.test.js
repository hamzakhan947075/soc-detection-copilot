'use strict';

const { isSafeDottedPath } = require('../src/utils/safePath');
const { normalizeEvent, setPath } = require('../src/normalization/normalizer');
const { generateDefaultTestCases } = require('../src/testing/testCaseGenerator');

// Safety net: if any fix under test regresses, don't let a real pollution
// leak from one test into every other test in the suite - clean it up
// immediately and still fail the assertion that caught it.
afterEach(() => {
  delete Object.prototype.polluted;
  delete Object.prototype.injected;
});

describe('isSafeDottedPath', () => {
  test('accepts ordinary ECS-style dotted paths', () => {
    expect(isSafeDottedPath('source.ip')).toBe(true);
    expect(isSafeDottedPath('user.name')).toBe(true);
    expect(isSafeDottedPath('a.b.c.d')).toBe(true);
  });

  test('rejects a path containing __proto__ at any position', () => {
    expect(isSafeDottedPath('__proto__')).toBe(false);
    expect(isSafeDottedPath('__proto__.polluted')).toBe(false);
    expect(isSafeDottedPath('a.__proto__.b')).toBe(false);
  });

  test('rejects a path containing constructor or prototype at any position', () => {
    expect(isSafeDottedPath('constructor.prototype.polluted')).toBe(false);
    expect(isSafeDottedPath('a.constructor.b')).toBe(false);
    expect(isSafeDottedPath('a.prototype.b')).toBe(false);
  });

  test('rejects non-string or empty input', () => {
    expect(isSafeDottedPath('')).toBe(false);
    expect(isSafeDottedPath(null)).toBe(false);
    expect(isSafeDottedPath(undefined)).toBe(false);
  });
});

describe('normalizer.setPath - prototype pollution regression (CWE-1321)', () => {
  test('a "__proto__.polluted" ecsField never reaches Object.prototype', () => {
    const target = {};
    setPath(target, '__proto__.polluted', 'hacked');
    expect(Object.prototype.polluted).toBeUndefined();
    expect(({}).polluted).toBeUndefined();
  });

  test('a "constructor.prototype.injected" ecsField never reaches Object.prototype', () => {
    const target = {};
    setPath(target, 'constructor.prototype.injected', 'hacked');
    expect(Object.prototype.injected).toBeUndefined();
    expect(({}).injected).toBeUndefined();
  });

  test('normalizeEvent with a malicious analyst-supplied ecsField does not pollute the global prototype', () => {
    const raw = { weird_field: 'anything' };
    const mappings = [{ rawField: 'weird_field', ecsField: '__proto__.polluted', ecsType: 'keyword' }];
    const { normalized } = normalizeEvent(raw, mappings);
    expect(Object.prototype.polluted).toBeUndefined();
    expect(({}).polluted).toBeUndefined();
    // The malicious mapping is simply dropped, not silently "successful" elsewhere.
    expect(normalized.polluted).toBeUndefined();
  });

  test('legitimate dotted ecsField mappings are unaffected by the guard', () => {
    const raw = { src_ip: '10.0.0.1' };
    const mappings = [{ rawField: 'src_ip', ecsField: 'source.ip', ecsType: 'ip' }];
    const { normalized } = normalizeEvent(raw, mappings);
    expect(normalized.source.ip).toBe('10.0.0.1');
  });
});

describe('testCaseGenerator - prototype pollution regression', () => {
  test('a condition with a dangerous field name does not pollute Object.prototype when generating synthetic events', () => {
    const conditions = [{ field: '__proto__.polluted', value: 'x' }];
    expect(() => generateDefaultTestCases(conditions)).not.toThrow();
    expect(Object.prototype.polluted).toBeUndefined();
    expect(({}).polluted).toBeUndefined();
  });
});
