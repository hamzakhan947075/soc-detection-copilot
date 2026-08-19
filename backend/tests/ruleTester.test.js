'use strict';

const { testRule } = require('../src/testing/ruleTester');
const { analyzeFalsePositives } = require('../src/false-positive/fpAnalysis');
const { recommendTuning } = require('../src/tuning/tuning');

function authEvent(ip, outcome, offsetSec) {
  return {
    '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, offsetSec)).toISOString(),
    source: { ip },
    event: { category: 'authentication', outcome },
  };
}

describe('testRule', () => {
  test('matches events satisfying all conditions', () => {
    const events = [authEvent('1.1.1.1', 'failure', 0), authEvent('1.1.1.1', 'success', 1)];
    const rule = { conditions: [{ field: 'event.category', value: 'authentication' }, { field: 'event.outcome', value: 'failure' }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(1);
    expect(result.eventsTested).toBe(2);
  });

  test('applies threshold + grouping when configured', () => {
    const events = Array.from({ length: 12 }, (_, i) => authEvent('2.2.2.2', 'failure', i));
    events.push(authEvent('3.3.3.3', 'failure', 20)); // only 1 event, below threshold
    const rule = {
      conditions: [{ field: 'event.category', value: 'authentication' }, { field: 'event.outcome', value: 'failure' }],
      threshold: { count: 10 },
      groupingFields: ['source.ip'],
    };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(12);
    expect(result.groupingSummary.find((g) => g.groupValue === '2.2.2.2').passesThreshold).toBe(true);
    expect(result.groupingSummary.find((g) => g.groupValue === '3.3.3.3').passesThreshold).toBe(false);
  });

  test('never executes the query text - only structured conditions', () => {
    const rule = { conditions: [{ field: 'event.category', value: 'authentication' }], threshold: null, groupingFields: [], query: 'process.exit()' };
    expect(() => testRule(rule, [authEvent('1.1.1.1', 'failure', 0)])).not.toThrow();
  });

  test('matches any value in an OR-list condition', () => {
    const events = [authEvent('1.1.1.1', 'failure', 0), authEvent('1.1.1.1', 'success', 1)];
    const rule = { conditions: [{ field: 'event.outcome', values: ['failure', 'denied'] }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(1);
  });

  test('exists condition matches only events where the field is present', () => {
    const events = [{ '@timestamp': new Date().toISOString(), destination: { port: 4444 } }, { '@timestamp': new Date().toISOString() }];
    const rule = { conditions: [{ field: 'destination.port', exists: true }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(1);
  });

  test('applies distinct-count threshold (e.g. distinct destination ports per source, for port scanning)', () => {
    const events = Array.from({ length: 20 }, (_, i) => ({
      '@timestamp': new Date().toISOString(),
      source: { ip: '9.9.9.9' },
      destination: { port: 1000 + i },
    }));
    // A second source hits the same 3 ports repeatedly - high event count, low port cardinality.
    const repeatedPortEvents = Array.from({ length: 20 }, (_, i) => ({
      '@timestamp': new Date().toISOString(),
      source: { ip: '8.8.4.4' },
      destination: { port: 443 },
    }));
    const rule = {
      conditions: [{ field: 'destination.port', exists: true }],
      threshold: { count: 15, distinctField: 'destination.port' },
      groupingFields: ['source.ip'],
    };
    const result = testRule(rule, [...events, ...repeatedPortEvents]);
    const scanner = result.groupingSummary.find((g) => g.groupValue === '9.9.9.9');
    const repeater = result.groupingSummary.find((g) => g.groupValue === '8.8.4.4');
    expect(scanner.passesThreshold).toBe(true);
    expect(repeater.passesThreshold).toBe(false);
  });

  test('a plain (non-exact) condition matches as a substring, by design (e.g. free-text/stem matches)', () => {
    const events = [{ '@timestamp': new Date().toISOString(), event: { action: 'denied' } }];
    const rule = { conditions: [{ field: 'event.action', values: ['den', 'block', 'drop'] }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(1);
  });

  test('an exact condition does not treat a different identity as a match (regression: "root" no longer matches "rootkit")', () => {
    const events = [{ '@timestamp': new Date().toISOString(), user: { name: 'rootkit' } }];
    const rule = { conditions: [{ field: 'user.name', value: 'root', exact: true }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(0);
  });

  test('an exact condition still matches the identical value', () => {
    const events = [{ '@timestamp': new Date().toISOString(), user: { name: 'root' } }];
    const rule = { conditions: [{ field: 'user.name', value: 'root', exact: true }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(1);
  });

  test('an exact numeric condition does not treat a superset port as a match (regression: port 4444 no longer matches 14444)', () => {
    const events = [{ '@timestamp': new Date().toISOString(), destination: { port: 14444 } }];
    const rule = { conditions: [{ field: 'destination.port', values: ['4444'], exact: true }], threshold: null, groupingFields: [] };
    const result = testRule(rule, events);
    expect(result.eventsMatched).toBe(0);
  });
});

describe('analyzeFalsePositives', () => {
  test('classifies events outside original detection evidence as potential false positives', () => {
    const testResult = {
      eventsTested: 10,
      eventsMatched: 4,
      matchRatePercent: 40,
      matchedEvents: [{ index: 0 }, { index: 1 }, { index: 2 }, { index: 3 }],
    };
    const detection = { matchedEventIndexes: [0, 1] };
    const fp = analyzeFalsePositives(testResult, detection);
    expect(fp.likelyTruePositiveCount).toBe(2);
    expect(fp.potentialFalsePositiveCount).toBe(2);
    expect(fp.falsePositiveRatePercent).toBe(50);
    expect(fp.riskLevel).toBe('high');
  });

  test('reports zero false positives when every match is in the original evidence', () => {
    const testResult = { eventsTested: 5, eventsMatched: 2, matchRatePercent: 40, matchedEvents: [{ index: 0 }, { index: 1 }] };
    const detection = { matchedEventIndexes: [0, 1] };
    const fp = analyzeFalsePositives(testResult, detection);
    expect(fp.falsePositiveRatePercent).toBe(0);
    expect(fp.riskLevel).toBe('low');
  });
});

describe('recommendTuning', () => {
  test('suggests raising the threshold when false-positive rate is high', () => {
    const events = Array.from({ length: 8 }, (_, i) => authEvent('4.4.4.4', 'failure', i));
    const rule = {
      conditions: [{ field: 'event.category', value: 'authentication' }, { field: 'event.outcome', value: 'failure' }],
      threshold: { count: 5 },
      groupingFields: ['source.ip'],
    };
    const fpAnalysis = { falsePositiveRatePercent: 30, eventsMatched: 8 };
    const tuning = recommendTuning(rule, fpAnalysis, events);
    expect(tuning.applicable).toBe(true);
    expect(tuning.suggestedThreshold).toBeGreaterThan(tuning.currentThreshold);
    expect(tuning.after).not.toBeNull();
  });

  test('recommends no change when false-positive rate is already acceptable', () => {
    const rule = { threshold: { count: 10 }, groupingFields: ['source.ip'], conditions: [] };
    const fpAnalysis = { falsePositiveRatePercent: 5, eventsMatched: 10 };
    const tuning = recommendTuning(rule, fpAnalysis, []);
    expect(tuning.suggestedThreshold).toBe(tuning.currentThreshold);
  });

  test('reports not applicable for rules without a threshold', () => {
    const tuning = recommendTuning({ threshold: null }, { falsePositiveRatePercent: 50 }, []);
    expect(tuning.applicable).toBe(false);
  });
});
