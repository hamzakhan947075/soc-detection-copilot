'use strict';

const { analyzeFalsePositives } = require('../src/false-positive/fpAnalysis');

function matchEntry(index, event) {
  return { index, event };
}

describe('analyzeFalsePositives - dimensional breakdown', () => {
  test('reports total/matched/non-matched counts alongside the FP rate', () => {
    const testResult = {
      eventsTested: 10,
      eventsMatched: 4,
      matchRatePercent: 40,
      matchedEvents: [matchEntry(0, {}), matchEntry(1, {}), matchEntry(2, {}), matchEntry(3, {})],
    };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [0, 1] });
    expect(fp.eventsTested).toBe(10);
    expect(fp.eventsMatched).toBe(4);
    expect(fp.nonMatchedEvents).toBe(6);
    expect(fp.potentialFalsePositiveCount).toBe(2);
  });

  test('ranks the field/value pairs that recur most often among potential false positives', () => {
    const testResult = {
      eventsTested: 5,
      eventsMatched: 5,
      matchRatePercent: 100,
      matchedEvents: [
        matchEntry(0, { process: { name: 'backup.exe' } }), // true positive (in evidence)
        matchEntry(1, { process: { name: 'backup.exe' } }),
        matchEntry(2, { process: { name: 'backup.exe' } }),
        matchEntry(3, { process: { name: 'other.exe' } }),
      ],
    };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [0] });
    expect(fp.potentialFalsePositiveCount).toBe(3);
    expect(fp.topFalsePositiveFields[0]).toMatchObject({ field: 'process.name', value: 'backup.exe', count: 2 });
  });

  test('recommends excluding a value that accounts for most potential false positives, with the real percentage', () => {
    const testResult = {
      eventsTested: 12,
      eventsMatched: 12,
      matchRatePercent: 100,
      matchedEvents: Array.from({ length: 10 }, (_, i) => matchEntry(i, { process: { name: 'backup.exe' } })),
    };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [] }); // nothing in original evidence -> all 10 are potential FPs
    expect(fp.potentialFalsePositiveCount).toBe(10);
    expect(fp.recommendedExclusions).toHaveLength(1);
    expect(fp.recommendedExclusions[0]).toMatchObject({
      field: 'process.name',
      value: 'backup.exe',
      percentOfPotentialFPs: 100,
      recommendation: 'Consider excluding: process.name = backup.exe',
    });
    // Never claims to have actually excluded anything - only surfaces the suggestion.
    expect(fp.note).toMatch(/nothing is ever excluded automatically/);
  });

  test('does not recommend an exclusion when no single value accounts for most potential false positives', () => {
    const testResult = {
      eventsTested: 4,
      eventsMatched: 4,
      matchRatePercent: 100,
      matchedEvents: [
        matchEntry(0, { user: { name: 'alice' } }),
        matchEntry(1, { user: { name: 'bob' } }),
        matchEntry(2, { user: { name: 'carol' } }),
        matchEntry(3, { user: { name: 'dave' } }),
      ],
    };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [] });
    expect(fp.recommendedExclusions).toEqual([]);
  });

  test('breaks down potential false positives by common dimensions (users, hosts, processes, destinations)', () => {
    const testResult = {
      eventsTested: 3,
      eventsMatched: 3,
      matchRatePercent: 100,
      matchedEvents: [
        matchEntry(0, { user: { name: 'svc-backup' }, host: { name: 'srv01' }, process: { name: 'backup.exe' }, destination: { ip: '10.0.0.9' } }),
        matchEntry(1, { user: { name: 'svc-backup' }, host: { name: 'srv02' }, process: { name: 'backup.exe' }, destination: { ip: '10.0.0.9' } }),
      ],
    };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [] });
    expect(fp.topUsers[0]).toMatchObject({ value: 'svc-backup', count: 2 });
    expect(fp.topProcesses[0]).toMatchObject({ value: 'backup.exe', count: 2 });
    expect(fp.topDestinations[0]).toMatchObject({ value: '10.0.0.9', count: 2 });
    expect(fp.topHosts).toHaveLength(2); // srv01 and srv02, each count 1
  });

  test('excludes noisy always-unique fields (message, @timestamp) from the ranking', () => {
    const testResult = {
      eventsTested: 2,
      eventsMatched: 2,
      matchRatePercent: 100,
      matchedEvents: [
        matchEntry(0, { '@timestamp': '2026-08-19T10:00:00Z', message: 'unique message A', user: { name: 'alice' } }),
        matchEntry(1, { '@timestamp': '2026-08-19T10:00:01Z', message: 'unique message B', user: { name: 'alice' } }),
      ],
    };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [] });
    expect(fp.topFalsePositiveFields.some((p) => p.field === '@timestamp' || p.field === 'message')).toBe(false);
    expect(fp.topFalsePositiveFields.some((p) => p.field === 'user.name')).toBe(true);
  });

  test('handles zero potential false positives without throwing or producing NaN', () => {
    const testResult = { eventsTested: 2, eventsMatched: 2, matchRatePercent: 100, matchedEvents: [matchEntry(0, {}), matchEntry(1, {})] };
    const fp = analyzeFalsePositives(testResult, { matchedEventIndexes: [0, 1] });
    expect(fp.potentialFalsePositiveCount).toBe(0);
    expect(fp.recommendedExclusions).toEqual([]);
    expect(fp.topFalsePositiveFields).toEqual([]);
  });
});
