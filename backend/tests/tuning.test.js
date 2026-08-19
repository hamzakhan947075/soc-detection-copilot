'use strict';

const { recommendTuning } = require('../src/tuning/tuning');

function authEvent(ip, outcome, offsetSec) {
  return {
    '@timestamp': new Date(Date.UTC(2026, 7, 19, 10, 0, offsetSec)).toISOString(),
    source: { ip },
    event: { category: 'authentication', outcome },
  };
}

describe('recommendTuning - verified before/after false-positive rate', () => {
  test('reports a verified improvement when the higher threshold genuinely gets under the ceiling', () => {
    // 20 failures from one IP (all real detection evidence) + 5 unrelated
    // failures from a second IP (not part of the original evidence -> FPs).
    const evidenceEvents = Array.from({ length: 20 }, (_, i) => authEvent('4.4.4.4', 'failure', i));
    const noiseEvents = Array.from({ length: 5 }, (_, i) => authEvent('5.5.5.5', 'failure', 100 + i));
    const events = [...evidenceEvents, ...noiseEvents];

    const rule = {
      conditions: [{ field: 'event.category', value: 'authentication' }, { field: 'event.outcome', value: 'failure' }],
      threshold: { count: 3 },
      groupingFields: ['source.ip'],
    };
    const detection = { matchedEventIndexes: evidenceEvents.map((_, i) => i) }; // only the 20 real events are "real" evidence

    // Before: threshold 3 matches everything (both IPs clear 3 events) -> high FP rate (5/25 = 20%, still above 10% ceiling)
    const fpAnalysisBefore = { eventsMatched: 25, falsePositiveRatePercent: 20 };
    const tuning = recommendTuning(rule, fpAnalysisBefore, events, detection);

    expect(tuning.applicable).toBe(true);
    expect(tuning.suggestedThreshold).toBeGreaterThan(3);
    expect(tuning.after.falsePositiveRatePercent).not.toBeNull();
    // At a higher threshold, the noise IP (5 events) no longer clears it, but the evidence IP (20 events) still does -> FP rate should drop to 0%.
    expect(tuning.after.falsePositiveRatePercent).toBe(0);
    expect(tuning.verifiedImprovement).toBe(true);
    expect(tuning.reason).toMatch(/verified/);
  });

  test('does not claim a verified improvement when the original detection is unavailable to re-check against', () => {
    const events = Array.from({ length: 8 }, (_, i) => authEvent('4.4.4.4', 'failure', i));
    const rule = { conditions: [{ field: 'event.category', value: 'authentication' }], threshold: { count: 5 }, groupingFields: ['source.ip'] };
    const fpAnalysisBefore = { eventsMatched: 8, falsePositiveRatePercent: 30 };

    const tuning = recommendTuning(rule, fpAnalysisBefore, events, null);
    expect(tuning.verifiedImprovement).toBeNull();
    expect(tuning.after.falsePositiveRatePercent).toBeNull();
    expect(tuning.reason).toMatch(/could not be re-verified/);
  });

  test('regression: does not claim a verified improvement when the raw formula would raise the threshold high enough to also destroy the true positives', () => {
    // 12 real evidence events + 10 noisy events sharing the same rule
    // conditions -> a naive proportional-scaling threshold overshoots far
    // past 12 (the actual evidence size), "fixing" the FP rate only by
    // matching nothing at all - including the real evidence.
    const evidenceEvents = Array.from({ length: 12 }, (_, i) => authEvent('198.51.100.5', 'failure', i));
    const noiseEvents = Array.from({ length: 10 }, (_, i) => authEvent('203.0.113.77', 'failure', 3600 + i));
    const events = [...evidenceEvents, ...noiseEvents];

    const rule = {
      conditions: [{ field: 'event.category', value: 'authentication' }, { field: 'event.outcome', value: 'failure' }],
      threshold: { count: 10 },
      groupingFields: ['source.ip'],
    };
    const detection = { matchedEventIndexes: evidenceEvents.map((_, i) => i) }; // only the 12 evidence events are real

    const fpAnalysisBefore = { eventsMatched: 22, falsePositiveRatePercent: 45.45 };
    const tuning = recommendTuning(rule, fpAnalysisBefore, events, detection);

    // The raw formula (10 * 4.545 ~= 45) would exceed the 12-event evidence
    // group entirely; the cap must keep the suggestion at or below 12.
    expect(tuning.suggestedThreshold).toBeLessThanOrEqual(12);
    expect(tuning.after.truePositiveCount).toBeGreaterThan(0);
    expect(tuning.verifiedImprovement).toBe(true);
  });

  test('reports no applicable change, and a null verifiedImprovement, when the current FP rate is already acceptable', () => {
    const rule = { threshold: { count: 10 }, groupingFields: ['source.ip'], conditions: [] };
    const fpAnalysis = { falsePositiveRatePercent: 5, eventsMatched: 10 };
    const tuning = recommendTuning(rule, fpAnalysis, [], { matchedEventIndexes: [] });
    expect(tuning.suggestedThreshold).toBe(tuning.currentThreshold);
    expect(tuning.verifiedImprovement).toBeNull();
    expect(tuning.after).toBeNull();
  });
});
